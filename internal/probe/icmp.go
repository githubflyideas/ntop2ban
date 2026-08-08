package probe

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// ICMP 探测。纯 syscall,无第三方依赖(算法搬自 pingping)。
//
// socket 选择优先 SOCK_DGRAM/IPPROTO_ICMP:它不需要 root,只要
// sysctl net.ipv4.ping_group_range 允许当前 gid。失败才回退 SOCK_RAW
// (需要 root 或 CAP_NET_RAW)。ntop2ban 本来就以 root 跑,但保留这个
// 优先顺序有实际好处——DGRAM socket 只收到自己发出去的那些回包,
// RAW socket 会收到本机所有 ICMP 回包,后者需要靠 id+nonce 自行隔离。

const icmpMagic = "ntop2banp1"

// icmpRound 对 host 发 packets 个 echo request,收集 RTT。
func icmpRound(host string, packets int, gap, timeout time.Duration) (Round, error) {
	r := Round{At: time.Now(), Sent: packets}

	ip, err := resolveIPv4(host)
	if err != nil {
		return r, err
	}

	fd, raw, err := icmpSocket()
	if err != nil {
		return r, fmt.Errorf("probe: 创建 ICMP socket 失败(需要 ping_group_range 或 CAP_NET_RAW): %w", err)
	}
	defer unix.Close(fd)

	id := os.Getpid() & 0xffff
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return r, err
	}
	dst := &unix.SockaddrInet4{Addr: ip}

	sendAt := make([]time.Time, packets)
	got := make([]bool, packets)

	for i := 0; i < packets; i++ {
		pkt := buildEcho(id, i, nonce)
		sendAt[i] = time.Now()
		if err := unix.Sendto(fd, pkt, 0, dst); err != nil {
			// 单包发送失败不终止整轮:一次 ENOBUFS 不代表链路不可用,
			// 那个包记为丢失即可,继续发后面的。
			continue
		}
		collect(fd, raw, id, nonce, sendAt, got, &r, time.Now().Add(gap))
	}
	// 尾窗:等最后一批还在路上的回包。没有这一步,最后几个包会被
	// 系统性地记成丢失——一轮 20 包能凭空多出 5% 丢包率。
	collect(fd, raw, id, nonce, sendAt, got, &r, time.Now().Add(timeout))
	return r, nil
}

func icmpSocket() (fd int, raw bool, err error) {
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
	if err == nil {
		return fd, false, nil
	}
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	return fd, true, err
}

// buildEcho 造一个带魔数与 nonce 的 echo request。
//
// 魔数 + nonce 不是为了安全,是为了在 RAW socket 上把自己的回包与
// 本机其他进程(以及另一个探测目标)的 ICMP 流量区分开——否则并发
// 探测多个目标时,A 的回包会被 B 当成自己的,RTT 全错。
func buildEcho(id, seq int, nonce [4]byte) []byte {
	p := make([]byte, 8+len(icmpMagic)+4)
	p[0] = 8 // echo request
	binary.BigEndian.PutUint16(p[4:6], uint16(id))
	binary.BigEndian.PutUint16(p[6:8], uint16(seq))
	copy(p[8:], icmpMagic)
	copy(p[8+len(icmpMagic):], nonce[:])
	binary.BigEndian.PutUint16(p[2:4], icmpChecksum(p))
	return p
}

// collect 在 deadline 前持续收包,匹配到未回收的 seq 就记 RTT。
//
// 乱序与迟到的回包都能被后续窗口捞回,RTT 按各自的 sendAt 计算而不是
// "收到的顺序",所以不失真——这一点对判断抖动很关键:如果按顺序配对,
// 一个迟到的包会让后面所有包的 RTT 都算错。
func collect(fd int, raw bool, id int, nonce [4]byte, sendAt []time.Time, got []bool, r *Round, deadline time.Time) {
	buf := make([]byte, 1500)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			return
		}
		wait := remain
		if wait > 50*time.Millisecond {
			wait = 50 * time.Millisecond // 50ms 一跳,保证能按时退出
		}
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		tv := unix.NsecToTimeval(wait.Nanoseconds())
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			return
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		now := time.Now()
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue
			}
			return
		}

		pkt := buf[:n]
		if raw && n >= 20 { // RAW socket 带 IP 头,剥掉
			ihl := int(pkt[0]&0x0f) * 4
			if n <= ihl {
				continue
			}
			pkt = pkt[ihl:n]
		}
		if len(pkt) < 8+len(icmpMagic)+4 || pkt[0] != 0 { // 只认 echo reply
			continue
		}
		if raw && int(binary.BigEndian.Uint16(pkt[4:6])) != id {
			continue
		}
		if string(pkt[8:8+len(icmpMagic)]) != icmpMagic ||
			string(pkt[8+len(icmpMagic):8+len(icmpMagic)+4]) != string(nonce[:]) {
			continue
		}
		seq := int(binary.BigEndian.Uint16(pkt[6:8]))
		if seq < 0 || seq >= len(sendAt) || got[seq] {
			continue
		}
		got[seq] = true
		r.Recv++
		r.RTTs = append(r.RTTs, float64(now.Sub(sendAt[seq]).Microseconds())/1000.0)
	}
}

func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 > 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func resolveIPv4(host string) ([4]byte, error) {
	var out [4]byte
	ips, err := net.LookupIP(host)
	if err != nil {
		return out, err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			copy(out[:], v4)
			return out, nil
		}
	}
	return out, fmt.Errorf("probe: %q 没有 IPv4 地址", host)
}

// tcpRound 用 TCP 连接建立耗时作为 RTT。
//
// 连上就立刻关闭:探测只关心握手耗时,不发任何数据。被拒绝(RST)也算
// "可达"——目标在线只是端口关着,这与超时(丢包/不可达)是不同的信息,
// 混为一谈会让"服务挂了"和"网络断了"看起来一样。
func tcpRound(addr string, packets int, gap, timeout time.Duration) Round {
	r := Round{At: time.Now(), Sent: packets}
	for i := 0; i < packets; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, timeout)
		elapsed := time.Since(start)
		if err == nil {
			conn.Close()
			r.Recv++
			r.RTTs = append(r.RTTs, float64(elapsed.Microseconds())/1000.0)
		} else if isRefused(err) {
			r.Recv++
			r.RTTs = append(r.RTTs, float64(elapsed.Microseconds())/1000.0)
		}
		if i < packets-1 {
			time.Sleep(gap)
		}
	}
	return r
}

// isRefused 判断错误是否为 ECONNREFUSED。
//
// 用 errors.Is 而不是字符串匹配:错误信息会随 Go 版本与语言环境变化,
// 字符串匹配在某些环境下会静默失效——表现为"端口关着的目标被记成丢包",
// 于是丢包图上凭空出现 100% 丢包。
func isRefused(err error) bool {
	return errors.Is(err, unix.ECONNREFUSED)
}
