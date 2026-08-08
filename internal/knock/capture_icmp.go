package knock

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// ICMP 敲门步的捕获:raw ICMP socket。
//
// 用 SOCK_RAW/IPPROTO_ICMP 而不是 AF_PACKET:内核会把收到的 ICMP 包
// 复制一份上来,不需要自己解析以太网头,而且**不影响内核照常回 ping**
// ——普通 ping 该通还是通,敲门只是旁听,行为上完全无副作用。这一点
// 很重要:如果敲门让 ping 不通了,运维排查网络时会被误导。
//
// 关心的是 ICMP echo request 的 payload 长度,也就是客户端 `ping -s N`
// 里那个 N。这样敲门用系统自带的 ping 就能完成,不需要任何自制工具。
type icmpCapture struct {
	fd int
}

func openICMPCapture() (*icmpCapture, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		return nil, fmt.Errorf("knock: 创建 raw ICMP socket 失败(需要 root 或 CAP_NET_RAW): %w", err)
	}
	return &icmpCapture{fd: fd}, nil
}

func (c *icmpCapture) Close() error {
	if c.fd >= 0 {
		err := unix.Close(c.fd)
		c.fd = -1
		return err
	}
	return nil
}

// Read 读一个 ICMP 包,返回来源 IP 与 echo request 的 payload 长度。
//
// 只认 echo request(type 8):echo reply 是本机 ping 别人得到的回包,
// 把它算进来会让本机自己发起的 ping 变成敲门事件。
func (c *icmpCapture) Read(buf []byte, timeout time.Duration) (net.IP, int, error) {
	tv := unix.NsecToTimeval(timeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, 0, err
	}
	n, _, err := unix.Recvfrom(c.fd, buf, 0)
	if err != nil {
		return nil, 0, err
	}
	return parseICMPEcho(buf[:n])
}

// parseICMPEcho 解析 raw ICMP socket 收到的包(带 IP 头)。
//
// 返回的长度是 **ICMP payload 长度**,即 `ping -s N` 的 N:
// 整个 IP 报文 - IP 头 - ICMP 头(8 字节)。这样界面上写
// `ping -s 56` 与守护进程比对的值是同一个数,用户不需要做任何换算——
// 如果这里返回的是包含 ICMP 头的长度,用户按界面提示敲就永远敲不开,
// 而且没有任何线索说明差在哪。
func parseICMPEcho(pkt []byte) (net.IP, int, error) {
	if len(pkt) < 20 {
		return nil, 0, fmt.Errorf("knock: ICMP 包过短: %d 字节", len(pkt))
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return nil, 0, fmt.Errorf("knock: IP 头长度异常: %d", ihl)
	}
	src := net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15])

	icmp := pkt[ihl:]
	const icmpTypeEchoRequest = 8
	if icmp[0] != icmpTypeEchoRequest {
		return nil, 0, errNotEchoRequest
	}
	payloadLen := len(icmp) - 8
	if payloadLen < 0 {
		return nil, 0, fmt.Errorf("knock: ICMP 载荷长度为负")
	}
	return src, payloadLen, nil
}

// errNotEchoRequest 不是错误条件,只是"这个包不关心"。单独定义以便
// 捕获循环安静地跳过,而不是把它当异常打日志——本机每一次 ping 的
// 回包都会走到这里,当异常记会瞬间刷满日志。
var errNotEchoRequest = fmt.Errorf("knock: 非 echo request")
