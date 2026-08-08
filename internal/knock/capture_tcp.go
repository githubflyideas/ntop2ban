package knock

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// TCP 敲门步的捕获:AF_PACKET socket + cBPF 过滤,只看 SYN。
//
// 为什么不用 net.Listen 监听那几个敲门端口:那样端口在扫描器眼里是
// **开着的**。虽然猜不出序列,但暴露了"这台机器有几个奇怪端口在听"
// 这个信号,与 knock 的初衷(让机器看起来什么都没有)相悖。用
// AF_PACKET 旁听,端口保持关闭、内核照常回 RST,扫描器看到的就是
// 普通的关闭端口。
//
// 为什么不用 XDP:一张网卡同时只能挂一个 XDP 程序,而 xdp-ban 的封禁
// 程序已经占了生产网卡那个位置——敲门也必须在生产网卡上看包,直接冲突。
// 而且敲门一分钟就几个包,XDP 那套线速处理能力毫无用处,换来的却是
// clang + libbpf 构建链和网卡驱动兼容性问题。cBPF 在这里是正确的量级。
//
// cBPF 而非 eBPF:cBPF 字节码可以用纯 Go 的 golang.org/x/net/bpf 在运行时
// 汇编出来,不需要编译期的 clang,ntop2ban 因此保持 `go build` 一步出二进制。

const ethHdrLen = 14

// tcpCapture 是一个 AF_PACKET 抓包 socket,内核侧已按敲门端口过滤。
type tcpCapture struct {
	fd int
}

// openTCPCapture 在 iface 上打开抓包 socket,只放行目的端口属于 ports
// 的 TCP SYN 包。iface 为空表示不绑定具体网卡(收所有网卡)。
//
// 过滤在内核侧做(SO_ATTACH_FILTER)而不是读上来再判断:生产网卡上
// 每秒可能几十万包,全部拷到用户态再丢弃是纯粹的浪费,而且会让敲门
// 进程成为整机性能问题的来源。
func openTCPCapture(iface string, ports []int) (*tcpCapture, error) {
	if len(ports) == 0 {
		return nil, fmt.Errorf("knock: 没有需要监听的 TCP 敲门端口")
	}

	prog, err := assembleTCPSYNFilter(ports)
	if err != nil {
		return nil, err
	}

	// htons(ETH_P_ALL):AF_PACKET 的 protocol 字段是网络字节序。
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("knock: 创建 AF_PACKET socket 失败(需要 root 或 CAP_NET_RAW): %w", err)
	}
	c := &tcpCapture{fd: fd}

	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, prog); err != nil {
		c.Close()
		return nil, fmt.Errorf("knock: 挂载 cBPF 过滤器失败: %w", err)
	}

	if iface != "" {
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("knock: 查找网卡 %q: %w", iface, err)
		}
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{
			Protocol: htons(unix.ETH_P_ALL),
			Ifindex:  ifi.Index,
		}); err != nil {
			c.Close()
			return nil, fmt.Errorf("knock: 绑定网卡 %q: %w", iface, err)
		}
	}
	return c, nil
}

func (c *tcpCapture) Close() error {
	if c.fd >= 0 {
		err := unix.Close(c.fd)
		c.fd = -1
		return err
	}
	return nil
}

// Read 阻塞读一个包,返回来源 IP 与目的端口。
//
// 超时靠 SO_RCVTIMEO:没有超时的话关闭流程会卡在 read 上等到下一个包,
// 而敲门端口可能几小时都没有流量。
func (c *tcpCapture) Read(buf []byte, timeout time.Duration) (net.IP, int, error) {
	tv := unix.NsecToTimeval(timeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, 0, err
	}
	n, _, err := unix.Recvfrom(c.fd, buf, 0)
	if err != nil {
		return nil, 0, err
	}
	return parseTCPSYN(buf[:n])
}

// tcpSYNFilterInstructions 生成 cBPF 指令序列:
// 以太网 IPv4 → TCP → 非分片 → SYN 且非 ACK → 目的端口在集合内。
//
// 逐条说明为什么每个检查都不能省:
//   - 只认 IPv4(ethertype):IPv6 头部处理完全不同,混进来会让后面的
//     偏移量全错。
//   - 非分片:分片包的后续片没有 TCP 头,按偏移读端口会读到载荷数据。
//   - SYN 且非 ACK:只认连接的第一个包。SYN+ACK 是本机发出连接的回包
//     方向,算进去会让本机自己的出站连接被误判成敲门。
//   - IP 头长度用 LoadMemShift 动态取(IHL 可变,带 option 时不是 20):
//     写死 20 会在带 option 的包上读错端口。
//
// 跳转偏移不手算:先按固定布局排好指令,再回填 reject/accept 的相对
// 距离。手算偏移是这类代码最常见的错误来源,而且错了不会报错——
// 过滤器会静默地放行或丢弃错误的包。
func tcpSYNFilterInstructions(ports []int) []bpf.Instruction {
	n := len(ports)

	insts := []bpf.Instruction{
		/* 0 */ bpf.LoadAbsolute{Off: 12, Size: 2}, // ethertype
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0x0800}, // -> reject
		/* 2 */ bpf.LoadAbsolute{Off: ethHdrLen + 9, Size: 1}, // ip.protocol
		/* 3 */ bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: unix.IPPROTO_TCP}, // -> reject
		/* 4 */ bpf.LoadAbsolute{Off: ethHdrLen + 6, Size: 2}, // flags+frag off
		/* 5 */ bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff}, // 分片 -> reject
		/* 6 */ bpf.LoadMemShift{Off: ethHdrLen}, // X = IHL*4
		/* 7 */ bpf.LoadIndirect{Off: ethHdrLen + 13, Size: 1}, // tcp flags
		/* 8 */ bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x12}, // SYN|ACK
		/* 9 */ bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0x02}, // 非纯 SYN -> reject
		/*10 */ bpf.LoadIndirect{Off: ethHdrLen + 2, Size: 2}, // tcp dst port
	}
	// 11 .. 11+n-1: 每个端口一条比较,命中 -> accept
	for _, p := range ports {
		insts = append(insts, bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(uint16(p))})
	}
	rejectIdx := 11 + n
	acceptIdx := rejectIdx + 1
	insts = append(insts,
		bpf.RetConstant{Val: 0},      // reject:丢弃
		bpf.RetConstant{Val: 0xffff}, // accept:整包收下
	)

	// 回填跳转距离。cBPF 的 skip 是"跳过多少条",即 目标下标-自身下标-1。
	for _, i := range []int{1, 3, 5, 9} {
		j := insts[i].(bpf.JumpIf)
		j.SkipTrue = uint8(rejectIdx - i - 1)
		insts[i] = j
	}
	for k := 0; k < n; k++ {
		i := 11 + k
		j := insts[i].(bpf.JumpIf)
		j.SkipTrue = uint8(acceptIdx - i - 1)
		insts[i] = j
	}
	return insts
}

func assembleTCPSYNFilter(ports []int) (*unix.SockFprog, error) {
	raw, err := bpf.Assemble(tcpSYNFilterInstructions(ports))
	if err != nil {
		return nil, fmt.Errorf("knock: 汇编 cBPF 过滤器: %w", err)
	}
	filters := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		filters[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	return &unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}, nil
}

// parseTCPSYN 从链路层帧里取出来源 IP 与目的端口。
// 到这里的包已经被 cBPF 过滤过,但仍做长度检查——过滤器保证的是
// "字段位置上的值符合条件",不保证包没被截断。
func parseTCPSYN(frame []byte) (net.IP, int, error) {
	if len(frame) < ethHdrLen+20 {
		return nil, 0, fmt.Errorf("knock: 帧过短: %d 字节", len(frame))
	}
	ip := frame[ethHdrLen:]
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+4 {
		return nil, 0, fmt.Errorf("knock: IP 头长度异常: %d", ihl)
	}
	src := net.IPv4(ip[12], ip[13], ip[14], ip[15])
	tcp := ip[ihl:]
	return src, int(tcp[2])<<8 | int(tcp[3]), nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }
