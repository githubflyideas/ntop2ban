package knock

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// buildEthIPv4TCP 造一个以太网 + IPv4 + TCP 的帧,用于测试过滤器与解析。
// ihlWords 允许造出带 IP option 的头(>5),这是 parseTCPSYN 最容易错的地方。
func buildEthIPv4TCP(t *testing.T, src, dst string, sport, dport int, flags byte, ihlWords int, fragOff uint16) []byte {
	t.Helper()
	if ihlWords < 5 {
		t.Fatalf("ihlWords must be >= 5, got %d", ihlWords)
	}
	ihl := ihlWords * 4
	frame := make([]byte, ethHdrLen+ihl+20)

	// 以太网:ethertype IPv4
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)

	ip := frame[ethHdrLen:]
	ip[0] = 0x40 | byte(ihlWords) // version 4 + IHL
	ip[9] = unix.IPPROTO_TCP
	binary.BigEndian.PutUint16(ip[6:8], fragOff)
	copy(ip[12:16], net.ParseIP(src).To4())
	copy(ip[16:20], net.ParseIP(dst).To4())

	tcp := ip[ihl:]
	binary.BigEndian.PutUint16(tcp[0:2], uint16(sport))
	binary.BigEndian.PutUint16(tcp[2:4], uint16(dport))
	tcp[13] = flags
	return frame
}

const (
	tcpSYN    = 0x02
	tcpSYNACK = 0x12
	tcpACK    = 0x10
)

// runFilter 在纯 Go 的 cBPF 虚拟机里跑过滤器,返回它是否放行这个包。
//
// 这是这批测试的关键手段:cBPF 的跳转偏移写错不会有任何报错,过滤器
// 只会静默地放行或丢弃错误的包——线上表现为"敲门偶尔不生效",几乎
// 无法从现象反推。用 bpf.NewVM 在单元测试里直接验证过滤语义,把这类
// 错误挡在提交之前,而且不需要 root、不需要真实网卡。
func runFilter(t *testing.T, ports []int, frame []byte) bool {
	t.Helper()
	vm, err := bpf.NewVM(tcpSYNFilterInstructions(ports))
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	n, err := vm.Run(frame)
	if err != nil {
		t.Fatalf("vm.Run: %v", err)
	}
	return n > 0
}

// TestFilterAcceptsKnockPortSYN 目标端口在集合内的纯 SYN 必须放行。
func TestFilterAcceptsKnockPortSYN(t *testing.T) {
	ports := []int{9001, 9003}
	for _, p := range ports {
		frame := buildEthIPv4TCP(t, "203.0.113.7", "198.51.100.1", 40000, p, tcpSYN, 5, 0)
		if !runFilter(t, ports, frame) {
			t.Errorf("端口 %d 的 SYN 应被放行", p)
		}
	}
}

// TestFilterRejectsOtherPorts 不在集合内的端口必须丢弃,否则任意端口的
// 连接都会被当成敲门步,序列形同虚设。
func TestFilterRejectsOtherPorts(t *testing.T) {
	ports := []int{9001, 9003}
	for _, p := range []int{22, 80, 9000, 9002, 9004} {
		frame := buildEthIPv4TCP(t, "203.0.113.7", "198.51.100.1", 40000, p, tcpSYN, 5, 0)
		if runFilter(t, ports, frame) {
			t.Errorf("端口 %d 不在敲门集合内,不应放行", p)
		}
	}
}

// TestFilterRejectsSYNACKAndACK 只认纯 SYN。
//
// SYN+ACK 是本机主动发起连接后对方的回包方向;如果放行它,本机自己
// 连出去的连接会被误当成敲门——那意味着任何一次出站连接都可能凑出
// 敲门序列,而且是本机自己触发的,排查时完全想不到这个方向。
func TestFilterRejectsSYNACKAndACK(t *testing.T) {
	ports := []int{9001}
	for name, flags := range map[string]byte{"SYN+ACK": tcpSYNACK, "ACK": tcpACK} {
		frame := buildEthIPv4TCP(t, "203.0.113.7", "198.51.100.1", 40000, 9001, flags, 5, 0)
		if runFilter(t, ports, frame) {
			t.Errorf("%s 不应被放行(只认纯 SYN)", name)
		}
	}
}

// TestFilterRejectsFragments 分片包的后续片没有 TCP 头,按偏移读端口
// 会读到载荷数据——可能恰好等于某个敲门端口,凭空产生一步。
func TestFilterRejectsFragments(t *testing.T) {
	ports := []int{9001}
	frame := buildEthIPv4TCP(t, "203.0.113.7", "198.51.100.1", 40000, 9001, tcpSYN, 5, 0x0001)
	if runFilter(t, ports, frame) {
		t.Error("分片包不应被放行")
	}
}

// TestFilterRejectsNonIPv4 非 IPv4 的 ethertype 必须早退:IPv6 头部长度
// 处理完全不同,继续按 IPv4 偏移读会全错。
func TestFilterRejectsNonIPv4(t *testing.T) {
	ports := []int{9001}
	frame := buildEthIPv4TCP(t, "203.0.113.7", "198.51.100.1", 40000, 9001, tcpSYN, 5, 0)
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd) // IPv6
	if runFilter(t, ports, frame) {
		t.Error("非 IPv4 不应被放行")
	}
}

// TestFilterRejectsNonTCP 协议号不是 TCP 的包必须丢弃。
func TestFilterRejectsNonTCP(t *testing.T) {
	ports := []int{9001}
	frame := buildEthIPv4TCP(t, "203.0.113.7", "198.51.100.1", 40000, 9001, tcpSYN, 5, 0)
	frame[ethHdrLen+9] = unix.IPPROTO_UDP
	if runFilter(t, ports, frame) {
		t.Error("非 TCP 不应被放行")
	}
}

// TestFilterHandlesIPOptions 带 IP option 的包(IHL>5)端口位置会后移。
// 过滤器用 LoadMemShift 动态取头长,这个测试守住那一点——写死 20 的话
// 这类包会读错端口,而带 option 的包在真实网络里确实存在。
func TestFilterHandlesIPOptions(t *testing.T) {
	ports := []int{9001}
	frame := buildEthIPv4TCP(t, "203.0.113.7", "198.51.100.1", 40000, 9001, tcpSYN, 8, 0)
	if !runFilter(t, ports, frame) {
		t.Error("带 IP option 的 SYN 应被正确识别并放行")
	}
}

// TestFilterSingleAndManyPorts 端口数量影响跳转偏移的回填,1 个和 8 个
// (Validate 允许的上限)都要正确。
func TestFilterSingleAndManyPorts(t *testing.T) {
	single := []int{9001}
	frame := buildEthIPv4TCP(t, "203.0.113.7", "198.51.100.1", 40000, 9001, tcpSYN, 5, 0)
	if !runFilter(t, single, frame) {
		t.Error("单端口集合应放行该端口")
	}

	many := []int{9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008}
	for _, p := range many {
		f := buildEthIPv4TCP(t, "203.0.113.7", "198.51.100.1", 40000, p, tcpSYN, 5, 0)
		if !runFilter(t, many, f) {
			t.Errorf("8 端口集合:端口 %d 应放行", p)
		}
	}
	f := buildEthIPv4TCP(t, "203.0.113.7", "198.51.100.1", 40000, 9999, tcpSYN, 5, 0)
	if runFilter(t, many, f) {
		t.Error("8 端口集合:集合外端口不应放行")
	}
}

func TestParseTCPSYN(t *testing.T) {
	frame := buildEthIPv4TCP(t, "203.0.113.7", "198.51.100.1", 40000, 9003, tcpSYN, 5, 0)
	src, port, err := parseTCPSYN(frame)
	if err != nil {
		t.Fatalf("parseTCPSYN: %v", err)
	}
	if !src.Equal(net.ParseIP("203.0.113.7")) {
		t.Errorf("src: want 203.0.113.7, got %s", src)
	}
	if port != 9003 {
		t.Errorf("port: want 9003, got %d", port)
	}
}

// TestParseTCPSYNWithIPOptions 解析侧也必须按 IHL 动态定位 TCP 头。
func TestParseTCPSYNWithIPOptions(t *testing.T) {
	frame := buildEthIPv4TCP(t, "192.0.2.5", "198.51.100.1", 40000, 9001, tcpSYN, 7, 0)
	src, port, err := parseTCPSYN(frame)
	if err != nil {
		t.Fatalf("parseTCPSYN: %v", err)
	}
	if !src.Equal(net.ParseIP("192.0.2.5")) || port != 9001 {
		t.Errorf("带 option 时解析错误: src=%s port=%d", src, port)
	}
}

// TestParseTCPSYNRejectsTruncated 过滤器保证字段值符合条件,不保证包
// 没被截断——解析侧必须自己检查,否则会越界 panic 把整个进程带走。
func TestParseTCPSYNRejectsTruncated(t *testing.T) {
	frame := buildEthIPv4TCP(t, "203.0.113.7", "198.51.100.1", 40000, 9001, tcpSYN, 5, 0)
	for _, n := range []int{0, 10, ethHdrLen, ethHdrLen + 10} {
		if _, _, err := parseTCPSYN(frame[:n]); err == nil {
			t.Errorf("截断到 %d 字节应报错而不是越界", n)
		}
	}
}
