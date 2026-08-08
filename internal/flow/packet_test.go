package flow

import (
	"encoding/binary"
	"net"
	"testing"
)

// buildEth 造以太网帧。vlan>0 时插入 802.1Q tag。
func buildEth(t *testing.T, vlan uint16, ipPayload []byte) []byte {
	t.Helper()
	hdr := make([]byte, 0, 18)
	hdr = append(hdr, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55) // dst mac
	hdr = append(hdr, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff) // src mac
	if vlan > 0 {
		hdr = append(hdr, 0x81, 0x00)
		tag := make([]byte, 2)
		binary.BigEndian.PutUint16(tag, vlan)
		hdr = append(hdr, tag...)
	}
	hdr = append(hdr, 0x08, 0x00) // IPv4
	return append(hdr, ipPayload...)
}

// buildIPv4 造 IPv4 报文。totalLen 为 0 时按实际长度填。
func buildIPv4(t *testing.T, proto uint8, sport, dport uint16, ihlWords int, fragOff uint16, totalLen int, l4extra int, tcpFlags uint16) []byte {
	t.Helper()
	ihl := ihlWords * 4
	l4len := 4 + l4extra
	pkt := make([]byte, ihl+l4len)
	pkt[0] = 0x40 | byte(ihlWords)
	pkt[9] = proto
	binary.BigEndian.PutUint16(pkt[6:8], fragOff)
	if totalLen == 0 {
		totalLen = ihl + l4len
	}
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	copy(pkt[12:16], net.ParseIP("203.0.113.7").To4())
	copy(pkt[16:20], net.ParseIP("198.51.100.1").To4())

	l4 := pkt[ihl:]
	binary.BigEndian.PutUint16(l4[0:2], sport)
	binary.BigEndian.PutUint16(l4[2:4], dport)
	if proto == 6 && len(l4) >= 14 {
		binary.BigEndian.PutUint16(l4[12:14], tcpFlags)
	}
	return pkt
}

func TestParseIPv4TCP(t *testing.T) {
	pkt := buildIPv4(t, 6, 40000, 443, 5, 0, 0, 16, 0x0018) // PSH+ACK
	p, err := ParseIPv4(pkt)
	if err != nil {
		t.Fatalf("ParseIPv4: %v", err)
	}
	if !p.SrcIP.Equal(net.ParseIP("203.0.113.7")) || !p.DstIP.Equal(net.ParseIP("198.51.100.1")) {
		t.Errorf("IP: src=%s dst=%s", p.SrcIP, p.DstIP)
	}
	if p.SrcPort != 40000 || p.DstPort != 443 {
		t.Errorf("端口: src=%d dst=%d", p.SrcPort, p.DstPort)
	}
	if p.Protocol != 6 {
		t.Errorf("协议: want 6, got %d", p.Protocol)
	}
	if p.TCPFlags != 0x0018 {
		t.Errorf("TCP flags: want 0x18, got 0x%x", p.TCPFlags)
	}
}

func TestParseIPv4UDP(t *testing.T) {
	pkt := buildIPv4(t, 17, 53000, 53, 5, 0, 0, 4, 0)
	p, err := ParseIPv4(pkt)
	if err != nil {
		t.Fatalf("ParseIPv4: %v", err)
	}
	if p.SrcPort != 53000 || p.DstPort != 53 || p.Protocol != 17 {
		t.Errorf("解析错误: %+v", p)
	}
}

// TestParseIPv4ICMPHasNoPorts ICMP 没有端口,不该把 type/code 填进端口
// 字段——那会让 Top Port 视图里出现莫名其妙的端口号。
func TestParseIPv4ICMPHasNoPorts(t *testing.T) {
	pkt := buildIPv4(t, 1, 0x0800, 0, 5, 0, 0, 4, 0)
	p, err := ParseIPv4(pkt)
	if err != nil {
		t.Fatalf("ParseIPv4: %v", err)
	}
	if p.SrcPort != 0 || p.DstPort != 0 {
		t.Errorf("ICMP 端口应为 0, got src=%d dst=%d", p.SrcPort, p.DstPort)
	}
	if p.Protocol != 1 {
		t.Errorf("协议: want 1, got %d", p.Protocol)
	}
}

// TestParseIPv4OtherProtoStillCounted GRE/ESP 等协议仍是真实流量,
// 应该计入总量,只是没有端口维度。返回错误会让它们从统计里消失。
func TestParseIPv4OtherProtoStillCounted(t *testing.T) {
	for _, proto := range []uint8{47, 50, 132} {
		pkt := buildIPv4(t, proto, 1234, 5678, 5, 0, 0, 4, 0)
		p, err := ParseIPv4(pkt)
		if err != nil {
			t.Errorf("协议 %d 不该报错: %v", proto, err)
			continue
		}
		if p.Protocol != proto {
			t.Errorf("协议: want %d, got %d", proto, p.Protocol)
		}
		if p.Length == 0 {
			t.Errorf("协议 %d 应有长度", proto)
		}
	}
}

// TestParseUsesIPTotalLengthNotCapturedBytes 这是三种输入口径一致的关键。
//
// sFlow 只带包头前 128/256 字节,AF_PACKET 可能被 snaplen 截断。用抓到的
// 字节数统计会让所有流量数字系统性缩水,而且没有任何报错——只会让人
// 以为链路比实际空闲。必须用 IP 头声明的 total length。
func TestParseUsesIPTotalLengthNotCapturedBytes(t *testing.T) {
	// 声明 1500,实际只给了 20+4 字节(模拟 sFlow 只带包头)
	pkt := buildIPv4(t, 6, 40000, 443, 5, 0, 1500, 0, 0)
	p, err := ParseIPv4(pkt)
	if err != nil {
		t.Fatalf("ParseIPv4: %v", err)
	}
	if p.Length != 1500 {
		t.Errorf("应采用 IP 头声明的总长 1500(而非抓到的 %d 字节), got %d",
			len(pkt), p.Length)
	}
}

// TestParseHandlesIPOptions IHL>5 时传输层头位置后移。写死 20 会读错端口。
func TestParseHandlesIPOptions(t *testing.T) {
	pkt := buildIPv4(t, 6, 12345, 8080, 8, 0, 0, 16, 0)
	p, err := ParseIPv4(pkt)
	if err != nil {
		t.Fatalf("ParseIPv4: %v", err)
	}
	if p.SrcPort != 12345 || p.DstPort != 8080 {
		t.Errorf("带 IP option 时端口解析错误: src=%d dst=%d", p.SrcPort, p.DstPort)
	}
}

// TestParseRejectsFragments 分片包的后续片没有传输层头,按偏移读端口
// 读到的是载荷,可能凭空造出一条五元组完全错误的流。
func TestParseRejectsFragments(t *testing.T) {
	pkt := buildIPv4(t, 6, 40000, 443, 5, 0x0001, 0, 16, 0)
	if _, err := ParseIPv4(pkt); err != ErrFragment {
		t.Errorf("want ErrFragment, got %v", err)
	}
}

func TestParseRejectsTruncatedAndNonIPv4(t *testing.T) {
	pkt := buildIPv4(t, 6, 40000, 443, 5, 0, 0, 16, 0)
	for _, n := range []int{0, 10, 19} {
		if _, err := ParseIPv4(pkt[:n]); err != ErrTooShort {
			t.Errorf("截断到 %d 字节: want ErrTooShort, got %v", n, err)
		}
	}
	v6 := make([]byte, 40)
	v6[0] = 0x60
	if _, err := ParseIPv4(v6); err != ErrNotIPv4 {
		t.Errorf("IPv6: want ErrNotIPv4, got %v", err)
	}
}

// TestParseTruncatedTCPKeepsPorts 半截的 TCP 头仍然能告诉我们"谁在连谁
// 的哪个端口",那是最有价值的信息。因为读不到 flags 就整条丢掉太浪费。
func TestParseTruncatedTCPKeepsPorts(t *testing.T) {
	pkt := buildIPv4(t, 6, 40000, 443, 5, 0, 1500, 0, 0) // l4 只有 4 字节
	p, err := ParseIPv4(pkt)
	if err != nil {
		t.Fatalf("半截 TCP 头不该报错: %v", err)
	}
	if p.SrcPort != 40000 || p.DstPort != 443 {
		t.Errorf("应保留端口: src=%d dst=%d", p.SrcPort, p.DstPort)
	}
	if p.TCPFlags != 0 {
		t.Errorf("读不到 flags 时应为 0, got 0x%x", p.TCPFlags)
	}
}

func TestParseEthernet(t *testing.T) {
	ip := buildIPv4(t, 6, 40000, 443, 5, 0, 0, 16, 0x0002)
	frame := buildEth(t, 0, ip)

	p, err := ParseEthernet(frame)
	if err != nil {
		t.Fatalf("ParseEthernet: %v", err)
	}
	if p.SrcPort != 40000 || p.DstPort != 443 {
		t.Errorf("端口解析错误: %+v", p)
	}
	if p.SrcMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("源 MAC: got %q", p.SrcMAC)
	}
	if p.DstMAC != "00:11:22:33:44:55" {
		t.Errorf("目的 MAC: got %q", p.DstMAC)
	}
}

// TestParseEthernetWithVLAN 交换机镜像口上的流量常常带 802.1Q tag。
// 不处理的话这些帧会被当成"非 IPv4"整个丢掉 —— 那等于在最需要它的
// 部署场景里什么都采不到。
func TestParseEthernetWithVLAN(t *testing.T) {
	ip := buildIPv4(t, 6, 40000, 443, 5, 0, 0, 16, 0)
	frame := buildEth(t, 100, ip)

	p, err := ParseEthernet(frame)
	if err != nil {
		t.Fatalf("带 VLAN tag 的帧应能解析: %v", err)
	}
	if p.VLAN != 100 {
		t.Errorf("VLAN: want 100, got %d", p.VLAN)
	}
	if p.SrcPort != 40000 || p.DstPort != 443 {
		t.Errorf("VLAN 帧的端口解析错误: src=%d dst=%d", p.SrcPort, p.DstPort)
	}
}

func TestParseEthernetRejectsNonIPv4(t *testing.T) {
	frame := make([]byte, 60)
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd) // IPv6
	if _, err := ParseEthernet(frame); err != ErrNotIPv4 {
		t.Errorf("want ErrNotIPv4, got %v", err)
	}
}

// TestApplySamplingKeepsObserved 采样还原必须同时保留实测值。
//
// 只存估算值的话,采样率事后发现配错就再也回不去了;只存实测值的话,
// 每次查询都要乘一遍,而采样率是逐流可变的(不同设备不同配置),
// 那要求把采样率也带进 GROUP BY,聚合基数会暴涨。
func TestApplySamplingKeepsObserved(t *testing.T) {
	f := Flow{Packets: 10, Bytes: 1500, SamplingRate: 100}
	f.ApplySampling()

	if f.ObservedPackets != 10 || f.ObservedBytes != 1500 {
		t.Errorf("实测值应被保留: pkts=%d bytes=%d", f.ObservedPackets, f.ObservedBytes)
	}
	if f.Packets != 1000 || f.Bytes != 150000 {
		t.Errorf("估算值应为实测 × 100: pkts=%d bytes=%d", f.Packets, f.Bytes)
	}
}

// TestApplySamplingRateOneIsIdentity 全量采集时估算值等于实测值,
// 不该因为除零或乘零变成 0。
func TestApplySamplingRateOneIsIdentity(t *testing.T) {
	for _, rate := range []uint32{0, 1} {
		f := Flow{Packets: 10, Bytes: 1500, SamplingRate: rate}
		f.ApplySampling()
		if f.Packets != 10 || f.Bytes != 1500 {
			t.Errorf("采样率 %d 应视为全量: pkts=%d bytes=%d", rate, f.Packets, f.Bytes)
		}
	}
}

func TestDurationMS(t *testing.T) {
	f := Flow{}
	if f.DurationMS() != 0 {
		t.Error("零值 Flow 的时长应为 0")
	}

	// End 早于 Start(时钟回拨或解码错误)不该得到一个巨大的负数回绕值
	f2 := Flow{}
	f2.Start = f2.Start.Add(1000)
	if f2.DurationMS() != 0 {
		t.Errorf("End 早于 Start 时应为 0, got %d", f2.DurationMS())
	}
}

func TestProtocolName(t *testing.T) {
	cases := map[uint8]string{1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 99: "other"}
	for p, want := range cases {
		if got := ProtocolName(p); got != want {
			t.Errorf("ProtocolName(%d) = %q, want %q", p, got, want)
		}
	}
}
