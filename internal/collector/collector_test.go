package collector

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/flow"
)

// --- 输入模式解析 ---

// TestParseModesDefaultsToLocalOnly 默认只抓本机,**不开任何 UDP 端口**。
//
// 这是刻意的:默认监听 UDP 意味着任何装上这个程序的机器都凭空多了两个
// 对外开放的端口,而绝大多数用户只想看本机流量。要收远端数据必须显式
// 打开,那时用户知道自己在开什么。
func TestParseModesDefaultsToLocalOnly(t *testing.T) {
	for _, spec := range []string{"", "   "} {
		modes, err := ParseModes(spec)
		if err != nil {
			t.Fatalf("ParseModes(%q): %v", spec, err)
		}
		if len(modes) != 1 || modes[0] != ModeLocal {
			t.Errorf("默认应只有 local, got %v", modes)
		}
		if HasMode(modes, ModeSFlow) || HasMode(modes, ModeNetFlow) {
			t.Error("默认不该开启任何 UDP 监听")
		}
	}
}

func TestParseModesMultiple(t *testing.T) {
	modes, err := ParseModes("local,sflow,netflow")
	if err != nil {
		t.Fatalf("ParseModes: %v", err)
	}
	if len(modes) != 3 {
		t.Fatalf("want 3 modes, got %v", modes)
	}
	for _, m := range []Mode{ModeLocal, ModeSFlow, ModeNetFlow} {
		if !HasMode(modes, m) {
			t.Errorf("缺少 %s", m)
		}
	}
}

func TestParseModesTolerantOfCaseAndSpace(t *testing.T) {
	modes, err := ParseModes(" SFlow , NETFLOW ")
	if err != nil {
		t.Fatalf("ParseModes: %v", err)
	}
	if len(modes) != 2 || !HasMode(modes, ModeSFlow) || !HasMode(modes, ModeNetFlow) {
		t.Errorf("got %v", modes)
	}
}

// TestParseModesDedupes 重复指定不该启动两个 collector —— 它们会抢同一个
// UDP 端口,第二个必然绑定失败,那个错误让人困惑。
func TestParseModesDedupes(t *testing.T) {
	modes, err := ParseModes("sflow,sflow,sflow")
	if err != nil {
		t.Fatalf("ParseModes: %v", err)
	}
	if len(modes) != 1 {
		t.Errorf("重复应去重, got %v", modes)
	}
}

func TestParseModesRejectsUnknown(t *testing.T) {
	if _, err := ParseModes("local,ipfix"); err == nil {
		t.Error("未知模式应报错")
	}
}

// --- NetFlow v5 ---

// buildNetFlowV5 造一个 v5 包。
func buildNetFlowV5(t *testing.T, count int, sysUptime, unixSecs uint32, samplingRaw uint16, recs []nfRec) []byte {
	t.Helper()
	pkt := make([]byte, netflowV5HeaderLen+len(recs)*netflowV5RecordLen)
	binary.BigEndian.PutUint16(pkt[0:2], 5)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(count))
	binary.BigEndian.PutUint32(pkt[4:8], sysUptime)
	binary.BigEndian.PutUint32(pkt[8:12], unixSecs)
	binary.BigEndian.PutUint32(pkt[12:16], 0)
	binary.BigEndian.PutUint16(pkt[22:24], samplingRaw)

	for i, rc := range recs {
		r := pkt[netflowV5HeaderLen+i*netflowV5RecordLen:][:netflowV5RecordLen]
		copy(r[0:4], net.ParseIP(rc.src).To4())
		copy(r[4:8], net.ParseIP(rc.dst).To4())
		binary.BigEndian.PutUint16(r[12:14], rc.inIf)
		binary.BigEndian.PutUint16(r[14:16], rc.outIf)
		binary.BigEndian.PutUint32(r[16:20], rc.pkts)
		binary.BigEndian.PutUint32(r[20:24], rc.bytes)
		binary.BigEndian.PutUint32(r[24:28], rc.first)
		binary.BigEndian.PutUint32(r[28:32], rc.last)
		binary.BigEndian.PutUint16(r[32:34], rc.sport)
		binary.BigEndian.PutUint16(r[34:36], rc.dport)
		r[37] = rc.tcpFlags
		r[38] = rc.proto
	}
	return pkt
}

type nfRec struct {
	src, dst     string
	sport, dport uint16
	proto        uint8
	tcpFlags     uint8
	pkts, bytes  uint32
	first, last  uint32
	inIf, outIf  uint16
}

func TestDecodeNetFlowV5Basic(t *testing.T) {
	exportSecs := uint32(1786000000)
	pkt := buildNetFlowV5(t, 1, 100000, exportSecs, 0, []nfRec{{
		src: "203.0.113.7", dst: "198.51.100.1",
		sport: 40000, dport: 443, proto: 6, tcpFlags: 0x18,
		pkts: 10, bytes: 1500, first: 95000, last: 99000,
		inIf: 3, outIf: 5,
	}})

	flows, err := DecodeNetFlowV5(pkt, net.ParseIP("10.0.0.1"))
	if err != nil {
		t.Fatalf("DecodeNetFlowV5: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("want 1 flow, got %d", len(flows))
	}
	f := flows[0]
	if f.SrcIP != "203.0.113.7" || f.DstIP != "198.51.100.1" {
		t.Errorf("IP: %+v", f)
	}
	if f.SrcPort != 40000 || f.DstPort != 443 || f.Protocol != 6 {
		t.Errorf("五元组: %+v", f)
	}
	if f.TCPFlags != 0x18 {
		t.Errorf("TCP flags: got 0x%x", f.TCPFlags)
	}
	if f.InputInterface != 3 || f.OutputInterface != 5 {
		t.Errorf("接口: in=%d out=%d", f.InputInterface, f.OutputInterface)
	}
	if f.SourceType != flow.SourceNetFlow {
		t.Errorf("SourceType: %s", f.SourceType)
	}
	// 未采样(mode 0)时采样率应为 1,估算值等于实测值
	if f.SamplingRate != 1 {
		t.Errorf("采样率: want 1, got %d", f.SamplingRate)
	}
	if f.Packets != 10 || f.ObservedPackets != 10 {
		t.Errorf("未采样时估算值应等于实测值: %d / %d", f.Packets, f.ObservedPackets)
	}
}

// TestDecodeNetFlowV5TimestampsAreAbsolute v5 记录里的 first/last 是
// **设备启动以来的毫秒数**,不是绝对时间。不换算的话所有 flow 的时间会
// 落在 1970 年附近 —— 那种错误在图上表现为"什么数据都没有",
// 很难想到是时间戳的问题。
func TestDecodeNetFlowV5TimestampsAreAbsolute(t *testing.T) {
	exportSecs := uint32(1786000000)
	sysUptime := uint32(100000) // 设备已运行 100 秒
	pkt := buildNetFlowV5(t, 1, sysUptime, exportSecs, 0, []nfRec{{
		src: "1.1.1.1", dst: "2.2.2.2", proto: 6,
		pkts: 1, bytes: 100,
		first: 90000, last: 95000, // 导出前 10 秒 / 5 秒
	}})

	flows, err := DecodeNetFlowV5(pkt, net.ParseIP("10.0.0.1"))
	if err != nil {
		t.Fatalf("DecodeNetFlowV5: %v", err)
	}
	f := flows[0]

	exportTime := time.Unix(int64(exportSecs), 0)
	wantStart := exportTime.Add(-10 * time.Second)
	wantEnd := exportTime.Add(-5 * time.Second)

	if !f.Start.Equal(wantStart) {
		t.Errorf("Start: want %v, got %v", wantStart, f.Start)
	}
	if !f.End.Equal(wantEnd) {
		t.Errorf("End: want %v, got %v", wantEnd, f.End)
	}
	// 绝对时间必须在 2020 年之后 —— 这是"没做换算"最直接的信号
	if f.Start.Year() < 2020 {
		t.Errorf("时间戳落在 %d 年,说明没做 sysUptime 换算", f.Start.Year())
	}
}

// TestDecodeNetFlowV5HandlesUptimeWraparound sysUptime 是 uint32 毫秒,
// 约 49.7 天回绕一次。回绕后 first 会大于 sysUptime,直接相减得到巨大的
// 正数,让 flow 时间落到未来几十天。
func TestDecodeNetFlowV5HandlesUptimeWraparound(t *testing.T) {
	exportSecs := uint32(1786000000)
	pkt := buildNetFlowV5(t, 1, 1000, exportSecs, 0, []nfRec{{
		src: "1.1.1.1", dst: "2.2.2.2", proto: 6, pkts: 1, bytes: 100,
		first: 4294000000, last: 4294000000, // 回绕前的大值
	}})

	flows, err := DecodeNetFlowV5(pkt, net.ParseIP("10.0.0.1"))
	if err != nil {
		t.Fatalf("DecodeNetFlowV5: %v", err)
	}
	f := flows[0]
	exportTime := time.Unix(int64(exportSecs), 0)
	// 应退回导出时刻,而不是一个未来几十天的时间
	if !f.Start.Equal(exportTime) {
		t.Errorf("回绕时应退回导出时刻 %v, got %v", exportTime, f.Start)
	}
}

// TestDecodeNetFlowV5Sampling 采样率在低 14 位,高 2 位是模式。
func TestDecodeNetFlowV5Sampling(t *testing.T) {
	// mode 1(确定性采样)+ rate 100
	samplingRaw := uint16(1)<<14 | 100
	pkt := buildNetFlowV5(t, 1, 100000, 1786000000, samplingRaw, []nfRec{{
		src: "1.1.1.1", dst: "2.2.2.2", proto: 6, pkts: 10, bytes: 1500,
	}})

	flows, err := DecodeNetFlowV5(pkt, net.ParseIP("10.0.0.1"))
	if err != nil {
		t.Fatalf("DecodeNetFlowV5: %v", err)
	}
	f := flows[0]
	if f.SamplingRate != 100 {
		t.Errorf("采样率: want 100, got %d", f.SamplingRate)
	}
	// 估算值 = 实测 × 100,实测值保留
	if f.Packets != 1000 || f.ObservedPackets != 10 {
		t.Errorf("采样还原错误: est=%d observed=%d", f.Packets, f.ObservedPackets)
	}
	if f.Bytes != 150000 || f.ObservedBytes != 1500 {
		t.Errorf("字节还原错误: est=%d observed=%d", f.Bytes, f.ObservedBytes)
	}
}

// TestDecodeNetFlowV5RejectsWrongVersion 把 v9 发到 v5 端口是很常见的
// 配置错误,要给出能定位问题的错误信息。
func TestDecodeNetFlowV5RejectsWrongVersion(t *testing.T) {
	pkt := make([]byte, netflowV5HeaderLen)
	binary.BigEndian.PutUint16(pkt[0:2], 9)
	_, err := DecodeNetFlowV5(pkt, net.ParseIP("10.0.0.1"))
	if err == nil {
		t.Fatal("v9 包应报错")
	}
	if !contains(err.Error(), "v9") {
		t.Errorf("错误应提到 v9 不支持: %v", err)
	}
}

// TestDecodeNetFlowV5RejectsBadCount count 字段损坏时按它循环会越界。
func TestDecodeNetFlowV5RejectsBadCount(t *testing.T) {
	// 声明 100 条记录但只给了 1 条的空间
	pkt := buildNetFlowV5(t, 100, 1000, 1786000000, 0, []nfRec{{
		src: "1.1.1.1", dst: "2.2.2.2", proto: 6,
	}})
	if _, err := DecodeNetFlowV5(pkt, net.ParseIP("10.0.0.1")); err == nil {
		t.Error("记录数超过包长应报错")
	}

	// 超过 v5 每包 30 条的上限
	big := make([]byte, netflowV5HeaderLen+31*netflowV5RecordLen)
	binary.BigEndian.PutUint16(big[0:2], 5)
	binary.BigEndian.PutUint16(big[2:4], 31)
	if _, err := DecodeNetFlowV5(big, net.ParseIP("10.0.0.1")); err == nil {
		t.Error("超过 30 条应报错")
	}
}

func TestDecodeNetFlowV5DeviceIDFromExporter(t *testing.T) {
	pkt := buildNetFlowV5(t, 1, 1000, 1786000000, 0, []nfRec{{
		src: "1.1.1.1", dst: "2.2.2.2", proto: 6,
	}})
	flows, err := DecodeNetFlowV5(pkt, net.ParseIP("10.0.0.5"))
	if err != nil {
		t.Fatalf("DecodeNetFlowV5: %v", err)
	}
	// v5 包头没有设备标识,只能用源地址区分是哪台设备报的
	want := binary.BigEndian.Uint32(net.ParseIP("10.0.0.5").To4())
	if flows[0].DeviceID != want {
		t.Errorf("DeviceID: want %d, got %d", want, flows[0].DeviceID)
	}
}

// --- sFlow v5 ---

// buildSFlowDatagram 造一个含单个 flow sample + raw packet header 的
// sFlow v5 datagram。
func buildSFlowDatagram(t *testing.T, samplingRate uint32, frameLen uint32, ethFrame []byte) []byte {
	t.Helper()

	// raw packet header record body
	rec := make([]byte, 16+len(ethFrame))
	binary.BigEndian.PutUint32(rec[0:4], sflowHeaderEthernet)
	binary.BigEndian.PutUint32(rec[4:8], frameLen)
	binary.BigEndian.PutUint32(rec[8:12], 0) // stripped
	binary.BigEndian.PutUint32(rec[12:16], uint32(len(ethFrame)))
	copy(rec[16:], ethFrame)

	// flow sample body
	var fs []byte
	app := func(v uint32) { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); fs = append(fs, b...) }
	app(1)            // sequence
	app(0)            // source_id
	app(samplingRate) // sampling rate
	app(0)            // sample pool
	app(0)            // drops
	app(3)            // input interface
	app(5)            // output interface
	app(1)            // num records
	app(sflowRawPacketHeader)
	app(uint32(len(rec)))
	fs = append(fs, rec...)

	// datagram
	var dg []byte
	appd := func(v uint32) { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); dg = append(dg, b...) }
	appd(sflowV5Version)
	appd(1) // agent address type = IPv4
	dg = append(dg, net.ParseIP("10.0.0.9").To4()...)
	appd(0) // sub agent id
	appd(1) // sequence
	appd(1000)
	appd(1) // num samples
	appd(sflowFlowSample)
	appd(uint32(len(fs)))
	dg = append(dg, fs...)
	return dg
}

// buildEthTCP 造一个以太网 + IPv4 + TCP 帧。
func buildEthTCP(t *testing.T, src, dst string, sport, dport uint16, totalLen int) []byte {
	t.Helper()
	frame := make([]byte, 14+20+20)
	copy(frame[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	copy(frame[6:12], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)

	ip := frame[14:]
	ip[0] = 0x45
	ip[9] = 6
	if totalLen == 0 {
		totalLen = 40
	}
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	copy(ip[12:16], net.ParseIP(src).To4())
	copy(ip[16:20], net.ParseIP(dst).To4())

	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint16(tcp[12:14], 0x0002) // SYN
	return frame
}

// TestDecodeSFlowV5Basic sFlow 送的是**采样到的原始包头**,不是聚合好的
// flow 记录。解码后必须与本机 AF_PACKET 抓到的东西同构 —— 那是共用
// internal/flow 那份包解析的意义。
func TestDecodeSFlowV5Basic(t *testing.T) {
	eth := buildEthTCP(t, "203.0.113.7", "198.51.100.1", 40000, 443, 1500)
	dg := buildSFlowDatagram(t, 1000, 1514, eth)

	flows, err := DecodeSFlowV5(dg, net.ParseIP("10.0.0.1"))
	if err != nil {
		t.Fatalf("DecodeSFlowV5: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("want 1 flow, got %d", len(flows))
	}
	f := flows[0]
	if f.SrcIP != "203.0.113.7" || f.DstIP != "198.51.100.1" {
		t.Errorf("IP: %+v", f)
	}
	if f.SrcPort != 40000 || f.DstPort != 443 || f.Protocol != 6 {
		t.Errorf("五元组: %+v", f)
	}
	if f.SourceType != flow.SourceSFlow {
		t.Errorf("SourceType: %s", f.SourceType)
	}
	if f.InputInterface != 3 || f.OutputInterface != 5 {
		t.Errorf("接口: in=%d out=%d", f.InputInterface, f.OutputInterface)
	}
	if f.SrcMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("源 MAC: %q", f.SrcMAC)
	}
}

// TestDecodeSFlowV5SamplingRestoresEstimate 一个采样包代表 samplingRate
// 个包。实测值保留为 1 个包。
func TestDecodeSFlowV5SamplingRestoresEstimate(t *testing.T) {
	eth := buildEthTCP(t, "1.1.1.1", "2.2.2.2", 1234, 80, 1500)
	dg := buildSFlowDatagram(t, 1000, 1514, eth)

	flows, err := DecodeSFlowV5(dg, net.ParseIP("10.0.0.1"))
	if err != nil {
		t.Fatalf("DecodeSFlowV5: %v", err)
	}
	f := flows[0]
	if f.SamplingRate != 1000 {
		t.Errorf("采样率: want 1000, got %d", f.SamplingRate)
	}
	if f.ObservedPackets != 1 {
		t.Errorf("实测应为 1 个包, got %d", f.ObservedPackets)
	}
	if f.Packets != 1000 {
		t.Errorf("估算应为 1000 个包, got %d", f.Packets)
	}
	// 字节数用 sFlow 自报的 frame_length(1514)而不是 IP total length,
	// 因为 sFlow 只截取包头,极端配置下 IP 头可能不完整
	if f.ObservedBytes != 1514 {
		t.Errorf("实测字节应为 frame_length 1514, got %d", f.ObservedBytes)
	}
	if f.Bytes != 1514*1000 {
		t.Errorf("估算字节: want %d, got %d", 1514*1000, f.Bytes)
	}
}

// TestDecodeSFlowV5UsesAgentAddressForDevice agent address 是设备自报的
// 身份,比 UDP 源地址可靠(源地址可能是 NAT 后的)。
func TestDecodeSFlowV5UsesAgentAddress(t *testing.T) {
	eth := buildEthTCP(t, "1.1.1.1", "2.2.2.2", 1234, 80, 100)
	dg := buildSFlowDatagram(t, 1, 100, eth)

	flows, err := DecodeSFlowV5(dg, net.ParseIP("192.0.2.99"))
	if err != nil {
		t.Fatalf("DecodeSFlowV5: %v", err)
	}
	wantAgent := binary.BigEndian.Uint32(net.ParseIP("10.0.0.9").To4())
	if flows[0].DeviceID != wantAgent {
		t.Errorf("DeviceID 应取 agent address, want %d, got %d", wantAgent, flows[0].DeviceID)
	}
}

func TestDecodeSFlowV5RejectsWrongVersion(t *testing.T) {
	dg := make([]byte, 32)
	binary.BigEndian.PutUint32(dg[0:4], 4)
	if _, err := DecodeSFlowV5(dg, net.ParseIP("10.0.0.1")); err == nil {
		t.Error("非 v5 应报错")
	}
}

// TestDecodeSFlowV5SkipsCounterSamples Counter sample 是接口计数器快照,
// 第一阶段不做。跳过而不是报错:设备通常同时发两种,报错会让一半的包
// 被记成解码失败。
func TestDecodeSFlowV5SkipsCounterSamples(t *testing.T) {
	var dg []byte
	app := func(v uint32) { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); dg = append(dg, b...) }
	app(sflowV5Version)
	app(1)
	dg = append(dg, net.ParseIP("10.0.0.9").To4()...)
	app(0)
	app(1)
	app(1000)
	app(1) // 一个 sample
	app(sflowCounterSample)
	app(8)
	dg = append(dg, make([]byte, 8)...)

	flows, err := DecodeSFlowV5(dg, net.ParseIP("10.0.0.1"))
	if err != nil {
		t.Fatalf("counter sample 不该报错: %v", err)
	}
	if len(flows) != 0 {
		t.Errorf("counter sample 不产出 flow, got %d", len(flows))
	}
}

// TestDecodeSFlowV5RejectsBogusLengths 上游设备的实现质量差异很大,
// 一个长度字段读错会让后面所有偏移全错。逐层校验不是防御性编程,
// 是必需的。
func TestDecodeSFlowV5RejectsBogusLengths(t *testing.T) {
	var dg []byte
	app := func(v uint32) { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); dg = append(dg, b...) }
	app(sflowV5Version)
	app(1)
	dg = append(dg, net.ParseIP("10.0.0.9").To4()...)
	app(0)
	app(1)
	app(1000)
	app(1)
	app(sflowFlowSample)
	app(999999) // 声明长度远超实际数据
	dg = append(dg, make([]byte, 8)...)

	if _, err := DecodeSFlowV5(dg, net.ParseIP("10.0.0.1")); err == nil {
		t.Error("sample 长度超出实际数据应报错")
	}

	// 不合理的 sample 数量
	var dg2 []byte
	app2 := func(v uint32) { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); dg2 = append(dg2, b...) }
	app2(sflowV5Version)
	app2(1)
	dg2 = append(dg2, net.ParseIP("10.0.0.9").To4()...)
	app2(0)
	app2(1)
	app2(1000)
	app2(999999) // 样本数量
	if _, err := DecodeSFlowV5(dg2, net.ParseIP("10.0.0.1")); err == nil {
		t.Error("不合理的 sample 数量应报错")
	}
}

// TestDecodeSFlowV5TruncatedDatagram 截断的 datagram 必须报错而不是
// 越界 panic —— collector 是暴露在网络上的,一个畸形包不该带走进程。
func TestDecodeSFlowV5TruncatedDatagram(t *testing.T) {
	eth := buildEthTCP(t, "1.1.1.1", "2.2.2.2", 1234, 80, 100)
	full := buildSFlowDatagram(t, 1, 100, eth)
	for n := 0; n < len(full); n += 7 {
		// 不断言一定报错(有些截断点恰好是合法的短包),只要求不 panic
		_, _ = DecodeSFlowV5(full[:n], net.ParseIP("10.0.0.1"))
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
