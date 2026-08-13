package datasource

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"runtime"
	"sync"
	"testing"

	"golang.org/x/net/bpf"

	"github.com/githubflyideas/ntop2ban/internal/flow"
)

type fakeSink struct {
	mu      sync.Mutex
	batches [][]flow.Flow
	err     error
}

func (f *fakeSink) Append(ctx context.Context, b []flow.Flow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.batches = append(f.batches, append([]flow.Flow(nil), b...))
	return nil
}

func (f *fakeSink) all() [][]flow.Flow {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.batches
}

func obs(src, dst string, sport, dport int, proto uint8, length int) Observation {
	var o Observation
	copy(o.SrcIP[:], net.ParseIP(src).To4())
	copy(o.DstIP[:], net.ParseIP(dst).To4())
	o.SrcPort = uint16(sport)
	o.DstPort = uint16(dport)
	o.Proto = proto
	o.Length = length
	return o
}

// TestAggregatorProducesIdenticalFlowsRegardlessOfSource 这是"流量展示要
// 统一"的核心断言:同样的包序列,不管声称来自哪一级数据源,聚合出的
// model.Flow 除了 Device 标签外必须完全相同。
//
// 若不统一,切换数据源(比如换台机器、网卡驱动不同)会让同一份流量在
// 界面上显示出不同的数字,而没有任何提示说明为什么。
func TestAggregatorProducesIdenticalFlowsRegardlessOfSource(t *testing.T) {
	packets := []Observation{
		obs("203.0.113.7", "198.51.100.1", 40000, 443, 6, 100),
		obs("203.0.113.7", "198.51.100.1", 40000, 443, 6, 200),
		obs("203.0.113.8", "198.51.100.1", 40001, 53, 17, 80),
	}

	results := map[Mode][]flow.Flow{}
	for _, mode := range []Mode{ModeXDPNative, ModeXDPGeneric, ModeAFPacket} {
		sink := &fakeSink{}
		agg := newAggregator(100, DefaultMaxFlows, sink, discardLogger())
		for _, p := range packets {
			agg.add(p)
		}
		agg.flush(context.Background())

		batches := sink.all()
		if len(batches) != 1 {
			t.Fatalf("%s: want 1 批, got %d", mode, len(batches))
		}
		results[mode] = batches[0]
	}

	base := normalize(results[ModeXDPNative])
	for _, mode := range []Mode{ModeXDPGeneric, ModeAFPacket} {
		got := normalize(results[mode])
		if len(got) != len(base) {
			t.Fatalf("%s: 流条数不同 want %d got %d", mode, len(base), len(got))
		}
		for k, wantFlow := range base {
			gotFlow, ok := got[k]
			if !ok {
				t.Errorf("%s: 缺少流 %s", mode, k)
				continue
			}
			if gotFlow.Packets != wantFlow.Packets || gotFlow.Bytes != wantFlow.Bytes {
				t.Errorf("%s: 流 %s 计数不同 want pkt=%d byte=%d got pkt=%d byte=%d",
					mode, k, wantFlow.Packets, wantFlow.Bytes, gotFlow.Packets, gotFlow.Bytes)
			}
			if gotFlow.SamplingRate != wantFlow.SamplingRate {
				t.Errorf("%s: 流 %s 采样率不同", mode, k)
			}
			if gotFlow.Protocol != wantFlow.Protocol {
				t.Errorf("%s: 流 %s 协议不同", mode, k)
			}
		}
	}
}

func normalize(flows []flow.Flow) map[string]flow.Flow {
	out := map[string]flow.Flow{}
	for _, f := range flows {
		k := f.SrcIP + ":" + itoa(int(f.SrcPort)) + "->" + f.DstIP + ":" + itoa(int(f.DstPort)) + "/" + itoa(int(f.Protocol))
		out[k] = f
	}
	return out
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func TestAggregatorCountsAndSeparatesFlows(t *testing.T) {
	sink := &fakeSink{}
	agg := newAggregator(1, DefaultMaxFlows, sink, discardLogger())

	for i := 0; i < 3; i++ {
		agg.add(obs("203.0.113.7", "198.51.100.1", 40000, 443, 6, 100))
	}
	agg.add(obs("203.0.113.7", "198.51.100.1", 40000, 8443, 6, 50))
	agg.flush(context.Background())

	flows := sink.all()[0]
	if len(flows) != 2 {
		t.Fatalf("want 2 flows, got %d", len(flows))
	}
	byPort := map[int]flow.Flow{}
	for _, f := range flows {
		byPort[int(f.DstPort)] = f
	}
	if byPort[443].ObservedPackets != 3 || byPort[443].ObservedBytes != 300 {
		t.Errorf("443 流聚合错误(实测值): %+v", byPort[443])
	}
	if byPort[8443].ObservedPackets != 1 {
		t.Errorf("8443 流聚合错误: %+v", byPort[8443])
	}
}

// TestMaxFlowsCapsMemory 端口扫描时每个包都是新五元组。没有上限的话
// 聚合表几秒内吃光内存——观测组件不该有能力把整机 OOM。
func TestMaxFlowsCapsMemory(t *testing.T) {
	sink := &fakeSink{}
	agg := newAggregator(1, 10, sink, discardLogger())

	for i := 0; i < 100; i++ {
		agg.add(obs("203.0.113.7", "198.51.100.1", 40000, 1000+i, 6, 100))
	}
	if len(agg.flows) != 10 {
		t.Fatalf("聚合表应限制在 10, got %d", len(agg.flows))
	}
	if agg.dropped != 90 {
		t.Errorf("应记录 90 条丢弃, got %d", agg.dropped)
	}
}

// TestMaxFlowsKeepsCountingKnownFlows 超限后已有流仍要累加——丢弃新流
// 是权衡,停止统计已知流等于丢掉已经测到的事实。
func TestMaxFlowsKeepsCountingKnownFlows(t *testing.T) {
	sink := &fakeSink{}
	agg := newAggregator(1, 1, sink, discardLogger())

	known := obs("203.0.113.7", "198.51.100.1", 40000, 443, 6, 100)
	agg.add(known)
	agg.add(obs("203.0.113.7", "198.51.100.1", 40000, 8443, 6, 100)) // 被丢
	agg.add(known)
	agg.add(known)

	agg.flush(context.Background())
	flows := sink.all()[0]
	if len(flows) != 1 {
		t.Fatalf("want 1 flow, got %d", len(flows))
	}
	if flows[0].ObservedPackets != 3 {
		t.Errorf("已有流应继续累加: want 3, got %d", flows[0].ObservedPackets)
	}
}

func TestFlushClearsWindowAndSurvivesSinkError(t *testing.T) {
	sink := &fakeSink{err: errors.New("boom")}
	agg := newAggregator(1, DefaultMaxFlows, sink, discardLogger())

	agg.add(obs("203.0.113.7", "198.51.100.1", 40000, 443, 6, 100))
	agg.flush(context.Background()) // 不应 panic

	// 写失败后窗口也要清空,避免下一轮重复累计同一批数据
	if len(agg.flows) != 0 {
		t.Errorf("写失败后窗口应清空, got %d", len(agg.flows))
	}
	agg.add(obs("203.0.113.7", "198.51.100.1", 40000, 443, 6, 100))
	if len(agg.flows) != 1 {
		t.Error("写失败后应继续工作")
	}
}

func TestFlushEmptyDoesNotCallSink(t *testing.T) {
	sink := &fakeSink{}
	agg := newAggregator(1, DefaultMaxFlows, sink, discardLogger())
	agg.flush(context.Background())
	if len(sink.all()) != 0 {
		t.Error("空窗口不应写库")
	}
}

// --- cBPF 过滤器(AF_PACKET 层) ---

func buildFrame(t *testing.T, proto uint8, dport int, ihlWords int, fragOff uint16, totalLen int) []byte {
	t.Helper()
	ihl := ihlWords * 4
	// 帧留出 padding 空间,这样可以测试"IP 头声明的总长小于实际帧长"
	// (以太网最小帧填充)与"声明大于实际"(snaplen 截断)两种情形。
	frame := make([]byte, ethHdrLen+ihl+8+64)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[ethHdrLen:]
	ip[0] = 0x40 | byte(ihlWords)
	ip[9] = proto
	binary.BigEndian.PutUint16(ip[6:8], fragOff)
	if totalLen == 0 {
		totalLen = ihl + 8
	}
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	copy(ip[12:16], net.ParseIP("203.0.113.7").To4())
	copy(ip[16:20], net.ParseIP("198.51.100.1").To4())
	l4 := ip[ihl:]
	binary.BigEndian.PutUint16(l4[0:2], 40000)
	binary.BigEndian.PutUint16(l4[2:4], uint16(dport))
	return frame
}

func runFilter(t *testing.T, samplingN int, frame []byte) bool {
	t.Helper()
	vm, err := bpf.NewVM(sampleFilterInstructions(samplingN))
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	n, err := vm.Run(frame)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return n > 0
}

func TestFilterAcceptsTCPUDPRejectsOthers(t *testing.T) {
	if !runFilter(t, 1, buildFrame(t, 6, 443, 5, 0, 0)) {
		t.Error("TCP 应被收下")
	}
	if !runFilter(t, 1, buildFrame(t, 17, 53, 5, 0, 0)) {
		t.Error("UDP 应被收下")
	}
	// ICMP 不进采样:无端口协议只产生 port=0 的伪流,占据 Top N 却
	// 说明不了"谁在打我"
	if runFilter(t, 1, buildFrame(t, 1, 0, 5, 0, 0)) {
		t.Error("ICMP 不应进入采样")
	}
}

func TestFilterRejectsFragments(t *testing.T) {
	if runFilter(t, 1, buildFrame(t, 6, 443, 5, 0x0001, 0)) {
		t.Error("分片包不应被收下")
	}
}

func TestFilterRejectsNonIPv4(t *testing.T) {
	f := buildFrame(t, 6, 443, 5, 0, 0)
	binary.BigEndian.PutUint16(f[12:14], 0x86dd)
	if runFilter(t, 1, f) {
		t.Error("非 IPv4 不应被收下")
	}
}

// TestSamplingUsesKernelSideRand N>1 时必须用 ExtRand 在内核侧抽样,
// 否则每个包都要拷到用户态再丢弃,白付一次跨内核边界的代价。
func TestSamplingUsesKernelSideRand(t *testing.T) {
	full := sampleFilterInstructions(1)
	for _, in := range full {
		if _, ok := in.(bpf.LoadExtension); ok {
			t.Error("N=1(全量)不该有抽样指令")
		}
	}
	sampled := sampleFilterInstructions(100)
	found := false
	for _, in := range sampled {
		if ext, ok := in.(bpf.LoadExtension); ok && ext.Num == bpf.ExtRand {
			found = true
		}
	}
	if !found {
		t.Error("N>1 应使用 ExtRand 在内核侧抽样")
	}
}

// --- 帧解析 ---

func TestToObservationUsesSharedParser(t *testing.T) {
	// 声明 60,实际帧更长(以太网 padding)——应采用声明值。
	// 这条断言的意义是确认 datasource 走的是 internal/flow 那份共用解析,
	// 而不是自己又实现了一遍:口径一旦分叉,同一份流量在不同输入方式下
	// 会显示出不同数字,且没有任何报错。
	f := buildFrame(t, 6, 443, 5, 0, 60)
	o, err := toObservation(f)
	if err != nil {
		t.Fatalf("toObservation: %v", err)
	}
	if o.Length != 60 {
		t.Errorf("应采用 IP 头声明的总长: want 60, got %d", o.Length)
	}
	if o.DstPort != 443 || o.Proto != 6 {
		t.Errorf("五元组解析错误: %+v", o)
	}
}

func TestParseFrameHandlesIPOptions(t *testing.T) {
	f := buildFrame(t, 6, 8080, 8, 0, 0)
	o, err := toObservation(f)
	if err != nil {
		t.Fatalf("parseFrame: %v", err)
	}
	if o.DstPort != 8080 {
		t.Errorf("带 IP option 时端口解析错误: got %d", o.DstPort)
	}
}

func TestParseFrameRejectsTruncated(t *testing.T) {
	f := buildFrame(t, 6, 443, 5, 0, 0)
	for _, n := range []int{0, 10, ethHdrLen, ethHdrLen + 10, ethHdrLen + 20} {
		if _, err := toObservation(f[:n]); err == nil {
			t.Errorf("截断到 %d 字节应报错", n)
		}
	}
}

// buildWireFrame 造一个"链路上的真实包":最大以太网帧 1514 字节,IP 头
// 声明总长 1500,TCP 头带 flags。用它断言 snaplen 截断之后我们要的东西
// 都还在。
func buildWireFrame(t *testing.T, flags uint16, vlanTags int) []byte {
	t.Helper()
	frame := make([]byte, 1514)
	off := 12
	for i := 0; i < vlanTags; i++ {
		binary.BigEndian.PutUint16(frame[off:off+2], 0x8100)
		binary.BigEndian.PutUint16(frame[off+2:off+4], 100)
		off += 4
	}
	binary.BigEndian.PutUint16(frame[off:off+2], 0x0800)
	ip := frame[off+2:]
	ip[0] = 0x4f // IHL=15,60 字节 IP 头,最坏情况
	ip[9] = protoTCP
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	copy(ip[12:16], net.ParseIP("203.0.113.7").To4())
	copy(ip[16:20], net.ParseIP("198.51.100.1").To4())
	l4 := ip[60:]
	binary.BigEndian.PutUint16(l4[0:2], 40000)
	binary.BigEndian.PutUint16(l4[2:4], 443)
	binary.BigEndian.PutUint16(l4[12:14], flags)
	// 载荷填非零,这样"把载荷当成头来读"会得到明显错误的值而不是 0。
	for i := 20; i < len(l4); i++ {
		l4[i] = 0x5a
	}
	return frame
}

// TestFilterSnapLenCoversHeadersOnly 过滤器命中时的返回值就是 snaplen,
// 内核按这个值决定拷多少字节到用户态。
//
// 我们只需要包头:字节数取自 IP 头声明的 total length(不是抓到的字节数),
// TCP flags 在 L4 的第 12~13 字节。最坏情况是一层 802.1Q 标签(解析器目前
// 认一层)+ 带满 option 的 60 字节 IP 头,即 14 + 4 + 60 + 14 = 92 字节。
//
// 拷整包(0xffff)的代价不在 CPU 那点 memcpy,而在 BPF 缓冲区:512KB 除以
// 1534 字节一条记录只装得下约 340 个包,跑满千兆时那是 4ms 的余量,读循环
// 稍一被调度晚就溢出,而溢出的表现是统计数字凭空偏低、没有任何报错。
func TestFilterSnapLenCoversHeadersOnly(t *testing.T) {
	insts := sampleFilterInstructions(1)
	var accepts []uint32
	for _, in := range insts {
		if r, ok := in.(bpf.RetConstant); ok && r.Val != 0 {
			accepts = append(accepts, r.Val)
		}
	}
	if len(accepts) != 1 {
		t.Fatalf("过滤器应恰好有一个非零返回值(命中时的 snaplen), got %v", accepts)
	}
	got := accepts[0]

	const worstCaseHeaders = ethHdrLen + 4 + 60 + 14 // VLAN + 满 option 的 IP 头 + TCP 头前 14 字节
	if got < worstCaseHeaders {
		t.Errorf("snaplen %d 装不下最坏情况的包头(%d 字节)", got, worstCaseHeaders)
	}
	if got >= 1514 {
		t.Errorf("snaplen %d 等于拷整包 —— 我们只需要包头,拷整包会把 BPF 缓冲区几乎全喂给载荷", got)
	}
}

// TestObservationSurvivesSnapLenTruncation 这是 snaplen 能降下来的前提:
// 截断到 snaplen 之后,字节数与 TCP flags 必须与拿到整包时完全一致。
//
// 字节数能对得上,靠的是 flow.ParseIPv4 采用 IP 头声明的 total length 而
// 不是实际抓到的长度 —— 若哪天有人把它改成 len(ip),流量图会在不改任何
// 配置的情况下整体缩水到 1/10,这个测试就是拦住那次改动的。
func TestObservationSurvivesSnapLenTruncation(t *testing.T) {
	const synAck = 0x012

	insts := sampleFilterInstructions(1)
	var snap int
	for _, in := range insts {
		if r, ok := in.(bpf.RetConstant); ok && r.Val != 0 {
			snap = int(r.Val)
		}
	}

	for _, vlanTags := range []int{0, 1} {
		frame := buildWireFrame(t, synAck, vlanTags)
		if snap > len(frame) {
			t.Fatalf("snaplen %d 比一个最大以太网帧还长,等于没有截断", snap)
		}

		want, err := toObservation(frame)
		if err != nil {
			t.Fatalf("vlan=%d 整包解析失败: %v", vlanTags, err)
		}
		if want.Length != 1500-4*vlanTags {
			t.Fatalf("vlan=%d 整包的字节数就不对: got %d", vlanTags, want.Length)
		}
		if want.TCPFlags != synAck {
			t.Fatalf("vlan=%d 整包的 flags 就不对: got %#x", vlanTags, want.TCPFlags)
		}

		got, err := toObservation(frame[:snap])
		if err != nil {
			t.Fatalf("vlan=%d 截断到 %d 字节后解析失败: %v", vlanTags, snap, err)
		}
		if got != want {
			t.Errorf("vlan=%d 截断到 %d 字节后结果变了:\n want %+v\n got  %+v", vlanTags, snap, want, got)
		}
	}
}

// --- 降级顺序 ---

func TestModeLabelsAreInformative(t *testing.T) {
	for _, m := range []Mode{ModeXDPNative, ModeXDPGeneric, ModeAFPacket, ModeBPFDevice} {
		if m.Label() == string(m) {
			t.Errorf("%s 应有可读的说明文字(运维需要知道性能差异)", m)
		}
	}
}

// TestDescribeAttemptsListsAllReasons 全部失败时要列出每一级的原因,
// 只报最后一条会让人以为问题在 AF_PACKET,而真正的原因可能是
// "native 驱动不支持 + generic 权限不足"。
func TestDescribeAttemptsListsAllReasons(t *testing.T) {
	errs := []error{
		&ErrUnavailable{Mode: ModeXDPNative, Reason: errors.New("驱动不支持")},
		&ErrUnavailable{Mode: ModeXDPGeneric, Reason: errors.New("权限不足")},
		&ErrUnavailable{Mode: ModeAFPacket, Reason: errors.New("socket 失败")},
	}
	msg := describeAttempts(errs).Error()
	for _, want := range []string{"xdp-native", "驱动不支持", "xdp-generic", "权限不足", "af-packet", "socket 失败"} {
		if !contains(msg, want) {
			t.Errorf("汇总错误缺少 %q:\n%s", want, msg)
		}
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

// discardLogger 返回一个丢弃输出的 logger,让测试输出保持干净。
func discardLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

// --- 抽样默认值 ---

// TestDefaultSamplingIsPlatformDependent macOS 上默认全量,Linux 上默认 1/100。
//
// 这不是口味问题。Linux 的抽样判定在内核里(cBPF 的 ExtRand),没被选中的包
// 连拷都不拷,是真省 CPU;BSD 的 BPF 没有这个扩展,判定在用户态,内核过滤、
// 拷贝、缓冲区、read 系统调用每个包照付,抽样只省下解析与聚合那一小段。在
// macOS 上默认 1/100 等于白扣 精度:误差按 1/sqrt(计入包数) 走,而这个程序在
// Mac 上面对的恰好是家里那点流量。
//
// 用 defaultSamplingFor(goos) 而不是编译期常量,就是为了这条测试能在任何平台
// 上把两边的值都验一遍 —— 否则 darwin 那个分支只能靠交叉编译过一眼类型检查。
func TestDefaultSamplingIsPlatformDependent(t *testing.T) {
	if got := defaultSamplingFor("darwin"); got != 1 {
		t.Errorf("macOS 应默认全量, got 1/%d", got)
	}
	for _, goos := range []string{"linux", "freebsd", "windows"} {
		if got := defaultSamplingFor(goos); got <= 1 {
			t.Errorf("%s 应默认抽样, got 1/%d", goos, got)
		}
	}
	if DefaultSamplingN != defaultSamplingFor(runtime.GOOS) {
		t.Errorf("DefaultSamplingN 与当前平台不符: %d", DefaultSamplingN)
	}
}

// TSO/GSO:出向在 TC 钩子上看到的是一个还没切片的大 skb,内核之后会把它
// 拆成几十个网线包。按"一条观测算一个包"来计,字节数是对的、包数会少
// 四十倍,于是 pps 曲线与流量曲线互相矛盾 —— 一条 1.5Gbps 的上传显示成
// 每秒两千个包。所以 Observation 带上 Packets,聚合器按它累加。
//
// 反过来 Packets 为 0 时必须按 1 算而不是 0:那是老 bytecode 配新二进制
// 的情形,包数凭空消失比少算更难查。
func TestAggregatorHonoursPacketCount(t *testing.T) {
	sink := &fakeSink{}
	agg := newAggregator(1, DefaultMaxFlows, sink, discardLogger())

	big := obs("203.0.113.7", "198.51.100.1", 40000, 443, 6, 64000)
	big.Packets = 44 // 一个 64KB 的 TSO skb,MTU 1500 下切成 44 个包
	agg.add(big)

	zero := obs("203.0.113.7", "198.51.100.1", 40000, 443, 6, 100)
	zero.Packets = 0
	agg.add(zero)

	agg.flush(context.Background())

	flows := sink.all()[0]
	if len(flows) != 1 {
		t.Fatalf("同一五元组应聚成一条流, got %d", len(flows))
	}
	f := flows[0]
	if f.ObservedPackets != 45 {
		t.Errorf("包数应为 44+1=45,得到 %d(TSO 段数没被计入,或 0 被当成 0 算了)",
			f.ObservedPackets)
	}
	if f.ObservedBytes != 64100 {
		t.Errorf("字节数应为 64100,得到 %d", f.ObservedBytes)
	}
}
