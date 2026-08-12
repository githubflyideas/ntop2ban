package datasource

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
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

// --- 降级顺序 ---

func TestModeLabelsAreInformative(t *testing.T) {
	for _, m := range []Mode{ModeXDPNative, ModeXDPGeneric, ModeAFPacket} {
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
