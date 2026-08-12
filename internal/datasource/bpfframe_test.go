package datasource

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
)

// bpfRecord 按 struct bpf_hdr 的布局拼一条记录(不含末尾对齐填充)。
func bpfRecord(pkt []byte, hdrlen int) []byte {
	if hdrlen == 0 {
		hdrlen = 20 // Darwin 上 sizeof(struct bpf_hdr) 补齐后是 20
	}
	rec := make([]byte, hdrlen+len(pkt))
	binary.LittleEndian.PutUint32(rec[bpfHdrCaplenOff:], uint32(len(pkt)))
	binary.LittleEndian.PutUint32(rec[bpfHdrDatalenOff:], uint32(len(pkt)))
	binary.LittleEndian.PutUint16(rec[bpfHdrLenOff:], uint16(hdrlen))
	copy(rec[hdrlen:], pkt)
	return rec
}

// bpfBuffer 拼一段内核会返回的读缓冲区。
//
// 对齐宽度这里写死 4 而不是用 bpfAlignment:这个值是内核那侧的事实
// (Darwin 的 BPF_ALIGNMENT 是 sizeof(int32_t)),测试要拿它来验证被测代码
// 里的常量。用同一个常量拼输入,那么把 bpfAlignment 改错测试也照样通过
// ——这是一条什么都不验证的测试。
const kernelBPFAlignment = 4

func bpfBuffer(pkts ...[]byte) []byte {
	var buf []byte
	for _, p := range pkts {
		buf = append(buf, bpfRecord(p, 0)...)
		for len(buf)%kernelBPFAlignment != 0 {
			buf = append(buf, 0xAA) // 填充字节刻意非 0,跳错了会看出来
		}
	}
	return buf
}

// TestWalkBPFBufferYieldsEveryPacket 一次 read 通常带回多条记录,而记录
// 之间要按字长对齐跳过填充。少跳或多跳都不会报错,只会让第二个包之后
// 全部解析成垃圾——这是这个函数存在的唯一原因,也是必须测的原因。
func TestWalkBPFBufferYieldsEveryPacket(t *testing.T) {
	// 长度刻意不是 4 的倍数,这样每条记录后面都有填充。
	want := [][]byte{
		{1, 2, 3},
		{4, 5, 6, 7, 8},
		{9},
	}
	var got [][]byte
	if err := walkBPFBuffer(bpfBuffer(want...), func(pkt []byte) {
		got = append(got, append([]byte(nil), pkt...))
	}); err != nil {
		t.Fatalf("walkBPFBuffer: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("包数量: want %d, got %d (%v)", len(want), len(got), got)
	}
	for i := range want {
		if string(got[i]) != string(want[i]) {
			t.Errorf("第 %d 个包: want %v, got %v", i, want[i], got[i])
		}
	}
}

// TestWalkBPFBufferDropsTruncatedTail read 的返回长度可能切在一条记录
// 中间。截断的记录必须整条丢掉而不是硬解——硬解会得到一个长度字段合法
// 但内容不全的"包"。
func TestWalkBPFBufferDropsTruncatedTail(t *testing.T) {
	buf := bpfBuffer([]byte{1, 2, 3, 4})
	buf = append(buf, bpfRecord([]byte{9, 9, 9, 9, 9, 9}, 0)[:24]...)

	var n int
	if err := walkBPFBuffer(buf, func(pkt []byte) { n++ }); err != nil {
		t.Fatalf("walkBPFBuffer: %v", err)
	}
	if n != 1 {
		t.Errorf("只应交出完整的那一个包, got %d", n)
	}
}

// TestWalkBPFBufferRejectsZeroLengthRecord 记录总长为 0 会让偏移量不前进,
// 循环永远不结束。宁可报错退出也不能挂住采集线程。
func TestWalkBPFBufferRejectsZeroLengthRecord(t *testing.T) {
	buf := make([]byte, 64) // 全 0:hdrlen=0 caplen=0
	if err := walkBPFBuffer(buf, func(pkt []byte) {}); err == nil {
		t.Error("hdrlen=0 的记录应报错,否则会死循环")
	}
}

// TestObserveLinkFrameHandlesNonEthernetLinkTypes 这是本文件最要紧的一条。
//
// lo0 是 DLT_NULL(4 字节 AF 头)、utun* 是 DLT_RAW(没有链路层头)。按
// 14 字节以太网头去解这两种,解析函数不会报错——它只会在错位的字节上
// 读出一个"合法"的 IPv4 头,于是界面上出现一批来源不明的流量,而没有
// 任何一处提示解析错了。
func TestObserveLinkFrameHandlesNonEthernetLinkTypes(t *testing.T) {
	eth := buildFrame(t, protoTCP, 443, 5, 0, 0)
	ip := eth[ethHdrLen:]

	base, err := observeLinkFrame(dltEthernet, eth)
	if err != nil {
		t.Fatalf("以太网帧: %v", err)
	}

	null := append([]byte{2, 0, 0, 0}, ip...) // AF_INET,本机(小端)字节序
	loop := append([]byte{0, 0, 0, 2}, ip...) // AF_INET,网络字节序

	for name, tc := range map[string]struct {
		dlt   int
		frame []byte
	}{
		"DLT_NULL": {dltNull, null},
		"DLT_LOOP": {dltLoop, loop},
		"DLT_RAW":  {dltRaw, ip},
	} {
		got, err := observeLinkFrame(tc.dlt, tc.frame)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got != base {
			t.Errorf("%s 解析结果与以太网不一致:\n want %+v\n got  %+v", name, base, got)
		}
	}

	// 反面:同一帧当成以太网解,要么报错要么解出不同的东西。若两者相同,
	// 说明上面的断言其实什么都没验证。
	if wrong, err := observeLinkFrame(dltEthernet, null); err == nil && wrong == base {
		t.Error("把 DLT_NULL 帧当以太网解居然得到相同结果,这条测试失去了意义")
	}
}

func TestObserveLinkFrameRejectsUnknownAndNonIPv4(t *testing.T) {
	if _, err := observeLinkFrame(0x77, make([]byte, 64)); err == nil {
		t.Error("未知 DLT 应报错,而不是按以太网猜")
	}
	// AF_INET6 是 30,不该被当成 IPv4 解析。
	v6 := append([]byte{30, 0, 0, 0}, make([]byte, 40)...)
	if _, err := observeLinkFrame(dltNull, v6); err == nil {
		t.Error("DLT_NULL 里的非 IPv4 负载应被拒绝")
	}
	if _, err := observeLinkFrame(dltNull, []byte{2, 0}); err == nil {
		t.Error("过短的 DLT_NULL 帧应报错")
	}
}

// TestLinkTypeSupportedCoversWhatObserveHandles 两处判断必须一致:
// linkTypeSupported 说支持但 observeLinkFrame 解不了,故障会推迟到运行时
// 每个包报一次错;反过来则是白白拒绝一块能用的网卡。
func TestLinkTypeSupportedCoversWhatObserveHandles(t *testing.T) {
	for _, dlt := range []int{dltEthernet, dltNull, dltLoop, dltRaw} {
		if !linkTypeSupported(dlt) {
			t.Errorf("DLT=%d observeLinkFrame 处理得了却被判为不支持", dlt)
		}
	}
	if linkTypeSupported(0x77) {
		t.Error("未知 DLT 不该被判为支持")
	}
}

// TestLinkFilterTruncatesEvenWhenItCannotFilter 非以太网链路上过滤器筛不了
// 协议(偏移量对不上),但仍然必须挂一个 —— BPF 设备在没有过滤器时按整包
// 长度拷贝,512KB 的缓冲区会被载荷吃光。挂一个 ret #snapLen 拿到截断,
// 协议筛选让给用户态。
func TestLinkFilterTruncatesEvenWhenItCannotFilter(t *testing.T) {
	for _, dlt := range []int{dltNull, dltLoop, dltRaw} {
		insts := linkFilterInstructions(dlt)
		if len(insts) != 1 {
			t.Fatalf("DLT=%d 的过滤器不该看任何偏移量, got %v", dlt, insts)
		}
		vm, err := bpf.NewVM(insts)
		if err != nil {
			t.Fatalf("DLT=%d NewVM: %v", dlt, err)
		}
		// 随便一段字节:这个过滤器不看内容,只负责收下并截断。
		n, err := vm.Run(make([]byte, 1514))
		if err != nil {
			t.Fatalf("DLT=%d Run: %v", dlt, err)
		}
		if n != snapLen {
			t.Errorf("DLT=%d 应收下并截断到 %d 字节, got %d", dlt, snapLen, n)
		}
	}

	// 以太网仍然走那套会筛协议的指令。
	if len(linkFilterInstructions(dltEthernet)) <= 1 {
		t.Error("以太网上应挂完整的筛选过滤器")
	}
}
