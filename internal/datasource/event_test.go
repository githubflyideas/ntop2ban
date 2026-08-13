//go:build linux

package datasource

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

// buildSampleEvent 按 C 侧的 20 字节布局手工拼一条事件。
func buildSampleEvent(srcIP, dstIP [4]byte, sport, dport, length uint16,
	proto, dir uint8, segs uint16) []byte {
	b := make([]byte, sampleEventSize)
	copy(b[0:4], srcIP[:])
	copy(b[4:8], dstIP[:])
	binary.LittleEndian.PutUint16(b[8:10], sport)
	binary.LittleEndian.PutUint16(b[10:12], dport)
	binary.LittleEndian.PutUint16(b[12:14], length)
	b[14] = proto
	b[15] = dir
	binary.LittleEndian.PutUint16(b[16:18], segs)
	return b
}

// 出向是靠 dir 字段区分的,而 dir 挤在 proto 后面 —— 加这个字段时整个
// 结构体的尾部都动了(从 16 字节变 20 字节)。C 侧和 Go 侧的偏移只要
// 差一个字节,解出来的就是能自圆其说的垃圾数据:端口变成天文数字或者
// 所有流量都被标成出向,而没有任何一处会报错。所以逐字段钉住。
func TestParseSampleEventDirectionAndSegs(t *testing.T) {
	src := [4]byte{192, 168, 1, 10}
	dst := [4]byte{1, 1, 1, 1}
	raw := buildSampleEvent(src, dst, 54321, 443, 1420, 6, dirEgress, 17)

	o, err := parseSampleEvent(raw)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if o.SrcIP != src || o.DstIP != dst {
		t.Errorf("IP 解析错位: src=%v dst=%v", o.SrcIP, o.DstIP)
	}
	if o.SrcPort != 54321 || o.DstPort != 443 {
		t.Errorf("端口解析错位: %d -> %d", o.SrcPort, o.DstPort)
	}
	if o.Length != 1420 || o.Proto != 6 {
		t.Errorf("长度/协议解析错位: len=%d proto=%d", o.Length, o.Proto)
	}
	if !o.Egress {
		t.Error("dir=1 应当解析成出向")
	}
	if o.Packets != 17 {
		t.Errorf("segs=17 应当解析成 17 个包,得到 %d", o.Packets)
	}

	in, err := parseSampleEvent(buildSampleEvent(src, dst, 1, 2, 60, 17, dirIngress, 1))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if in.Egress {
		t.Error("dir=0 应当解析成入向")
	}
}

// segs 为 0 时按 1 算。老 bytecode(不写 segs 字段)配新二进制、或者
// 内核在某个钩子上给不出 gso_segs,都会让这里拿到 0。按 0 计入的后果是
// 字节数在、包数没了,pps 曲线与流量曲线互相矛盾,而且查不出来源。
func TestParseSampleEventZeroSegsCountsAsOne(t *testing.T) {
	o, err := parseSampleEvent(buildSampleEvent([4]byte{10, 0, 0, 1},
		[4]byte{10, 0, 0, 2}, 80, 80, 100, 6, dirIngress, 0))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if o.Packets != 1 {
		t.Errorf("segs=0 应当按 1 个包算,得到 %d", o.Packets)
	}
}

// C 侧的结构体定义是这份契约的另一半,而编译器管不到跨语言的一致性。
// 这条测试直接读 bpf/sampler.c,盯住那几个决定偏移量的字段还在、
// 顺序没变 —— 以及三个程序段都还在。改 C 结构体时这里会红,提醒同时
// 改 event.go 的偏移量。
func TestBPFSourceKeepsWireContract(t *testing.T) {
	b, err := os.ReadFile("../../bpf/sampler.c")
	if err != nil {
		t.Skipf("读不到 bpf 源码: %v", err)
	}
	src := string(b)

	i := strings.Index(src, "struct sample_event {")
	if i < 0 {
		t.Fatal("bpf/sampler.c 里找不到 struct sample_event")
	}
	body := src[i:]
	if j := strings.Index(body, "};"); j > 0 {
		body = body[:j]
	}
	// 字段必须按这个顺序出现,与 event.go 里的偏移量一一对应。
	order := []string{"src_ip", "dst_ip", "src_port", "dst_port",
		"pkt_len", "proto", "dir", "segs", "_pad"}
	at := 0
	for _, f := range order {
		k := strings.Index(body[at:], f)
		if k < 0 {
			t.Fatalf("struct sample_event 里字段 %s 缺失或顺序与 event.go 不一致", f)
		}
		at += k + len(f)
	}

	for _, sec := range []string{`SEC("xdp")`, `SEC("tc")`, `SEC("cgroup_skb/egress")`} {
		if !strings.Contains(src, sec) {
			t.Errorf("bpf/sampler.c 里缺少 %s 程序段", sec)
		}
	}
}
