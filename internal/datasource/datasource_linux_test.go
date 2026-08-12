//go:build linux

package datasource

import (
	"encoding/binary"
	"net"
	"testing"
)

// --- ringbuf 事件解析(XDP 层) ---

// TestParseSampleEventLayout 二进制布局是跨语言契约,编译器抓不到不一致。
// C 侧改一个字段顺序,Go 侧照旧解析就会读到错位数据,而且不报错——
// 只会让流量图上出现无法解释的数值。
func TestParseSampleEventLayout(t *testing.T) {
	raw := make([]byte, sampleEventSize)
	copy(raw[0:4], net.ParseIP("203.0.113.7").To4())
	copy(raw[4:8], net.ParseIP("198.51.100.1").To4())
	binary.LittleEndian.PutUint16(raw[8:10], 40000)
	binary.LittleEndian.PutUint16(raw[10:12], 443)
	binary.LittleEndian.PutUint16(raw[12:14], 1500)
	raw[14] = 6

	o, err := parseSampleEvent(raw)
	if err != nil {
		t.Fatalf("parseSampleEvent: %v", err)
	}
	if o.SrcPort != 40000 || o.DstPort != 443 {
		t.Errorf("端口解析错误: src=%d dst=%d", o.SrcPort, o.DstPort)
	}
	if o.Length != 1500 {
		t.Errorf("长度: want 1500, got %d", o.Length)
	}
	if o.Proto != 6 {
		t.Errorf("协议: want 6, got %d", o.Proto)
	}
	wantSrc := [4]byte{203, 0, 113, 7}
	if o.SrcIP != wantSrc {
		t.Errorf("源 IP: want %v, got %v", wantSrc, o.SrcIP)
	}
}

func TestParseSampleEventRejectsShort(t *testing.T) {
	for _, n := range []int{0, 8, sampleEventSize - 1} {
		if _, err := parseSampleEvent(make([]byte, n)); err == nil {
			t.Errorf("长度 %d 应报错(bytecode 版本不匹配的信号)", n)
		}
	}
}

// TestAttemptOrderDefaultsToNativeFirst 默认必须先试性能最好的那级。
func TestAttemptOrderDefaultsToNativeFirst(t *testing.T) {
	order := attemptOrder("")
	want := []Mode{ModeXDPNative, ModeXDPGeneric, ModeAFPacket}
	if len(order) != len(want) {
		t.Fatalf("want %v, got %v", want, order)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("降级顺序错误: want %v, got %v", want, order)
		}
	}
}

// TestAttemptOrderRespectsExplicitPreference 显式指定某一级时不该悄悄
// 降级——用户要求"强制走 AF_PACKET 排查问题",结果程序自己跑去用 XDP,
// 他看到的日志与意图不符,只会更困惑。
func TestAttemptOrderRespectsExplicitPreference(t *testing.T) {
	order := attemptOrder(ModeAFPacket)
	if len(order) != 1 || order[0] != ModeAFPacket {
		t.Errorf("显式指定应只试那一级, got %v", order)
	}
}

// TestAssembleSampleFilterAcceptsRealisticN 汇编成 unix.SockFprog 是
// Linux 专属的一步(BSD 用 syscall.BpfInsn),放在这里。
func TestAssembleSampleFilterAcceptsRealisticN(t *testing.T) {
	for _, n := range []int{2, 10, 100, 4096} {
		if _, err := assembleSampleFilter(n); err != nil {
			t.Errorf("samplingN=%d 汇编失败: %v", n, err)
		}
	}
}
