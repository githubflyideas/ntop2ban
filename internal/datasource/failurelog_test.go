package datasource

import (
	"errors"
	"strings"
	"testing"
)

// 降级日志里原因相同的层级必须合成一行。
//
// 现场是这样的:虚拟机里启动,连着两行
//
//	[flow]   上一级失败原因:xdp-native 不可用: 内嵌 eBPF bytecode 为空(...)
//	[flow]   上一级失败原因:xdp-generic 不可用: 内嵌 eBPF bytecode 为空(...)
//
// 两句话除了层级名一字不差 —— 因为 native 与 generic 共用同一份 bytecode,
// 前置检查当然一起失败。用户看到的是重复的噪音,而不是多出来的信息。
func TestMergedFailureLinesFoldsIdenticalReasons(t *testing.T) {
	reason := errors.New("内嵌 eBPF bytecode 为空(从源码构建需先执行 make bpf)")
	lines := mergedFailureLines([]error{
		&ErrUnavailable{Mode: ModeXDPNative, Reason: reason},
		&ErrUnavailable{Mode: ModeXDPGeneric, Reason: reason},
	})
	if len(lines) != 1 {
		t.Fatalf("原因相同应合成一行,得到 %d 行:%v", len(lines), lines)
	}
	if !strings.Contains(lines[0], string(ModeXDPNative)) ||
		!strings.Contains(lines[0], string(ModeXDPGeneric)) {
		t.Errorf("合并后的行里两个层级都得留名:%q", lines[0])
	}
	if !strings.Contains(lines[0], reason.Error()) {
		t.Errorf("合并后的行里丢了原因:%q", lines[0])
	}
}

// 原因不同的层级不许合 —— 合掉就等于把"native 是驱动不支持、generic 是
// 权限不足"这类真正有用的区别抹平了。
func TestMergedFailureLinesKeepsDistinctReasons(t *testing.T) {
	lines := mergedFailureLines([]error{
		&ErrUnavailable{Mode: ModeXDPNative, Reason: errors.New("网卡驱动不支持 native")},
		&ErrUnavailable{Mode: ModeXDPGeneric, Reason: errors.New("权限不足")},
	})
	if len(lines) != 2 {
		t.Fatalf("原因不同应各占一行,得到 %d 行:%v", len(lines), lines)
	}
}

// 不是 ErrUnavailable 的错误照原样留一行,不要凭空造一个层级名出来。
func TestMergedFailureLinesPassesThroughPlainErrors(t *testing.T) {
	lines := mergedFailureLines([]error{errors.New("打开 /dev/bpf0: 权限不足")})
	if len(lines) != 1 || lines[0] != "打开 /dev/bpf0: 权限不足" {
		t.Errorf("普通错误应原样输出,得到 %v", lines)
	}
}
