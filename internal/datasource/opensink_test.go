//go:build linux || darwin

package datasource

import "testing"

// TestOpenRequiresSink 没有 Sink 就该在打开阶段失败。
//
// 两个平台都得守:静默丢弃数据是最难发现的故障——服务起来了、日志干净、
// 界面上什么都没有,而没有任何一处指向"根本没人接收数据"。
func TestOpenRequiresSink(t *testing.T) {
	if _, err := Open(Config{Iface: "lo"}, discardLogger()); err == nil {
		t.Error("没有 Sink 应报错而不是静默丢弃数据")
	}
}
