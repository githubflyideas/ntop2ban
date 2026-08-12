//go:build !linux

package datasource

import (
	"errors"
	"log"
)

// ErrUnsupportedPlatform 表示当前平台没有本机抓包能力。
//
// 只有 Linux 有 XDP 与 AF_PACKET。但整个程序不该因此只能在 Linux 上编译:
// ntop2ban 的另外两个输入源(sFlow、NetFlow)是纯 UDP 收包,和内核没关系,
// 在 macOS 上跑一个只接收交换机/路由器导出流的实例是完全成立的用法,
// 功能验证时尤其方便。
//
// 因此非 Linux 平台保留 Open 的签名并返回这个错误,把"能不能抓本机包"
// 的判断推迟到运行时:用户加了 -input local 才会看到它,而且看到的是一句
// 说得清原因的中文,不是一屏 undefined: unix.AF_PACKET。
var ErrUnsupportedPlatform = errors.New("datasource: 本机抓包(XDP / AF_PACKET)只在 Linux 上可用,当前平台请用 -input netflow 或 -input sflow")

func Open(cfg Config, lg *log.Logger) (Source, error) {
	return nil, ErrUnsupportedPlatform
}
