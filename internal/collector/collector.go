// Package collector 是输入侧的统一抽象:本机 XDP/AF_PACKET 抓包,
// 或远端设备通过 UDP 送来的 sFlow v5 / NetFlow v5。
//
// 技术设计 §5 要求所有输入走同一个接口进入后续处理链,解析结果不能
// 直接绑定 ClickHouse,必须先转成 Canonical Flow。这个包提供那个接口
// 与远端输入的实现;本机输入在 internal/datasource。
//
// 输入方式由启动参数选择,**默认只开本机抓包**。这一点是刻意的:
// 默认监听 UDP 端口意味着任何装上这个程序的机器都凭空多了两个对外
// 开放的端口,而绝大多数用户只想看本机流量。要收远端数据必须显式
// 打开,那时用户知道自己在开什么。
package collector

import (
	"context"
	"fmt"
	"strings"

	"github.com/githubflyideas/ntop2ban/internal/flow"
)

// Sink 接收归一化后的 flow。存储层实现它。
type Sink interface {
	Append(ctx context.Context, batch []flow.Flow) error
}

// Source 是一个输入源。
type Source interface {
	// Name 用于日志与界面展示。
	Name() string
	// Run 持续采集直到 ctx 取消。
	Run(ctx context.Context) error
	// Close 释放资源。
	Close() error
}

// Mode 是输入模式。
type Mode string

const (
	// ModeLocal 本机抓包(XDP 优先,自动降级到 AF_PACKET)。默认。
	ModeLocal Mode = "local"
	// ModeSFlow 接收远端 sFlow v5。
	ModeSFlow Mode = "sflow"
	// ModeNetFlow 接收远端 NetFlow v5。
	ModeNetFlow Mode = "netflow"
)

// 默认监听端口。这两个是行业约定,但**必须可配置**——技术设计 §4.2
// 明确要求端口不写死,因为一台机器上可能已经有别的 collector 占着它们。
const (
	DefaultSFlowPort   = 6343
	DefaultNetFlowPort = 2055
)

// ParseModes 解析 -input 参数:逗号分隔的模式列表。
//
// 空字符串返回 {local} —— 默认只抓本机,不开任何 UDP 端口。
func ParseModes(spec string) ([]Mode, error) {
	if strings.TrimSpace(spec) == "" {
		return []Mode{ModeLocal}, nil
	}

	seen := map[Mode]bool{}
	var out []Mode
	for _, part := range strings.Split(spec, ",") {
		m := Mode(strings.ToLower(strings.TrimSpace(part)))
		if m == "" {
			continue
		}
		switch m {
		case ModeLocal, ModeSFlow, ModeNetFlow:
		default:
			return nil, fmt.Errorf("未知输入模式 %q(可用:local, sflow, netflow)", m)
		}
		if seen[m] {
			// 重复指定不报错但也不重复启动:两个 sflow collector 抢同一个
			// UDP 端口,第二个必然绑定失败,那个错误会让人困惑。
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	if len(out) == 0 {
		return []Mode{ModeLocal}, nil
	}
	return out, nil
}

// HasMode 判断列表里是否包含某个模式。
func HasMode(modes []Mode, m Mode) bool {
	for _, x := range modes {
		if x == m {
			return true
		}
	}
	return false
}
