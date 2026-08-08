// Package datasource 统一流量观测的数据来源。
//
// 这是本包存在的唯一理由:**流量展示必须统一**,不管数据是从 XDP native、
// XDP generic 还是 AF_PACKET 来的。上层(存储、界面)只看到
// []model.Flow,不知道也不需要知道底层挂在哪一层。
//
// 三级降级不是给旧代码找退路,而是真实的兼容性需求:
//
//   - XDP native —— 驱动层处理,最快。需要网卡驱动支持 XDP。
//   - XDP generic —— 内核在 netif_receive_skb 处模拟 XDP,任何网卡都能挂,
//     但已经在 sk_buff 分配之后,性能接近 AF_PACKET。虚拟网卡(veth、
//     容器环境、部分云主机的 virtio 配置)常常只能走这一级。
//   - AF_PACKET + cBPF —— 完全不依赖 XDP。内核太老(<4.8)、或 XDP 被
//     其他程序占用、或权限受限时的最后退路。
//
// 关键取舍:**降级发生在启动时,一次决定,之后不变**。不做运行时自动
// 切换——切换会导致同一时间窗口内两种口径的数据混在一起,流量曲线上
// 出现无法解释的跳变,而排查时没人会想到是数据源换了。
package datasource

import (
	"context"
	"fmt"
	"strings"

	"github.com/githubflyideas/ntop2ban/internal/model"
)

// Mode 是实际生效的数据源层级。
type Mode string

const (
	ModeXDPNative  Mode = "xdp-native"
	ModeXDPGeneric Mode = "xdp-generic"
	ModeAFPacket   Mode = "af-packet"
)

// Label 返回给界面展示的说明文字。
//
// 明确告知用户当前处于哪一级很重要:同样的采样率下,AF_PACKET 在高
// 流量时的丢包(内核缓冲区溢出)会明显高于 XDP native,而这体现为
// "统计偏低"。不告知的话用户会以为流量真的少。
func (m Mode) Label() string {
	switch m {
	case ModeXDPNative:
		return "XDP native(驱动层,性能最佳)"
	case ModeXDPGeneric:
		return "XDP generic(内核模拟层,网卡驱动不支持 native)"
	case ModeAFPacket:
		return "AF_PACKET(未使用 XDP,兼容模式)"
	default:
		return string(m)
	}
}

// Source 是一个已启动的观测数据源。
type Source interface {
	// Mode 返回实际生效的层级。
	Mode() Mode
	// Run 持续观测并把聚合结果交给 sink,直到 ctx 取消。
	Run(ctx context.Context) error
	// Close 释放资源。
	Close() error
}

// Sink 接收聚合后的流记录。存储层实现它。
type Sink interface {
	Append(ctx context.Context, batch []model.Flow) error
}

// KnockSink 接收敲门观测。只有 XDP 数据源能提供精确捕获;
// AF_PACKET 模式下敲门由 internal/knock 自己的 socket 负责。
type KnockSink interface {
	FeedTCP(srcIP string, port int)
	FeedICMP(srcIP string, payloadLen int)
}

// Config 是数据源的构造参数。
type Config struct {
	Iface     string
	SamplingN int

	// Prefer 指定优先尝试的层级。空表示按 native → generic → af-packet
	// 顺序自动降级。显式指定用于排查问题("强制走 AF_PACKET 看看是不是
	// XDP 的锅")与测试。
	Prefer Mode

	Sink      Sink
	KnockSink KnockSink

	// KnockTCPPorts / KnockICMPLens 是敲门序列涉及的端口与 ICMP 长度。
	// XDP 模式下写入 BPF map 做精确匹配。
	KnockTCPPorts []int
	KnockICMPLens []int
}

// ErrUnavailable 表示某一层级在当前环境不可用,应继续降级。
//
// 单独定义是为了让 Open 能区分"这一级不行,试下一级"与"配置本身错了,
// 试下一级也没用"——后者应该直接失败,而不是一路降级到 AF_PACKET
// 然后用同一个错误配置再失败一次,把真正的原因埋在三条日志之后。
type ErrUnavailable struct {
	Mode   Mode
	Reason error
}

func (e *ErrUnavailable) Error() string {
	return fmt.Sprintf("%s 不可用: %v", e.Mode, e.Reason)
}
func (e *ErrUnavailable) Unwrap() error { return e.Reason }

// attemptOrder 返回要依次尝试的层级。
func attemptOrder(prefer Mode) []Mode {
	all := []Mode{ModeXDPNative, ModeXDPGeneric, ModeAFPacket}
	if prefer == "" {
		return all
	}
	// 显式指定时只试那一个:用户要求"强制走某一级"就不该悄悄降级,
	// 否则他看到的日志与他的意图不符,排查时会更困惑。
	for _, m := range all {
		if m == prefer {
			return []Mode{m}
		}
	}
	return all
}

// describeAttempts 把多次失败汇总成一条可读的错误。
//
// 逐条列出每一级为什么不行,而不是只报最后一个:用户需要知道
// "native 因为驱动不支持、generic 因为权限不足",而不只是
// "AF_PACKET 打不开"。
func describeAttempts(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString("所有观测数据源均不可用:")
	for _, e := range errs {
		b.WriteString("\n  - ")
		b.WriteString(e.Error())
	}
	return fmt.Errorf("%s", b.String())
}
