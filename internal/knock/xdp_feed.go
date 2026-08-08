package knock

import (
	"net"
	"time"
)

// XDPFeeder 把 XDP 数据源捕获的敲门事件投喂给状态机。
//
// 存在理由:XDP 模式下敲门事件来自内核 ringbuf(精确匹配,不抽样),
// 由 internal/datasource 读出后调用这里;AF_PACKET 模式下 datasource
// 无法做精确捕获(它的过滤器带 1/N 抽样),敲门仍走 Daemon 自己的
// socket。两条路径最终都汇到同一个 Matcher,所以判定逻辑只有一份。
//
// 实现 datasource.KnockSink 接口。
type XDPFeeder struct {
	matcher *Matcher
}

// NewXDPFeeder 构造投喂器。
func NewXDPFeeder(m *Matcher) *XDPFeeder {
	return &XDPFeeder{matcher: m}
}

// FeedTCP 投喂一次 TCP 敲门观测。
func (f *XDPFeeder) FeedTCP(srcIP string, port int) {
	ip := net.ParseIP(srcIP)
	if ip == nil {
		return
	}
	f.matcher.Feed(Observation{
		Source: ip,
		Step:   Step{Kind: StepTCP, Port: port},
		At:     time.Now(),
	})
}

// FeedICMP 投喂一次 ICMP 敲门观测。payloadLen 是 ping -s 的值。
func (f *XDPFeeder) FeedICMP(srcIP string, payloadLen int) {
	ip := net.ParseIP(srcIP)
	if ip == nil {
		return
	}
	f.matcher.Feed(Observation{
		Source: ip,
		Step:   Step{Kind: StepICMP, PayloadLen: payloadLen},
		At:     time.Now(),
	})
}

// NewMatcherOnly 构造一个只有状态机的敲门处理器,不自建捕获 socket。
//
// XDP 模式下用这个:捕获由 datasource 负责,这里只要状态机 + 放行动作。
// 与 NewDaemon 的区别是它不碰任何 socket,因此也不需要 CAP_NET_RAW
// 之外的东西——权限需求已经由 datasource 那边满足了。
func NewMatcherOnly(cfg DaemonConfig) (*Matcher, *XDPFeeder, error) {
	if err := cfg.Sequence.Validate(); err != nil {
		return nil, nil, err
	}
	d := &Daemon{
		opener:   cfg.Opener,
		recorder: cfg.Recorder,
		seqID:    cfg.SequenceID,
		log:      cfg.logger(),
	}
	m := NewMatcher(cfg.Sequence, d.onOpen)
	d.matcher = m
	return m, NewXDPFeeder(m), nil
}

// TCPPorts 返回序列里所有 TCP 步的端口,供写入 XDP 的匹配 map。
func (seq Sequence) TCPPorts() []int {
	var out []int
	for _, st := range seq.Steps {
		if st.Kind == StepTCP {
			out = append(out, st.Port)
		}
	}
	return out
}

// ICMPLens 返回序列里所有 ICMP 步的 payload 长度,供写入 XDP 的匹配 map。
func (seq Sequence) ICMPLens() []int {
	var out []int
	for _, st := range seq.Steps {
		if st.Kind == StepICMP {
			out = append(out, st.PayloadLen)
		}
	}
	return out
}
