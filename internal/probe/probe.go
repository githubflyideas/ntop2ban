// Package probe 是链路探测:周期性 ICMP/TCP 探测目标,记录每轮的 RTT
// 分布与丢包,供界面画延迟/丢包图。
//
// 来源与改动:探测与突发判定的算法搬自 pingping
// (github.com/githubflyideas/pingping)。**没有搬它的 store.go**——
// 那边用 mattn/go-sqlite3(cgo 驱动),带进来就毁掉 ntop2ban
// 的 CGO_ENABLED=0 静态编译。探测结果落 ntop2ban 已有的那一个 SQLite
// 库(modernc.org/sqlite,纯 Go),只是多几张表,整个程序仍然只有
// 一个 .db 文件。
//
// 保留"存分布而不是均值"这个核心取舍:一轮 20 个包,存下 min/p50/p90/
// p99/max 而不是一个平均值。平均值会把"一半包 5ms、一半包 500ms"和
// "所有包 250ms"显示成同一条线,而这两种链路对用户的体感完全不同。
package probe

import (
	"sort"
	"time"
)

// Round 是一轮探测的结果。
type Round struct {
	Target string
	At     time.Time
	Sent   int
	Recv   int
	RTTs   []float64 // 毫秒,只含收到的包
	Burst  bool      // 是否判定为丢包突发
	ZScore float64   // 判定依据(robust z),供界面 tooltip 展示
}

// LossPct 丢包率百分比。
func (r Round) LossPct() float64 {
	if r.Sent == 0 {
		return 0
	}
	return float64(r.Sent-r.Recv) / float64(r.Sent) * 100
}

// Distribution 返回 RTT 的分位数摘要 [min, p50, p90, p99, max]。
// 全丢包时返回全 0。
func (r Round) Distribution() [5]float64 {
	if len(r.RTTs) == 0 {
		return [5]float64{}
	}
	s := append([]float64(nil), r.RTTs...)
	sort.Float64s(s)
	return [5]float64{
		s[0],
		percentile(s, 50),
		percentile(s, 90),
		percentile(s, 99),
		s[len(s)-1],
	}
}

// percentile 取已排序序列的分位数(最近秩法)。
func percentile(sorted []float64, p int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := (p * len(sorted)) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// Target 是一个探测目标。
type Target struct {
	Name string
	Kind string // "icmp" | "tcp"
	Host string
	Port int // 仅 tcp

	// Interval 探测间隔。零值时由 Pace 决定。
	Interval time.Duration
	// Packets 每轮包数。零值用默认。
	Packets int
}

// 默认探测参数。沿用 pingping 的取值:20 个包、200ms 间隔、1s 超时。
// 20 个包是分位数有意义的下限——再少 p90/p99 就只是"第二大的那个值"。
const (
	DefaultInterval = time.Minute
	DefaultPackets  = 20
	DefaultGap      = 200 * time.Millisecond
	DefaultTimeout  = time.Second
)

func (t Target) interval() time.Duration {
	if t.Interval > 0 {
		return t.Interval
	}
	return DefaultInterval
}

func (t Target) packets() int {
	if t.Packets > 0 {
		return t.Packets
	}
	return DefaultPackets
}

// burstZ 是 Iglewicz-Hoaglin 的常规判定阈值。
const burstZ = 3.5

// CheckBurst 判定这一轮是否为丢包突发。history 是同一目标最近若干轮的
// 丢包数序列。
//
// 用 robust z(中位数 + MAD)而不是均值加标准差:丢包序列充满异常值,
// 均值和标准差本身会被异常值带跑,导致"只要以前抖过一次,后面再抖就
// 不算异常了"。中位数与 MAD 对异常值不敏感,这是这类判定的标准做法。
//
// 两个兜底路径都是必要的:
//   - 样本不足(冷启动):没有基线可比,退回绝对阈值 25%。
//   - MAD 为 0(健康链路长期零丢包):此时任何非零丢包的 z 都是无穷大,
//     公式失效。退回较低的绝对阈值 10%——零丢包的链路突然丢 10% 确实
//     值得标记。
func CheckBurst(sent, recv int, history []int) (bool, float64) {
	loss := sent - recv
	if loss < 2 {
		// 单个丢包在互联网上是常态噪声,不值得标记。
		return false, 0
	}
	if sent == 0 {
		return false, 0
	}
	if len(history) < 30 {
		return float64(loss)/float64(sent) >= 0.25, 0
	}

	series := make([]float64, len(history))
	for i, h := range history {
		series[i] = float64(h)
	}
	z := robustZ(float64(loss), series)
	if z < 0 { // MAD == 0
		return float64(loss)/float64(sent) >= 0.10, 0
	}
	return z >= burstZ, float64(int(z*100)) / 100
}

// robustZ = 0.6745*(x-median)/MAD。MAD 为 0 时返回 -1 让调用方走兜底。
func robustZ(x float64, series []float64) float64 {
	med := median(series)
	dev := make([]float64, len(series))
	for i, v := range series {
		if v > med {
			dev[i] = v - med
		} else {
			dev[i] = med - v
		}
	}
	mad := median(dev)
	if mad == 0 {
		return -1
	}
	return 0.6745 * (x - med) / mad
}

func median(s []float64) float64 {
	if len(s) == 0 {
		return 0
	}
	c := append([]float64(nil), s...)
	sort.Float64s(c)
	n := len(c)
	if n%2 == 1 {
		return c[n/2]
	}
	return (c[n/2-1] + c[n/2]) / 2
}
