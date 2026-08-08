package datasource

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/model"
)

// aggregator 是三种数据源共用的五元组聚合器。
//
// 这是"流量展示要统一"的技术落点:无论包从 XDP ringbuf 还是 AF_PACKET
// socket 来,都归到这里做同样的聚合、产出同样的 model.Flow。上层看不出
// 差别,曲线口径一致。
//
// 唯一体现差别的地方是 Flow.Device 里带上的模式标签,以及界面上单独
// 展示的"当前数据源"——那是给运维看的,不是数据本身的差异。
type aggregator struct {
	mu    sync.Mutex
	flows map[flowKey]*flowAgg

	device    string
	samplingN int
	maxFlows  int

	// dropped 因超过 maxFlows 被丢弃的流数。随窗口一起打日志——
	// 静默丢弃会让人看着不完整的数据下错判断。
	dropped int

	sink Sink
	log  *log.Logger
}

type flowKey struct {
	src, dst [4]byte
	sport    uint16
	dport    uint16
	proto    uint8
}

type flowAgg struct {
	pkts     int64
	bytes    int64
	lastSeen time.Time
}

// Observation 是一个已解析的包,由各数据源投喂。
type Observation struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
	Proto   uint8 // 6 = tcp, 17 = udp
	Length  int
}

const (
	// DefaultFlushInterval 聚合窗口。10 秒够把突发聚合掉,又不至于让
	// 界面上的"当前流量"滞后到失去意义。
	DefaultFlushInterval = 10 * time.Second

	// DefaultMaxFlows 是内存上限,不是性能调优。遭遇端口扫描或 SYN
	// flood 时每个包都是新五元组,没有上限的话聚合表会在几秒内吃光内存
	// ——观测组件不该有能力把整机 OOM。
	DefaultMaxFlows = 20000
)

func newAggregator(device string, samplingN, maxFlows int, sink Sink, lg *log.Logger) *aggregator {
	if maxFlows <= 0 {
		maxFlows = DefaultMaxFlows
	}
	if lg == nil {
		lg = log.Default()
	}
	return &aggregator{
		flows:     make(map[flowKey]*flowAgg),
		device:    device,
		samplingN: samplingN,
		maxFlows:  maxFlows,
		sink:      sink,
		log:       lg,
	}
}

func (a *aggregator) add(o Observation) {
	k := flowKey{src: o.SrcIP, dst: o.DstIP, sport: o.SrcPort, dport: o.DstPort, proto: o.Proto}

	a.mu.Lock()
	defer a.mu.Unlock()

	if agg, ok := a.flows[k]; ok {
		agg.pkts++
		agg.bytes += int64(o.Length)
		agg.lastSeen = time.Now()
		return
	}
	if len(a.flows) >= a.maxFlows {
		// 丢新流而不是驱逐老流:老流已经积累了计数,丢掉它等于
		// 丢掉已经测到的事实。
		a.dropped++
		return
	}
	a.flows[k] = &flowAgg{pkts: 1, bytes: int64(o.Length), lastSeen: time.Now()}
}

// flush 把窗口内的聚合结果写入 sink 并清空。
func (a *aggregator) flush(ctx context.Context) {
	a.mu.Lock()
	if len(a.flows) == 0 {
		dropped := a.dropped
		a.dropped = 0
		a.mu.Unlock()
		if dropped > 0 {
			a.log.Printf("[flow] 窗口内丢弃 %d 条新流(超过上限 %d)", dropped, a.maxFlows)
		}
		return
	}

	now := time.Now()
	batch := make([]model.Flow, 0, len(a.flows))
	for k, agg := range a.flows {
		batch = append(batch, model.Flow{
			ReportedAt: now,
			Device:     a.device,
			SamplingN:  a.samplingN,
			SrcIP:      net.IPv4(k.src[0], k.src[1], k.src[2], k.src[3]).String(),
			DstIP:      net.IPv4(k.dst[0], k.dst[1], k.dst[2], k.dst[3]).String(),
			SrcPort:    int(k.sport),
			DstPort:    int(k.dport),
			Proto:      protoName(k.proto),
			PktCount:   agg.pkts,
			ByteCount:  agg.bytes,
			LastSeen:   agg.lastSeen,
		})
	}
	// 先清空再写库:写库可能耗时(SQLite 事务),期间到达的包应计入
	// 下一个窗口,而不是被这次 flush 顺带清掉。
	a.flows = make(map[flowKey]*flowAgg)
	dropped := a.dropped
	a.dropped = 0
	a.mu.Unlock()

	if err := a.sink.Append(ctx, batch); err != nil {
		// 采样数据允许丢:写失败记日志继续跑下一个窗口,不让观测循环停下来。
		a.log.Printf("[flow] 写入 %d 条流失败: %v", len(batch), err)
		return
	}
	if dropped > 0 {
		a.log.Printf("[flow] 已写入 %d 条流;本窗口丢弃 %d 条新流(超过上限 %d)",
			len(batch), dropped, a.maxFlows)
	}
}

// runFlushLoop 周期 flush,直到 ctx 取消。退出前再 flush 一次,
// 否则最后一个窗口(最多 10 秒)的观测会白丢。
func (a *aggregator) runFlushLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultFlushInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			a.flush(context.Background())
			return
		case <-t.C:
			a.flush(ctx)
		}
	}
}

func protoName(p uint8) string {
	switch p {
	case 17:
		return "udp"
	case 1:
		return "icmp"
	default:
		return "tcp"
	}
}
