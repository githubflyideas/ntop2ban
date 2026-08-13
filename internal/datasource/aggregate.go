package datasource

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/flow"
)

// aggregator 是三种数据源共用的五元组聚合器。
//
// 这是"流量展示要统一"的技术落点:无论包从 XDP ringbuf 还是 AF_PACKET
// socket 来,都归到这里做同样的聚合、产出同样的 flow.Flow。上层看不出
// 差别,曲线口径一致。
//
// 唯一体现差别的地方是 Flow.Device 里带上的模式标签,以及界面上单独
// 展示的"当前数据源"——那是给运维看的,不是数据本身的差异。
type aggregator struct {
	mu    sync.Mutex
	flows map[flowKey]*flowAgg

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
	pkts  int64
	bytes int64
	// firstSeen/lastSeen 构成 Canonical Flow 的 Start/End。
	// 只记一个时间点的话,一条持续整个窗口的流会被压成一个瞬间,
	// duration 永远是 0,时间序列对齐也会失真。
	firstSeen time.Time
	lastSeen  time.Time
	// tcpFlags 是窗口内所有包的按位或:一条流里 SYN 与 FIN 分别在不同
	// 的包上,取任意单个包的 flags 都会丢掉另一半信息。
	tcpFlags uint16
	vlan     uint16
}

// Observation 是一个已解析的包,由各数据源投喂。
type Observation struct {
	SrcIP    [4]byte
	DstIP    [4]byte
	SrcPort  uint16
	DstPort  uint16
	Proto    uint8 // IANA 协议号
	Length   int
	TCPFlags uint16
	VLAN     uint16

	// Packets 是这一次观测代表的网线包数。0 视同 1。
	//
	// 绝大多数情况就是 1:一个包一次观测。例外是出向的 TC 钩子——大块
	// 发送在那里还没被 TSO 切片,一个 skb 对应网线上几十个包,Length 也是
	// 切片前的大长度。这时字节数是对的而包数会少算几十倍,上传的 pps 看
	// 起来会莫名低于下载。所以让数据源把"这次代表几个包"一起报上来。
	Packets int

	// Egress 标记这是出向观测。入向来自 XDP,出向来自 TC 或
	// cgroup_skb/egress —— 两者进同一个聚合器、同一套口径。
	Egress bool
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

func newAggregator(samplingN, maxFlows int, sink Sink, lg *log.Logger) *aggregator {
	if maxFlows <= 0 {
		maxFlows = DefaultMaxFlows
	}
	if lg == nil {
		lg = log.Default()
	}
	return &aggregator{
		flows:     make(map[flowKey]*flowAgg),
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

	pkts := int64(o.Packets)
	if pkts < 1 {
		pkts = 1
	}

	now := time.Now()
	if agg, ok := a.flows[k]; ok {
		agg.pkts += pkts
		agg.bytes += int64(o.Length)
		agg.lastSeen = now
		agg.tcpFlags |= o.TCPFlags
		return
	}
	if len(a.flows) >= a.maxFlows {
		// 丢新流而不是驱逐老流:老流已经积累了计数,丢掉它等于
		// 丢掉已经测到的事实。
		a.dropped++
		return
	}
	a.flows[k] = &flowAgg{
		pkts: pkts, bytes: int64(o.Length),
		firstSeen: now, lastSeen: now,
		tcpFlags: o.TCPFlags, vlan: o.VLAN,
	}
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

	batch := make([]flow.Flow, 0, len(a.flows))
	for k, agg := range a.flows {
		f := flow.Flow{
			Start:    agg.firstSeen,
			End:      agg.lastSeen,
			SrcIP:    net.IPv4(k.src[0], k.src[1], k.src[2], k.src[3]).String(),
			DstIP:    net.IPv4(k.dst[0], k.dst[1], k.dst[2], k.dst[3]).String(),
			SrcPort:  k.sport,
			DstPort:  k.dport,
			Protocol: k.proto,
			Packets:  uint64(agg.pkts),
			Bytes:    uint64(agg.bytes),

			SamplingRate: uint32(a.samplingN),
			SourceType:   flow.SourceLocalXDP,
			TCPFlags:     agg.tcpFlags,
			VLAN:         agg.vlan,
		}
		// 按采样率还原估算值,同时保留实测值(见 flow.ApplySampling)。
		f.ApplySampling()
		batch = append(batch, f)
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
