package knock

import (
	"net"
	"sync"
	"time"
)

// Observation 是捕获层交给状态机的一次事件:某来源 IP 触发了某一步。
//
// 捕获层(raw socket)负责把链路上的包翻译成这个结构,状态机不关心
// 包是怎么来的——这样状态机可以完全在内存里做单元测试,不需要网卡。
type Observation struct {
	Source net.IP
	Step   Step
	At     time.Time
}

// Matcher 是敲门序列的状态机。
//
// 每个来源 IP 独立记进度。**只记进行中的进度与成功事件,不记失败**:
// 敲错的包就是互联网噪声,记下来只会淹没有用信息。
//
// 并发:捕获层是单 goroutine 读包,但 Feed 与 Sweep/Sequence 可能来自
// 不同 goroutine(后者来自配置热更新与定时清理),因此加锁。
type Matcher struct {
	mu  sync.Mutex
	seq Sequence

	// progress 记录每个来源 IP 已完成到第几步,以及序列的起始时刻。
	// key 用 IP 的字符串形式而非 [16]byte,是为了让 IPv4 与 IPv4-mapped
	// IPv6 形式归一到同一个 key——否则同一个来源用不同协议栈敲会被
	// 当成两个不同的进度。
	progress map[string]*attempt

	// onOpen 敲门成功时的回调:参数是来源 IP 与要放行的端口/时长。
	// 放行动作本身(写防火墙/eBPF map)不在这个包里,由调用方注入,
	// 这样状态机测试不需要碰真实网络配置。
	onOpen func(src net.IP, port int, d time.Duration)
}

type attempt struct {
	// next 是下一步应该命中的下标。
	next int
	// startedAt 是第一步命中的时刻,用于判断整个序列是否超时。
	startedAt time.Time
}

// NewMatcher 构造状态机。seq 须已通过 Validate。
func NewMatcher(seq Sequence, onOpen func(src net.IP, port int, d time.Duration)) *Matcher {
	return &Matcher{
		seq:      seq,
		progress: make(map[string]*attempt),
		onOpen:   onOpen,
	}
}

// SetSequence 热更新序列定义(审批通过后调用)。
//
// 更新时清空所有进行中的进度:旧序列的半途进度在新序列下没有意义,
// 留着会让某个来源莫名其妙地"少敲两步就开门了"。
func (m *Matcher) SetSequence(seq Sequence) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq = seq
	m.progress = make(map[string]*attempt)
}

// Sequence 返回当前生效的序列(供界面展示客户端命令)。
func (m *Matcher) Sequence() Sequence {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.seq
}

// Feed 投喂一次观测。返回 true 表示这次观测让序列完整命中、已触发放行。
//
// 语义要点:
//   - 命中当前期望的那一步 → 进度 +1;若是最后一步 → 放行并清除进度。
//   - 超出时限 → 进度作废。若这次观测恰好是第一步,则作为新序列的开始
//     (而不是直接丢弃),否则用户在超时边界上敲会莫名其妙地要多敲一轮。
//   - 敲错 → 进度作废,不做任何记录。这里刻意不"容忍"错误包:序列的
//     安全性来自"必须精确按顺序",容忍会把 4 步序列削弱成"4 个端口
//     碰到过就行"。
func (m *Matcher) Feed(obs Observation) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.seq.Steps) == 0 {
		return false
	}

	key := obs.Source.String()
	att := m.progress[key]

	// 超时的进度先作废,再按"这次是否是第一步"重新判断。
	if att != nil && obs.At.Sub(att.startedAt) > m.seq.Window {
		delete(m.progress, key)
		att = nil
	}

	if att == nil {
		// 没有进度:只有命中第一步才开始计数。
		if obs.Step == m.seq.Steps[0] {
			if len(m.seq.Steps) == 1 {
				// Validate 会拒绝 1 步序列,这里是防御性分支。
				m.fireOpen(obs.Source)
				return true
			}
			m.progress[key] = &attempt{next: 1, startedAt: obs.At}
		}
		return false
	}

	if obs.Step != m.seq.Steps[att.next] {
		// 敲错:作废进度,不记录。
		// 例外:如果敲错的这个包恰好是第一步,视为重新开始——用户中途
		// 发现敲错了从头再来是很自然的操作,不该被迫等到超时。
		delete(m.progress, key)
		if obs.Step == m.seq.Steps[0] && len(m.seq.Steps) > 1 {
			m.progress[key] = &attempt{next: 1, startedAt: obs.At}
		}
		return false
	}

	att.next++
	if att.next >= len(m.seq.Steps) {
		delete(m.progress, key)
		m.fireOpen(obs.Source)
		return true
	}
	return false
}

func (m *Matcher) fireOpen(src net.IP) {
	if m.onOpen == nil {
		return
	}
	// 复制一份 IP:调用方可能异步持有它,而捕获层的缓冲区会被复用。
	cp := make(net.IP, len(src))
	copy(cp, src)
	m.onOpen(cp, m.seq.OpenPort, m.seq.OpenFor)
}

// Sweep 清除超时的进度。由定时器周期调用。
//
// 存在理由:Feed 只在同一来源再次发包时才发现它超时了。一个敲了两步
// 就消失的来源会把进度永久留在 map 里,长期运行下这是内存泄漏——
// 互联网上会有大量只敲中第一步的扫描器。
func (m *Matcher) Sweep(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, att := range m.progress {
		if now.Sub(att.startedAt) > m.seq.Window {
			delete(m.progress, k)
			n++
		}
	}
	return n
}

// InFlight 返回当前进行中的进度数,供仪表板与测试观察。
func (m *Matcher) InFlight() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.progress)
}
