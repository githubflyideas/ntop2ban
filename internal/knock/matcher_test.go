package knock

import (
	"net"
	"testing"
	"time"
)

// demoSeq 就是需求里给的那个例子:TCP 9001 → ICMP 56 → TCP 9003 → ICMP 90。
func demoSeq() Sequence {
	return Sequence{
		Steps: []Step{
			{Kind: StepTCP, Port: 9001},
			{Kind: StepICMP, PayloadLen: 56},
			{Kind: StepTCP, Port: 9003},
			{Kind: StepICMP, PayloadLen: 90},
		},
		Window:   DefaultWindow,
		OpenPort: 22,
		OpenFor:  DefaultOpenFor,
	}
}

type opened struct {
	src  net.IP
	port int
	dur  time.Duration
}

func newTestMatcher(t *testing.T, seq Sequence) (*Matcher, *[]opened) {
	t.Helper()
	var log []opened
	m := NewMatcher(seq, func(src net.IP, port int, d time.Duration) {
		log = append(log, opened{src: src, port: port, dur: d})
	})
	return m, &log
}

func feedAll(m *Matcher, src string, base time.Time, steps []Step) {
	ip := net.ParseIP(src)
	for i, st := range steps {
		m.Feed(Observation{Source: ip, Step: st, At: base.Add(time.Duration(i) * time.Second)})
	}
}

// TestFullSequenceOpens 正常路径:按顺序敲完 4 步,放行一次。
func TestFullSequenceOpens(t *testing.T) {
	seq := demoSeq()
	m, log := newTestMatcher(t, seq)

	feedAll(m, "203.0.113.7", time.Now(), seq.Steps)

	if len(*log) != 1 {
		t.Fatalf("want 1 次放行, got %d", len(*log))
	}
	got := (*log)[0]
	if got.port != 22 {
		t.Errorf("放行端口: want 22, got %d", got.port)
	}
	if !got.src.Equal(net.ParseIP("203.0.113.7")) {
		t.Errorf("放行来源: want 203.0.113.7, got %s", got.src)
	}
	if m.InFlight() != 0 {
		t.Errorf("成功后进度应清空, got %d", m.InFlight())
	}
}

// TestWrongOrderDoesNotOpen 乱序不放行——这是敲门安全性的核心。
// 顺序无关的话,4 步序列就退化成"这 4 个端口都碰过就行",
// 一次全端口扫描就能顺带敲开。
func TestWrongOrderDoesNotOpen(t *testing.T) {
	seq := demoSeq()
	m, log := newTestMatcher(t, seq)

	shuffled := []Step{seq.Steps[0], seq.Steps[2], seq.Steps[1], seq.Steps[3]}
	feedAll(m, "203.0.113.8", time.Now(), shuffled)

	if len(*log) != 0 {
		t.Fatalf("乱序不应放行, got %d 次", len(*log))
	}
}

// TestPortScanDoesNotOpen 一次把所有涉及的 TCP 端口都扫一遍(扫描器的
// 典型行为)不应该敲开任何东西。
func TestPortScanDoesNotOpen(t *testing.T) {
	seq := demoSeq()
	m, log := newTestMatcher(t, seq)

	scan := []Step{
		{Kind: StepTCP, Port: 9001},
		{Kind: StepTCP, Port: 9002},
		{Kind: StepTCP, Port: 9003},
		{Kind: StepTCP, Port: 9004},
	}
	feedAll(m, "198.51.100.5", time.Now(), scan)

	if len(*log) != 0 {
		t.Fatalf("端口扫描不应放行, got %d 次", len(*log))
	}
}

// TestSequenceMustCompleteWithinWindow 整个序列必须在时限内完成:
// 最后一步来得太晚就不算。
func TestSequenceMustCompleteWithinWindow(t *testing.T) {
	seq := demoSeq()
	m, log := newTestMatcher(t, seq)
	base := time.Now()
	ip := net.ParseIP("203.0.113.9")

	m.Feed(Observation{Source: ip, Step: seq.Steps[0], At: base})
	m.Feed(Observation{Source: ip, Step: seq.Steps[1], At: base.Add(2 * time.Second)})
	m.Feed(Observation{Source: ip, Step: seq.Steps[2], At: base.Add(4 * time.Second)})
	// 第 4 步超过 1 分钟窗口才到
	m.Feed(Observation{Source: ip, Step: seq.Steps[3], At: base.Add(seq.Window + time.Second)})

	if len(*log) != 0 {
		t.Fatalf("超时的序列不应放行, got %d 次", len(*log))
	}
}

// TestRestartFromFirstStepAfterMistake 敲错之后立刻重敲第一步应该能
// 重新开始,不必等到超时——用户发现敲错了从头来是很自然的操作。
func TestRestartFromFirstStepAfterMistake(t *testing.T) {
	seq := demoSeq()
	m, log := newTestMatcher(t, seq)
	base := time.Now()
	ip := net.ParseIP("203.0.113.10")

	m.Feed(Observation{Source: ip, Step: seq.Steps[0], At: base})
	// 敲错第二步
	m.Feed(Observation{Source: ip, Step: Step{Kind: StepICMP, PayloadLen: 999}, At: base.Add(time.Second)})
	// 立刻从第一步重来,完整敲完
	feedAll(m, "203.0.113.10", base.Add(2*time.Second), seq.Steps)

	if len(*log) != 1 {
		t.Fatalf("重敲后应放行 1 次, got %d", len(*log))
	}
}

// TestSourcesAreIndependent 两个来源各敲一半,不能凑成一次完整序列。
// 若状态机按全局进度而非按来源记,攻击者就能借别人敲过的进度捡漏。
func TestSourcesAreIndependent(t *testing.T) {
	seq := demoSeq()
	m, log := newTestMatcher(t, seq)
	base := time.Now()
	a := net.ParseIP("203.0.113.11")
	b := net.ParseIP("203.0.113.12")

	m.Feed(Observation{Source: a, Step: seq.Steps[0], At: base})
	m.Feed(Observation{Source: a, Step: seq.Steps[1], At: base.Add(time.Second)})
	// b 接着敲后两步
	m.Feed(Observation{Source: b, Step: seq.Steps[2], At: base.Add(2 * time.Second)})
	m.Feed(Observation{Source: b, Step: seq.Steps[3], At: base.Add(3 * time.Second)})

	if len(*log) != 0 {
		t.Fatalf("不同来源的进度不应互相借用, got %d 次放行", len(*log))
	}
}

// TestSweepEvictsStaleProgress 只敲了一步就消失的来源(互联网上大量
// 存在)必须被清掉,否则 map 会无限增长。
func TestSweepEvictsStaleProgress(t *testing.T) {
	seq := demoSeq()
	m, _ := newTestMatcher(t, seq)
	base := time.Now()

	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		m.Feed(Observation{Source: net.ParseIP(ip), Step: seq.Steps[0], At: base})
	}
	if m.InFlight() != 3 {
		t.Fatalf("want 3 in-flight, got %d", m.InFlight())
	}

	evicted := m.Sweep(base.Add(seq.Window + time.Second))
	if evicted != 3 {
		t.Errorf("want 3 evicted, got %d", evicted)
	}
	if m.InFlight() != 0 {
		t.Errorf("Sweep 后应为 0, got %d", m.InFlight())
	}
}

// TestSetSequenceClearsProgress 热更新序列后,旧进度必须作废,
// 否则某个来源可能凭旧序列的进度在新序列下少敲几步就开门。
func TestSetSequenceClearsProgress(t *testing.T) {
	seq := demoSeq()
	m, log := newTestMatcher(t, seq)
	base := time.Now()
	ip := net.ParseIP("203.0.113.13")

	m.Feed(Observation{Source: ip, Step: seq.Steps[0], At: base})
	m.Feed(Observation{Source: ip, Step: seq.Steps[1], At: base.Add(time.Second)})

	newSeq := demoSeq()
	newSeq.Steps[2] = Step{Kind: StepTCP, Port: 9500}
	m.SetSequence(newSeq)

	if m.InFlight() != 0 {
		t.Fatalf("SetSequence 后进度应清空, got %d", m.InFlight())
	}
	// 接着敲新序列的第 3、4 步不应放行(因为进度已清)
	m.Feed(Observation{Source: ip, Step: newSeq.Steps[2], At: base.Add(2 * time.Second)})
	m.Feed(Observation{Source: ip, Step: newSeq.Steps[3], At: base.Add(3 * time.Second)})
	if len(*log) != 0 {
		t.Fatalf("清空进度后不应放行, got %d", len(*log))
	}
}

// TestIPv4MappedFormsShareProgress 同一个来源用 IPv4 与 IPv4-mapped-IPv6
// 两种表示形式敲门,必须算同一个进度,否则跨协议栈敲门永远敲不开。
func TestIPv4MappedFormsShareProgress(t *testing.T) {
	seq := demoSeq()
	m, log := newTestMatcher(t, seq)
	base := time.Now()

	v4 := net.ParseIP("203.0.113.20")
	mapped := net.ParseIP("::ffff:203.0.113.20")

	m.Feed(Observation{Source: v4, Step: seq.Steps[0], At: base})
	m.Feed(Observation{Source: mapped, Step: seq.Steps[1], At: base.Add(time.Second)})
	m.Feed(Observation{Source: v4, Step: seq.Steps[2], At: base.Add(2 * time.Second)})
	m.Feed(Observation{Source: mapped, Step: seq.Steps[3], At: base.Add(3 * time.Second)})

	if len(*log) != 1 {
		t.Fatalf("IPv4 与 IPv4-mapped 形式应共享进度, got %d 次放行", len(*log))
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Sequence)
		wantErr bool
	}{
		{"合法序列", func(s *Sequence) {}, false},
		{"只有一步", func(s *Sequence) { s.Steps = s.Steps[:1] }, true},
		{"超过八步", func(s *Sequence) {
			s.Steps = make([]Step, 9)
			for i := range s.Steps {
				s.Steps[i] = Step{Kind: StepTCP, Port: 9000 + i}
			}
		}, true},
		{"敲门端口等于放行端口", func(s *Sequence) { s.Steps[0].Port = s.OpenPort }, true},
		{"ICMP 长度过大会分片", func(s *Sequence) { s.Steps[1].PayloadLen = 2000 }, true},
		{"ICMP 长度过小", func(s *Sequence) { s.Steps[1].PayloadLen = 2 }, true},
		{"相邻两步相同", func(s *Sequence) { s.Steps[1] = s.Steps[0] }, true},
		{"不支持 udp", func(s *Sequence) { s.Steps[0].Kind = StepKind("udp") }, true},
		{"时限为零", func(s *Sequence) { s.Window = 0 }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seq := demoSeq()
			tc.mutate(&seq)
			err := seq.Validate()
			if tc.wantErr && err == nil {
				t.Error("want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("want no error, got %v", err)
			}
		})
	}
}

// TestClientScriptIsCopyPastable 界面要能直接给出可复制的命令。
// 断言生成的脚本里确实出现了 ping -s 与 nc -z 这两种系统自带命令,
// 而不是某个需要用户先装工具的东西——这是这个 knock 设计的前提。
func TestClientScriptIsCopyPastable(t *testing.T) {
	seq := demoSeq()
	script := seq.ClientScript("198.51.100.9")
	for _, want := range []string{"nc -z -w1 198.51.100.9 9001", "ping -s 56 -c 1 198.51.100.9", "ping -s 90"} {
		if !contains(script, want) {
			t.Errorf("客户端脚本缺少 %q\n实际:\n%s", want, script)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
