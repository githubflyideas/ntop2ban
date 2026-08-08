package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/probe"
)

func sampleRound(target string, at time.Time, sent, recv int, rtts []float64) probe.Round {
	return probe.Round{Target: target, At: at, Sent: sent, Recv: recv, RTTs: rtts}
}

// TestProbeRoundTrip RTT 样本经打包存盘再读出必须保持原值(float32 精度内)。
//
// 打包成 blob 是刻意的存储优化(4 字节/样本 vs JSON 的 ~6 字符),
// 但一旦打包/解包不对称,读出来的就是垃圾数值——而且图表照样画得出来,
// 只是数字全错,不会有任何报错。所以这个往返断言是必须的。
func TestProbeRoundTrip(t *testing.T) {
	s := openTempStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	want := []float64{0.512, 1.25, 12.5, 250.75, 1000.125}
	if err := s.AppendRound(ctx, sampleRound("link-a", now, 20, 5, want)); err != nil {
		t.Fatalf("AppendRound: %v", err)
	}

	got, err := s.ProbeRounds(ctx, "link-a", now.Add(-time.Minute), now.Add(time.Minute), 10)
	if err != nil {
		t.Fatalf("ProbeRounds: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 round, got %d", len(got))
	}
	r := got[0]
	if r.Sent != 20 || r.Recv != 5 {
		t.Errorf("计数未原样返回: sent=%d recv=%d", r.Sent, r.Recv)
	}
	if len(r.RTTs) != len(want) {
		t.Fatalf("样本数不符: want %d, got %d", len(want), len(r.RTTs))
	}
	for i := range want {
		// float32 精度:1000.125 这种量级的相对误差约 1e-7,给足余量
		if diff := r.RTTs[i] - want[i]; diff > 0.01 || diff < -0.01 {
			t.Errorf("RTT[%d]: want %v, got %v", i, want[i], r.RTTs[i])
		}
	}
	if !r.At.Equal(now) {
		t.Errorf("时间戳未原样返回: want %v, got %v", now, r.At)
	}
}

// TestProbeRoundEmptyRTTs 全丢包的轮次(RTTs 为空)要能存能读,
// 不能因为 blob 为 NULL 就报错——全丢包恰恰是最需要记录的情况。
func TestProbeRoundEmptyRTTs(t *testing.T) {
	s := openTempStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	if err := s.AppendRound(ctx, sampleRound("link-down", now, 20, 0, nil)); err != nil {
		t.Fatalf("AppendRound: %v", err)
	}
	got, err := s.ProbeRounds(ctx, "link-down", now.Add(-time.Minute), now.Add(time.Minute), 10)
	if err != nil {
		t.Fatalf("ProbeRounds: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 round, got %d", len(got))
	}
	if got[0].Recv != 0 || len(got[0].RTTs) != 0 {
		t.Errorf("全丢包轮次应为 recv=0 且无样本, got recv=%d rtts=%d", got[0].Recv, len(got[0].RTTs))
	}
	if got[0].LossPct() != 100 {
		t.Errorf("丢包率: want 100, got %v", got[0].LossPct())
	}
}

// TestAppendRoundIsIdempotentOnSameSecond 同目标同一秒重复写不该报主键
// 冲突把数据丢掉——进程重启后会立刻探一轮,可能正好撞上上次那一秒。
func TestAppendRoundIsIdempotentOnSameSecond(t *testing.T) {
	s := openTempStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	if err := s.AppendRound(ctx, sampleRound("link-a", now, 20, 20, []float64{1})); err != nil {
		t.Fatalf("first AppendRound: %v", err)
	}
	if err := s.AppendRound(ctx, sampleRound("link-a", now, 20, 10, []float64{2})); err != nil {
		t.Fatalf("second AppendRound(同一秒): %v", err)
	}

	got, err := s.ProbeRounds(ctx, "link-a", now.Add(-time.Minute), now.Add(time.Minute), 10)
	if err != nil {
		t.Fatalf("ProbeRounds: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("同一秒应只有一行(后写覆盖), got %d", len(got))
	}
	if got[0].Recv != 10 {
		t.Errorf("应为后写的值, want recv=10, got %d", got[0].Recv)
	}
}

// TestRecentLossFeedsBurstDetection RecentLoss 返回的是丢包数序列,
// 直接喂给 probe.CheckBurst。这个测试把存储与判定之间的契约钉住:
// 顺序、数量、语义(sent-recv)都要对。
func TestRecentLossFeedsBurstDetection(t *testing.T) {
	s := openTempStore(t)
	ctx := context.Background()
	base := time.Now().Truncate(time.Second)

	// 40 轮,每轮丢 2 个
	for i := 0; i < 40; i++ {
		at := base.Add(-time.Duration(i) * time.Minute)
		if err := s.AppendRound(ctx, sampleRound("link-a", at, 20, 18, []float64{1, 2})); err != nil {
			t.Fatalf("AppendRound %d: %v", i, err)
		}
	}

	hist, err := s.RecentLoss(ctx, "link-a", base.Add(-4*time.Hour), 240)
	if err != nil {
		t.Fatalf("RecentLoss: %v", err)
	}
	if len(hist) != 40 {
		t.Fatalf("want 40 轮基线, got %d", len(hist))
	}
	for i, v := range hist {
		if v != 2 {
			t.Fatalf("hist[%d]: want 2(=sent-recv), got %d", i, v)
		}
	}
}

// TestRecentLossIsPerTarget 不同目标的基线不能混——A 目标的丢包史
// 混进 B 的判定,会让稳定链路上的抖动被"别人的历史"掩盖掉。
func TestRecentLossIsPerTarget(t *testing.T) {
	s := openTempStore(t)
	ctx := context.Background()
	base := time.Now().Truncate(time.Second)

	if err := s.AppendRound(ctx, sampleRound("link-a", base, 20, 20, nil)); err != nil {
		t.Fatalf("append a: %v", err)
	}
	if err := s.AppendRound(ctx, sampleRound("link-b", base, 20, 5, nil)); err != nil {
		t.Fatalf("append b: %v", err)
	}

	histA, err := s.RecentLoss(ctx, "link-a", base.Add(-time.Hour), 100)
	if err != nil {
		t.Fatalf("RecentLoss a: %v", err)
	}
	if len(histA) != 1 || histA[0] != 0 {
		t.Errorf("link-a 基线应只含自己的数据, got %v", histA)
	}
}

// TestProbeRetentionDeletesOldRounds 探测数据也要按保留期清理,
// 否则一分钟一轮、多目标的库会无限增长。
func TestProbeRetentionDeletesOldRounds(t *testing.T) {
	s := openTempStore(t)
	ctx := context.Background()
	recent := time.Now().Truncate(time.Second)
	old := recent.AddDate(0, 0, -50)

	if err := s.AppendRound(ctx, sampleRound("link-a", recent, 20, 20, nil)); err != nil {
		t.Fatalf("append recent: %v", err)
	}
	if err := s.AppendRound(ctx, sampleRound("link-a", old, 20, 20, nil)); err != nil {
		t.Fatalf("append old: %v", err)
	}

	// 40 天保留期(与 -days 默认值一致)
	if err := s.ProbeRetention(ctx, 40*24*time.Hour); err != nil {
		t.Fatalf("ProbeRetention: %v", err)
	}

	got, err := s.ProbeRounds(ctx, "link-a", recent.AddDate(0, 0, -100), recent.Add(time.Minute), 100)
	if err != nil {
		t.Fatalf("ProbeRounds: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("清理后应只剩最近一轮, got %d", len(got))
	}
	if !got[0].At.Equal(recent) {
		t.Errorf("留下的应是最近那轮, got %v", got[0].At)
	}
}

func TestProbeTargets(t *testing.T) {
	s := openTempStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	for _, name := range []string{"link-b", "link-a", "link-a"} {
		if err := s.AppendRound(ctx, sampleRound(name, now.Add(time.Duration(len(name))*time.Second), 20, 20, nil)); err != nil {
			t.Fatalf("append %s: %v", name, err)
		}
	}
	names, err := s.ProbeTargets(ctx)
	if err != nil {
		t.Fatalf("ProbeTargets: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("want 2 distinct targets, got %v", names)
	}
	if names[0] != "link-a" || names[1] != "link-b" {
		t.Errorf("应按名字排序, got %v", names)
	}
}

// TestProbeBurstFlagPersists 突发标记与 z 值要能存下来——界面靠它们
// 在图上画标记并在 tooltip 里给出依据。
func TestProbeBurstFlagPersists(t *testing.T) {
	s := openTempStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	r := sampleRound("link-a", now, 20, 5, []float64{1})
	r.Burst = true
	r.ZScore = 7.25
	if err := s.AppendRound(ctx, r); err != nil {
		t.Fatalf("AppendRound: %v", err)
	}

	got, err := s.ProbeRounds(ctx, "link-a", now.Add(-time.Minute), now.Add(time.Minute), 10)
	if err != nil {
		t.Fatalf("ProbeRounds: %v", err)
	}
	if !got[0].Burst {
		t.Error("burst 标记未持久化")
	}
	if got[0].ZScore != 7.25 {
		t.Errorf("z 值未持久化: want 7.25, got %v", got[0].ZScore)
	}
}
