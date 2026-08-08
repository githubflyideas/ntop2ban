package probe

import (
	"math"
	"testing"
	"time"
)

// TestDistributionKeepsShapeNotJustMean 这是 pingping 的立项理由,也是
// 搬过来时最该守住的东西:两条链路的平均延迟相同,但一条稳定、一条
// 一半快一半极慢——分布必须能区分它们。存均值就永远看不出差别。
func TestDistributionKeepsShapeNotJustMean(t *testing.T) {
	steady := Round{Sent: 20, Recv: 20}
	for i := 0; i < 20; i++ {
		steady.RTTs = append(steady.RTTs, 250)
	}

	bimodal := Round{Sent: 20, Recv: 20}
	for i := 0; i < 10; i++ {
		bimodal.RTTs = append(bimodal.RTTs, 5)
	}
	for i := 0; i < 10; i++ {
		bimodal.RTTs = append(bimodal.RTTs, 495)
	}

	// 两者平均值都是 250
	if avg(steady.RTTs) != avg(bimodal.RTTs) {
		t.Fatalf("测试前提不成立: %v vs %v", avg(steady.RTTs), avg(bimodal.RTTs))
	}

	ds, db := steady.Distribution(), bimodal.Distribution()
	if ds[0] == db[0] {
		t.Error("min 应该能区分稳定链路与双峰链路")
	}
	if db[0] >= 10 {
		t.Errorf("双峰链路 min 应接近 5ms, got %v", db[0])
	}
	if ds[0] < 200 {
		t.Errorf("稳定链路 min 应接近 250ms, got %v", ds[0])
	}
}

func avg(v []float64) float64 {
	var s float64
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

// TestDistributionAllLost 全丢包时不能 panic,返回全 0。
func TestDistributionAllLost(t *testing.T) {
	r := Round{Sent: 20, Recv: 0}
	d := r.Distribution()
	for i, v := range d {
		if v != 0 {
			t.Errorf("全丢包时 d[%d] 应为 0, got %v", i, v)
		}
	}
}

func TestLossPct(t *testing.T) {
	cases := []struct {
		sent, recv int
		want       float64
	}{
		{20, 20, 0},
		{20, 10, 50},
		{20, 0, 100},
		{0, 0, 0}, // 不能除零 panic
	}
	for _, c := range cases {
		r := Round{Sent: c.sent, Recv: c.recv}
		if got := r.LossPct(); math.Abs(got-c.want) > 0.001 {
			t.Errorf("LossPct(%d,%d) = %v, want %v", c.sent, c.recv, got, c.want)
		}
	}
}

// TestCheckBurstIgnoresSinglePacketLoss 单个丢包是互联网常态噪声。
// 不忽略的话,每天会产生成百上千个无意义的标记,真正的突发就被淹没了。
func TestCheckBurstIgnoresSinglePacketLoss(t *testing.T) {
	hist := make([]int, 60) // 60 轮零丢包基线
	burst, _ := CheckBurst(20, 19, hist)
	if burst {
		t.Error("丢 1 个包不应判定为突发")
	}
}

// TestCheckBurstColdStartUsesAbsoluteFloor 样本不足时没有基线可比,
// 退回绝对阈值 25%。没有这条兜底,刚上线的目标永远不会报突发——
// 而新上线恰恰是最需要发现问题的时候。
func TestCheckBurstColdStartUsesAbsoluteFloor(t *testing.T) {
	short := []int{0, 0, 0} // 远少于 30 轮

	if burst, _ := CheckBurst(20, 10, short); !burst {
		t.Error("冷启动时丢 50% 应判定为突发")
	}
	if burst, _ := CheckBurst(20, 18, short); burst {
		t.Error("冷启动时丢 10% 不应触发 25% 阈值")
	}
}

// TestCheckBurstZeroMADFallsBackToAbsolute 长期零丢包的健康链路 MAD=0,
// robust z 公式退化(除零)。必须走兜底阈值,否则要么永远不报、要么
// 任何丢包都报。
func TestCheckBurstZeroMADFallsBackToAbsolute(t *testing.T) {
	perfect := make([]int, 60) // 60 轮全零丢包 -> median=0, MAD=0

	// 丢 10%(2/20)达到兜底阈值
	if burst, z := CheckBurst(20, 18, perfect); !burst {
		t.Errorf("零丢包基线下丢 10%% 应判定为突发, z=%v", z)
	}
	// 丢 5%(1/20)先被"单包忽略"挡掉
	if burst, _ := CheckBurst(20, 19, perfect); burst {
		t.Error("丢 1 个包仍不应判定为突发")
	}
}

// TestCheckBurstUsesRobustBaseline 一条本来就经常丢 2-3 个包的链路,
// 再丢 3 个不该报警;丢 15 个应该报。
//
// 这正是用 robust z(中位数+MAD)而不是均值+标准差的理由:历史里那些
// 大丢包本身会把均值和标准差抬高,于是"以前抖过,现在抖就不算异常"。
func TestCheckBurstUsesRobustBaseline(t *testing.T) {
	noisy := make([]int, 0, 60)
	for i := 0; i < 60; i++ {
		noisy = append(noisy, 2+i%2) // 在 2 与 3 之间波动
	}

	if burst, _ := CheckBurst(20, 17, noisy); burst {
		t.Error("与基线相当的丢包(3)不应判定为突发")
	}
	if burst, z := CheckBurst(20, 5, noisy); !burst {
		t.Errorf("远超基线的丢包(15)应判定为突发, z=%v", z)
	}
}

// TestCheckBurstReportsZForTooltip 判定为突发时要给出 z 值,界面靠它
// 在 tooltip 里解释"为什么标了这个点"。给不出依据的标记只会让人不信任。
func TestCheckBurstReportsZForTooltip(t *testing.T) {
	noisy := make([]int, 0, 60)
	for i := 0; i < 60; i++ {
		noisy = append(noisy, 2+i%2)
	}
	burst, z := CheckBurst(20, 5, noisy)
	if !burst {
		t.Fatal("前提:应判定为突发")
	}
	if z <= 0 {
		t.Errorf("突发应带上 z 值作为依据, got %v", z)
	}
}

func TestTargetDefaults(t *testing.T) {
	var tg Target
	if tg.interval() != DefaultInterval {
		t.Errorf("interval 默认值: want %v, got %v", DefaultInterval, tg.interval())
	}
	if tg.packets() != DefaultPackets {
		t.Errorf("packets 默认值: want %d, got %d", DefaultPackets, tg.packets())
	}

	tg = Target{Interval: 15 * time.Second, Packets: 30}
	if tg.interval() != 15*time.Second || tg.packets() != 30 {
		t.Error("显式设置应覆盖默认值")
	}
}
