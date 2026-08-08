package probe

import (
	"context"
	"log"
	"net"
	"strconv"
	"time"
)

// Store 是探测结果的落地接口。实现见 internal/storage/sqlite。
//
// 抽成接口而不是直接依赖 sqlite 包,是为了让探测循环可以在测试里用
// 内存假实现驱动,不必开数据库文件。
type Store interface {
	AppendRound(ctx context.Context, r Round) error
	// RecentLoss 返回同一目标最近 n 轮的丢包数,供突发判定做基线。
	RecentLoss(ctx context.Context, target string, since time.Time, limit int) ([]int, error)
}

// Runner 按配置对一组目标做周期探测。
type Runner struct {
	store Store
	log   *log.Logger
}

func NewRunner(store Store, lg *log.Logger) *Runner {
	if lg == nil {
		lg = log.Default()
	}
	return &Runner{store: store, log: lg}
}

// Run 为每个目标起一个探测循环,直到 ctx 取消。
//
// 一个目标一个 goroutine 而不是一个循环轮流探测所有目标:探测是阻塞的
// (一轮 20 包 × 200ms 间隔至少 4 秒),串行的话目标一多,后面的目标
// 就被前面的拖着,实际间隔完全对不上配置值。
func (r *Runner) Run(ctx context.Context, targets []Target) {
	for _, t := range targets {
		go r.loop(ctx, t)
	}
}

func (r *Runner) loop(ctx context.Context, t Target) {
	// 立刻探一轮再进入定时循环:否则新加的目标要等一个完整间隔
	// (默认一分钟)才在界面上出现,让人以为配置没生效。
	r.once(ctx, t)

	ticker := time.NewTicker(t.interval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.once(ctx, t)
		}
	}
}

func (r *Runner) once(ctx context.Context, t Target) {
	var round Round
	var err error

	switch t.Kind {
	case "tcp":
		round = tcpRound(addrOf(t), t.packets(), DefaultGap, DefaultTimeout)
	default: // icmp
		round, err = icmpRound(t.Host, t.packets(), DefaultGap, DefaultTimeout)
	}
	round.Target = t.Name

	if err != nil {
		// 解析失败等错误按"整轮全丢"记录,而不是跳过这一轮。
		// 跳过会在图上留下时间空洞,让人误以为探测器自己停了;
		// 记成全丢才如实反映"这段时间目标不可达"。
		r.log.Printf("[probe] %s 探测出错(按全丢记录): %v", t.Name, err)
		round.Sent = t.packets()
		round.Recv = 0
		round.RTTs = nil
	}

	// 突发判定需要历史基线。取最近 4 小时、最多 240 轮。
	hist, herr := r.store.RecentLoss(ctx, t.Name, round.At.Add(-4*time.Hour), 240)
	if herr != nil {
		// 基线取不到就不判定突发,但这一轮数据仍要存——
		// 丢掉测量结果比丢掉一个标记严重得多。
		r.log.Printf("[probe] %s 读取基线失败(本轮不做突发判定): %v", t.Name, herr)
	} else {
		round.Burst, round.ZScore = CheckBurst(round.Sent, round.Recv, hist)
	}

	if err := r.store.AppendRound(ctx, round); err != nil {
		r.log.Printf("[probe] %s 写入失败: %v", t.Name, err)
	}
}

func addrOf(t Target) string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}
