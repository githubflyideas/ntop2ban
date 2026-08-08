package knock

import (
	"context"
	"errors"
	"log"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// Opener 是放行动作的抽象:敲门成功后为某个来源 IP 临时放行端口。
//
// 抽成接口有两个理由:一是状态机与捕获层的测试不该去碰真实防火墙;
// 二是放行手段是可换的——当前实现是 nftables(见 nftables.go),
// 小企业单机场景够用;将来若要跟 xdp-ban 的 eBPF map 对接,换一个
// 实现即可,守护进程逻辑不动。
type Opener interface {
	// Open 为 src 放行 port,持续 d。实现须自行处理到期回收。
	Open(src net.IP, port int, d time.Duration) error
}

// Recorder 记录成功授权。只记成功——失败的敲门不写任何东西。
type Recorder interface {
	RecordGrant(ctx context.Context, sourceIP string, openPort int, grantedAt time.Time, openFor time.Duration, sequenceID int64) error
}

// Daemon 把捕获层、状态机、放行动作接起来。
type Daemon struct {
	iface    string
	matcher  *Matcher
	opener   Opener
	recorder Recorder
	seqID    int64

	log *log.Logger
}

// DaemonConfig 是守护进程的构造参数。
type DaemonConfig struct {
	// Iface 抓 TCP SYN 的网卡。空字符串表示所有网卡。
	Iface string
	// Sequence 当前生效的序列(来自库里 state='active' 的那一版)。
	Sequence Sequence
	// SequenceID 用于把授权记录关联到具体哪一版序列——事后审计时
	// 需要知道"当时生效的是哪一版",否则序列改过之后旧记录就无从解释。
	SequenceID int64
	Opener     Opener
	Recorder   Recorder
	Logger     *log.Logger
}

func NewDaemon(cfg DaemonConfig) (*Daemon, error) {
	if err := cfg.Sequence.Validate(); err != nil {
		return nil, err
	}
	if cfg.Opener == nil {
		return nil, errors.New("knock: 必须提供 Opener,否则敲门成功也不会放行任何端口")
	}
	lg := cfg.Logger
	if lg == nil {
		lg = log.Default()
	}

	d := &Daemon{
		iface:    cfg.Iface,
		opener:   cfg.Opener,
		recorder: cfg.Recorder,
		seqID:    cfg.SequenceID,
		log:      lg,
	}
	d.matcher = NewMatcher(cfg.Sequence, d.onOpen)
	return d, nil
}

// SetSequence 热更新序列(审批通过后调用)。
//
// 注意 TCP 捕获的 cBPF 过滤器是按端口集合生成的,序列换了端口就要重建
// socket。Run 里通过监听 reload 通道处理,不在这里直接改——在别的
// goroutine 里换掉正在被读的 fd 会引入竞态。
func (d *Daemon) SetSequence(seq Sequence, seqID int64) {
	d.matcher.SetSequence(seq)
	d.seqID = seqID
}

func (d *Daemon) onOpen(src net.IP, port int, dur time.Duration) {
	if err := d.opener.Open(src, port, dur); err != nil {
		// 放行失败必须显眼:敲门对了却进不来,用户会以为敲门本身坏了。
		d.log.Printf("[knock] 放行失败 src=%s port=%d: %v", src, port, err)
		return
	}
	d.log.Printf("[knock] 已放行 src=%s port=%d 时长=%s", src, port, dur)

	if d.recorder != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := d.recorder.RecordGrant(ctx, src.String(), port, time.Now(), dur, d.seqID); err != nil {
			// 记录失败不撤销放行:用户已经敲对了,不该因为写库问题被拒之门外。
			d.log.Printf("[knock] 记录授权失败(放行仍然生效) src=%s: %v", src, err)
		}
	}
}

// Run 启动捕获循环,直到 ctx 取消。
//
// 两个 socket 各跑一个 goroutine:ICMP 与 TCP 是两种不同的 socket 类型,
// 没法在一个 read 里同时等。观测统一投喂给同一个状态机,由它按来源 IP
// 维护进度——两类步骤混在一个序列里正是靠这一点。
func (d *Daemon) Run(ctx context.Context) error {
	seq := d.matcher.Sequence()

	var tcpPorts []int
	needICMP := false
	for _, st := range seq.Steps {
		switch st.Kind {
		case StepTCP:
			tcpPorts = append(tcpPorts, st.Port)
		case StepICMP:
			needICMP = true
		}
	}

	errCh := make(chan error, 2)
	started := 0

	if len(tcpPorts) > 0 {
		cap, err := openTCPCapture(d.iface, tcpPorts)
		if err != nil {
			return err
		}
		defer cap.Close()
		started++
		go func() { errCh <- d.loopTCP(ctx, cap) }()
	}

	if needICMP {
		cap, err := openICMPCapture()
		if err != nil {
			return err
		}
		defer cap.Close()
		started++
		go func() { errCh <- d.loopICMP(ctx, cap) }()
	}

	if started == 0 {
		return errors.New("knock: 序列里既没有 TCP 步也没有 ICMP 步")
	}

	// 定期清理超时进度。没有这个,只敲中第一步就消失的来源(互联网上
	// 大量存在的扫描器)会把进度永久留在内存里。
	go d.sweepLoop(ctx, seq.Window)

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func (d *Daemon) sweepLoop(ctx context.Context, window time.Duration) {
	t := time.NewTicker(window)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.matcher.Sweep(time.Now())
		}
	}
}

// readTimeout 是两个捕获循环的单次读超时。
//
// 存在的唯一理由是让循环能定期回头检查 ctx 是否已取消——敲门端口可能
// 几小时没有任何流量,没有超时的话进程退出会一直卡在 read 上。
const readTimeout = time.Second

func (d *Daemon) loopTCP(ctx context.Context, c *tcpCapture) error {
	buf := make([]byte, 2048)
	for {
		if ctx.Err() != nil {
			return nil
		}
		src, port, err := c.Read(buf, readTimeout)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			return err
		}
		d.matcher.Feed(Observation{
			Source: src,
			Step:   Step{Kind: StepTCP, Port: port},
			At:     time.Now(),
		})
	}
}

func (d *Daemon) loopICMP(ctx context.Context, c *icmpCapture) error {
	buf := make([]byte, 2048)
	for {
		if ctx.Err() != nil {
			return nil
		}
		src, payloadLen, err := c.Read(buf, readTimeout)
		if err != nil {
			if isTimeout(err) || errors.Is(err, errNotEchoRequest) {
				continue
			}
			// 解析类错误(包截断等)不该终止循环——一个畸形包不代表
			// socket 坏了,继续读下一个。
			continue
		}
		d.matcher.Feed(Observation{
			Source: src,
			Step:   Step{Kind: StepICMP, PayloadLen: payloadLen},
			At:     time.Now(),
		})
	}
}

func isTimeout(err error) bool {
	return errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR)
}
