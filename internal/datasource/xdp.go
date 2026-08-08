package datasource

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// xdpSource 是 XDP 数据源,native 与 generic 共用同一份实现——
// 两者的区别只在 attach 时的 flags,程序、map、解析逻辑完全相同。
type xdpSource struct {
	mode Mode
	coll *ebpf.Collection
	lnk  link.Link

	sampleRD *ringbuf.Reader
	knockRD  *ringbuf.Reader

	agg       *aggregator
	knockSink KnockSink
	log       *log.Logger

	flushInterval time.Duration
}

// openXDP 加载嵌入的 bytecode 并按 mode 指定的方式 attach。
//
// bytecode 为空时直接判定为不可用,让调用方降级——这发生在从源码构建
// 但没跑 make bpf 的情况下。给出明确的原因比一个 verifier 错误可读。
func openXDP(mode Mode, cfg Config, lg *log.Logger) (Source, error) {
	if len(samplerBytecode) == 0 {
		return nil, &ErrUnavailable{Mode: mode,
			Reason: errors.New("内嵌 eBPF bytecode 为空(从源码构建需先执行 make bpf)")}
	}

	spec, err := loadSpec()
	if err != nil {
		return nil, &ErrUnavailable{Mode: mode, Reason: err}
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, &ErrUnavailable{Mode: mode, Reason: fmt.Errorf("加载 eBPF 程序: %w", err)}
	}

	s := &xdpSource{
		mode:          mode,
		coll:          coll,
		agg:           newAggregator(cfg.Iface+"("+string(mode)+")", cfg.SamplingN, DefaultMaxFlows, cfg.Sink, lg),
		knockSink:     cfg.KnockSink,
		log:           lg,
		flushInterval: DefaultFlushInterval,
	}

	if err := s.configure(cfg); err != nil {
		s.Close()
		return nil, &ErrUnavailable{Mode: mode, Reason: err}
	}

	if err := s.attach(cfg.Iface, mode); err != nil {
		s.Close()
		return nil, &ErrUnavailable{Mode: mode, Reason: err}
	}

	if err := s.openReaders(); err != nil {
		s.Close()
		return nil, &ErrUnavailable{Mode: mode, Reason: err}
	}
	return s, nil
}

// configure 写入采样率与敲门匹配集合。
func (s *xdpSource) configure(cfg Config) error {
	rateMap := s.coll.Maps["sampling_rate"]
	if rateMap == nil {
		return errors.New("bytecode 缺少 sampling_rate map(与本程序版本不匹配)")
	}
	n := cfg.SamplingN
	if n < 1 {
		n = 1
	}
	var idx uint32
	if err := rateMap.Put(idx, uint32(n)); err != nil {
		return fmt.Errorf("写入采样率: %w", err)
	}

	// 敲门匹配集合。map 为空时 XDP 侧不会上报任何敲门事件,
	// 这正是"还没配置序列"时应有的行为。
	if err := fillU16Set(s.coll.Maps["knock_ports"], cfg.KnockTCPPorts); err != nil {
		return fmt.Errorf("写入敲门端口: %w", err)
	}
	if err := fillU16Set(s.coll.Maps["knock_icmp_lens"], cfg.KnockICMPLens); err != nil {
		return fmt.Errorf("写入敲门 ICMP 长度: %w", err)
	}
	return nil
}

func fillU16Set(m *ebpf.Map, values []int) error {
	if m == nil {
		return errors.New("map 不存在")
	}
	one := uint8(1)
	for _, v := range values {
		k := uint16(v)
		if err := m.Put(k, one); err != nil {
			return fmt.Errorf("写入 %d: %w", v, err)
		}
	}
	return nil
}

// UpdateKnockSets 热更新敲门匹配集合(序列审批通过后调用)。
//
// 直接改 map 而不是重新加载程序:重载会短暂丢失观测,而敲门配置变更
// 是常规操作,不该每次都造成采样中断。
func (s *xdpSource) UpdateKnockSets(ports, icmpLens []int) error {
	if err := clearAndFill(s.coll.Maps["knock_ports"], ports); err != nil {
		return err
	}
	return clearAndFill(s.coll.Maps["knock_icmp_lens"], icmpLens)
}

func clearAndFill(m *ebpf.Map, values []int) error {
	if m == nil {
		return errors.New("map 不存在")
	}
	// 先删旧键:直接覆盖会留下上一版序列的端口仍然匹配,
	// 那意味着旧序列在新序列生效后还能敲开门。
	var k uint16
	var v uint8
	it := m.Iterate()
	var stale []uint16
	for it.Next(&k, &v) {
		stale = append(stale, k)
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, key := range stale {
		if err := m.Delete(key); err != nil {
			return err
		}
	}
	return fillU16Set(m, values)
}

// attach 挂载 XDP 程序。
//
// native 与 generic 的唯一差别就是这个 flag。分开尝试而不是让内核
// 自选,是为了让日志能明确说出"用的是哪一级"——性能差异很大,
// 运维需要知道自己在哪一级上。
func (s *xdpSource) attach(iface string, mode Mode) error {
	prog := s.coll.Programs["xdp_sampler"]
	if prog == nil {
		return errors.New("bytecode 缺少 xdp_sampler 程序(与本程序版本不匹配)")
	}
	if iface == "" {
		return errors.New("XDP 必须指定具体网卡(-iface),不支持所有网卡")
	}

	ifi, err := interfaceByName(iface)
	if err != nil {
		return err
	}

	var flags link.XDPAttachFlags
	switch mode {
	case ModeXDPNative:
		flags = link.XDPDriverMode
	case ModeXDPGeneric:
		flags = link.XDPGenericMode
	}

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifi.Index,
		Flags:     flags,
	})
	if err != nil {
		return fmt.Errorf("attach 到 %s 失败: %w"+
			"(常见原因:权限不足需 root/CAP_NET_ADMIN、网卡驱动不支持该模式、"+
			"或已有其他 XDP 程序占用该网卡)", iface, err)
	}
	s.lnk = lnk
	return nil
}

func (s *xdpSource) openReaders() error {
	sampleRD, err := ringbuf.NewReader(s.coll.Maps["sample_events"])
	if err != nil {
		return fmt.Errorf("打开采样 ringbuf: %w", err)
	}
	s.sampleRD = sampleRD

	knockRD, err := ringbuf.NewReader(s.coll.Maps["knock_events"])
	if err != nil {
		return fmt.Errorf("打开敲门 ringbuf: %w", err)
	}
	s.knockRD = knockRD
	return nil
}

func (s *xdpSource) Mode() Mode { return s.mode }

// Run 读两个 ringbuf 并周期 flush。
//
// 采样与敲门用两个独立的 ringbuf、两个 goroutine:共用一个缓冲区时,
// 高流量下敲门事件会因为缓冲区被采样事件占满而丢失——那正是最不能丢的
// 东西。分开之后采样再怎么溢出也不影响敲门。
func (s *xdpSource) Run(ctx context.Context) error {
	go s.agg.runFlushLoop(ctx, s.flushInterval)

	errCh := make(chan error, 2)
	go func() { errCh <- s.readSamples(ctx) }()
	go func() { errCh <- s.readKnocks(ctx) }()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *xdpSource) readSamples(ctx context.Context) error {
	for {
		rec, err := s.sampleRD.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			// 单次读失败不终止:一个畸形记录不代表 ringbuf 坏了。
			continue
		}
		ev, err := parseSampleEvent(rec.RawSample)
		if err != nil {
			continue
		}
		s.agg.add(ev)
	}
}

func (s *xdpSource) readKnocks(ctx context.Context) error {
	for {
		rec, err := s.knockRD.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			continue
		}
		srcIP, kind, value, err := parseKnockEvent(rec.RawSample)
		if err != nil || s.knockSink == nil {
			continue
		}
		switch kind {
		case 1:
			s.knockSink.FeedTCP(srcIP, int(value))
		case 2:
			s.knockSink.FeedICMP(srcIP, int(value))
		}
	}
}

func (s *xdpSource) Close() error {
	if s.sampleRD != nil {
		s.sampleRD.Close()
	}
	if s.knockRD != nil {
		s.knockRD.Close()
	}
	if s.lnk != nil {
		s.lnk.Close()
	}
	if s.coll != nil {
		s.coll.Close()
	}
	return nil
}
