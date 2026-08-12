//go:build linux

package datasource

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// afPacketSource 是不依赖 XDP 的兼容层:AF_PACKET socket + cBPF 过滤。
//
// 什么时候会走到这里:内核太老(<4.8 无 XDP)、网卡驱动连 XDP generic
// 都挂不上、XDP 被其他程序占用、或权限不足以 attach XDP。
//
// 与 XDP 的性能差距是实打实的:包要走完协议栈、分配 sk_buff 之后才轮到
// 过滤器,而 XDP 在驱动层就处理掉了。缓解手段是抽样判定也放在内核侧
// (cBPF 的 ExtRand 扩展),用户态只收 1/N,跨内核边界的拷贝不是瓶颈。
//
// **产出的 model.Flow 与 XDP 模式完全一致**——用的是同一个 aggregator。
// 这是"流量展示要统一"的保证:界面看不出数据来自哪一层,只有单独展示的
// "当前数据源"字段会说明。
type afPacketSource struct {
	fd  int
	agg *aggregator
	log *log.Logger

	flushInterval time.Duration
}

func openAFPacket(cfg Config, lg *log.Logger) (Source, error) {
	n := cfg.SamplingN
	if n < 1 {
		n = 1
	}

	prog, err := assembleSampleFilter(n)
	if err != nil {
		return nil, &ErrUnavailable{Mode: ModeAFPacket, Reason: err}
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, &ErrUnavailable{Mode: ModeAFPacket,
			Reason: fmt.Errorf("创建 AF_PACKET socket(需 root 或 CAP_NET_RAW): %w", err)}
	}

	s := &afPacketSource{
		fd:            fd,
		agg:           newAggregator(n, DefaultMaxFlows, cfg.Sink, lg),
		log:           lg,
		flushInterval: DefaultFlushInterval,
	}

	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, prog); err != nil {
		s.Close()
		return nil, &ErrUnavailable{Mode: ModeAFPacket, Reason: fmt.Errorf("挂载 cBPF 过滤器: %w", err)}
	}

	if cfg.Iface != "" {
		ifi, err := net.InterfaceByName(cfg.Iface)
		if err != nil {
			s.Close()
			return nil, &ErrUnavailable{Mode: ModeAFPacket, Reason: fmt.Errorf("查找网卡 %q: %w", cfg.Iface, err)}
		}
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{
			Protocol: htons(unix.ETH_P_ALL),
			Ifindex:  ifi.Index,
		}); err != nil {
			s.Close()
			return nil, &ErrUnavailable{Mode: ModeAFPacket, Reason: fmt.Errorf("绑定网卡 %q: %w", cfg.Iface, err)}
		}
	}
	return s, nil
}

func (s *afPacketSource) Mode() Mode { return ModeAFPacket }

func (s *afPacketSource) Run(ctx context.Context) error {
	go s.agg.runFlushLoop(ctx, s.flushInterval)

	buf := make([]byte, 65536)
	for {
		if ctx.Err() != nil {
			return nil
		}
		tv := unix.NsecToTimeval((500 * time.Millisecond).Nanoseconds())
		if err := unix.SetsockoptTimeval(s.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			return err
		}
		n, _, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			// 读错误不终止:一个畸形包或瞬时 ENOBUFS 不代表 socket 坏了。
			continue
		}
		obs, err := toObservation(buf[:n])
		if err != nil {
			continue
		}
		s.agg.add(obs)
	}
}

func (s *afPacketSource) Close() error {
	if s.fd >= 0 {
		err := unix.Close(s.fd)
		s.fd = -1
		return err
	}
	return nil
}

func assembleSampleFilter(samplingN int) (*unix.SockFprog, error) {
	raw, err := bpf.Assemble(sampleFilterInstructions(samplingN))
	if err != nil {
		return nil, fmt.Errorf("汇编 cBPF 过滤器: %w", err)
	}
	filters := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		filters[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	return &unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}, nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func isTimeout(err error) bool {
	return errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR)
}
