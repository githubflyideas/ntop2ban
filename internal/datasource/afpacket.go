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

const ethHdrLen = 14

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
		agg:           newAggregator(deviceLabel(cfg.Iface, ModeAFPacket), n, DefaultMaxFlows, cfg.Sink, lg),
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
		obs, err := parseFrame(buf[:n])
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

// sampleFilterInstructions 生成采样过滤器:1/N 抽样 → IPv4 → 非分片 →
// TCP/UDP。
//
// 抽样判定刻意放在最前面:它会丢掉 (N-1)/N 的包,先抽样能省下绝大部分
// 后续指令的执行。
func sampleFilterInstructions(samplingN int) []bpf.Instruction {
	var insts []bpf.Instruction

	if samplingN > 1 {
		// ExtRand 是内核提供的均匀随机数(cBPF 的 Linux 扩展)。
		// rand % N != 0 就丢弃——判定在内核完成,不命中的包根本不会
		// 拷到用户态。这正是 tcpdump 做采样的办法。
		insts = append(insts,
			bpf.LoadExtension{Num: bpf.ExtRand},
			bpf.ALUOpConstant{Op: bpf.ALUOpMod, Val: uint32(samplingN)},
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0},
		)
	}

	insts = append(insts,
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0x0800},
		bpf.LoadAbsolute{Off: ethHdrLen + 6, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff},
		bpf.LoadAbsolute{Off: ethHdrLen + 9, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.IPPROTO_TCP},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.IPPROTO_UDP},
	)

	rejectIdx := len(insts)
	acceptIdx := rejectIdx + 1
	insts = append(insts, bpf.RetConstant{Val: 0}, bpf.RetConstant{Val: 0xffff})

	// 回填跳转距离。不手算偏移——算错了不会报错,过滤器只会静默
	// 放行或丢弃错误的包,线上表现为"统计数字不对"却无从追查。
	for i, in := range insts {
		j, ok := in.(bpf.JumpIf)
		if !ok {
			continue
		}
		if j.Cond == bpf.JumpEqual && (j.Val == unix.IPPROTO_TCP || j.Val == unix.IPPROTO_UDP) {
			j.SkipTrue = uint8(acceptIdx - i - 1)
		} else {
			j.SkipTrue = uint8(rejectIdx - i - 1)
		}
		insts[i] = j
	}
	return insts
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

// parseFrame 解析以太网 + IPv4 + TCP/UDP,产出与 XDP 侧同构的 Observation。
//
// 逐层做长度检查:过滤器保证的是"指定偏移上的值符合条件",不保证包
// 没被截断。少一个检查就是一次越界 panic,而观测是最不重要的功能,
// 不该有能力把封禁与敲门一起带走。
func parseFrame(frame []byte) (Observation, error) {
	var o Observation
	if len(frame) < ethHdrLen+20 {
		return o, errors.New("帧过短")
	}
	if frame[12] != 0x08 || frame[13] != 0x00 {
		return o, errors.New("非 IPv4")
	}

	ip := frame[ethHdrLen:]
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+4 {
		return o, errors.New("IP 头长度异常")
	}

	// 长度取 IP 头声明的总长,不是抓到的字节数:抓包可能被 snaplen
	// 截断,用截断长度统计会让流量图系统性缩水,且不会有任何报错。
	totalLen := int(ip[2])<<8 | int(ip[3])
	if totalLen == 0 || totalLen > len(ip) {
		totalLen = len(ip)
	}
	o.Length = totalLen

	copy(o.SrcIP[:], ip[12:16])
	copy(o.DstIP[:], ip[16:20])

	switch ip[9] {
	case 6:
		o.Proto = 6
	case 17:
		o.Proto = 17
	default:
		return o, errors.New("协议不在采集范围")
	}

	l4 := ip[ihl:]
	o.SrcPort = uint16(l4[0])<<8 | uint16(l4[1])
	o.DstPort = uint16(l4[2])<<8 | uint16(l4[3])
	return o, nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func isTimeout(err error) bool {
	return errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR)
}

func deviceLabel(iface string, m Mode) string {
	if iface == "" {
		iface = "any"
	}
	return iface + "(" + string(m) + ")"
}
