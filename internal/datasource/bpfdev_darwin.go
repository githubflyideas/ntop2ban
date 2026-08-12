//go:build darwin

package datasource

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// bpfDevSource 是 macOS 上的本机抓包:/dev/bpfN + cBPF 过滤。
//
// BPF 是 BSD 的原生设施,Linux 的 AF_PACKET + cBPF 是后来的仿制,所以这一
// 档与 af-packet 大致同级,而不是它的降级目标。XDP 在 macOS 上没有任何
// 对应物,这里就是 macOS 上唯一的一级。
//
// 与 Linux 侧两个实打实的差别,都会影响用户看到的数字,所以都在日志里
// 说明:
//
// 一是抽样在用户态做。Linux 侧靠 cBPF 的 ExtRand 扩展在内核里丢掉
// (N-1)/N 的包,BSD 的 BPF 解释器没有随机数扩展,判定只能等包拷到用户
// 态之后。统计外推依然成立(聚合器照样乘 N),但 -sampling-n 在 macOS 上
// 不再是"免费"的:每个通过过滤器的包都付了一次拷贝。
//
// 二是链路层类型不能假设。en0 是以太网,lo0 是 DLT_NULL,utun* 是
// DLT_RAW;而 cBPF 过滤器里的偏移量是按以太网写的,所以过滤器只在
// DLT_EN10MB 下挂载,其余类型放全量进来由用户态解析筛。
//
// 实现刻意只用标准库 syscall 而不是 x/sys/unix:BIOCSETIF、BIOCIMMEDIATE
// 这套 ioctl 的封装只有标准库有(syscall/bpf_bsd.go),而两个包的 Errno
// 是不同类型,混用会让 errors.Is 静默失配——那是最不该在错误处理里出现
// 的 bug。unix 只在编译期断言里用到类型。
type bpfDevSource struct {
	fd        int
	dlt       int
	iface     string
	buf       []byte
	samplingN int

	agg *aggregator
	log *log.Logger

	flushInterval time.Duration
}

// 编译期核对 bpfframe.go 里手写的偏移量与内核结构一致。
//
// 差值不为 0 就会因为数组下标越界而编译失败。这条断言比注释可靠:
// bh_tstamp 在 Darwin 上是 32 位的 timeval(哪怕在 arm64 上),这种细节
// 一旦上游改了,靠人读注释是发现不了的。
var (
	_ = [1]struct{}{}[unsafe.Offsetof(unix.BpfHdr{}.Caplen)-bpfHdrCaplenOff]
	_ = [1]struct{}{}[unsafe.Offsetof(unix.BpfHdr{}.Datalen)-bpfHdrDatalenOff]
	_ = [1]struct{}{}[unsafe.Offsetof(unix.BpfHdr{}.Hdrlen)-bpfHdrLenOff]
)

// bpfDevMaxUnits 是探测 /dev/bpfN 的上限。
//
// 逐个试而不是用 BIOCGBLEN 之类的办法找空闲设备,是因为 BSD 没有提供
// "给我一个空闲 bpf 设备"的接口;每个设备同一时刻只能被一个进程占用,
// 已占用时 open 返回 EBUSY。macOS 默认按需创建到 /dev/bpf255。
const bpfDevMaxUnits = 256

// bpfBufLen 是内核读缓冲区大小。
//
// 512KB 是 macOS 的 debug.bpf_maxbufsize 默认值,再大 BIOCSBLEN 会失败。
// 缓冲区越大,一次 read 带回来的包越多、系统调用越少;这里不是省内存的
// 地方——缓冲区满了内核就丢包,而丢包表现为"统计偏低",无从追查。
const bpfBufLen = 512 * 1024

// bpfReadTimeout 是 BIOCSRTIMEOUT。
//
// 不开 BIOCIMMEDIATE(那会让每来一个包就唤醒一次进程),而是让 read 在
// 缓冲区满或超时后返回。500ms 是与 ctx 取消的响应速度之间的折中:关掉
// 服务时最多等这么久。
const bpfReadTimeout = 500 * time.Millisecond

func openBPFDevice(cfg Config, lg *log.Logger) (Source, error) {
	if cfg.Iface == "" {
		// AF_PACKET 不绑网卡就是"所有网卡",BPF 设备没有这个语义:
		// BIOCSETIF 是必须的一步。与其让用户看到一个 ioctl 错误码,
		// 不如直接说清要什么。
		return nil, &ErrUnavailable{Mode: ModeBPFDevice,
			Reason: errors.New("macOS 上必须用 -iface 指定网卡(BPF 设备不支持监听全部网卡),例如 -iface en0")}
	}

	n := cfg.SamplingN
	if n < 1 {
		n = 1
	}

	fd, err := openFreeBPFDevice()
	if err != nil {
		return nil, &ErrUnavailable{Mode: ModeBPFDevice, Reason: err}
	}

	s := &bpfDevSource{
		fd:            fd,
		iface:         cfg.Iface,
		samplingN:     n,
		agg:           newAggregator(n, DefaultMaxFlows, cfg.Sink, lg),
		log:           lg,
		flushInterval: DefaultFlushInterval,
	}

	if err := s.configure(); err != nil {
		s.Close()
		return nil, &ErrUnavailable{Mode: ModeBPFDevice, Reason: err}
	}
	return s, nil
}

// openFreeBPFDevice 找一个没被占用的 /dev/bpfN。
//
// 权限错误单独说明:/dev/bpf* 默认是 root:wheel 0600,普通用户一个都打不
// 开。这是 macOS 上最常见的失败原因,而 EACCES 本身指不到任何方向——
// Wireshark 装那个 ChmodBPF 启动项就是为了这件事。
func openFreeBPFDevice() (int, error) {
	var lastErr error
	for i := 0; i < bpfDevMaxUnits; i++ {
		path := fmt.Sprintf("/dev/bpf%d", i)
		fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
		if err == nil {
			return fd, nil
		}
		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
			return -1, fmt.Errorf("打开 %s 需要 root:请用 sudo 运行,"+
				"或把 /dev/bpf* 的属主改成当前用户(Wireshark 的 ChmodBPF 就是干这个的): %w", path, err)
		}
		if errors.Is(err, syscall.EBUSY) {
			continue // 被别的抓包程序占着,试下一个
		}
		lastErr = err
		if errors.Is(err, syscall.ENOENT) {
			// 编号连续,遇到不存在的就不用再往后试了。
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("全部被占用")
	}
	return -1, fmt.Errorf("找不到可用的 /dev/bpf 设备: %w", lastErr)
}

// configure 按 libpcap 的顺序设置设备。顺序不是随意的:BIOCSBLEN 必须在
// BIOCSETIF 之前(内核在绑定网卡时才分配缓冲区),而 DLT 只有绑定之后
// 才知道。
func (s *bpfDevSource) configure() error {
	bufLen, err := syscall.SetBpfBuflen(s.fd, bpfBufLen)
	if err != nil {
		return fmt.Errorf("设置 BPF 缓冲区大小: %w", err)
	}
	s.buf = make([]byte, bufLen)

	if err := syscall.SetBpfInterface(s.fd, s.iface); err != nil {
		return fmt.Errorf("绑定网卡 %q(名字是否正确?用 ifconfig 看,常见是 en0): %w", s.iface, err)
	}

	dlt, err := syscall.BpfDatalink(s.fd)
	if err != nil {
		return fmt.Errorf("查询链路层类型: %w", err)
	}
	s.dlt = dlt
	if !linkTypeSupported(dlt) {
		return fmt.Errorf("网卡 %q 的链路层类型 DLT=%d 不支持(只支持以太网、DLT_NULL 与 DLT_RAW)", s.iface, dlt)
	}

	if err := syscall.SetBpfImmediate(s.fd, 0); err != nil {
		return fmt.Errorf("关闭 BPF immediate 模式: %w", err)
	}
	tv := syscall.NsecToTimeval(bpfReadTimeout.Nanoseconds())
	if err := syscall.SetBpfTimeout(s.fd, &tv); err != nil {
		return fmt.Errorf("设置 BPF 读超时: %w", err)
	}

	// 过滤器只在以太网下挂:里面的偏移量(12 处的 ethertype、
	// ethHdrLen+9 处的协议号)是按以太网头写的,DLT_NULL 与 DLT_RAW 的
	// 头长度不同,同一份指令会读到错位的字节并静默丢错包。
	if dlt == dltEthernet {
		insns, err := assembleBPFDevFilter()
		if err != nil {
			return err
		}
		if err := syscall.SetBpf(s.fd, insns); err != nil {
			return fmt.Errorf("挂载 cBPF 过滤器: %w", err)
		}
	}
	return nil
}

// assembleBPFDevFilter 汇编过滤器。samplingN 传 1:抽样不在这里做。
func assembleBPFDevFilter() ([]syscall.BpfInsn, error) {
	raw, err := bpf.Assemble(sampleFilterInstructions(1))
	if err != nil {
		return nil, fmt.Errorf("汇编 cBPF 过滤器: %w", err)
	}
	insns := make([]syscall.BpfInsn, len(raw))
	for i, r := range raw {
		insns[i] = syscall.BpfInsn{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	return insns, nil
}

func (s *bpfDevSource) Mode() Mode { return ModeBPFDevice }

func (s *bpfDevSource) Run(ctx context.Context) error {
	go s.agg.runFlushLoop(ctx, s.flushInterval)

	if s.samplingN > 1 {
		s.log.Printf("[flow] macOS 上抽样(1/%d)在用户态完成——BSD 的 BPF 无内核随机数扩展,"+
			"统计外推不受影响,但高流量下 CPU 开销高于 Linux", s.samplingN)
	}
	if s.dlt != dltEthernet {
		s.log.Printf("[flow] 网卡 %s 的链路层类型 DLT=%d 非以太网,未挂载内核过滤器,全部包进用户态筛选", s.iface, s.dlt)
	}

	for {
		if ctx.Err() != nil {
			return nil
		}
		n, err := syscall.Read(s.fd, s.buf)
		if err != nil {
			if isBPFTimeout(err) {
				continue
			}
			// 读错误不终止:瞬时 ENOBUFS 或被信号打断不代表设备坏了。
			continue
		}
		if n <= 0 {
			continue // 超时且缓冲区为空
		}
		if err := walkBPFBuffer(s.buf[:n], s.observe); err != nil {
			// 走缓冲区失败意味着我们对内核结构的理解不对,这不是丢一个包
			// 的问题,继续读只会继续解出垃圾。报出来让上层记录并退出。
			return err
		}
	}
}

func (s *bpfDevSource) observe(pkt []byte) {
	if !s.keep() {
		return
	}
	o, err := observeLinkFrame(s.dlt, pkt)
	if err != nil {
		return
	}
	s.agg.add(o)
}

// keep 是用户态的 1/N 抽样。
//
// 用随机而不是"每 N 个取一个":周期性流量(心跳、轮询)与固定步长一撞,
// 会被系统性地全取或全漏,而这种偏差在图上看起来完全正常。
func (s *bpfDevSource) keep() bool {
	if s.samplingN <= 1 {
		return true
	}
	return rand.IntN(s.samplingN) == 0
}

func (s *bpfDevSource) Close() error {
	if s.fd >= 0 {
		err := syscall.Close(s.fd)
		s.fd = -1
		return err
	}
	return nil
}

func isBPFTimeout(err error) bool {
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR)
}
