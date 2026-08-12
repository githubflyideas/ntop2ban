package datasource

import (
	"golang.org/x/net/bpf"

	"github.com/githubflyideas/ntop2ban/internal/flow"
)

// 这里放的是与操作系统无关的两件事:cBPF 过滤器的构造,以及把一帧原始
// 字节变成聚合器要的 Observation。
//
// 之所以不留在 afpacket.go 里:macOS 的 /dev/bpf 用的是同一套 cBPF 指令
// (Linux 那套本来就是从 BSD 抄的),同一份偏移量与跳转回填逻辑没有任何
// 理由写两遍。写两遍的失败方式还特别难查——过滤器算错偏移不会报错,
// 只会静默放行或丢弃错误的包,表现为"两个平台上同一份流量数字不一样"。
//
// 放在无构建约束的文件里的另一个好处是测试能在任何平台上跑。偏移量和
// 跳转距离恰恰是最需要测试守着的部分。

const ethHdrLen = 14

// snapLen 是过滤器命中时告诉内核"拷这么多字节到用户态"的值,也就是
// snaplen。我们只统计五元组、字节数与 TCP flags,全都在包头里:最坏情况是
// 一层 802.1Q 标签(flow.ParseEthernet 目前认一层)加一个带满 option 的 60
// 字节 IP 头,再加 TCP 头的前 14 字节(flags 在第 12~13 字节),即
// 14 + 4 + 60 + 14 = 92 字节。128 留了余量又是个整数 —— 将来若支持 QinQ,
// 多一层标签也还在 128 以内。
//
// 字节数不受截断影响:flow.ParseIPv4 取的是 IP 头里声明的 total length,
// 不是实际抓到的长度,那才是链路上真实的包长。
//
// 为什么不拷整包:代价主要不在 memcpy,而在缓冲区。macOS 那侧 512KB 的 BPF
// 缓冲区,按每条记录 20 字节头 + 1514 字节包算只装得下约 340 个包,跑满
// 千兆(约 81k pps)时那是 4ms 的余量 —— 读循环被调度晚一点就溢出,而内核
// 缓冲溢出的表现是统计数字凭空偏低,不报任何错。降到 128 之后一个缓冲区
// 装得下约 3500 个包,余量变成 43ms。Linux 的 AF_PACKET 侧同样受益,只是
// 那边还有内核抽样兜着,没这么紧。
const snapLen = 128

// IPv4 协议号。不从 x/sys/unix 取:这个文件要在所有平台上编译,而
// 协议号是 IANA 定的常量,不是操作系统的东西。
const (
	protoTCP = 6
	protoUDP = 17
)

// sampleFilterInstructions 生成采样过滤器:1/N 抽样 → IPv4 → 非分片 →
// TCP/UDP。
//
// 抽样判定刻意放在最前面:它会丢掉 (N-1)/N 的包,先抽样能省下绝大部分
// 后续指令的执行。
//
// samplingN <= 1 时不生成抽样前缀。macOS 一侧永远这样调用——BSD 的 BPF
// 解释器没有随机数扩展,抽样只能在用户态做,详见 bpfdev_darwin.go。
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
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: protoTCP},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: protoUDP},
	)

	rejectIdx := len(insts)
	acceptIdx := rejectIdx + 1
	insts = append(insts, bpf.RetConstant{Val: 0}, bpf.RetConstant{Val: snapLen})

	// 回填跳转距离。不手算偏移——算错了不会报错,过滤器只会静默
	// 放行或丢弃错误的包,线上表现为"统计数字不对"却无从追查。
	for i, in := range insts {
		j, ok := in.(bpf.JumpIf)
		if !ok {
			continue
		}
		if j.Cond == bpf.JumpEqual && (j.Val == protoTCP || j.Val == protoUDP) {
			j.SkipTrue = uint8(acceptIdx - i - 1)
		} else {
			j.SkipTrue = uint8(rejectIdx - i - 1)
		}
		insts[i] = j
	}
	return insts
}

// toObservation 把 flow.ParseEthernet 的结果转成聚合器要的形态。
//
// 解析本身在 internal/flow 里,几种输入(AF_PACKET / BPF 设备 / sFlow /
// XDP)共用同一份实现——各自写一份迟早会在"长度算不算以太网头"
// "分片怎么处理"这类细节上分叉,而分叉的表现是同一份流量在不同输入下
// 显示出不同数字,没有任何报错。
func toObservation(frame []byte) (Observation, error) {
	p, err := flow.ParseEthernet(frame)
	if err != nil {
		return Observation{}, err
	}
	return packetToObservation(p), nil
}

func packetToObservation(p flow.Packet) Observation {
	var o Observation
	if v4 := p.SrcIP.To4(); v4 != nil {
		copy(o.SrcIP[:], v4)
	}
	if v4 := p.DstIP.To4(); v4 != nil {
		copy(o.DstIP[:], v4)
	}
	o.SrcPort, o.DstPort = p.SrcPort, p.DstPort
	o.Proto, o.Length = p.Protocol, p.Length
	o.TCPFlags, o.VLAN = p.TCPFlags, p.VLAN
	return o
}

func deviceLabel(iface string, m Mode) string {
	if iface == "" {
		iface = "any"
	}
	return iface + "(" + string(m) + ")"
}
