package datasource

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/githubflyideas/ntop2ban/internal/flow"
)

// BSD BPF 设备(/dev/bpfN)一次 read 返回的不是一个包,而是一段由多条
// 记录拼起来的缓冲区,每条记录是 struct bpf_hdr + 包内容,记录之间按
// 字长对齐。这个文件把"怎么走这段缓冲区"与"链路层类型决定包从哪里开始"
// 两件纯计算的事从系统调用里分出来。
//
// 分出来的理由是能测。偏移量算错、对齐算错、DLT 判断错,这三类 bug 都
// 不会报错——只会让流量数字不对或者解析出一堆垃圾;而它们又恰好完全
// 不需要一台 macOS 才能验证。系统调用那部分留在 bpfdev_darwin.go,
// 那里有编译期断言把下面这些偏移量与内核结构对上。

// struct bpf_hdr 在 Darwin 上的布局(见 bpfdev_darwin.go 的断言):
//
//	struct timeval32 bh_tstamp;  // 0,  8 字节(注意是 32 位的 timeval)
//	bpf_u_int32      bh_caplen;  // 8
//	bpf_u_int32      bh_datalen; // 12
//	u_short          bh_hdrlen;  // 16
//
// 头长度用记录里自带的 bh_hdrlen,不用 sizeof 推算:内核在这里明确告诉
// 了我们包内容从哪开始,自己算就得处理编译器补齐的差异。
const (
	bpfHdrCaplenOff  = 8
	bpfHdrDatalenOff = 12
	bpfHdrLenOff     = 16
	bpfHdrMinSize    = 18

	// Darwin 的 BPF_ALIGNMENT 是 sizeof(int32_t)。
	bpfAlignment = 4
)

// 链路层类型(DLT_*)。取值与 x/sys/unix 的 DLT_* 一致,这里自己写一遍
// 是为了让本文件在任何平台上都能编译与测试。
const (
	dltNull     = 0    // 4 字节 AF 头,本机字节序。lo0 是这个
	dltEthernet = 1    // 普通以太网。en0 是这个
	dltRaw      = 0xc  // 没有链路层头,直接是 IP 包。utun* 是这个
	dltLoop     = 0x6c // 同 DLT_NULL,但 AF 头是网络字节序
)

var errBPFBufferCorrupt = errors.New("datasource: BPF 缓冲区记录长度为 0")

// walkBPFBuffer 遍历一段 BPF 读缓冲区,对每个包调用 each。
//
// each 收到的是记录里实际抓到的那部分(caplen),不是包的原始长度
// (datalen)——被 snaplen 截断的包依然要交给上层,因为 IP 头里的总长度
// 字段仍然可信,而流量统计要的是那个数字。
//
// 记录长度为 0 时立刻停下并报错,而不是继续:那说明缓冲区被误读或者
// 结构体布局对不上,继续走下去会死循环。
func walkBPFBuffer(buf []byte, each func(pkt []byte)) error {
	for off := 0; off+bpfHdrMinSize <= len(buf); {
		rec := buf[off:]
		caplen := int(binary.LittleEndian.Uint32(rec[bpfHdrCaplenOff:]))
		hdrlen := int(binary.LittleEndian.Uint16(rec[bpfHdrLenOff:]))

		if hdrlen < bpfHdrMinSize || caplen < 0 {
			return fmt.Errorf("datasource: BPF 记录头异常(hdrlen=%d caplen=%d)", hdrlen, caplen)
		}
		total := hdrlen + caplen
		if total == 0 {
			return errBPFBufferCorrupt
		}
		// 最后一条记录可能被 read 的返回长度截断。截断的记录直接丢弃:
		// 内核不会这么做,真出现了说明我们读错了,硬解会得到垃圾数据。
		if total > len(rec) {
			break
		}
		each(rec[hdrlen:total])

		off += (total + bpfAlignment - 1) & ^(bpfAlignment - 1)
	}
	return nil
}

// observeLinkFrame 按链路层类型把一帧变成 Observation。
//
// 不能一律当以太网处理:en0 是 DLT_EN10MB,但 lo0 是 DLT_NULL(4 字节
// AF 头)、VPN 的 utun* 是 DLT_RAW(根本没有链路层头)。按 14 字节以太网
// 头硬解这两种,解出来的源 IP、端口、协议全是错位的垃圾,而且解析函数
// 不会报错——它只会看到一个"合法"的 IPv4 头。
func observeLinkFrame(dlt int, frame []byte) (Observation, error) {
	switch dlt {
	case dltEthernet:
		return toObservation(frame)

	case dltNull, dltLoop:
		if len(frame) < 4 {
			return Observation{}, fmt.Errorf("datasource: DLT_NULL 帧太短(%d 字节)", len(frame))
		}
		// AF 字段在 DLT_NULL 下是本机字节序、DLT_LOOP 下是网络字节序。
		// 与其分别处理,不如两头都看:唯一要判断的是"是不是 AF_INET(2)",
		// 而 2 在两种字节序下分别落在第一个和最后一个字节。
		if frame[0] != 2 && frame[3] != 2 {
			return Observation{}, errNotIPv4Link
		}
		return parseIPv4Frame(frame[4:])

	case dltRaw:
		return parseIPv4Frame(frame)
	}
	return Observation{}, fmt.Errorf("datasource: 不支持的链路层类型 DLT=%d", dlt)
}

var errNotIPv4Link = errors.New("datasource: 非 IPv4 链路层负载")

func parseIPv4Frame(ip []byte) (Observation, error) {
	p, err := flow.ParseIPv4(ip)
	if err != nil {
		return Observation{}, err
	}
	return packetToObservation(p), nil
}

// linkTypeSupported 供打开设备时提前判断,避免起来之后每个包都报同一个错。
func linkTypeSupported(dlt int) bool {
	switch dlt {
	case dltEthernet, dltNull, dltLoop, dltRaw:
		return true
	}
	return false
}
