package datasource

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

// sample_event / knock_event 的二进制布局必须与 bpf/sampler.c 里的
// struct 定义完全一致。
//
// 这是跨语言契约,编译器抓不到不一致:C 侧加一个字段、改一次字段顺序,
// Go 侧照旧解析就会读到错位的数据——而且不会报错,只会让流量图上出现
// 无法解释的数值。所以下面用显式的偏移量解析并断言长度,而不是
// binary.Read 到一个结构体上(那样字段顺序错了同样静默)。
//
// C 侧:
//
//	struct sample_event {
//	    __u32 src_ip; __u32 dst_ip;
//	    __u16 src_port; __u16 dst_port; __u16 pkt_len;
//	    __u8 proto; __u8 _pad;
//	};  // 16 字节
const sampleEventSize = 16

//	struct knock_event {
//	    __u32 src_ip; __u16 value; __u8 kind; __u8 _pad;
//	};  // 8 字节
const knockEventSize = 8

func parseSampleEvent(raw []byte) (Observation, error) {
	var o Observation
	if len(raw) < sampleEventSize {
		return o, fmt.Errorf("采样事件长度 %d 小于预期 %d(bytecode 与本程序版本可能不匹配)",
			len(raw), sampleEventSize)
	}
	// BPF 侧的 __u32 IP 是网络字节序(直接取自 iphdr),端口在 C 侧
	// 已经 bpf_ntohs 转成主机序。两者字节序处理不同,是这里最容易搞错
	// 的地方——IP 用大端解析、端口用本机字节序。
	copy(o.SrcIP[:], raw[0:4])
	copy(o.DstIP[:], raw[4:8])
	o.SrcPort = nativeUint16(raw[8:10])
	o.DstPort = nativeUint16(raw[10:12])
	o.Length = int(nativeUint16(raw[12:14]))
	o.Proto = raw[14]
	return o, nil
}

// nativeUint16 按本机字节序解析。
//
// ringbuf 里的整数是内核按本机字节序写的,不是网络字节序。在 x86/arm64
// 上都是小端,但显式写出来比假设更安全,也让意图清楚。
func nativeUint16(b []byte) uint16 {
	return binary.LittleEndian.Uint16(b)
}

func loadSpec() (*ebpf.CollectionSpec, error) {
	return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(samplerBytecode))
}

func interfaceByName(name string) (*net.Interface, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("查找网卡 %q: %w", name, err)
	}
	return ifi, nil
}
