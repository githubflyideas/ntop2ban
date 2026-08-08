// Package flow 定义 Canonical Flow —— 整个系统最重要的接口。
//
// 设计原则(技术设计文档 §36):**Input 可替换,Flow Model 不变。**
// XDP、sFlow v5、NetFlow v5 三种输入各自解码后都归一到这里,后续的
// 富化、存储、查询引擎都只认识 Canonical Flow,不知道数据从哪来。
// 将来加 NetFlow v9 / IPFIX 只需要新增一个 Normalizer,ClickHouse 表
// 结构与 Query Engine 一行都不用改。
package flow

import "time"

// SourceType 标识这条 flow 的来源方式。
//
// 保留这个字段的实际用途:sFlow 是采样的、XDP 本机采集通常是实际
// 包计数,两者的 packets 含义不同。查询层要能区分,否则把一台交换机
// 的采样估算值和本机的实际值加在一起,得到的数字没有意义。
type SourceType string

const (
	SourceLocalXDP SourceType = "LOCAL_XDP"
	SourceSFlow    SourceType = "SFLOW"
	SourceNetFlow  SourceType = "NETFLOW"
	SourceIPFIX    SourceType = "IPFIX" // 预留,第一阶段不实现
	SourcePCAP     SourceType = "PCAP"  // 预留
)

// Flow 是归一化后的流记录。
//
// 字段命名与技术设计文档 §6 / §10 的 ClickHouse 表保持一致,减少
// 一层心智映射。
type Flow struct {
	// 时间。Start 是流的首包时刻,End 是末包时刻。
	// 分开存是为了算 duration 与做时间序列对齐——只有一个时间点的话,
	// 一条持续 10 分钟的长流会被整个算进某一分钟的桶里。
	Start time.Time
	End   time.Time

	// 五元组。IP 用 string 承载,ClickHouse 侧是 IPv6 列
	// (IPv4 以 IPv4-mapped 形式存进去,这样一张表同时容纳两种协议,
	// 不必为 IPv6 单独建表)。
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8 // IANA 协议号:6=TCP 17=UDP 1=ICMP

	// 计数。
	//
	// Packets/Bytes 是**估算值**(已按采样率还原),
	// ObservedPackets/ObservedBytes 是**实测值**(采样器真正看到的)。
	// 两者都保留,理由见技术设计 §7:UI 必须区分 Observed 与 Estimated。
	// 只存估算值的话,采样率事后发现配错就再也回不去了;只存实测值的话,
	// 每次查询都要乘一遍采样率,而采样率是逐流可变的(不同设备不同配置)。
	Packets         uint64
	Bytes           uint64
	ObservedPackets uint64
	ObservedBytes   uint64
	SamplingRate    uint32 // 1/N 的 N;1 表示全量

	TCPFlags uint16

	SrcMAC string
	DstMAC string

	InputInterface  uint32
	OutputInterface uint32

	VLAN      uint16
	InnerVLAN uint16

	// 来源标识。
	SourceType SourceType
	SensorID   uint32 // 采集点(本机 = 0)
	DeviceID   uint32 // 上报设备(交换机)
	SiteID     uint32 // 站点/机房

	// Application 是分类结果(见 internal/enrich)。
	// 第一阶段基于端口 + 协议,不做 DPI——技术设计 §23 明确要求不能把
	// dst_port=443 直接等同于 100% HTTPS,所以这个字段的语义是
	// "按已知端口推断的应用",不是"确认的应用"。
	Application string

	// 富化快照。写入时打上,不在查询时 JOIN——技术设计 §34.5 明确禁止
	// 让亿级 flow 实时 JOIN GeoIP 表。代价是 GeoIP 库更新后历史数据
	// 保持当时的快照,这是想要的行为(§8.1):历史应该反映当时的归属。
	SrcCountry string
	DstCountry string
	SrcRegion  string
	DstRegion  string
	SrcCity    string
	DstCity    string
	SrcASN     uint32
	DstASN     uint32
	SrcOrg     string
	DstOrg     string
}

// Duration 返回流的持续时间。
func (f Flow) Duration() time.Duration {
	if f.End.Before(f.Start) {
		return 0
	}
	return f.End.Sub(f.Start)
}

// DurationMS 返回毫秒数,供 ClickHouse 的 UInt32 列使用。
func (f Flow) DurationMS() uint32 {
	ms := f.Duration().Milliseconds()
	if ms < 0 {
		return 0
	}
	// 超过 UInt32 上限(约 49.7 天)的流不可能是真实的,饱和处理
	// 而不是回绕——回绕会让一条异常长的流显示成极短。
	if ms > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(ms)
}

// ApplySampling 按采样率把实测值还原成估算值。
//
// 在 Normalizer 里调用一次,而不是在查询时乘:采样率是逐流的,
// 不同设备、不同接口可以配不同的值,查询时再乘需要把采样率也带进
// GROUP BY,那会让聚合基数暴涨。
func (f *Flow) ApplySampling() {
	n := uint64(f.SamplingRate)
	if n < 1 {
		n = 1
	}
	f.ObservedPackets = f.Packets
	f.ObservedBytes = f.Bytes
	f.Packets *= n
	f.Bytes *= n
}

// ProtocolName 返回协议名,用于展示与按协议分组。
func ProtocolName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 58:
		return "icmpv6"
	case 132:
		return "sctp"
	default:
		return "other"
	}
}
