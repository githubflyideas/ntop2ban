// Package model 定义 NTop2ban 的核心数据模型:Flow 记录与查询/存储相关类型。
//
// Flow 字段直接对齐 xdp-ban/cmd/xdp-sampler 上报的 FlowSample/SampleReport
// JSON 结构(见 internal/web/samples.go 里的 fromSampleReport),这样接收端
// 不需要额外的字段映射层,复用上报即建模。GeoIP/ASN/服务名是写入时富化的
// 字段(阶段三),这里先占位为空值,阶段三接入 enrich-on-write 时补上。
package model

import "time"

// Flow 是一条聚合后的流记录,对应 ClickHouse/SQLite 明细表的一行。
//
// 设计取舍:不在这里存原始采样包,只存 xdp-sampler 已经做完五元组聚合的
// 结果(PktCount/ByteCount 是聚合窗口内的累计值)——这与 xdp-ban 现有
// 行为一致,ntop2ban 只是把同样的聚合结果多存一份到持久层,而不是重新
// 定义一套聚合语义。
type Flow struct {
	// 上报维度:同一批 flows 共享的上下文,来自 SampleReport 外层字段。
	ReportedAt time.Time `json:"reported_at"` // 采样器上报时刻(SampleReport.Timestamp)
	Device     string    `json:"device"`      // 采样网卡设备名
	SamplingN  int       `json:"sampling_n"`  // 采样率 1/N,用于流量还原

	// 五元组
	SrcIP   string `json:"src_ip"`
	DstIP   string `json:"dst_ip"`
	SrcPort int    `json:"src_port"`
	DstPort int    `json:"dst_port"`
	Proto   string `json:"proto"`

	// 聚合计数(采样窗口内的累计值,非还原后的真实流量——
	// 还原 = 该值 × SamplingN,查询层按需计算,不在写入时预乘,
	// 避免采样率事后校正时需要重写历史数据)
	PktCount  int64     `json:"pkt_count"`
	ByteCount int64     `json:"byte_count"`
	LastSeen  time.Time `json:"last_seen"`

	// 写入时富化(阶段三接入,当前占位为空字符串/0):
	SrcCountry  string `json:"src_country,omitempty"` // ISO alpha-2
	DstCountry  string `json:"dst_country,omitempty"`
	SrcASN      uint32 `json:"src_asn,omitempty"`
	DstASN      uint32 `json:"dst_asn,omitempty"`
	ServiceName string `json:"service_name,omitempty"` // IANA service name,按 DstPort+Proto 解析
}

// Query 描述一次流量查询的筛选与聚合维度。
//
// 字段全部可选:零值表示"不限"。这是查询接口的第一版,阶段四展示层
// 落地具体图表需求(Top Clients/Servers、Country/ASN 视图等)时,
// 这里可能需要扩展 GroupBy 维度,保持向后兼容地加字段而非改签名。
type Query struct {
	Since   time.Time
	Until   time.Time
	SrcIP   string
	DstIP   string
	Country string
	ASN     uint32
	Proto   string
	Limit   int    // Top N;0 = 不限
	OrderBy string // "bytes" | "packets",默认 "bytes"
}

// Result 是一次查询的返回结果。
//
// 这里先给一个通用的行集合形态;阶段四如果发现某类图表(如时间序列
// 堆叠面积图)需要专门的返回结构,再加对应的查询方法,不强行把所有
// 图表需求塞进同一个 Result 形状。
type Result struct {
	Rows  []Flow
	Total int // 满足筛选条件的总行数(用于分页/展示"共 N 条"),Limit 生效时 Total 可能大于 len(Rows)
}

// RetentionPolicy 描述数据保留策略。
type RetentionPolicy struct {
	DetailTTL time.Duration // 采样明细留存时长;0 = 不清理
}

// StorageStats 存储层运行状态,供运维/仪表板展示。
type StorageStats struct {
	Backend      string // "sqlite"
	TotalRows    int64
	OldestRecord time.Time
	NewestRecord time.Time
}
