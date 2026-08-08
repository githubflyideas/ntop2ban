package store

// ClickHouse schema。技术设计文档 §9-15。
//
// 核心原则:**Raw Flow 是事实数据;Aggregation 是查询加速层;
// Metadata 是维度数据。**
//
// 第一阶段只建必要的几张:flows(主表)+ flows_1m(时间序列加速)+
// ip_metadata(IP 维度权威源)。§15 明确警告不要为每个 Dashboard 建
// 一张物化视图——那会造成写放大、存储膨胀、merge 压力。

// flowsDDL 是 Raw Flow 主表。
//
// 几个设计决定与它们的理由:
//
// IP 用 IPv6 列而不是分开的 IPv4/IPv6 表:IPv4 以 IPv4-mapped 形式
// (::ffff:1.2.3.4)存进 IPv6 列,一张表同时容纳两种协议。分表会让
// 每个查询都要 UNION,而 Query Engine 的复杂度翻倍换不来性能。
//
// PARTITION BY 按天(§11):适合时间范围查询与 TTL,便于整分区丢弃
// 历史数据。不用小时分区——单机长期运行会产生上万个小分区,
// merge 压力与元数据开销都不划算。
//
// ORDER BY 是**草案**,技术设计 §12 与 §34.10 都明确要求必须通过真实
// query benchmark 才能定稿。当前顺序 (timestamp, src_ip, dst_ip,
// src_port, dst_port) 对应最高频的场景"最近 1h/24h + 某个 IP"。
// 一旦发现 Top ASN / Top Country 这类查询成为瓶颈,再考虑 Projection,
// 而不是先堆一堆 Projection 上去(§16)。
//
// TTL 用占位的 90 天,实际值由 retention_days 配置项在建表后 ALTER
// 调整(§13 要求可配置)。
const flowsDDL = `
CREATE TABLE IF NOT EXISTS flows
(
    timestamp       DateTime64(3),
    timestamp_end   DateTime64(3),

    src_ip          IPv6,
    dst_ip          IPv6,
    src_port        UInt16,
    dst_port        UInt16,
    protocol        UInt8,

    packets         UInt64,
    bytes           UInt64,
    observed_packets UInt64,
    observed_bytes   UInt64,
    sampling_rate   UInt32,

    tcp_flags       UInt16,

    src_mac         String,
    dst_mac         String,

    input_interface  UInt32,
    output_interface UInt32,

    vlan            UInt16,
    inner_vlan      UInt16,

    duration_ms     UInt32,

    source_type     LowCardinality(String),
    sensor_id       UInt32,
    device_id       UInt32,
    site_id         UInt32,

    application     LowCardinality(String),

    src_country     LowCardinality(String),
    dst_country     LowCardinality(String),
    src_region      LowCardinality(String),
    dst_region      LowCardinality(String),
    src_city        LowCardinality(String),
    dst_city        LowCardinality(String),
    src_asn         UInt32,
    dst_asn         UInt32,
    src_org         LowCardinality(String),
    dst_org         LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, src_ip, dst_ip, src_port, dst_port)
TTL toDateTime(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192
`

// flows1mDDL 是分钟级聚合表,用于时间序列与长期趋势(§14)。
//
// SummingMergeTree 而不是 AggregatingMergeTree:这里的指标全是可加的
// (bytes/packets/flows 求和),SummingMergeTree 直接存和值,查询时
// 不需要 -Merge 组合子,SQL 更简单、也更容易被 Query Engine 生成。
// 需要 uniq/quantile 之类不可加的指标时才有必要上 AggregatingMergeTree。
//
// 维度刻意收窄:只保留 src_ip/dst_ip/protocol/application 以及 geo/asn。
// 带上端口会让基数爆炸——每条连接一个随机源端口,聚合表会退化成和
// 明细表一样大,失去加速意义。要按端口看趋势就查明细表加时间限制。
//
// TTL 比明细表长(365 天 vs 90 天):这正是分层的目的,长期趋势用聚合
// 数据保留,明细只留近期(§26)。
const flows1mDDL = `
CREATE TABLE IF NOT EXISTS flows_1m
(
    ts_minute       DateTime,

    src_ip          IPv6,
    dst_ip          IPv6,
    protocol        UInt8,
    application     LowCardinality(String),

    source_type     LowCardinality(String),
    device_id       UInt32,
    input_interface UInt32,

    src_country     LowCardinality(String),
    dst_country     LowCardinality(String),
    src_asn         UInt32,
    dst_asn         UInt32,

    bytes           UInt64,
    packets         UInt64,
    flows           UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(ts_minute)
ORDER BY (ts_minute, src_ip, dst_ip, protocol, application, source_type, device_id, input_interface, src_country, dst_country, src_asn, dst_asn)
TTL ts_minute + INTERVAL 365 DAY
`

// flows1mMVDDL 物化视图:每次向 flows 插入时自动累加到 flows_1m。
//
// 写入时聚合而不是查询时聚合:Dashboard 的时间序列是最高频的查询,
// 让它扫明细表在数据量大之后必然拖垮 ClickHouse(§14 开头那句"不能让
// 所有 Dashboard 查询都扫描 Raw Flow")。
//
// count() 作为 flows 列:一条 flow 记录算一条流。这个数字与
// packets/bytes 的语义不同——1000 个包可能是 1 条流也可能是 1000 条,
// 两者一起看才能区分"大文件传输"与"端口扫描"。
const flows1mMVDDL = `
CREATE MATERIALIZED VIEW IF NOT EXISTS flows_1m_mv TO flows_1m AS
SELECT
    toStartOfMinute(timestamp) AS ts_minute,
    src_ip, dst_ip, protocol, application,
    source_type, device_id, input_interface,
    src_country, dst_country, src_asn, dst_asn,
    sum(bytes)   AS bytes,
    sum(packets) AS packets,
    count()      AS flows
FROM flows
GROUP BY ts_minute, src_ip, dst_ip, protocol, application,
         source_type, device_id, input_interface,
         src_country, dst_country, src_asn, dst_asn
`

// ipMetadataDDL 是 IP 维度的权威数据源(§8)。
//
// 与 flow 行上的富化快照并存,不矛盾:快照服务于查询性能(避免 JOIN),
// 这张表服务于"这个 IP 现在到底属于谁"这类维度查询,以及 Drill-down
// 时展示 IP 的完整画像(is_datacenter / is_vpn / reputation 等)。
//
// ReplacingMergeTree 按 ip 去重:GeoIP 库更新时直接插新行,旧行会在
// merge 时被替换掉,不需要先 DELETE。updated_at 作为版本列,保留最新。
const ipMetadataDDL = `
CREATE TABLE IF NOT EXISTS ip_metadata
(
    ip            IPv6,
    prefix        String,

    country       LowCardinality(String),
    region        LowCardinality(String),
    city          String,
    continent     LowCardinality(String),

    asn           UInt32,
    organization  String,
    isp           String,

    latitude      Float32,
    longitude     Float32,

    is_datacenter UInt8,
    is_cloud      UInt8,
    is_hosting    UInt8,
    is_vpn        UInt8,
    is_proxy      UInt8,
    is_tor        UInt8,

    reputation    Int16,

    updated_at    DateTime
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY ip
`

// allDDL 是建表顺序。物化视图必须在两张表都存在之后创建。
func allDDL() []string {
	return []string{flowsDDL, flows1mDDL, flows1mMVDDL, ipMetadataDDL}
}
