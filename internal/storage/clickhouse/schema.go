package clickhouse

import (
	"context"
	"fmt"
)

// ensureSchema 建立三层 schema:
//  1. flows —— 明细表,MergeTree,按天分区,TTL 由 Retention 调整
//  2. flows_1m —— 分钟级增量聚合,AggregatingMergeTree + 物化视图从
//     flows 自动填充
//  3. flows_1h / flows_1d —— 从 flows_1m 卷起来的小时/天级 rollup
//
// 三层都建在 Open 时是幂等的(全部 IF NOT EXISTS),重复调用安全。
func (s *Store) ensureSchema(ctx context.Context) error {
	stmts := []string{flowsDDL, flows1mDDL, flows1mMVDDL, flows1hDDL, flows1dDDL}
	for _, stmt := range stmts {
		if err := s.conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("exec ddl: %w\n--- statement ---\n%s", err, stmt)
		}
	}
	return nil
}

// flows 明细表。
//
// 分区按天(toYYYYMMDD)是 ClickHouse 的常规实践:分区粒度决定了
// Retention/Compact/Drop 的最小操作单元,按天分区让"删除 30 天前的
// 数据"变成一次 DROP PARTITION(秒级),而不是逐行 DELETE(ClickHouse
// 上逐行删除代价很高,MergeTree 不是为此设计的)。
//
// ORDER BY (reported_at, src_ip, dst_ip) 是主键也是排序键:查询层的
// Top Clients/Servers 大量按时间范围 + src/dst 过滤,这个顺序让这类
// 查询能利用主键索引跳过整个 granule,而不必扫全表再过滤。
const flowsDDL = `
CREATE TABLE IF NOT EXISTS flows (
	reported_at   DateTime,
	device        LowCardinality(String),
	sampling_n    UInt32,

	src_ip        String,
	dst_ip        String,
	src_port      UInt16,
	dst_port      UInt16,
	proto         LowCardinality(String),

	pkt_count     Int64,
	byte_count    Int64,
	last_seen     DateTime,

	src_country   LowCardinality(String) DEFAULT '',
	dst_country   LowCardinality(String) DEFAULT '',
	src_asn       UInt32 DEFAULT 0,
	dst_asn       UInt32 DEFAULT 0,
	service_name  LowCardinality(String) DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(reported_at)
ORDER BY (reported_at, src_ip, dst_ip)
`

// flows_1m 分钟级聚合表。AggregatingMergeTree 存的是聚合函数的中间
// 状态(-State 后缀),查询时用对应的 -Merge 组合子还原——这样多次
// 写入的部分聚合结果会在后台合并阶段自动汇总,不需要应用层做读时聚合。
//
// src_country/dst_country/src_asn/dst_asn 必须进 ORDER BY(排序键),
// 不能只是普通列:AggregatingMergeTree 后台 merge 时,同一排序键的行
// 会被折叠成一行,任何不在排序键、又不是聚合函数列的字段都会在折叠时
// 取到任意值——这不是理论风险,是集成测试(NTOP2BAN_CH_TEST_ADDR)
// 直接在 CREATE TABLE 阶段就报错拦下来的:ClickHouse 26.x 把这个检查
// 做成了建表时的硬校验(code 36),不给静默产生错误结果的机会。
const flows1mDDL = `
CREATE TABLE IF NOT EXISTS flows_1m (
	bucket        DateTime,
	src_ip        String,
	dst_ip        String,
	proto         LowCardinality(String),
	src_country   LowCardinality(String),
	dst_country   LowCardinality(String),
	src_asn       UInt32,
	dst_asn       UInt32,

	pkt_count     AggregateFunction(sum, Int64),
	byte_count    AggregateFunction(sum, Int64),
	flow_count    AggregateFunction(count, UInt8)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMMDD(bucket)
ORDER BY (bucket, src_ip, dst_ip, proto, src_country, dst_country, src_asn, dst_asn)
`

// flows_1m 的物化视图:每次向 flows 插入新数据时,自动按分钟桶
// 增量计算并写入 flows_1m 对应的聚合状态。这是"写入时聚合"而不是
// "查询时聚合"——物化视图在 INSERT 触发,查询 flows_1m 直接读现成结果。
const flows1mMVDDL = `
CREATE MATERIALIZED VIEW IF NOT EXISTS flows_1m_mv
TO flows_1m
AS SELECT
	toStartOfMinute(reported_at) AS bucket,
	src_ip, dst_ip, proto,
	src_country, dst_country, src_asn, dst_asn,
	sumState(pkt_count) AS pkt_count,
	sumState(byte_count) AS byte_count,
	countState() AS flow_count
FROM flows
GROUP BY bucket, src_ip, dst_ip, proto, src_country, dst_country, src_asn, dst_asn
`

// flows_1h / flows_1d 是从 flows_1m 卷起来的小时/天级 rollup,供长时间
// 范围的趋势图查询(不需要在分钟粒度上扫描数月数据)。这两层不建物化
// 视图自动填充——由 Aggregate(ctx, model.Window) 按调度周期显式触发
// INSERT SELECT,理由是 rollup 的触发时机需要业务控制(比如等一小时
// 内的分钟数据全部到齐再卷),自动物化视图在源表尚有迟到数据时卷早了
// 会产生不完整的小时/天汇总。
const flows1hDDL = `
CREATE TABLE IF NOT EXISTS flows_1h (
	bucket        DateTime,
	src_ip        String,
	dst_ip        String,
	proto         LowCardinality(String),
	src_country   LowCardinality(String),
	dst_country   LowCardinality(String),
	src_asn       UInt32,
	dst_asn       UInt32,
	pkt_count     Int64,
	byte_count    Int64,
	flow_count    UInt64
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(bucket)
ORDER BY (bucket, src_ip, dst_ip, proto)
`

const flows1dDDL = `
CREATE TABLE IF NOT EXISTS flows_1d (
	bucket        Date,
	src_ip        String,
	dst_ip        String,
	proto         LowCardinality(String),
	src_country   LowCardinality(String),
	dst_country   LowCardinality(String),
	src_asn       UInt32,
	dst_asn       UInt32,
	pkt_count     Int64,
	byte_count    Int64,
	flow_count    UInt64
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(bucket)
ORDER BY (bucket, src_ip, dst_ip, proto)
`
