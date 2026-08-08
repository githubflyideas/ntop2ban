package clickhouse

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/model"
)

// Query 按筛选条件查询明细表,用于展示层。
//
// 直接查 flows 明细表而不是 flows_1m/1h/1d——rollup 表是给"看趋势"用的
// (查询时间序列曲线不需要五元组明细),Top Clients/Servers 这类"看具体
// 是谁"的查询需要明细表才有 src_ip/dst_ip 可分组。查询层要不要走
// rollup,交给调用方通过 q.Since/q.Until 的跨度自行判断——跨度过大时
// 扫明细表的成本问题留给阶段四按实际查询模式决定是否需要专门的
// "趋势图走 rollup"分支,这里先保证语义正确。
func (s *Store) Query(ctx context.Context, q model.Query) (model.Result, error) {
	var where []string
	var args []any

	if !q.Since.IsZero() {
		where = append(where, "reported_at >= ?")
		args = append(args, q.Since)
	}
	if !q.Until.IsZero() {
		where = append(where, "reported_at < ?")
		args = append(args, q.Until)
	}
	if q.SrcIP != "" {
		where = append(where, "src_ip = ?")
		args = append(args, q.SrcIP)
	}
	if q.DstIP != "" {
		where = append(where, "dst_ip = ?")
		args = append(args, q.DstIP)
	}
	if q.Country != "" {
		where = append(where, "(src_country = ? OR dst_country = ?)")
		args = append(args, q.Country, q.Country)
	}
	if q.ASN != 0 {
		where = append(where, "(src_asn = ? OR dst_asn = ?)")
		args = append(args, q.ASN, q.ASN)
	}
	if q.Proto != "" {
		where = append(where, "proto = ?")
		args = append(args, q.Proto)
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	orderCol := "byte_count"
	if q.OrderBy == "packets" {
		orderCol = "pkt_count"
	}

	limit := q.Limit
	if limit <= 0 {
		limit = 1000 // 与调用方约定的默认上限,避免 Limit=0 被误读成"不限"扫全表
	}

	sql := fmt.Sprintf(`
		SELECT reported_at, device, sampling_n, src_ip, dst_ip, src_port, dst_port, proto,
		       pkt_count, byte_count, last_seen, src_country, dst_country, src_asn, dst_asn, service_name
		FROM flows
		%s
		ORDER BY %s DESC
		LIMIT %d
	`, whereClause, orderCol, limit)

	rows, err := s.conn.Query(ctx, sql, args...)
	if err != nil {
		return model.Result{}, fmt.Errorf("clickhouse: query: %w", err)
	}
	defer rows.Close()

	var result model.Result
	for rows.Next() {
		var f model.Flow
		var samplingN uint32
		var srcPort, dstPort uint16
		var srcASN, dstASN uint32

		if err := rows.Scan(
			&f.ReportedAt, &f.Device, &samplingN, &f.SrcIP, &f.DstIP, &srcPort, &dstPort, &f.Proto,
			&f.PktCount, &f.ByteCount, &f.LastSeen, &f.SrcCountry, &f.DstCountry, &srcASN, &dstASN, &f.ServiceName,
		); err != nil {
			return model.Result{}, fmt.Errorf("clickhouse: scan row: %w", err)
		}
		f.SamplingN = int(samplingN)
		f.SrcPort = int(srcPort)
		f.DstPort = int(dstPort)
		f.SrcASN = srcASN
		f.DstASN = dstASN

		result.Rows = append(result.Rows, f)
	}
	if err := rows.Err(); err != nil {
		return model.Result{}, fmt.Errorf("clickhouse: row iteration: %w", err)
	}

	result.Total = len(result.Rows)
	return result, nil
}

// Aggregate 把 flows_1m 卷到 flows_1h/flows_1d 对应的时间窗口。
//
// 显式 INSERT SELECT 而不是物化视图自动触发(理由见 schema.go 里
// flows1hDDL 的注释):调用方(后台调度)决定"现在卷 window 这段时间",
// 通常滞后当前时间一小段以等迟到数据到齐。
func (s *Store) Aggregate(ctx context.Context, w model.Window) error {
	switch w.Granularity {
	case "hour":
		return s.rollupInto(ctx, "flows_1h", "toStartOfHour", w)
	case "day":
		return s.rollupInto(ctx, "flows_1d", "toStartOfDay", w)
	case "minute", "":
		// 分钟级由物化视图自动维护,无需显式触发。
		return nil
	default:
		return fmt.Errorf("clickhouse: 不支持的聚合粒度 %q", w.Granularity)
	}
}

func (s *Store) rollupInto(ctx context.Context, table, bucketFn string, w model.Window) error {
	sql := fmt.Sprintf(`
		INSERT INTO %s
		SELECT
			%s(bucket) AS bucket,
			src_ip, dst_ip, proto, src_country, dst_country, src_asn, dst_asn,
			sumMerge(pkt_count) AS pkt_count,
			sumMerge(byte_count) AS byte_count,
			countMerge(flow_count) AS flow_count
		FROM flows_1m
		WHERE bucket >= ? AND bucket < ?
		GROUP BY bucket, src_ip, dst_ip, proto, src_country, dst_country, src_asn, dst_asn
	`, table, bucketFn)

	if err := s.conn.Exec(ctx, sql, w.Since, w.Until); err != nil {
		return fmt.Errorf("clickhouse: rollup into %s: %w", table, err)
	}
	return nil
}

// Retention 按分区丢弃过期数据。
//
// 用 ALTER TABLE ... DROP PARTITION 而不是 DELETE:MergeTree 系列引擎
// 的逐行删除通过 mutation 实现,代价高且是异步的,大范围过期数据的
// 常规清理方式是整分区丢弃(见 schema.go 里 flowsDDL 的分区注释)。
// 这里按天枚举需要丢弃的分区,而不是一次 ALTER TABLE ... DELETE WHERE。
func (s *Store) Retention(ctx context.Context, policy model.RetentionPolicy) error {
	if policy.DetailTTL > 0 {
		if err := s.dropPartitionsOlderThan(ctx, "flows", "toYYYYMMDD(reported_at)", time.Now().Add(-policy.DetailTTL)); err != nil {
			return fmt.Errorf("clickhouse: retention flows: %w", err)
		}
	}
	if policy.MinuteTTL > 0 {
		if err := s.dropPartitionsOlderThan(ctx, "flows_1m", "toYYYYMMDD(bucket)", time.Now().Add(-policy.MinuteTTL)); err != nil {
			return fmt.Errorf("clickhouse: retention flows_1m: %w", err)
		}
	}
	if policy.HourTTL > 0 {
		if err := s.dropPartitionsOlderThan(ctx, "flows_1h", "toYYYYMMDD(bucket)", time.Now().Add(-policy.HourTTL)); err != nil {
			return fmt.Errorf("clickhouse: retention flows_1h: %w", err)
		}
	}
	if policy.DayTTL > 0 {
		if err := s.dropPartitionsOlderThan(ctx, "flows_1d", "toYYYYMM(bucket)", time.Now().Add(-policy.DayTTL)); err != nil {
			return fmt.Errorf("clickhouse: retention flows_1d: %w", err)
		}
	}
	return nil
}

// dropPartitionsOlderThan 枚举早于 cutoff 的分区并逐个 DROP。
//
// 逐个 DROP PARTITION 而非一次 DROP PARTITION ALL WHERE 之类的写法,
// 是因为 ClickHouse 的 DROP PARTITION 需要具体分区 ID,没有"按条件
// 批量丢弃分区"的原生语法——只能先查 system.parts 拿到分区列表再逐一处理。
func (s *Store) dropPartitionsOlderThan(ctx context.Context, table, partitionExpr string, cutoff time.Time) error {
	rows, err := s.conn.Query(ctx, fmt.Sprintf(
		`SELECT DISTINCT partition FROM system.parts WHERE database = currentDatabase() AND table = ? AND active`,
	), table)
	if err != nil {
		return fmt.Errorf("list partitions: %w", err)
	}
	defer rows.Close()

	var partitions []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return fmt.Errorf("scan partition: %w", err)
		}
		partitions = append(partitions, p)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	cutoffKey := partitionKey(table, cutoff)
	for _, p := range partitions {
		if p >= cutoffKey {
			continue // 分区键是字典序可比的日期/月份数字字符串,小于 cutoff 才需要丢弃
		}
		if err := s.conn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s DROP PARTITION %s", table, p)); err != nil {
			return fmt.Errorf("drop partition %s on %s: %w", p, table, err)
		}
	}
	return nil
}

// partitionKey 按各表的分区表达式计算 cutoff 对应的分区键字符串,
// 用于和 system.parts 里取到的分区键做字典序比较。
func partitionKey(table string, t time.Time) string {
	if table == "flows_1d" {
		return t.Format("200601") // toYYYYMM
	}
	return t.Format("20060102") // toYYYYMMDD
}

// Compact 触发后台合并优化。OPTIMIZE TABLE 成本较高(强制合并 part),
// 不应该在请求路径上调用,只由运维/后台调度按需触发。
func (s *Store) Compact(ctx context.Context) error {
	for _, table := range []string{"flows", "flows_1m", "flows_1h", "flows_1d"} {
		if err := s.conn.Exec(ctx, fmt.Sprintf("OPTIMIZE TABLE %s FINAL", table)); err != nil {
			return fmt.Errorf("clickhouse: optimize %s: %w", table, err)
		}
	}
	return nil
}

// Stats 返回明细表的行数与时间范围,供运维/仪表板展示。
func (s *Store) Stats(ctx context.Context) (model.StorageStats, error) {
	var stats model.StorageStats
	stats.Backend = "clickhouse"

	row := s.conn.QueryRow(ctx, `
		SELECT count(), min(reported_at), max(reported_at)
		FROM flows
	`)
	var oldest, newest time.Time
	var total uint64
	if err := row.Scan(&total, &oldest, &newest); err != nil {
		return model.StorageStats{}, fmt.Errorf("clickhouse: stats: %w", err)
	}
	stats.TotalRows = int64(total)
	stats.OldestRecord = oldest
	stats.NewestRecord = newest
	return stats, nil
}
