package sqlite

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/model"
)

// Append 批量写入。用单条事务包住整批 INSERT——SQLite 上逐条 INSERT
// 各自隐式提交一次事务,批量时会有大量 fsync;一个显式事务把整批的
// 提交合成一次,这是 SQLite 批量写入的标准做法。
func (s *Store) Append(ctx context.Context, batch []model.Flow) error {
	if len(batch) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin tx: %w", err)
	}
	defer tx.Rollback() // 提交成功后 Rollback 是 no-op;失败路径靠它兜底

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO flows (
			reported_at, device, sampling_n, src_ip, dst_ip, src_port, dst_port, proto,
			pkt_count, byte_count, last_seen, src_country, dst_country, src_asn, dst_asn, service_name
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
	`)
	if err != nil {
		return fmt.Errorf("sqlite: prepare insert: %w", err)
	}
	defer stmt.Close()

	for _, f := range batch {
		if _, err := stmt.ExecContext(ctx,
			f.ReportedAt.Unix(), f.Device, f.SamplingN, f.SrcIP, f.DstIP, f.SrcPort, f.DstPort, f.Proto,
			f.PktCount, f.ByteCount, f.LastSeen.Unix(), f.SrcCountry, f.DstCountry, f.SrcASN, f.DstASN, f.ServiceName,
		); err != nil {
			return fmt.Errorf("sqlite: insert row: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit (%d rows): %w", len(batch), err)
	}
	return nil
}

// Query 按筛选条件查询,语义与 ClickHouse 实现保持一致(同一套
// model.Query 契约),这样上层展示代码切换后端时行为不变。
func (s *Store) Query(ctx context.Context, q model.Query) (model.Result, error) {
	var where []string
	var args []any

	if !q.Since.IsZero() {
		where = append(where, "reported_at >= ?")
		args = append(args, q.Since.Unix())
	}
	if !q.Until.IsZero() {
		where = append(where, "reported_at < ?")
		args = append(args, q.Until.Unix())
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
		limit = 1000 // 与 ClickHouse 实现约定一致的默认上限,Limit=0 不当"不限"
	}

	sqlText := fmt.Sprintf(`
		SELECT reported_at, device, sampling_n, src_ip, dst_ip, src_port, dst_port, proto,
		       pkt_count, byte_count, last_seen, src_country, dst_country, src_asn, dst_asn, service_name
		FROM flows
		%s
		ORDER BY %s DESC
		LIMIT %d
	`, whereClause, orderCol, limit)

	rows, err := s.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return model.Result{}, fmt.Errorf("sqlite: query: %w", err)
	}
	defer rows.Close()

	var result model.Result
	for rows.Next() {
		var f model.Flow
		var reportedAt, lastSeen int64
		if err := rows.Scan(
			&reportedAt, &f.Device, &f.SamplingN, &f.SrcIP, &f.DstIP, &f.SrcPort, &f.DstPort, &f.Proto,
			&f.PktCount, &f.ByteCount, &lastSeen, &f.SrcCountry, &f.DstCountry, &f.SrcASN, &f.DstASN, &f.ServiceName,
		); err != nil {
			return model.Result{}, fmt.Errorf("sqlite: scan row: %w", err)
		}
		f.ReportedAt = time.Unix(reportedAt, 0)
		f.LastSeen = time.Unix(lastSeen, 0)
		result.Rows = append(result.Rows, f)
	}
	if err := rows.Err(); err != nil {
		return model.Result{}, fmt.Errorf("sqlite: row iteration: %w", err)
	}

	result.Total = len(result.Rows)
	return result, nil
}

// Aggregate 在兜底模式下是空操作:SQLite 版本不维护分钟/小时/天级
// rollup(那是 ClickHouse 物化视图的能力)。返回 nil 而不是报错,
// 让调用方(后台调度)可以对两种后端用同一套调用逻辑,不必先判断
// 后端类型——降级体现在"不做",而不是"调用会失败"。
func (s *Store) Aggregate(ctx context.Context, w model.Window) error {
	return nil
}

// Retention 按时间删除明细表里过期的行。
//
// SQLite 没有 ClickHouse 的分区概念,只能 DELETE WHERE。这在兜底
// 模式下可接受:兜底用户的数据量本就不大(否则该上 ClickHouse),
// 一次按时间的 DELETE 不构成问题。只处理 DetailTTL——其余粒度的
// TTL 对应的 rollup 表在 SQLite 版本里根本不存在。
func (s *Store) Retention(ctx context.Context, policy model.RetentionPolicy) error {
	if policy.DetailTTL <= 0 {
		return nil
	}
	cutoff := time.Now().Add(-policy.DetailTTL).Unix()
	if _, err := s.db.ExecContext(ctx, "DELETE FROM flows WHERE reported_at < ?", cutoff); err != nil {
		return fmt.Errorf("sqlite: retention: %w", err)
	}
	return nil
}

// Compact 执行 VACUUM 回收删除后的空间。
//
// 与 ClickHouse 的 Compact 一样,这是重操作(VACUUM 会重写整个
// 数据库文件),只应由运维/后台调度按需触发,不在请求路径上调用。
func (s *Store) Compact(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, "VACUUM"); err != nil {
		return fmt.Errorf("sqlite: vacuum: %w", err)
	}
	return nil
}

// Stats 返回行数与时间范围,并把 Degraded 置为 true——这是 SQLite
// 后端向前端表明"当前处于功能降级模式"的唯一信号,前端据此隐藏
// 依赖历史趋势/多维聚合的入口。
func (s *Store) Stats(ctx context.Context) (model.StorageStats, error) {
	stats := model.StorageStats{Backend: "sqlite", Degraded: true}

	var total int64
	var oldest, newest *int64
	row := s.db.QueryRowContext(ctx, "SELECT count(*), min(reported_at), max(reported_at) FROM flows")
	if err := row.Scan(&total, &oldest, &newest); err != nil {
		return model.StorageStats{}, fmt.Errorf("sqlite: stats: %w", err)
	}
	stats.TotalRows = total
	if oldest != nil {
		stats.OldestRecord = time.Unix(*oldest, 0)
	}
	if newest != nil {
		stats.NewestRecord = time.Unix(*newest, 0)
	}
	return stats, nil
}
