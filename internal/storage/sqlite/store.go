// Package sqlite 是 FlowStorage 的极简兜底实现,面向不愿/无法部署外部
// ClickHouse 的用户(见 xdp-ban-架构方案 v0.3 第一节)。
//
// 这是**功能降级**模式:能收、能存、能做基础的 Top-N 查询与按时间
// 清理,但没有 ClickHouse 那套物化视图/rollup 的分层聚合能力。因此
// Aggregate 是空操作,Stats 会把 Degraded 置为 true,供前端据此隐藏
// 依赖历史趋势/多维聚合的展示入口。
//
// 底层用 modernc.org/sqlite(纯 Go,无 cgo),与 xdp-ban 的审批库
// 保持同一套技术选型,ntop2ban 主二进制仍可 CGO_ENABLED=0 静态编译。
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// Store 是 FlowStorage 的 SQLite 实现。
type Store struct {
	db *sql.DB
}

// Open 打开(或创建)SQLite 数据库文件并建表。
//
// PRAGMA 调优直接沿用 xdp-ban/internal/model.go 里验证过的那组参数:
// WAL 让读写不互相阻塞(仪表板的读不会被一次写入卡住)、busy_timeout
// 避免并发写直接返回 SQLITE_BUSY、synchronous=NORMAL 是 WAL 下的
// 安全/性能常规折中。这些不是可选项,少一个都会在并发下出问题——
// 这条经验是从 xdp-ban 借来的,不重新踩一遍。
func Open(path string) (*Store, error) {
	dsn := path + "?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=synchronous(NORMAL)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}

	// SQLite 是单文件嵌入库,写并发靠文件锁,连接数堆高只会把争抢
	// 从 Go 层挪到文件锁层。写连接压到 1,避免 modernc 驱动下的
	// "database is locked"。读靠 WAL 不受影响。
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.ensureSchema(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: ensure schema: %w", err)
	}

	// 确认 WAL 真的生效:DSN pragma 写错名字时驱动会静默忽略,
	// 不验证的话会以为开了 WAL 其实没开(同样借自 xdp-ban 的教训)。
	var mode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: check journal_mode: %w", err)
	}
	if !strings.EqualFold(mode, "wal") {
		db.Close()
		return nil, fmt.Errorf("sqlite: 期望 WAL 模式,实际为 %q", mode)
	}

	return s, nil
}

func (s *Store) ensureSchema(ctx context.Context) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS flows (
	reported_at   INTEGER NOT NULL,   -- unix 秒
	device        TEXT NOT NULL,
	sampling_n    INTEGER NOT NULL,
	src_ip        TEXT NOT NULL,
	dst_ip        TEXT NOT NULL,
	src_port      INTEGER NOT NULL,
	dst_port      INTEGER NOT NULL,
	proto         TEXT NOT NULL,
	pkt_count     INTEGER NOT NULL,
	byte_count    INTEGER NOT NULL,
	last_seen     INTEGER NOT NULL,
	src_country   TEXT NOT NULL DEFAULT '',
	dst_country   TEXT NOT NULL DEFAULT '',
	src_asn       INTEGER NOT NULL DEFAULT 0,
	dst_asn       INTEGER NOT NULL DEFAULT 0,
	service_name  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_flows_reported_at ON flows(reported_at);
CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows(src_ip);
`
	if _, err := s.db.ExecContext(ctx, ddl); err != nil {
		return err
	}
	return nil
}

func (s *Store) Close() error {
	return s.db.Close()
}
