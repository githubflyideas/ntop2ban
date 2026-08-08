// Package sqlite 是 ntop2ban 唯一的存储实现。
//
// 这不是"兜底":ClickHouse 那套分层聚合已经搬去 xdp-ban(它才需要处理
// 大流量镜像),ntop2ban 面向小企业,一个 SQLite 文件就是全部持久层——
// 采样流量、审批流、knock 配置、pingping 探测结果都落这一个文件,
// 拷走这个文件就是完整备份。
//
// 驱动用 modernc.org/sqlite(纯 Go,无 cgo),这是硬约束:ntop2ban 要
// 保持 CGO_ENABLED=0 静态编译、scp 即可运行。这也是搬 pingping 探测
// 能力过来时不能直接复用它 store.go 的原因——那边用的 mattn/go-sqlite3
// 是 cgo 驱动。
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
	// auto_vacuum=INCREMENTAL 必须在任何表建立之前设置,否则无效——
	// 它决定文件格式。有了它,Retention 删完数据可以用
	// PRAGMA incremental_vacuum 把页还给文件系统,不必做全量 VACUUM。
	dsn := path + "?_pragma=auto_vacuum(INCREMENTAL)" +
		"&_pragma=journal_mode(WAL)" +
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
	// 敲门相关的表(序列定义 + 成功授权记录),见 knock.go。
	if _, err := s.db.ExecContext(ctx, knockSchema); err != nil {
		return fmt.Errorf("knock schema: %w", err)
	}
	// 链路探测轮次表,见 probe.go。
	if _, err := s.db.ExecContext(ctx, probeSchema); err != nil {
		return fmt.Errorf("probe schema: %w", err)
	}
	// 用户与审计,见 users.go。
	if _, err := s.db.ExecContext(ctx, userSchema); err != nil {
		return fmt.Errorf("user schema: %w", err)
	}
	return nil
}

func (s *Store) Close() error {
	return s.db.Close()
}
