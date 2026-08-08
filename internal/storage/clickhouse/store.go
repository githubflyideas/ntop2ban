// Package clickhouse 是 FlowStorage 的 ClickHouse 实现,NTop2ban 的默认
// 流量存储后端(见 xdp-ban-架构方案 v0.3 第一节)。
//
// 依赖 ClickHouse/clickhouse-go/v2 的 native protocol 驱动——纯 Go 实现,
// 不需要 cgo,这样 ntop2ban 主二进制仍可 CGO_ENABLED=0 静态编译;
// ClickHouse 本身作为外部服务独立部署,不侵入 ntop2ban 二进制。
package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

// Config 是连接与建表所需的最小配置。
type Config struct {
	Addr     string // "host:port",native protocol 默认端口 9000
	Database string
	Username string
	Password string

	// Database 不存在时是否自动创建。生产环境建议由运维预先建库并
	// 授予最小权限,这里默认关闭,显式开启才会尝试 CREATE DATABASE。
	AutoCreateDatabase bool
}

// Store 是 FlowStorage 的 ClickHouse 实现。
type Store struct {
	conn clickhouse.Conn
	db   string
}

// Open 建立连接并确保 schema 存在(库、明细表、物化视图、rollup 表)。
//
// 建表在 Open 时做而不是留给外部迁移工具,是刻意的取舍:v0.3 文档的
// 三层 schema(明细 + 分钟级物化视图 + 小时/天级 rollup)属于这个存储
// 后端的实现细节,不应该要求部署者手工维护一份 DDL 脚本并保持同步——
// 那样版本升级时 schema 漂移的风险落在每个部署者身上,而不是这里。
func Open(ctx context.Context, cfg Config) (*Store, error) {
	if cfg.Database == "" {
		return nil, fmt.Errorf("clickhouse: Database 不能为空")
	}

	opts := &clickhouse.Options{
		Addr: []string{cfg.Addr},
		Auth: clickhouse.Auth{
			Database: "default", // 先连 default,库不存在时才能执行 CREATE DATABASE
			Username: cfg.Username,
			Password: cfg.Password,
		},
		DialTimeout: 10 * time.Second,
	}

	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: open: %w", err)
	}
	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("clickhouse: ping: %w", err)
	}

	if cfg.AutoCreateDatabase {
		if err := conn.Exec(ctx, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", quoteIdent(cfg.Database))); err != nil {
			return nil, fmt.Errorf("clickhouse: create database: %w", err)
		}
	}

	// 切换到目标库:native protocol 连接不能像 SQL USE 语句那样切库,
	// 需要用带 Database 的新连接。重新以目标库建连,避免每条 SQL 都要
	// 手写 db.table 前缀。
	conn.Close()
	opts.Auth.Database = cfg.Database
	conn, err = clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: reopen with database %q: %w", cfg.Database, err)
	}
	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("clickhouse: ping after reopen: %w", err)
	}

	s := &Store{conn: conn, db: cfg.Database}
	if err := s.ensureSchema(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("clickhouse: ensure schema: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.conn.Close()
}

// quoteIdent 是最小化的标识符转义,仅用于 Database 名——这个值来自
// 部署配置而非用户输入,不是一般意义上的 SQL 注入面,但仍按标识符
// 规则转义,不依赖调用方自律。
func quoteIdent(name string) string {
	return "`" + name + "`"
}
