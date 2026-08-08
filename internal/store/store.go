// Package store 是 ClickHouse 存储层。
//
// ClickHouse 是**唯一**存储,没有兜底后端。这是 v0.2 的明确决定:
// 之前那套 FlowStorage 接口 + SQLite 兜底被删掉了。理由是维护两个
// 后端的代价没有换来对应价值——SQLite 版本永远做不到分层聚合与
// 亿级明细查询,而那正是这个产品的核心能力。留着它只会让每个新功能
// 都要问一句"兜底模式下怎么办"。
//
// ClickHouse 以子进程方式托管(见 managed.go),官方静态二进制随发布包
// 附带,所以用户体验仍然是"拷贝即用",不需要单独安装数据库服务。
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

// Config 是连接配置。
type Config struct {
	Addr     string // host:port,native protocol 默认 9000
	Database string
	Username string
	Password string

	// RetentionDays 明细表保留天数。0 表示不改动建表时的默认值(90 天)。
	// 技术设计 §13 要求这个值可配置。
	RetentionDays int

	// AutoCreateDatabase 库不存在时自动创建。
	AutoCreateDatabase bool
}

// Store 是 ClickHouse 存储。
type Store struct {
	conn clickhouse.Conn
	db   string
}

// Open 建立连接并确保 schema 存在。
//
// 建表放在 Open 里而不是交给外部迁移脚本:三层 schema 是这个存储层的
// 实现细节,要求部署者手工维护一份 DDL 并保持同步,等于把版本升级时
// schema 漂移的风险转移给每个部署者。
func Open(ctx context.Context, cfg Config) (*Store, error) {
	if cfg.Database == "" {
		return nil, fmt.Errorf("store: Database 不能为空")
	}

	opts := &clickhouse.Options{
		Addr: []string{cfg.Addr},
		Auth: clickhouse.Auth{
			Database: "default",
			Username: cfg.Username,
			Password: cfg.Password,
		},
		DialTimeout: 10 * time.Second,
		// 压缩:flow 数据高度重复(同一个 IP 反复出现),LZ4 的
		// 收益明显而 CPU 代价很低。
		Compression: &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
	}

	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	if err := conn.Ping(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}

	if cfg.AutoCreateDatabase {
		if err := conn.Exec(ctx, "CREATE DATABASE IF NOT EXISTS "+quoteIdent(cfg.Database)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("store: create database: %w", err)
		}
	}
	conn.Close()

	// native protocol 不能像 SQL 的 USE 那样切库,必须以目标库重连。
	opts.Auth.Database = cfg.Database
	conn, err = clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("store: reopen with database %q: %w", cfg.Database, err)
	}
	if err := conn.Ping(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("store: ping after reopen: %w", err)
	}

	s := &Store{conn: conn, db: cfg.Database}
	if err := s.ensureSchema(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	if cfg.RetentionDays > 0 {
		if err := s.SetRetention(ctx, cfg.RetentionDays); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) ensureSchema(ctx context.Context) error {
	for _, stmt := range allDDL() {
		if err := s.conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("store: 执行 DDL: %w\n--- 语句 ---\n%s", err, stmt)
		}
	}
	return nil
}

// SetRetention 调整明细表的 TTL。
//
// 用 ALTER 而不是重建表:改保留期不该丢数据。ClickHouse 的 TTL 修改是
// 元数据操作,立即返回,实际清理由后台 merge 完成。
func (s *Store) SetRetention(ctx context.Context, days int) error {
	if days <= 0 {
		return fmt.Errorf("store: 保留天数必须为正数")
	}
	sql := fmt.Sprintf(
		"ALTER TABLE flows MODIFY TTL toDateTime(timestamp) + INTERVAL %d DAY", days)
	if err := s.conn.Exec(ctx, sql); err != nil {
		return fmt.Errorf("store: 设置明细表保留期 %d 天: %w", days, err)
	}
	return nil
}

// Conn 暴露底层连接给 query 包用。
//
// 不把查询逻辑塞进 store:store 负责 schema 与写入,query 负责把
// Query AST 编译成 SQL 并执行。两者分开是因为查询侧的复杂度(AST 校验、
// 字段白名单、SQL 生成)与存储侧无关,混在一个包里会让文件迅速膨胀。
func (s *Store) Conn() clickhouse.Conn { return s.conn }

func (s *Store) Close() error { return s.conn.Close() }

// quoteIdent 转义标识符。这个值来自部署配置而非用户输入,
// 但仍按标识符规则处理,不依赖调用方自律。
func quoteIdent(name string) string { return "`" + name + "`" }
