package store

import (
	"context"
	"fmt"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/query"
)

// Result 是一次查询的结果。
//
// 用 columns + rows 的通用形态而不是给每种图表定义专门的结构体:
// 同一个查询引擎要服务 Table / Bar / Line / Pie / TopN(技术设计 §19),
// 为每种图表定义返回类型意味着每加一种图就要改后端。
type Result struct {
	Columns []string `json:"columns"`
	Rows    [][]any  `json:"rows"`

	// Stats 是执行统计,开发阶段用来定位慢查询(技术设计 §30 建议保留)。
	Stats ResultStats `json:"statistics"`
}

// ResultStats 执行统计。
type ResultStats struct {
	Table        string `json:"table"`
	ElapsedMS    int64  `json:"elapsed_ms"`
	RowsReturned int    `json:"rows_returned"`
	// SQL 只在 explain 时返回。平时不返回是因为它对界面没用,
	// 而且暴露内部表结构没必要。
	SQL string `json:"sql,omitempty"`
}

// Query 执行一次编译好的查询。
//
// 超时用 context 而不是只依赖 ClickHouse 的 max_execution_time:
// 客户端超时了服务端还在跑那条查询,资源不会立刻释放,两层都设才能
// 保证界面不会卡在一个已经放弃的请求上。
func (s *Store) Query(ctx context.Context, q query.Query) (Result, error) {
	if err := q.Validate(); err != nil {
		return Result{}, err
	}
	c, err := query.Compile(q)
	if err != nil {
		return Result{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, query.QueryTimeout)
	defer cancel()

	start := time.Now()
	rows, err := s.conn.Query(ctx, c.SQL, c.Args...)
	if err != nil {
		return Result{}, fmt.Errorf("查询失败: %w", err)
	}
	defer rows.Close()

	out := Result{Columns: c.Columns}

	// 用 ColumnTypes 动态构造扫描目标:结果列随 group_by / metrics 变化,
	// 没法预先声明一组变量。ScanType 给出驱动期望的 Go 类型,按它分配
	// 才不会因为 UInt64 扫进 int32 之类的不匹配而失败。
	types := rows.ColumnTypes()
	for rows.Next() {
		holders := make([]any, len(types))
		for i, ct := range types {
			holders[i] = newHolder(ct.ScanType().String())
		}
		if err := rows.Scan(holders...); err != nil {
			return Result{}, fmt.Errorf("读取结果行: %w", err)
		}
		row := make([]any, len(holders))
		for i, h := range holders {
			row[i] = deref(h)
		}
		out.Rows = append(out.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return Result{}, fmt.Errorf("遍历结果: %w", err)
	}

	out.Stats = ResultStats{
		Table:        c.Table,
		ElapsedMS:    time.Since(start).Milliseconds(),
		RowsReturned: len(out.Rows),
	}
	return out, nil
}

// Explain 返回将要执行的 SQL 而不真正执行。
//
// 存在理由是调试:界面上组合出一个复杂查询,结果不对时需要知道后端
// 究竟生成了什么 SQL。没有这个入口就只能靠日志去猜。
func (s *Store) Explain(q query.Query) (ResultStats, error) {
	if err := q.Validate(); err != nil {
		return ResultStats{}, err
	}
	c, err := query.Compile(q)
	if err != nil {
		return ResultStats{}, err
	}
	return ResultStats{Table: c.Table, SQL: c.SQL}, nil
}

// newHolder 按驱动给出的 Go 类型名分配扫描目标。
//
// 只处理实际会出现的类型:ClickHouse 侧的列类型是我们自己定的
// (见 schema.go),所以这个列表是封闭的。遇到没列出的类型退回
// interface{},让驱动自己决定——那样可能得到一个不好序列化的值,
// 但比 panic 好。
func newHolder(goType string) any {
	switch goType {
	case "uint8":
		return new(uint8)
	case "uint16":
		return new(uint16)
	case "uint32":
		return new(uint32)
	case "uint64":
		return new(uint64)
	case "int32":
		return new(int32)
	case "int64":
		return new(int64)
	case "float32":
		return new(float32)
	case "float64":
		return new(float64)
	case "string":
		return new(string)
	case "time.Time":
		return new(time.Time)
	default:
		return new(any)
	}
}

// deref 解引用并把时间转成 unix 秒。
//
// 时间转 unix 秒而不是 RFC3339 字符串:前端画时间序列要的是数字,
// 拿到字符串还得再 parse 一次,而且时区处理容易出错。
func deref(h any) any {
	switch v := h.(type) {
	case *uint8:
		return *v
	case *uint16:
		return *v
	case *uint32:
		return *v
	case *uint64:
		return *v
	case *int32:
		return *v
	case *int64:
		return *v
	case *float32:
		return *v
	case *float64:
		return *v
	case *string:
		return *v
	case *time.Time:
		return v.Unix()
	case *any:
		return *v
	default:
		return h
	}
}
