// Package query 是 Query AST 与查询引擎:把结构化的查询描述编译成
// ClickHouse SQL,并保证它不会拖垮数据库。
//
// 为什么不让界面直接拼 SQL(技术设计 §17、§29 明确禁止):
//
//   - 一次没加时间范围的聚合就能扫全表,单机 ClickHouse 会被一个查询打满
//   - 字段名拼错在 SQL 里是运行时错误,在 AST 里是编译期就能拦的白名单校验
//   - 任何允许提交 SQL 的接口都等于给了执行任意语句的能力
//
// 所有查询都强制带时间范围、limit 与 timeout —— 这三样不是可选项,
// 缺任何一个都能让一次误操作变成一次故障。
package query

import (
	"fmt"
	"strings"
	"time"
)

// Op 是过滤条件的逻辑运算符。
type Op string

const (
	OpAnd Op = "AND"
	OpOr  Op = "OR"
	OpNot Op = "NOT"
)

// Operator 是单个条件的比较运算符。
type Operator string

const (
	OpEq       Operator = "eq"
	OpNe       Operator = "ne"
	OpGt       Operator = "gt"
	OpGte      Operator = "gte"
	OpLt       Operator = "lt"
	OpLte      Operator = "lte"
	OpIn       Operator = "in"
	OpNotIn    Operator = "not_in"
	OpLike     Operator = "like"
	OpContains Operator = "contains"
	OpPrefix   Operator = "prefix"
	OpCIDR     Operator = "cidr"
)

// Condition 是一个叶子条件,或者一个嵌套的逻辑组合。
//
// 用同一个结构体承载两者(而不是接口 + 多个实现)是为了让 JSON 直接
// 反序列化成树,不需要自定义 UnmarshalJSON 去判断类型。代价是有一半
// 字段在任意时刻是空的,靠 Validate 保证不会同时填。
type Condition struct {
	// 叶子条件:字段 + 运算符 + 值。
	Field    string   `json:"field,omitempty"`
	Operator Operator `json:"operator,omitempty"`
	Value    any      `json:"value,omitempty"`

	// 逻辑组合:Op + 子条件。
	Op         Op          `json:"op,omitempty"`
	Conditions []Condition `json:"conditions,omitempty"`
}

// isLeaf 判断这是叶子条件还是逻辑组合。
func (c Condition) isLeaf() bool { return c.Field != "" }

// TimeRange 是查询的时间范围。**必填**。
type TimeRange struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// Query 是一次完整的查询描述。
//
// 对应技术设计 §19 的 JSON 形态,能同时表达 Table / Bar / Line / Pie /
// TopN 各种展示——同一个引擎服务所有图表,而不是每种图一个专用接口。
type Query struct {
	TimeRange TimeRange `json:"time_range"`

	// Filters 可为零值(不过滤)。
	Filters Condition `json:"filters,omitempty"`

	// GroupBy 分组维度。为空表示不分组,返回明细行(受 Limit 限制)。
	GroupBy []string `json:"group_by,omitempty"`

	// Metrics 要聚合的指标。为空时默认 bytes + packets + flows。
	Metrics []string `json:"metrics,omitempty"`

	// Interval 非空时按时间桶分组,用于时间序列。
	// 取值 "minute" | "hour" | "day"。
	Interval string `json:"interval,omitempty"`

	Sort  Sort `json:"sort,omitempty"`
	Limit int  `json:"limit,omitempty"`

	// Table 指定查哪张表。为空时由 planner 按 Interval 与时间跨度自动
	// 选择 flows 或 flows_1m —— 让调用方不必理解分层存储。
	Table string `json:"table,omitempty"`
}

// Sort 排序。
type Sort struct {
	Field string `json:"field"`
	Desc  bool   `json:"desc"`
}

// 限制常量。
//
// MaxLimit 的作用不是防止界面卡顿(那是前端的事),而是防止一次
// GROUP BY 高基数字段(比如 src_ip)返回上百万行把内存吃光。
const (
	DefaultLimit = 100
	MaxLimit     = 10000

	// MaxTimeRange 单次查询的最大时间跨度。
	//
	// 一年:超过这个跨度的查询在单机上必然很慢,而且几乎肯定是误操作
	// (比如时间控件的默认值没设对)。需要更长范围的分析应该走导出,
	// 不该走交互式查询接口。
	MaxTimeRange = 366 * 24 * time.Hour

	// QueryTimeout 单次查询超时。与 ClickHouse 侧的 max_execution_time
	// 呼应(见 store/managed.go 的 users.xml),两层都设是因为客户端
	// 超时了服务端还在跑那条查询,资源不会立刻释放。
	QueryTimeout = 30 * time.Second
)

// Validate 校验 AST 并填上默认值。
//
// 返回的错误是给用户看的:界面会直接展示,所以要说清楚哪里不对、
// 允许的取值是什么,而不是一句 "invalid query"。
func (q *Query) Validate() error {
	if q.TimeRange.From.IsZero() || q.TimeRange.To.IsZero() {
		return fmt.Errorf("必须指定时间范围(from 与 to)—— 没有时间范围的查询会扫描整个历史数据")
	}
	if !q.TimeRange.To.After(q.TimeRange.From) {
		return fmt.Errorf("时间范围无效:to(%s)必须晚于 from(%s)",
			q.TimeRange.To.Format(time.RFC3339), q.TimeRange.From.Format(time.RFC3339))
	}
	if span := q.TimeRange.To.Sub(q.TimeRange.From); span > MaxTimeRange {
		return fmt.Errorf("时间跨度 %.0f 天超过上限 %.0f 天;更长范围的分析请走导出接口",
			span.Hours()/24, MaxTimeRange.Hours()/24)
	}

	if q.Limit <= 0 {
		q.Limit = DefaultLimit
	}
	if q.Limit > MaxLimit {
		return fmt.Errorf("limit %d 超过上限 %d", q.Limit, MaxLimit)
	}

	for _, g := range q.GroupBy {
		if _, ok := groupableFields[g]; !ok {
			return fmt.Errorf("不支持按 %q 分组(可用维度见 /api/v1/query/fields)", g)
		}
	}

	if len(q.Metrics) == 0 {
		q.Metrics = []string{"bytes", "packets", "flows"}
	}
	for _, m := range q.Metrics {
		if _, ok := metricExprs[m]; !ok {
			return fmt.Errorf("不支持的指标 %q(可用:%s)", m, strings.Join(metricNames(), ", "))
		}
	}

	if q.Interval != "" {
		if _, ok := intervalFuncs[q.Interval]; !ok {
			return fmt.Errorf("不支持的时间粒度 %q(可用:minute, hour, day)", q.Interval)
		}
	}

	if q.Sort.Field != "" {
		// 排序字段必须是选出来的列之一 —— 按没选的列排序在 SQL 里合法
		// 但结果无法解释,而且会强制 ClickHouse 多读一列。
		if !q.selectsField(q.Sort.Field) {
			return fmt.Errorf("排序字段 %q 不在 group_by 或 metrics 里", q.Sort.Field)
		}
	} else if len(q.Metrics) > 0 {
		// 默认按第一个指标降序:Top N 是最常见的意图。
		q.Sort = Sort{Field: q.Metrics[0], Desc: true}
	}

	if err := validateCondition(q.Filters, 0); err != nil {
		return err
	}
	return nil
}

func (q *Query) selectsField(name string) bool {
	if q.Interval != "" && name == "ts" {
		return true
	}
	for _, g := range q.GroupBy {
		if g == name {
			return true
		}
	}
	for _, m := range q.Metrics {
		if m == name {
			return true
		}
	}
	return false
}

// maxNestDepth 限制过滤条件的嵌套深度。
//
// 存在理由:嵌套是递归编译的,没有上限的话一个恶意(或手滑生成的)
// 深度嵌套 JSON 能让编译过程栈溢出,那是进程级崩溃而不是一次查询失败。
const maxNestDepth = 8

func validateCondition(c Condition, depth int) error {
	if depth > maxNestDepth {
		return fmt.Errorf("过滤条件嵌套超过 %d 层", maxNestDepth)
	}

	// 零值条件表示"不过滤",合法。
	if c.Field == "" && c.Op == "" && len(c.Conditions) == 0 {
		return nil
	}

	if c.isLeaf() {
		if c.Op != "" || len(c.Conditions) > 0 {
			return fmt.Errorf("条件 %q 同时指定了 field 与 op/conditions,应二选一", c.Field)
		}
		fd, ok := filterableFields[c.Field]
		if !ok {
			return fmt.Errorf("不支持按 %q 过滤(可用字段见 /api/v1/query/fields)", c.Field)
		}
		if !fd.allows(c.Operator) {
			return fmt.Errorf("字段 %q 不支持运算符 %q(该字段可用:%s)",
				c.Field, c.Operator, strings.Join(fd.operatorNames(), ", "))
		}
		if c.Value == nil {
			return fmt.Errorf("条件 %q %q 缺少 value", c.Field, c.Operator)
		}
		return nil
	}

	switch c.Op {
	case OpAnd, OpOr:
		if len(c.Conditions) == 0 {
			return fmt.Errorf("%s 至少需要一个子条件", c.Op)
		}
	case OpNot:
		if len(c.Conditions) != 1 {
			return fmt.Errorf("NOT 只能有一个子条件,得到 %d 个", len(c.Conditions))
		}
	default:
		return fmt.Errorf("不支持的逻辑运算符 %q(可用:AND, OR, NOT)", c.Op)
	}

	for _, sub := range c.Conditions {
		if err := validateCondition(sub, depth+1); err != nil {
			return err
		}
	}
	return nil
}
