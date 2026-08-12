package query

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Compiled 是编译结果:SQL 加上按顺序排列的参数。
//
// 参数化而不是拼字符串:值全部走 ClickHouse 的参数绑定,所以即使某个
// 字段的值来自用户输入,也不可能改变 SQL 的结构。列名不能参数化,
// 那部分靠白名单(见 fields.go)。
type Compiled struct {
	SQL   string
	Args  []any
	Table string
	// Columns 是结果列名,顺序与 SELECT 一致,供 API 直接输出。
	Columns []string
}

// Compile 把 AST 编译成 SQL。调用前必须先 Validate。
func Compile(q Query) (Compiled, error) {
	table := q.Table
	if table == "" {
		table = planTable(q)
	}
	agg := table == "flows_1m"

	tsCol := "timestamp"
	if agg {
		tsCol = "ts_minute"
	}

	var (
		sel     []string
		cols    []string
		groupBy []string
		args    []any
	)

	// 时间桶。放在最前面是为了让时间序列结果的第一列总是时间,
	// 前端不用按名字找。
	if q.Interval != "" {
		fn := intervalFuncs[q.Interval]
		sel = append(sel, fmt.Sprintf("%s(%s) AS ts", fn, tsCol))
		cols = append(cols, "ts")
		groupBy = append(groupBy, "ts")
	}

	// 显式指定了聚合表时,先把"这张表没有这个维度/字段"讲清楚。自动选表
	// 的路径走不到这里(planTable 已经排掉了),所以这条只服务于调用方明确
	// 写了 table=flows_1m 的情况 —— 否则用户拿到的是 ClickHouse 的
	// "Unknown expression identifier",那个报错指不到任何操作方向。
	if agg {
		if bad := firstNonAggField(q); bad != "" {
			return Compiled{}, fmt.Errorf(
				"字段 %q 不在分钟聚合表里(端口、城市、组织等维度只存在于明细表);"+
					"去掉 table=flows_1m 让引擎自动选表,或指定 table=flows", bad)
		}
	}

	for _, g := range q.GroupBy {
		col := groupableFields[g]
		// IP 列转成字符串输出:驱动返回 net.IP,直接进 JSON 是字节数组。
		// 在 SQL 里转比在 Go 里转省一次反射。
		if isIPField(g) {
			sel = append(sel, fmt.Sprintf("%s AS %s", ipToString(col), g))
		} else {
			sel = append(sel, fmt.Sprintf("%s AS %s", col, g))
		}
		cols = append(cols, g)
		groupBy = append(groupBy, col)
	}

	for _, m := range q.Metrics {
		expr := metricExprs[m]
		e := expr.raw
		if agg {
			if expr.agg == "" {
				// 这个指标在聚合表上算不出来(基数类指标、实测值)。
				// 明确报错而不是静默返回 0——静默的话用户会看到一列
				// 全是 0 的数据并信以为真。
				return Compiled{}, fmt.Errorf(
					"指标 %q 无法在分钟聚合表上计算;请缩小时间范围或指定 table=flows", m)
			}
			e = expr.agg
		}
		sel = append(sel, fmt.Sprintf("%s AS %s", e, m))
		cols = append(cols, m)
	}

	// 没有分组也没有时间桶时返回明细行。
	if len(sel) == 0 {
		return compileDetail(q, table, tsCol)
	}

	var b strings.Builder
	b.WriteString("SELECT ")
	b.WriteString(strings.Join(sel, ", "))
	b.WriteString("\nFROM ")
	b.WriteString(table)

	// 时间范围永远进 WHERE,而且是第一个条件:ORDER BY 以 timestamp
	// 开头,这让 ClickHouse 能直接按主键跳过无关 granule。
	b.WriteString("\nWHERE ")
	b.WriteString(tsCol)
	b.WriteString(" >= ? AND ")
	b.WriteString(tsCol)
	b.WriteString(" < ?")
	args = append(args, q.TimeRange.From, q.TimeRange.To)

	where, wargs, err := compileCondition(q.Filters)
	if err != nil {
		return Compiled{}, err
	}
	if where != "" {
		b.WriteString(" AND ")
		b.WriteString(where)
		args = append(args, wargs...)
	}

	if len(groupBy) > 0 {
		b.WriteString("\nGROUP BY ")
		b.WriteString(strings.Join(groupBy, ", "))
	}

	if q.Sort.Field != "" {
		dir := "ASC"
		if q.Sort.Desc {
			dir = "DESC"
		}
		b.WriteString("\nORDER BY ")
		b.WriteString(q.Sort.Field)
		b.WriteString(" ")
		b.WriteString(dir)
	}

	// LIMIT 用字面量而不是参数:它已经被 Validate 限制在 1..MaxLimit
	// 的整数范围内,拼进去是安全的,而且让 EXPLAIN 出来的 SQL 可读。
	b.WriteString("\nLIMIT ")
	b.WriteString(strconv.Itoa(q.Limit))

	return Compiled{SQL: b.String(), Args: args, Table: table, Columns: cols}, nil
}

// compileDetail 生成明细行查询(Flow Detail / 下钻到最后一层)。
func compileDetail(q Query, table, tsCol string) (Compiled, error) {
	if table != "flows" {
		return Compiled{}, fmt.Errorf("明细查询只能在 flows 表上进行")
	}
	cols := []string{
		"ts", "ts_end", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
		"bytes", "packets", "observed_bytes", "observed_packets", "sampling_rate",
		"tcp_flags", "application", "src_country", "dst_country",
		"src_asn", "dst_asn", "src_org", "dst_org",
		"source_type", "device_id", "input_interface", "vlan", "duration_ms",
	}
	sel := `SELECT
    toUnixTimestamp(timestamp) AS ts,
    toUnixTimestamp(timestamp_end) AS ts_end,
    replaceOne(IPv6NumToString(src_ip), '::ffff:', '') AS src_ip,
    replaceOne(IPv6NumToString(dst_ip), '::ffff:', '') AS dst_ip,
    src_port, dst_port, protocol,
    bytes, packets, observed_bytes, observed_packets, sampling_rate,
    tcp_flags, application, src_country, dst_country,
    src_asn, dst_asn, src_org, dst_org,
    source_type, device_id, input_interface, vlan, duration_ms
FROM flows
WHERE timestamp >= ? AND timestamp < ?`

	args := []any{q.TimeRange.From, q.TimeRange.To}
	where, wargs, err := compileCondition(q.Filters)
	if err != nil {
		return Compiled{}, err
	}
	if where != "" {
		sel += " AND " + where
		args = append(args, wargs...)
	}
	// 明细默认按时间倒序:看最近发生了什么是主要意图。
	sel += "\nORDER BY timestamp DESC\nLIMIT " + strconv.Itoa(q.Limit)

	return Compiled{SQL: sel, Args: args, Table: table, Columns: cols}, nil
}

// planTable 选择查明细表还是分钟聚合表。
//
// 规则:带时间粒度(时间序列)且粒度不小于分钟 → 聚合表;否则明细表。
// 时间跨度也参与判断——跨度大于 3 天的聚合查询走明细表几乎必然很慢,
// 而分钟聚合已经够用(3 天 = 4320 个分钟桶,画图完全够)。
//
// 让调用方不必理解分层存储是刻意的:界面上用户只选"最近 7 天",
// 不该还要懂"7 天该查哪张表"。
func planTable(q Query) string {
	span := q.TimeRange.To.Sub(q.TimeRange.From)

	// 聚合表答不上来就没得选,先排除。界面上用户选的是"按目的端口看
	// 趋势",他没有义务知道分层存储的存在;把 Interval 当成"用聚合表"
	// 的同义词,一旦维度或过滤字段不在聚合表里,ClickHouse 会报
	// Unknown expression identifier —— 用户看到的是一个指不到任何操作
	// 方向的报错。选表是引擎的责任。
	if !aggCanAnswer(q) {
		return "flows"
	}

	if q.Interval != "" {
		return "flows_1m"
	}
	// 无时间粒度但跨度很大、且分组维度都在聚合表里 → 也可以用聚合表。
	if span > 3*24*time.Hour {
		return "flows_1m"
	}
	return "flows"
}

// aggCanAnswer 判断分钟聚合表能不能回答这个查询。
//
// 三处都要看:GROUP BY 的维度、WHERE 里出现的字段、以及指标。漏掉 WHERE
// 是原来那个 bug 的一半 —— 趋势图按端口堆叠时会带上
// dst_port IN (Top N 端口) 把范围收窄,只检查 GROUP BY 的话照样撞上
// flows_1m 里不存在的列。
//
// 指标这里只做选表参考:真正"这个指标在聚合表上算不出来"的报错留在
// Compile 里,因为调用方可能显式指定了 table=flows_1m,那种情况下应该
// 得到明确的失败而不是被悄悄换表。
func aggCanAnswer(q Query) bool {
	return groupableInAgg(q.GroupBy) &&
		metricsInAgg(q.Metrics) &&
		fieldsInAgg(q.Filters)
}

// firstNonAggField 返回第一个不在聚合表里的分组维度或过滤字段,都在则返回 ""。
func firstNonAggField(q Query) string {
	for _, g := range q.GroupBy {
		if !aggDims[g] {
			return g
		}
	}
	return firstNonAggFilter(q.Filters)
}

func firstNonAggFilter(c Condition) string {
	if c.isLeaf() {
		if !aggDims[c.Field] {
			return c.Field
		}
		return ""
	}
	for _, sub := range c.Conditions {
		if f := firstNonAggFilter(sub); f != "" {
			return f
		}
	}
	return ""
}

// fieldsInAgg 递归检查过滤条件里引用的字段是否都存在于聚合表。
func fieldsInAgg(c Condition) bool {
	if c.isLeaf() {
		return aggDims[c.Field]
	}
	for _, sub := range c.Conditions {
		if !fieldsInAgg(sub) {
			return false
		}
	}
	return true
}

// aggDims 是 flows_1m 里存在的维度(见 store/schema.go 的 ORDER BY)。
//
// 端口不在里面:带上端口会让聚合表基数爆炸(每条连接一个随机源端口),
// 退化成和明细表一样大,失去加速意义。所以按端口分组必须走明细表。
var aggDims = map[string]bool{
	"src_ip": true, "dst_ip": true, "protocol": true, "application": true,
	"source_type": true, "device_id": true, "input_interface": true,
	"src_country": true, "dst_country": true, "src_asn": true, "dst_asn": true,
}

func groupableInAgg(groups []string) bool {
	for _, g := range groups {
		if !aggDims[g] {
			return false
		}
	}
	return true
}

func metricsInAgg(metrics []string) bool {
	for _, m := range metrics {
		if metricExprs[m].agg == "" {
			return false
		}
	}
	return true
}

func isIPField(name string) bool {
	return name == "src_ip" || name == "dst_ip"
}

// ipToString 把 IPv6 列渲染成人读得懂的字符串。
//
// 剥掉 IPv4-mapped 的 "::ffff:" 前缀是必须的:IPv4 地址存进 IPv6 列后
// IPv6NumToString 会返回 "::ffff:203.0.113.7"。界面上显示成那样,用户
// 复制这个地址去 ping 或查防火墙规则都对不上,而且 Top Talkers 里一列
// 全是 ::ffff: 前缀纯属噪声。
//
// 用 replaceOne 而不是 if(isIPv4Mapped(...)):后者需要额外的类型判断
// 函数,而这个前缀是固定的 7 个字符,直接替换更简单也更快。
func ipToString(col string) string {
	return fmt.Sprintf("replaceOne(IPv6NumToString(%s), '::ffff:', '')", col)
}

// compileCondition 递归编译过滤条件。
func compileCondition(c Condition) (string, []any, error) {
	if c.Field == "" && c.Op == "" && len(c.Conditions) == 0 {
		return "", nil, nil
	}

	if c.isLeaf() {
		return compileLeaf(c)
	}

	if c.Op == OpNot {
		inner, args, err := compileCondition(c.Conditions[0])
		if err != nil {
			return "", nil, err
		}
		if inner == "" {
			return "", nil, nil
		}
		return "NOT (" + inner + ")", args, nil
	}

	var parts []string
	var args []any
	for _, sub := range c.Conditions {
		s, a, err := compileCondition(sub)
		if err != nil {
			return "", nil, err
		}
		if s == "" {
			continue
		}
		parts = append(parts, s)
		args = append(args, a...)
	}
	if len(parts) == 0 {
		return "", nil, nil
	}
	if len(parts) == 1 {
		return parts[0], args, nil
	}
	return "(" + strings.Join(parts, " "+string(c.Op)+" ") + ")", args, nil
}

func compileLeaf(c Condition) (string, []any, error) {
	fd := filterableFields[c.Field]
	col := fd.column

	switch c.Operator {
	case OpEq, OpNe, OpGt, OpGte, OpLt, OpLte:
		op := map[Operator]string{
			OpEq: "=", OpNe: "!=", OpGt: ">", OpGte: ">=", OpLt: "<", OpLte: "<=",
		}[c.Operator]
		if fd.kind == kindIP {
			// IP 列比较要先把字符串转成 IPv6 数值,否则类型不匹配。
			return fmt.Sprintf("%s %s toIPv6(?)", col, op), []any{fmt.Sprint(c.Value)}, nil
		}
		return fmt.Sprintf("%s %s ?", col, op), []any{c.Value}, nil

	case OpIn, OpNotIn:
		vals, ok := toSlice(c.Value)
		if !ok {
			return "", nil, fmt.Errorf("字段 %q 的 %s 运算符需要数组值", c.Field, c.Operator)
		}
		if len(vals) == 0 {
			return "", nil, fmt.Errorf("字段 %q 的 %s 列表为空", c.Field, c.Operator)
		}
		// 上限防止一个巨大的 IN 列表让 SQL 长到 ClickHouse 拒收。
		if len(vals) > 1000 {
			return "", nil, fmt.Errorf("字段 %q 的 %s 列表有 %d 项,超过 1000 上限",
				c.Field, c.Operator, len(vals))
		}
		ph := make([]string, len(vals))
		args := make([]any, len(vals))
		for i, v := range vals {
			if fd.kind == kindIP {
				ph[i] = "toIPv6(?)"
				args[i] = fmt.Sprint(v)
			} else {
				ph[i] = "?"
				args[i] = v
			}
		}
		neg := ""
		if c.Operator == OpNotIn {
			neg = "NOT "
		}
		return fmt.Sprintf("%s %sIN (%s)", col, neg, strings.Join(ph, ", ")), args, nil

	case OpContains:
		// position() 而不是 LIKE '%x%':语义一样但不需要转义用户输入里的
		// % 和 _,少一处能出错的地方。
		return fmt.Sprintf("position(%s, ?) > 0", col), []any{fmt.Sprint(c.Value)}, nil

	case OpPrefix:
		return fmt.Sprintf("startsWith(%s, ?)", col), []any{fmt.Sprint(c.Value)}, nil

	case OpLike:
		// LIKE 里的 % 由用户自己写,这是它与 contains 的区别。
		return fmt.Sprintf("%s LIKE ?", col), []any{fmt.Sprint(c.Value)}, nil

	case OpCIDR:
		// isIPAddressInRange 接受 CIDR 字符串,由 ClickHouse 做前缀比较,
		// 比在 Go 侧展开成 IP 范围再生成 BETWEEN 更准确(也支持 IPv6)。
		return fmt.Sprintf("isIPAddressInRange(IPv6NumToString(%s), ?)", col),
			[]any{fmt.Sprint(c.Value)}, nil
	}

	return "", nil, fmt.Errorf("字段 %q 不支持运算符 %q", c.Field, c.Operator)
}

// toSlice 把 JSON 反序列化出来的值转成切片。
//
// JSON 数字会变成 float64,直接传给 ClickHouse 的 UInt16 列会报类型错误,
// 所以整数值在这里转成 int64。这个转换必须做在编译期而不是让驱动去猜。
func toSlice(v any) ([]any, bool) {
	switch vv := v.(type) {
	case []any:
		out := make([]any, len(vv))
		for i, x := range vv {
			out[i] = normalizeNumber(x)
		}
		return out, true
	case []string:
		out := make([]any, len(vv))
		for i, x := range vv {
			out[i] = x
		}
		return out, true
	case []int:
		out := make([]any, len(vv))
		for i, x := range vv {
			out[i] = int64(x)
		}
		return out, true
	}
	return nil, false
}

func normalizeNumber(v any) any {
	if f, ok := v.(float64); ok && f == float64(int64(f)) {
		return int64(f)
	}
	return v
}
