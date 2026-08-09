package query

import (
	"strings"
	"testing"
	"time"
)

func baseQuery() Query {
	return Query{
		TimeRange: TimeRange{
			From: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
			To:   time.Date(2026, 8, 1, 1, 0, 0, 0, time.UTC),
		},
	}
}

// TestValidateRequiresTimeRange 没有时间范围的查询会扫描整个历史数据,
// 在单机 ClickHouse 上一次就能把库打满。这是最重要的一道闸。
func TestValidateRequiresTimeRange(t *testing.T) {
	var q Query
	err := q.Validate()
	if err == nil {
		t.Fatal("缺少时间范围应报错")
	}
	if !strings.Contains(err.Error(), "时间范围") {
		t.Errorf("错误信息应说明缺时间范围: %v", err)
	}
}

func TestValidateRejectsInvertedRange(t *testing.T) {
	q := baseQuery()
	q.TimeRange.From, q.TimeRange.To = q.TimeRange.To, q.TimeRange.From
	if err := q.Validate(); err == nil {
		t.Error("to 早于 from 应报错")
	}
}

// TestValidateCapsTimeSpan 超长跨度几乎肯定是误操作(时间控件默认值
// 没设对),而且在单机上必然很慢。
func TestValidateCapsTimeSpan(t *testing.T) {
	q := baseQuery()
	q.TimeRange.To = q.TimeRange.From.Add(400 * 24 * time.Hour)
	err := q.Validate()
	if err == nil {
		t.Fatal("超过一年的跨度应报错")
	}
	if !strings.Contains(err.Error(), "导出") {
		t.Errorf("错误应指引用户走导出接口: %v", err)
	}
}

func TestValidateFillsDefaults(t *testing.T) {
	q := baseQuery()
	if err := q.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if q.Limit != DefaultLimit {
		t.Errorf("limit 默认值: want %d, got %d", DefaultLimit, q.Limit)
	}
	if len(q.Metrics) != 3 {
		t.Errorf("默认应有 3 个指标, got %v", q.Metrics)
	}
	// 默认按第一个指标降序 —— Top N 是最常见的意图
	if q.Sort.Field != "bytes" || !q.Sort.Desc {
		t.Errorf("默认排序应为 bytes DESC, got %+v", q.Sort)
	}
}

func TestValidateCapsLimit(t *testing.T) {
	q := baseQuery()
	q.Limit = MaxLimit + 1
	if err := q.Validate(); err == nil {
		t.Error("超过上限的 limit 应报错")
	}
}

// TestValidateRejectsUnknownField 字段白名单是安全边界:能出现在 SQL 里
// 的列名只有白名单里的,所以不存在通过字段名注入的可能。
func TestValidateRejectsUnknownField(t *testing.T) {
	q := baseQuery()
	q.GroupBy = []string{"src_ip; DROP TABLE flows"}
	if err := q.Validate(); err == nil {
		t.Fatal("未知分组字段应报错")
	}

	q2 := baseQuery()
	q2.Filters = Condition{Field: "password", Operator: OpEq, Value: "x"}
	if err := q2.Validate(); err == nil {
		t.Fatal("未知过滤字段应报错")
	}
}

// TestValidateRejectsWrongOperatorForField 逐字段限制运算符,而不是全局
// 放开:对 src_ip 用 like 会在 IPv6 列上做字符串匹配,能跑但结果反直觉;
// 对 bytes 用 cidr 更是荒谬。允许了只会让人写出错误的查询。
func TestValidateRejectsWrongOperatorForField(t *testing.T) {
	cases := []struct {
		field string
		op    Operator
	}{
		{"src_ip", OpLike},
		{"src_ip", OpGt},
		{"bytes", OpCIDR},
		{"bytes", OpContains},
		{"src_country", OpCIDR},
	}
	for _, c := range cases {
		q := baseQuery()
		q.Filters = Condition{Field: c.field, Operator: c.op, Value: "x"}
		if err := q.Validate(); err == nil {
			t.Errorf("%s 不该支持 %s", c.field, c.op)
		}
	}
}

func TestValidateRejectsMixedLeafAndGroup(t *testing.T) {
	q := baseQuery()
	q.Filters = Condition{
		Field:      "src_ip",
		Operator:   OpEq,
		Value:      "1.2.3.4",
		Op:         OpAnd,
		Conditions: []Condition{{Field: "dst_port", Operator: OpEq, Value: 443}},
	}
	if err := q.Validate(); err == nil {
		t.Error("同时指定 field 与 op/conditions 应报错")
	}
}

// TestValidateLimitsNestDepth 嵌套是递归编译的,没有上限的话一个深度
// 嵌套的 JSON 能让编译栈溢出 —— 那是进程崩溃,不是一次查询失败。
func TestValidateLimitsNestDepth(t *testing.T) {
	deep := Condition{Field: "dst_port", Operator: OpEq, Value: 443}
	for i := 0; i < 20; i++ {
		deep = Condition{Op: OpNot, Conditions: []Condition{deep}}
	}
	q := baseQuery()
	q.Filters = deep
	if err := q.Validate(); err == nil {
		t.Error("过深的嵌套应报错")
	}
}

func TestValidateNotRequiresExactlyOneChild(t *testing.T) {
	q := baseQuery()
	q.Filters = Condition{Op: OpNot, Conditions: []Condition{
		{Field: "dst_port", Operator: OpEq, Value: 443},
		{Field: "src_port", Operator: OpEq, Value: 80},
	}}
	if err := q.Validate(); err == nil {
		t.Error("NOT 有两个子条件应报错")
	}
}

func TestValidateRejectsSortOnUnselectedField(t *testing.T) {
	q := baseQuery()
	q.GroupBy = []string{"src_ip"}
	q.Metrics = []string{"bytes"}
	q.Sort = Sort{Field: "packets", Desc: true}
	if err := q.Validate(); err == nil {
		t.Error("按未选中的列排序应报错")
	}
}

// --- 编译 ---

func mustCompile(t *testing.T, q Query) Compiled {
	t.Helper()
	if err := q.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	c, err := Compile(q)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return c
}

// TestCompileTopTalker 设计文档 §22 的第一个 P0 场景。
func TestCompileTopTalker(t *testing.T) {
	q := baseQuery()
	q.GroupBy = []string{"src_ip"}
	q.Metrics = []string{"bytes", "packets", "flows"}
	q.Limit = 10

	c := mustCompile(t, q)

	// IP 列必须转成字符串输出,否则驱动返回 net.IP,进 JSON 是字节数组。
	// 而且要剥掉 IPv4-mapped 的 ::ffff: 前缀 —— 带着前缀的地址复制出去
	// 拿不去 ping、也对不上防火墙规则。
	if !strings.Contains(c.SQL, "replaceOne(IPv6NumToString(src_ip), '::ffff:', '') AS src_ip") {
		t.Errorf("IP 列应转字符串并剥掉 ::ffff: 前缀:\n%s", c.SQL)
	}
	if !strings.Contains(c.SQL, "GROUP BY src_ip") {
		t.Errorf("缺少 GROUP BY:\n%s", c.SQL)
	}
	if !strings.Contains(c.SQL, "ORDER BY bytes DESC") {
		t.Errorf("缺少排序:\n%s", c.SQL)
	}
	if !strings.Contains(c.SQL, "LIMIT 10") {
		t.Errorf("缺少 LIMIT:\n%s", c.SQL)
	}
	// 时间范围必须是第一个 WHERE 条件,让 ClickHouse 能按主键跳 granule
	if !strings.Contains(c.SQL, "WHERE timestamp >= ? AND timestamp < ?") {
		t.Errorf("时间范围应是第一个条件:\n%s", c.SQL)
	}
	if len(c.Args) != 2 {
		t.Errorf("want 2 args(时间范围), got %d: %v", len(c.Args), c.Args)
	}
	wantCols := []string{"src_ip", "bytes", "packets", "flows"}
	if strings.Join(c.Columns, ",") != strings.Join(wantCols, ",") {
		t.Errorf("列名: want %v, got %v", wantCols, c.Columns)
	}
}

// TestCompileConversation Top Conversation:按源+目的分组。
func TestCompileConversation(t *testing.T) {
	q := baseQuery()
	q.GroupBy = []string{"src_ip", "dst_ip"}
	c := mustCompile(t, q)
	if !strings.Contains(c.SQL, "GROUP BY src_ip, dst_ip") {
		t.Errorf("SQL:\n%s", c.SQL)
	}
}

// TestCompileTimeSeriesUsesAggTable 时间序列必须走分钟聚合表 ——
// 让 Dashboard 的时间序列扫明细表在数据量大之后必然拖垮 ClickHouse。
func TestCompileTimeSeriesUsesAggTable(t *testing.T) {
	q := baseQuery()
	q.Interval = "minute"
	c := mustCompile(t, q)

	if c.Table != "flows_1m" {
		t.Errorf("时间序列应走 flows_1m, got %s", c.Table)
	}
	if !strings.Contains(c.SQL, "toStartOfMinute(ts_minute) AS ts") {
		t.Errorf("缺少时间桶:\n%s", c.SQL)
	}
	// 聚合表上 flows 是已存好的列,要 sum 而不是 count()
	if !strings.Contains(c.SQL, "sum(flows) AS flows") {
		t.Errorf("聚合表上 flows 应为 sum(flows):\n%s", c.SQL)
	}
	if strings.Contains(c.SQL, "count()") {
		t.Errorf("聚合表上不该出现 count():\n%s", c.SQL)
	}
	// 时间列名在聚合表里是 ts_minute 而不是 timestamp
	if !strings.Contains(c.SQL, "WHERE ts_minute >= ?") {
		t.Errorf("聚合表的时间列应为 ts_minute:\n%s", c.SQL)
	}
	if c.Columns[0] != "ts" {
		t.Errorf("时间序列第一列应为 ts, got %v", c.Columns)
	}
}

// TestCompileRawTableUsesCountForFlows 明细表上 flows 是 count()。
// 两张表写法不同,搞混会让数字差好几个数量级。
func TestCompileRawTableUsesCountForFlows(t *testing.T) {
	q := baseQuery()
	q.GroupBy = []string{"dst_port"}
	c := mustCompile(t, q)
	if c.Table != "flows" {
		t.Fatalf("按端口分组应走明细表, got %s", c.Table)
	}
	if !strings.Contains(c.SQL, "count() AS flows") {
		t.Errorf("明细表上 flows 应为 count():\n%s", c.SQL)
	}
}

// TestPortGroupingForcesRawTable 端口不在聚合表的维度里 —— 带上端口会让
// 聚合表基数爆炸(每条连接一个随机源端口),退化成和明细表一样大。
func TestPortGroupingForcesRawTable(t *testing.T) {
	q := baseQuery()
	q.TimeRange.To = q.TimeRange.From.Add(30 * 24 * time.Hour) // 跨度很大
	q.GroupBy = []string{"dst_port"}
	c := mustCompile(t, q)
	if c.Table != "flows" {
		t.Errorf("按端口分组必须走明细表, got %s", c.Table)
	}
}

// TestLongSpanUsesAggTableWhenPossible 跨度大且维度都在聚合表里时应该
// 自动走聚合表 —— 界面上用户只选"最近 30 天",不该还要懂查哪张表。
func TestLongSpanUsesAggTableWhenPossible(t *testing.T) {
	q := baseQuery()
	q.TimeRange.To = q.TimeRange.From.Add(30 * 24 * time.Hour)
	q.GroupBy = []string{"src_country"}
	c := mustCompile(t, q)
	if c.Table != "flows_1m" {
		t.Errorf("长跨度 + 聚合表维度应走 flows_1m, got %s", c.Table)
	}
}

// TestMetricUnavailableOnAggTableIsAnError 基数类指标在聚合表上算不出来
// (同一个 IP 在多个分钟桶里被合并)。必须明确报错 —— 静默返回 0 的话
// 用户会看到一列全 0 并信以为真。
func TestMetricUnavailableOnAggTableIsAnError(t *testing.T) {
	q := baseQuery()
	q.Interval = "hour"
	q.Metrics = []string{"uniq_src_ip"}
	if err := q.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	_, err := Compile(q)
	if err == nil {
		t.Fatal("基数指标在聚合表上应报错")
	}
	if !strings.Contains(err.Error(), "flows") {
		t.Errorf("错误应指引用户指定 table=flows: %v", err)
	}
}

// --- 过滤条件编译 ---

func TestCompileFilterEquality(t *testing.T) {
	q := baseQuery()
	q.Filters = Condition{Field: "dst_port", Operator: OpEq, Value: 443}
	c := mustCompile(t, q)
	if !strings.Contains(c.SQL, "dst_port = ?") {
		t.Errorf("SQL:\n%s", c.SQL)
	}
	if len(c.Args) != 3 || c.Args[2] != 443 {
		t.Errorf("参数应包含 443: %v", c.Args)
	}
}

// TestCompileIPFilterUsesToIPv6 IP 列比较要先把字符串转成 IPv6 数值,
// 否则类型不匹配直接报错。
func TestCompileIPFilterUsesToIPv6(t *testing.T) {
	q := baseQuery()
	q.Filters = Condition{Field: "src_ip", Operator: OpEq, Value: "203.0.113.7"}
	c := mustCompile(t, q)
	if !strings.Contains(c.SQL, "src_ip = toIPv6(?)") {
		t.Errorf("SQL:\n%s", c.SQL)
	}
}

func TestCompileCIDR(t *testing.T) {
	q := baseQuery()
	q.Filters = Condition{Field: "src_ip", Operator: OpCIDR, Value: "10.0.0.0/8"}
	c := mustCompile(t, q)
	if !strings.Contains(c.SQL, "isIPAddressInRange") {
		t.Errorf("CIDR 应用 isIPAddressInRange:\n%s", c.SQL)
	}
}

// TestCompileContainsAvoidsLikeEscaping position() 而不是 LIKE '%x%':
// 语义一样但不用转义用户输入里的 % 和 _,少一处能出错的地方。
func TestCompileContainsAvoidsLikeEscaping(t *testing.T) {
	q := baseQuery()
	q.Filters = Condition{Field: "src_org", Operator: OpContains, Value: "100%_Cloud"}
	c := mustCompile(t, q)
	if !strings.Contains(c.SQL, "position(src_org, ?) > 0") {
		t.Errorf("contains 应用 position():\n%s", c.SQL)
	}
	// 值原样传参,不做任何转义
	if c.Args[2] != "100%_Cloud" {
		t.Errorf("值应原样传参: %v", c.Args[2])
	}
}

func TestCompileAndOrNot(t *testing.T) {
	q := baseQuery()
	q.Filters = Condition{
		Op: OpAnd,
		Conditions: []Condition{
			{Field: "src_country", Operator: OpEq, Value: "JP"},
			{Op: OpOr, Conditions: []Condition{
				{Field: "dst_port", Operator: OpEq, Value: 443},
				{Field: "dst_port", Operator: OpEq, Value: 80},
			}},
			{Op: OpNot, Conditions: []Condition{
				{Field: "src_asn", Operator: OpEq, Value: 15169},
			}},
		},
	}
	c := mustCompile(t, q)
	for _, want := range []string{"src_country = ?", "OR", "NOT (", "src_asn = ?"} {
		if !strings.Contains(c.SQL, want) {
			t.Errorf("SQL 缺少 %q:\n%s", want, c.SQL)
		}
	}
	// 时间范围 2 个 + 4 个条件值
	if len(c.Args) != 6 {
		t.Errorf("want 6 args, got %d: %v", len(c.Args), c.Args)
	}
}

func TestCompileInList(t *testing.T) {
	q := baseQuery()
	q.Filters = Condition{Field: "dst_port", Operator: OpIn, Value: []any{80.0, 443.0, 8080.0}}
	c := mustCompile(t, q)
	if !strings.Contains(c.SQL, "dst_port IN (?, ?, ?)") {
		t.Errorf("SQL:\n%s", c.SQL)
	}
	// JSON 数字是 float64,必须转成 int64 —— 直接传 float 给 UInt16 列
	// 会报类型错误
	for _, a := range c.Args[2:] {
		if _, ok := a.(int64); !ok {
			t.Errorf("整数值应转成 int64, got %T", a)
		}
	}
}

func TestCompileInListRejectsEmptyAndHuge(t *testing.T) {
	q := baseQuery()
	q.Filters = Condition{Field: "dst_port", Operator: OpIn, Value: []any{}}
	if err := q.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if _, err := Compile(q); err == nil {
		t.Error("空 IN 列表应报错")
	}

	huge := make([]any, 1001)
	for i := range huge {
		huge[i] = float64(i)
	}
	q2 := baseQuery()
	q2.Filters = Condition{Field: "dst_port", Operator: OpIn, Value: huge}
	_ = q2.Validate()
	if _, err := Compile(q2); err == nil {
		t.Error("超长 IN 列表应报错")
	}
}

func TestCompileNotInIPList(t *testing.T) {
	q := baseQuery()
	q.Filters = Condition{Field: "src_ip", Operator: OpNotIn,
		Value: []any{"10.0.0.1", "10.0.0.2"}}
	c := mustCompile(t, q)
	if !strings.Contains(c.SQL, "src_ip NOT IN (toIPv6(?), toIPv6(?))") {
		t.Errorf("SQL:\n%s", c.SQL)
	}
}

// TestCompileDetailRows 没有分组也没有时间桶时返回明细行(Flow Detail /
// 下钻到最后一层)。
func TestCompileDetailRows(t *testing.T) {
	q := baseQuery()
	q.Metrics = []string{} // 显式清空,Validate 会填回默认值
	q.Filters = Condition{Field: "src_ip", Operator: OpEq, Value: "203.0.113.7"}
	if err := q.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// Validate 填了默认指标,所以这里是聚合查询;要拿明细必须显式指定
	q.Metrics = nil
	q.GroupBy = nil
	q.Interval = ""
	c, err := Compile(q)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !strings.Contains(c.SQL, "ORDER BY timestamp DESC") {
		t.Errorf("明细应按时间倒序:\n%s", c.SQL)
	}
	// 明细里同时给出估算值与实测值 —— 让人能判断这个数字是量出来的
	// 还是算出来的
	for _, want := range []string{"observed_bytes", "sampling_rate"} {
		if !strings.Contains(c.SQL, want) {
			t.Errorf("明细缺少 %s:\n%s", want, c.SQL)
		}
	}
}

// TestNoFilterProducesNoExtraArgs 零值 Filters 表示不过滤,不该生成
// 多余的 WHERE 片段或参数。
func TestNoFilterProducesNoExtraArgs(t *testing.T) {
	q := baseQuery()
	q.GroupBy = []string{"protocol"}
	c := mustCompile(t, q)
	if len(c.Args) != 2 {
		t.Errorf("无过滤条件时只应有时间范围两个参数, got %v", c.Args)
	}
	if strings.Count(c.SQL, "?") != 2 {
		t.Errorf("占位符数量应为 2:\n%s", c.SQL)
	}
}

// TestFieldsInfoIsServedFromBackend 界面从接口拿字段列表而不是硬编码:
// 硬编码那份迟早与后端不同步,表现为界面上能选的字段查询时报"不支持"。
func TestFieldsInfoIsServedFromBackend(t *testing.T) {
	info := Fields()
	if len(info.Filterable) < 10 {
		t.Errorf("可过滤字段太少: %d", len(info.Filterable))
	}
	if len(info.Groupable) < 10 {
		t.Errorf("可分组字段太少: %d", len(info.Groupable))
	}
	if len(info.Metrics) < 3 {
		t.Errorf("指标太少: %v", info.Metrics)
	}
	// 每个可过滤字段都要带上它允许的运算符,界面才能只显示有意义的选项
	for _, f := range info.Filterable {
		if len(f.Operators) == 0 {
			t.Errorf("字段 %s 没有可用运算符", f.Name)
		}
		if f.Kind == "" {
			t.Errorf("字段 %s 缺少类型", f.Name)
		}
	}
}
