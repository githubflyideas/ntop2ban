package query

import "sort"

// 字段白名单。这是安全边界:能出现在 SQL 里的列名只有这里列出的这些,
// 因此不存在通过字段名注入的可能。
//
// 白名单而不是黑名单:新增列时忘了加进白名单,后果是"这个字段不能查",
// 用户会立刻报告;而黑名单漏了一项,后果是暴露了不该暴露的东西,
// 没人会报告。

// fieldKind 决定值怎么被绑定成 SQL 参数。
type fieldKind int

const (
	kindString fieldKind = iota
	kindInt
	kindIP
)

type fieldDef struct {
	// column 是实际的 ClickHouse 列名。与 API 字段名分开是为了让列名
	// 将来能改而不破坏 API。
	column string
	kind   fieldKind
	// ops 该字段允许的运算符。
	//
	// 逐字段限制而不是全局放开:对 src_ip 用 like 是没意义的(IPv6 列
	// 上做字符串匹配会全表扫且结果反直觉),对 bytes 用 cidr 更是荒谬。
	// 允许了只会让人写出能跑但结果错误的查询。
	ops map[Operator]bool
}

func (f fieldDef) allows(op Operator) bool { return f.ops[op] }

func (f fieldDef) operatorNames() []string {
	out := make([]string, 0, len(f.ops))
	for op := range f.ops {
		out = append(out, string(op))
	}
	sort.Strings(out)
	return out
}

var (
	stringOps = map[Operator]bool{
		OpEq: true, OpNe: true, OpIn: true, OpNotIn: true,
		OpLike: true, OpContains: true, OpPrefix: true,
	}
	numOps = map[Operator]bool{
		OpEq: true, OpNe: true, OpGt: true, OpGte: true, OpLt: true, OpLte: true,
		OpIn: true, OpNotIn: true,
	}
	// IP 列支持 cidr 而不支持 like:cidr 能用上 IPv6 列的原生比较,
	// like 会退化成字符串匹配。
	ipOps = map[Operator]bool{
		OpEq: true, OpNe: true, OpIn: true, OpNotIn: true, OpCIDR: true,
	}
)

// filterableFields 可用于过滤的字段。
var filterableFields = map[string]fieldDef{
	"src_ip":   {column: "src_ip", kind: kindIP, ops: ipOps},
	"dst_ip":   {column: "dst_ip", kind: kindIP, ops: ipOps},
	"src_port": {column: "src_port", kind: kindInt, ops: numOps},
	"dst_port": {column: "dst_port", kind: kindInt, ops: numOps},
	"protocol": {column: "protocol", kind: kindInt, ops: numOps},

	"bytes":   {column: "bytes", kind: kindInt, ops: numOps},
	"packets": {column: "packets", kind: kindInt, ops: numOps},

	"src_country": {column: "src_country", kind: kindString, ops: stringOps},
	"dst_country": {column: "dst_country", kind: kindString, ops: stringOps},
	"src_region":  {column: "src_region", kind: kindString, ops: stringOps},
	"dst_region":  {column: "dst_region", kind: kindString, ops: stringOps},
	"src_city":    {column: "src_city", kind: kindString, ops: stringOps},
	"dst_city":    {column: "dst_city", kind: kindString, ops: stringOps},
	"src_asn":     {column: "src_asn", kind: kindInt, ops: numOps},
	"dst_asn":     {column: "dst_asn", kind: kindInt, ops: numOps},
	"src_org":     {column: "src_org", kind: kindString, ops: stringOps},
	"dst_org":     {column: "dst_org", kind: kindString, ops: stringOps},

	"application": {column: "application", kind: kindString, ops: stringOps},
	"source_type": {column: "source_type", kind: kindString, ops: stringOps},

	"device_id":        {column: "device_id", kind: kindInt, ops: numOps},
	"sensor_id":        {column: "sensor_id", kind: kindInt, ops: numOps},
	"site_id":          {column: "site_id", kind: kindInt, ops: numOps},
	"input_interface":  {column: "input_interface", kind: kindInt, ops: numOps},
	"output_interface": {column: "output_interface", kind: kindInt, ops: numOps},
	"vlan":             {column: "vlan", kind: kindInt, ops: numOps},
	"tcp_flags":        {column: "tcp_flags", kind: kindInt, ops: numOps},
}

// groupableFields 可用于分组的维度。
//
// 是 filterable 的子集:bytes/packets 能过滤但不能分组(按字节数分组
// 会产生几乎和行数一样多的组,那不是聚合而是把明细换个写法)。
var groupableFields = map[string]string{
	"src_ip":   "src_ip",
	"dst_ip":   "dst_ip",
	"src_port": "src_port",
	"dst_port": "dst_port",
	"protocol": "protocol",

	"src_country": "src_country",
	"dst_country": "dst_country",
	"src_region":  "src_region",
	"dst_region":  "dst_region",
	"src_city":    "src_city",
	"dst_city":    "dst_city",
	"src_asn":     "src_asn",
	"dst_asn":     "dst_asn",
	"src_org":     "src_org",
	"dst_org":     "dst_org",

	"application": "application",
	"source_type": "source_type",

	"device_id":        "device_id",
	"sensor_id":        "sensor_id",
	"site_id":          "site_id",
	"input_interface":  "input_interface",
	"output_interface": "output_interface",
	"vlan":             "vlan",
}

// metricExprs 指标名 → 聚合表达式。
//
// 每个指标同时给出明细表与聚合表两种写法:flows_1m 里的 bytes 已经是
// 求和后的值,再 sum 一次是对的;但 flows 数是 count(),而 flows_1m 里
// 是一个已存好的 flows 列 —— 两张表上写法不同,这里分开定义,
// 让 planner 选表之后不必再判断。
type metricExpr struct {
	// raw 是在 flows(明细表)上的表达式。
	raw string
	// agg 是在 flows_1m(聚合表)上的表达式。
	agg string
}

var metricExprs = map[string]metricExpr{
	"bytes":   {raw: "sum(bytes)", agg: "sum(bytes)"},
	"packets": {raw: "sum(packets)", agg: "sum(packets)"},
	"flows":   {raw: "count()", agg: "sum(flows)"},

	// 实测值:采样还原前的原始计数。UI 上与估算值并列展示,
	// 让人能判断"这个数字是量出来的还是算出来的"(技术设计 §7)。
	"observed_bytes":   {raw: "sum(observed_bytes)", agg: ""},
	"observed_packets": {raw: "sum(observed_packets)", agg: ""},

	// 基数类指标只能在明细表上算:flows_1m 已经按维度聚合过,
	// 那里的 uniq 会少算(同一个 IP 在多个分钟桶里被合并成一行)。
	"uniq_src_ip":   {raw: "uniqExact(src_ip)", agg: ""},
	"uniq_dst_ip":   {raw: "uniqExact(dst_ip)", agg: ""},
	"uniq_dst_port": {raw: "uniqExact(dst_port)", agg: ""},
}

func metricNames() []string {
	out := make([]string, 0, len(metricExprs))
	for k := range metricExprs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// intervalFuncs 时间粒度 → ClickHouse 函数。
var intervalFuncs = map[string]string{
	"minute": "toStartOfMinute",
	"hour":   "toStartOfHour",
	"day":    "toStartOfDay",
}

// FieldsInfo 返回字段元信息,供界面构建查询构造器。
//
// 让界面从接口拿字段列表而不是硬编码一份:硬编码的那份迟早与后端不同步,
// 表现为界面上能选的字段查询时报 "不支持"。
type FieldsInfo struct {
	Filterable []FieldMeta `json:"filterable"`
	Groupable  []string    `json:"groupable"`
	Metrics    []string    `json:"metrics"`
	Intervals  []string    `json:"intervals"`
}

type FieldMeta struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Operators []string `json:"operators"`
}

func Fields() FieldsInfo {
	info := FieldsInfo{
		Metrics:   metricNames(),
		Intervals: []string{"minute", "hour", "day"},
	}
	for name, def := range filterableFields {
		kind := "string"
		switch def.kind {
		case kindInt:
			kind = "int"
		case kindIP:
			kind = "ip"
		}
		info.Filterable = append(info.Filterable, FieldMeta{
			Name: name, Kind: kind, Operators: def.operatorNames(),
		})
	}
	sort.Slice(info.Filterable, func(i, j int) bool {
		return info.Filterable[i].Name < info.Filterable[j].Name
	})
	for name := range groupableFields {
		info.Groupable = append(info.Groupable, name)
	}
	sort.Strings(info.Groupable)
	return info
}
