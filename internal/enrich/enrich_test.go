package enrich

import (
	"net"
	"strings"
	"testing"

	"github.com/githubflyideas/ntop2ban/internal/flow"
)

// sampleTSV 是 ip2asn 的真实格式:5 列 TSV。
// 刻意包含一个空洞(1.0.1.0-1.0.3.255 之后跳到 8.8.8.0)与一条
// ASN 0 记录,两者都是真实数据里存在的情况。
const sampleTSV = `1.0.0.0	1.0.0.255	13335	US	CLOUDFLARENET
1.0.1.0	1.0.3.255	0	None	Not routed
8.8.8.0	8.8.8.255	15169	US	GOOGLE
203.0.113.0	203.0.113.255	64496	JP	EXAMPLE-JP
`

func loadSample(t *testing.T) *DB {
	t.Helper()
	db := New()
	if err := db.Load(strings.NewReader(sampleTSV)); err != nil {
		t.Fatalf("Load: %v", err)
	}
	return db
}

func TestLookupBasic(t *testing.T) {
	db := loadSample(t)

	cases := []struct {
		ip      string
		asn     uint32
		country string
		org     string
	}{
		{"1.0.0.1", 13335, "US", "CLOUDFLARENET"},
		{"1.0.0.255", 13335, "US", "CLOUDFLARENET"},
		{"8.8.8.8", 15169, "US", "GOOGLE"},
		{"203.0.113.7", 64496, "JP", "EXAMPLE-JP"},
	}
	for _, c := range cases {
		got := db.Lookup(net.ParseIP(c.ip))
		if got.ASN != c.asn || got.Country != c.country || got.Org != c.org {
			t.Errorf("Lookup(%s) = %+v, want asn=%d country=%s org=%s",
				c.ip, got, c.asn, c.country, c.org)
		}
	}
}

// TestLookupRespectsUpperBound 相邻条目之间可能有空洞(未分配地址段)。
// 只看 start 做二分会把空洞里的 IP 错归到前一个 AS —— 那会让 Top ASN
// 里某个 AS 凭空多出一堆不属于它的流量。
func TestLookupRespectsUpperBound(t *testing.T) {
	db := loadSample(t)

	// 4.0.0.1 落在 1.0.3.255 与 8.8.8.0 之间的空洞里
	if got := db.Lookup(net.ParseIP("4.0.0.1")); got.ASN != 0 {
		t.Errorf("空洞里的 IP 应查不到,got %+v", got)
	}
	// 8.8.9.1 超出 8.8.8.255
	if got := db.Lookup(net.ParseIP("8.8.9.1")); got.ASN != 0 {
		t.Errorf("超出上界的 IP 应查不到,got %+v", got)
	}
}

// TestLookupBeforeFirstEntry 小于第一个条目的 IP。
func TestLookupBeforeFirstEntry(t *testing.T) {
	db := loadSample(t)
	if got := db.Lookup(net.ParseIP("0.0.0.1")); got.ASN != 0 {
		t.Errorf("第一个条目之前的 IP 应查不到, got %+v", got)
	}
}

// TestASN0IsSkipped ip2asn 里 ASN 0 是 "not routed" 的占位记录。
// 留着会让 Top ASN 出现一个巨大的 AS0,而那不是一个真实的自治系统。
func TestASN0IsSkipped(t *testing.T) {
	db := loadSample(t)
	if db.Size() != 3 {
		t.Errorf("ASN 0 记录应被跳过, 期望 3 条, got %d", db.Size())
	}
	if got := db.Lookup(net.ParseIP("1.0.2.1")); got.ASN != 0 || got.Org != "" {
		t.Errorf("not-routed 段应查不到, got %+v", got)
	}
}

// TestLookupPrivateAddressIsEmpty 私有地址不在 ip2asn 里。给内网 IP
// 编一个国家出来只会误导。
func TestLookupPrivateAddressIsEmpty(t *testing.T) {
	db := loadSample(t)
	for _, ip := range []string{"10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1"} {
		if got := db.Lookup(net.ParseIP(ip)); got.ASN != 0 {
			t.Errorf("私有地址 %s 应查不到, got %+v", ip, got)
		}
	}
}

// TestLookupIPv6ReturnsEmptyNotError IPv6 不在 v4 库范围内。返回零值
// 而不是报错:IPv6 流量仍该被采集,只是没有 ASN 维度。
func TestLookupIPv6ReturnsEmpty(t *testing.T) {
	db := loadSample(t)
	if got := db.Lookup(net.ParseIP("2001:db8::1")); got.ASN != 0 {
		t.Errorf("IPv6 应返回零值, got %+v", got)
	}
}

// TestUnloadedDBIsNoOp 没加载数据时富化是空操作,不 panic。
// ip2asn 库是可选的——没有它 flow 仍该被采集与存储。
func TestUnloadedDBIsNoOp(t *testing.T) {
	db := New()
	if db.Loaded() {
		t.Error("空库不该报告已加载")
	}
	if got := db.Lookup(net.ParseIP("8.8.8.8")); got.ASN != 0 {
		t.Errorf("空库应返回零值, got %+v", got)
	}
}

// TestLoadSkipsMalformedLines 一个上游数据问题不该让富化完全不可用。
func TestLoadSkipsMalformedLines(t *testing.T) {
	bad := `# 注释
1.0.0.0	1.0.0.255	13335	US	CLOUDFLARENET
这行不是 TSV
1.0.1.0	notanip	100	US	X
1.0.2.0	1.0.2.255	notanumber	US	X

8.8.8.0	8.8.8.255	15169	US	GOOGLE
`
	db := New()
	if err := db.Load(strings.NewReader(bad)); err != nil {
		t.Fatalf("畸形行不该让加载失败: %v", err)
	}
	if db.Size() != 2 {
		t.Errorf("应加载 2 条有效记录, got %d", db.Size())
	}
	if got := db.Lookup(net.ParseIP("8.8.8.8")); got.ASN != 15169 {
		t.Errorf("有效记录应能查到, got %+v", got)
	}
}

// TestLoadEmptyIsAnError 全空或格式完全不对时要报错 —— 那通常意味着
// 下错了文件(比如下到一个 HTML 错误页),静默当成"库是空的"会让人
// 以为富化在工作。
func TestLoadEmptyIsAnError(t *testing.T) {
	db := New()
	if err := db.Load(strings.NewReader("")); err == nil {
		t.Error("空数据应报错")
	}
	if err := db.Load(strings.NewReader("<html>404</html>\n")); err == nil {
		t.Error("完全不符格式应报错")
	}
}

func TestParseIPv4ToUint32(t *testing.T) {
	cases := map[string]uint32{
		"0.0.0.0":         0,
		"1.0.0.0":         0x01000000,
		"8.8.8.8":         0x08080808,
		"255.255.255.255": 0xffffffff,
	}
	for s, want := range cases {
		got, ok := parseIPv4ToUint32(s)
		if !ok || got != want {
			t.Errorf("parseIPv4ToUint32(%q) = %d, %v; want %d", s, got, ok, want)
		}
	}
	for _, bad := range []string{"", "1.2.3", "1.2.3.4.5", "256.0.0.1", "a.b.c.d", "1.2.3.", "1..3.4"} {
		if _, ok := parseIPv4ToUint32(bad); ok {
			t.Errorf("parseIPv4ToUint32(%q) 应失败", bad)
		}
	}
}

// --- 应用分类 ---

// TestClassifyPrefersDestinationPort 客户端源端口是随机高位端口,
// 目的端口才是服务端口。反过来看会把"某人访问 443"识别成
// "某人从 443 提供服务"。
func TestClassifyPrefersDestinationPort(t *testing.T) {
	if got := Classify(6, 54321, 443); got != "https" {
		t.Errorf("want https, got %q", got)
	}
	// 回程方向:源端口是服务端口,也应识别出来
	if got := Classify(6, 443, 54321); got != "https" {
		t.Errorf("回程方向 want https, got %q", got)
	}
}

func TestClassifyCommonPorts(t *testing.T) {
	cases := []struct {
		proto    uint8
		src, dst uint16
		want     string
	}{
		{6, 40000, 22, "ssh"},
		{6, 40000, 80, "http"},
		{6, 40000, 3306, "mysql"},
		{6, 40000, 9200, "elasticsearch"},
		{17, 40000, 53, "dns"},
		{17, 40000, 123, "ntp"},
		{17, 40000, 443, "quic"},
		{17, 40000, 6343, "sflow"},
		{17, 40000, 2055, "netflow"},
		{17, 40000, 51820, "wireguard"},
	}
	for _, c := range cases {
		if got := Classify(c.proto, c.src, c.dst); got != c.want {
			t.Errorf("Classify(%d, %d, %d) = %q, want %q", c.proto, c.src, c.dst, got, c.want)
		}
	}
}

// TestClassifyUnknownPortKeepsNumber 两个端口都不认识时返回
// "tcp/12345" 而不是空字符串或 "unknown"。
//
// 空字符串会让 Top Application 里出现一个匿名的巨大条目;带端口号的
// 形式仍然可以下钻 —— 用户看到 "tcp/9999" 至少知道该去查那个端口。
func TestClassifyUnknownPortKeepsNumber(t *testing.T) {
	if got := Classify(6, 40000, 9999); got != "tcp/9999" {
		t.Errorf("want tcp/9999, got %q", got)
	}
	if got := Classify(17, 40000, 12345); got != "udp/12345" {
		t.Errorf("want udp/12345, got %q", got)
	}
}

// TestClassifyZeroPortDoesNotProduceSlashZero 端口 0 出现在畸形包或
// 非端口协议上,不该拼成 "tcp/0" 那种看起来像真实服务的东西。
func TestClassifyZeroPort(t *testing.T) {
	if got := Classify(6, 0, 0); got != "tcp" {
		t.Errorf("want tcp, got %q", got)
	}
	if got := Classify(17, 0, 0); got != "udp" {
		t.Errorf("want udp, got %q", got)
	}
}

func TestClassifyNonPortProtocols(t *testing.T) {
	cases := map[uint8]string{
		1: "icmp", 47: "gre", 50: "esp", 51: "ah", 89: "ospf", 132: "sctp", 2: "igmp",
	}
	for proto, want := range cases {
		if got := Classify(proto, 0, 0); got != want {
			t.Errorf("Classify(%d) = %q, want %q", proto, got, want)
		}
	}
	if got := Classify(200, 0, 0); got != "proto/200" {
		t.Errorf("未知协议 want proto/200, got %q", got)
	}
}

// --- 端到端富化 ---

func TestEnricherApply(t *testing.T) {
	e := NewEnricher(loadSample(t), nil)

	batch := []flow.Flow{
		{SrcIP: "8.8.8.8", DstIP: "203.0.113.7", Protocol: 6, SrcPort: 53000, DstPort: 443},
		{SrcIP: "10.0.0.5", DstIP: "8.8.8.8", Protocol: 17, SrcPort: 40000, DstPort: 53},
	}
	e.Apply(batch)

	f := batch[0]
	if f.SrcASN != 15169 || f.SrcCountry != "US" || f.SrcOrg != "GOOGLE" {
		t.Errorf("源富化错误: %+v", f)
	}
	if f.DstASN != 64496 || f.DstCountry != "JP" {
		t.Errorf("目的富化错误: %+v", f)
	}
	if f.Application != "https" {
		t.Errorf("应用分类: want https, got %q", f.Application)
	}

	// 内网源:ASN/国家为空,但目的仍应被富化
	g := batch[1]
	if g.SrcASN != 0 || g.SrcCountry != "" {
		t.Errorf("内网源不该被编造归属: %+v", g)
	}
	if g.DstASN != 15169 {
		t.Errorf("目的应被富化: %+v", g)
	}
	if g.Application != "dns" {
		t.Errorf("应用分类: want dns, got %q", g.Application)
	}
}

// TestEnricherLeavesCityEmptyWithoutMMDB 没加载 mmdb 时 city/region
// 保持为空,界面上对应视图不显示 —— 而不是编一个值出来。
func TestEnricherLeavesCityEmptyWithoutMMDB(t *testing.T) {
	e := NewEnricher(loadSample(t), nil)
	batch := []flow.Flow{{SrcIP: "8.8.8.8", DstIP: "203.0.113.7", Protocol: 6, DstPort: 443}}
	e.Apply(batch)

	f := batch[0]
	if f.SrcCity != "" || f.DstCity != "" || f.SrcRegion != "" || f.DstRegion != "" {
		t.Errorf("ip2asn 没有 city/region,这些字段应为空: %+v", f)
	}
	// 但 ASN 与国家必须有 —— 那是 ip2asn 提供的
	if f.SrcASN == 0 || f.SrcCountry == "" {
		t.Errorf("ASN 与国家应被填上: %+v", f)
	}
}

// TestEnricherWithNilDBDoesNotPanic 富化库缺失时仍要能跑:
// 只是没有 ASN/国家维度,应用分类照旧(它不依赖外部数据)。
func TestEnricherWithNilDBDoesNotPanic(t *testing.T) {
	e := NewEnricher(nil, nil)
	batch := []flow.Flow{{SrcIP: "8.8.8.8", DstIP: "1.1.1.1", Protocol: 6, DstPort: 22}}
	e.Apply(batch)

	if batch[0].SrcASN != 0 {
		t.Error("没有富化库时 ASN 应为 0")
	}
	if batch[0].Application != "ssh" {
		t.Errorf("应用分类不依赖富化库, want ssh, got %q", batch[0].Application)
	}
}
