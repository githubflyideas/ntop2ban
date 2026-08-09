package enrich

import (
	"strings"
	"testing"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/flow"
)

// db-ip city-lite 的真实格式(实测取自 download.db-ip.com)。
// 刻意包含 ZZ 占位行、带引号且含空格的城市名、以及一个地址空洞。
const sampleDBIPCity = `0.0.0.0,0.255.255.255,ZZ,ZZ,,,0,0
1.0.0.0,1.0.0.255,OC,AU,Queensland,"South Brisbane",-27.4767,153.017
1.0.1.0,1.0.3.255,AS,CN,Fujian,Wenquan,26.0998,119.297
8.8.8.0,8.8.8.255,NA,US,California,"Mountain View",37.4056,-122.0775
203.0.113.0,203.0.113.255,AS,JP,Tokyo,"Chiyoda, Tokyo",35.6939,139.753
`

func TestLoadDBIPCity(t *testing.T) {
	db := NewCityDB()
	if err := db.LoadDBIPCity(strings.NewReader(sampleDBIPCity)); err != nil {
		t.Fatalf("LoadDBIPCity: %v", err)
	}

	// ZZ(未知)行应被跳过 —— 留着会让 Top Country 出现一个叫 ZZ 的
	// 巨大条目,而那不是一个国家。
	if db.Size() != 4 {
		t.Fatalf("ZZ 行应被跳过, want 4 条, got %d", db.Size())
	}

	got := db.Lookup(mustIPv4(t, "8.8.8.8"))
	if got.Country != "US" || got.Region != "California" || got.City != "Mountain View" {
		t.Errorf("查表错误: %+v", got)
	}
	if got.Lat < 37 || got.Lat > 38 {
		t.Errorf("纬度不对: %v", got.Lat)
	}
}

// TestLoadDBIPCityHandlesQuotedCommas 城市名里带逗号("Chiyoda, Tokyo")
// 是真实存在的。手写 strings.Split 会在这里切错,导致经纬度串位、
// 城市名被截断 —— 而且不会报错。
func TestLoadDBIPCityHandlesQuotedCommas(t *testing.T) {
	db := NewCityDB()
	if err := db.LoadDBIPCity(strings.NewReader(sampleDBIPCity)); err != nil {
		t.Fatalf("LoadDBIPCity: %v", err)
	}
	got := db.Lookup(mustIPv4(t, "203.0.113.7"))
	if got.City != "Chiyoda, Tokyo" {
		t.Errorf("含逗号的城市名应完整保留, got %q", got.City)
	}
	if got.Country != "JP" {
		t.Errorf("国家: want JP, got %q", got.Country)
	}
	// 经纬度没有串位
	if got.Lat < 35 || got.Lat > 36 || got.Lon < 139 || got.Lon > 140 {
		t.Errorf("经纬度串位了: lat=%v lon=%v", got.Lat, got.Lon)
	}
}

// TestCityDBRespectsUpperBound 地址空洞里的 IP 必须查不到。只看 start
// 做二分会把空洞归到前一条 —— 那会让某个城市凭空多出不属于它的流量。
func TestCityDBRespectsUpperBound(t *testing.T) {
	db := NewCityDB()
	if err := db.LoadDBIPCity(strings.NewReader(sampleDBIPCity)); err != nil {
		t.Fatalf("LoadDBIPCity: %v", err)
	}
	// 4.0.0.1 落在 1.0.3.255 与 8.8.8.0 之间
	if got := db.Lookup(mustIPv4(t, "4.0.0.1")); got.Country != "" {
		t.Errorf("空洞里的 IP 应查不到, got %+v", got)
	}
	if got := db.Lookup(mustIPv4(t, "8.8.9.1")); got.Country != "" {
		t.Errorf("超出上界应查不到, got %+v", got)
	}
}

func TestLoadDBIPCityRejectsWrongFormat(t *testing.T) {
	db := NewCityDB()
	if err := db.LoadDBIPCity(strings.NewReader("")); err == nil {
		t.Error("空数据应报错")
	}
	// 下到 HTML 错误页是很常见的失败 —— 静默当成"库是空的"会让用户
	// 以为富化在工作
	if err := db.LoadDBIPCity(strings.NewReader("<html><body>404</body></html>\n")); err == nil {
		t.Error("完全不符格式应报错")
	}
}

// 纯真文本导出格式。
const sampleQQWry = `1.0.1.0 1.0.3.255 福建省福州市 电信
1.0.8.0 1.0.15.255 广东省广州市 电信
14.0.0.0 14.0.15.255 北京市 联通
`

// TestLoadQQWryTextDoesNotFillCountry 这是最重要的一条断言。
//
// 纯真输出的是中文自由文本("福建省福州市"),不是 ISO 国家码。
// 混进 country 会让同一批流量的 Top Country 里同时出现 "CN" 和
// "福建省福州市" 两种东西,口径彻底乱掉,而且没人能从现象反推原因。
func TestLoadQQWryTextDoesNotFillCountry(t *testing.T) {
	db := NewCityDB()
	if err := db.LoadQQWryText(strings.NewReader(sampleQQWry)); err != nil {
		t.Fatalf("LoadQQWryText: %v", err)
	}
	got := db.Lookup(mustIPv4(t, "1.0.1.5"))
	if got.Country != "" {
		t.Errorf("纯真不该填 country(它给的是中文文本不是 ISO 码), got %q", got.Country)
	}
	if got.Region == "" {
		t.Error("region 应被填上")
	}
}

// TestLoadQQWryTextSplitsProvinceAndCity "福建省福州市" 里省市粘在一起。
// 不拆的话 Top Region 与 Top City 会显示成完全一样的东西。
func TestLoadQQWryTextSplitsProvinceAndCity(t *testing.T) {
	db := NewCityDB()
	if err := db.LoadQQWryText(strings.NewReader(sampleQQWry)); err != nil {
		t.Fatalf("LoadQQWryText: %v", err)
	}
	got := db.Lookup(mustIPv4(t, "1.0.1.5"))
	if got.Region != "福建省" {
		t.Errorf("region: want 福建省, got %q", got.Region)
	}
	if got.City != "福州市" {
		t.Errorf("city: want 福州市, got %q", got.City)
	}

	// 直辖市没有"省",region 与 city 的处理不该出错
	bj := db.Lookup(mustIPv4(t, "14.0.0.5"))
	if bj.Region == "" && bj.City == "" {
		t.Error("直辖市至少应填上一个维度")
	}
}

func TestCityDBSourceIsLabelled(t *testing.T) {
	db := NewCityDB()
	_ = db.LoadDBIPCity(strings.NewReader(sampleDBIPCity))
	if db.Source() != "db-ip city-lite" {
		t.Errorf("应标注数据来源, got %q", db.Source())
	}

	db2 := NewCityDB()
	_ = db2.LoadQQWryText(strings.NewReader(sampleQQWry))
	if db2.Source() != "纯真 qqwry" {
		t.Errorf("应标注数据来源, got %q", db2.Source())
	}
}

func TestUnloadedCityDBIsNoOp(t *testing.T) {
	db := NewCityDB()
	if db.Loaded() {
		t.Error("空库不该报告已加载")
	}
	if got := db.Lookup(mustIPv4(t, "8.8.8.8")); got.Country != "" || got.City != "" {
		t.Errorf("空库应返回零值, got %+v", got)
	}
}

// --- 源列表 ---

// TestSourcesAllDeclareFieldsAndLicense 每个源都必须说明它能填哪些字段
// 与许可。用户最常问的就是"我装了库为什么某一列还是空的",这两项是
// 界面上回答那个问题的依据。
func TestSourcesAllDeclareFieldsAndLicense(t *testing.T) {
	if len(Sources) < 4 {
		t.Fatalf("内置源太少: %d", len(Sources))
	}
	seen := map[string]bool{}
	for _, s := range Sources {
		if s.ID == "" || s.Name == "" {
			t.Errorf("源缺少 ID 或 Name: %+v", s)
		}
		if seen[s.ID] {
			t.Errorf("源 ID 重复: %s", s.ID)
		}
		seen[s.ID] = true
		if s.Fields == "" {
			t.Errorf("源 %s 未声明能填哪些字段", s.ID)
		}
		if s.License == "" {
			t.Errorf("源 %s 未声明许可", s.ID)
		}
		if s.Note == "" {
			t.Errorf("源 %s 未说明归属口径", s.ID)
		}
		if s.URL() == "" {
			t.Errorf("源 %s 生成了空 URL", s.ID)
		}
	}
}

// TestDBIPURLFollowsCurrentMonth db-ip 的路径带年月。
func TestDBIPURLFollowsCurrentMonth(t *testing.T) {
	src, ok := SourceByID("dbip-city")
	if !ok {
		t.Fatal("找不到 dbip-city")
	}
	now := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	if got := src.url(now); !strings.Contains(got, "2026-08") {
		t.Errorf("应带当月年月: %s", got)
	}
}

// TestDBIPHasPreviousMonthFallback 新月份文件不是 1 号零点就位的。
// 没有退路的话每个月头几天同步都会失败,而 404 这个错误完全指不到
// "等几天或用上个月的"。
func TestDBIPHasPreviousMonthFallback(t *testing.T) {
	for _, id := range []string{"dbip-city", "dbip-asn"} {
		src, ok := SourceByID(id)
		if !ok {
			t.Fatalf("找不到 %s", id)
		}
		if src.fallbackURL == nil {
			t.Fatalf("%s 必须有上个月的退路", id)
		}
		now := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
		if got := src.fallbackURL(now); !strings.Contains(got, "2026-07") {
			t.Errorf("%s 退路应指向上个月: %s", id, got)
		}
	}
}

// TestQQWrySourceIsCityTextKind 纯真必须是 city_text 类型 —— 那个类型
// 决定了它不会去填 country。分类错了会让国家维度被中文文本污染。
func TestQQWrySourceIsCityTextKind(t *testing.T) {
	src, ok := SourceByID("qqwry")
	if !ok {
		t.Fatal("找不到 qqwry")
	}
	if src.Kind != KindCityText {
		t.Errorf("纯真应为 KindCityText, got %q", src.Kind)
	}
	if !strings.Contains(src.Note, "不填国家") {
		t.Error("Note 应明确说明它不填国家,否则用户会困惑于国家维度为空")
	}
}

func TestSourceByIDUnknown(t *testing.T) {
	if _, ok := SourceByID("nope"); ok {
		t.Error("未知 ID 应返回 false")
	}
}

func mustIPv4(t *testing.T, s string) uint32 {
	t.Helper()
	v, ok := parseIPv4ToUint32(s)
	if !ok {
		t.Fatalf("无法解析 %q", s)
	}
	return v
}

// TestCityCountryOverridesASNCountry 城市库带 ISO 码时它的 country 覆盖
// ASN 库给的那个。
//
// 这条是实测发现的:114.114.114.114 在 ip2asn 里归 US(按 BGP 路由归属,
// 该前缀确实被一个美国 AS 宣告),而 db-ip 定位到山东济南。保留 ASN 库的
// country 会产出 country=US / city=济南 这种自相矛盾的行 —— 那比两个库
// 口径不一致更糟,因为矛盾就在同一行里,用户第一眼就会看到且无法解释。
func TestCityCountryOverridesASNCountry(t *testing.T) {
	asn := New()
	// ASN 库把这段归到 US
	if err := asn.Load(strings.NewReader("1.0.0.0\t1.0.0.255\t65001\tUS\tSOME-US-AS\n")); err != nil {
		t.Fatalf("Load asn: %v", err)
	}
	// 城市库把同一段定位到 CN
	city := NewCityDB()
	if err := city.LoadDBIPCity(strings.NewReader(
		"1.0.0.0,1.0.0.255,AS,CN,Shandong,Jinan,36.6,117.0\n")); err != nil {
		t.Fatalf("Load city: %v", err)
	}

	e := NewEnricher(asn, nil, city)
	batch := []flow.Flow{{SrcIP: "1.0.0.5", DstIP: "192.0.2.1", Protocol: 6, DstPort: 443}}
	e.Apply(batch)
	f := batch[0]

	if f.SrcCountry != "CN" {
		t.Errorf("country 应取城市库的 CN(与 city 自洽), got %q", f.SrcCountry)
	}
	if f.SrcCity != "Jinan" {
		t.Errorf("city: want Jinan, got %q", f.SrcCity)
	}
	// ASN 与 org 仍来自 ASN 库 —— 那是它的强项
	if f.SrcASN != 65001 {
		t.Errorf("ASN 应来自 ASN 库, got %d", f.SrcASN)
	}
	if f.SrcOrg != "SOME-US-AS" {
		t.Errorf("org 应来自 ASN 库, got %q", f.SrcOrg)
	}
}
