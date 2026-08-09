package enrich

import (
	"fmt"
	"net"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// MMDB 是可选的 MaxMind GeoLite2 City 库,补上 ip2asn 没有的
// city / region / 经纬度。
//
// 为什么是可选叠加而不是替代 ip2asn:GeoLite2 需要注册 MaxMind 账号拿
// license key 才能下载,不能随发行包分发。ip2asn 免费无许可,所以它是
// 必备底线(ASN + country 总是有);mmdb 存在时才叠加城市维度。
//
// 两个库的分工刻意不重叠地覆盖同一字段:country 以 ip2asn 为准,
// mmdb 只补 region/city/经纬度。这样即使两边数据略有分歧,国家维度的
// 统计口径也是稳定的——否则同一批流量的 Top Country 会因为"有没有加载
// mmdb"而变化,那种差异没人能解释。
type MMDB struct {
	mu     sync.RWMutex
	reader *maxminddb.Reader
	path   string
}

// cityRecord 只解出用得到的字段。
//
// maxminddb 按结构体标签选择性解码,不声明的字段完全不解析——
// GeoLite2-City 的每条记录有几十个字段(时区、邮编、精度半径、
// 各语言的地名),全解出来是查表路径上纯粹的浪费。
type cityRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Subdivisions []struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

func NewMMDB() *MMDB { return &MMDB{} }

// Open 加载 mmdb 文件。
//
// 校验数据库类型:用户很容易下错文件(GeoLite2-ASN 与 GeoLite2-City
// 都是 .mmdb),而下错的后果是 city 永远为空却没有任何报错。
func (m *MMDB) Open(path string) error {
	r, err := maxminddb.Open(path)
	if err != nil {
		return fmt.Errorf("enrich: 打开 mmdb %s: %w", path, err)
	}

	dbType := r.Metadata.DatabaseType
	if dbType != "GeoLite2-City" && dbType != "GeoIP2-City" {
		r.Close()
		return fmt.Errorf("enrich: %s 的类型是 %q,需要 GeoLite2-City 或 GeoIP2-City"+
			"(ASN 与国家由 ip2asn 提供,这里只用来补城市与经纬度)", path, dbType)
	}

	m.mu.Lock()
	old := m.reader
	m.reader, m.path = r, path
	m.mu.Unlock()

	// 热替换时关掉旧的:用户上传新库后不该泄漏上一个 mmap。
	if old != nil {
		old.Close()
	}
	return nil
}

func (m *MMDB) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reader != nil {
		err := m.reader.Close()
		m.reader = nil
		return err
	}
	return nil
}

// Loaded 是否已加载。
func (m *MMDB) Loaded() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.reader != nil
}

// Info 返回库的元信息,供界面展示"城市维度是否可用、库有多新"。
func (m *MMDB) Info() (path string, buildEpoch uint, nodeCount uint, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.reader == nil {
		return "", 0, 0, false
	}
	md := m.reader.Metadata
	return m.path, md.BuildEpoch, md.NodeCount, true
}

// CityInfo 是 mmdb 查表结果。
type CityInfo struct {
	Region    string
	City      string
	Latitude  float64
	Longitude float64
}

// Lookup 查 city/region/经纬度。未加载或查不到返回零值。
func (m *MMDB) Lookup(ip net.IP) CityInfo {
	m.mu.RLock()
	r := m.reader
	m.mu.RUnlock()
	if r == nil {
		return CityInfo{}
	}

	var rec cityRecord
	if err := r.Lookup(ip, &rec); err != nil {
		return CityInfo{}
	}

	var out CityInfo
	// 英文名优先。不做多语言:界面上混着中英文城市名会让同一个城市
	// 在 Top City 里出现两行(比如 "Tokyo" 与 "東京"),那比统一用英文
	// 更难用。
	out.City = pickName(rec.City.Names)
	if len(rec.Subdivisions) > 0 {
		// 第一个 subdivision 是最大的行政区划(省/州)。
		sd := rec.Subdivisions[0]
		out.Region = sd.ISOCode
		if out.Region == "" {
			out.Region = pickName(sd.Names)
		}
	}
	out.Latitude = rec.Location.Latitude
	out.Longitude = rec.Location.Longitude
	return out
}

func pickName(names map[string]string) string {
	if names == nil {
		return ""
	}
	if v, ok := names["en"]; ok {
		return v
	}
	// 没有英文名时取任意一个:总比空着好,至少能看出是个地名。
	for _, v := range names {
		return v
	}
	return ""
}
