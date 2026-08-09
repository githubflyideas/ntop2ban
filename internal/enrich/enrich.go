package enrich

import (
	"net"

	"github.com/githubflyideas/ntop2ban/internal/flow"
)

// Enricher 把 ASN/国家/组织/城市与应用分类打到 flow 上。
//
// 两个数据源分工:ip2asn 是必备底线(ASN + country + org),mmdb 可选
// 叠加(region + city + 经纬度)。country 以 ip2asn 为准,mmdb 不覆盖它——
// 否则同一批流量的 Top Country 会因为"有没有加载 mmdb"而变化,
// 那种差异没人能解释。
type Enricher struct {
	asn  *DB
	mmdb *MMDB
	city *CityDB
}

func NewEnricher(asnDB *DB, mmdb *MMDB, city *CityDB) *Enricher {
	if asnDB == nil {
		asnDB = New()
	}
	if mmdb == nil {
		mmdb = NewMMDB()
	}
	if city == nil {
		city = NewCityDB()
	}
	return &Enricher{asn: asnDB, mmdb: mmdb, city: city}
}

// Apply 就地富化一批 flow。
//
// 批量而不是逐条:采集侧本来就按聚合窗口分批,而批量让查表的 RLock
// 只取一次(见 lookupBatch)。逐条加锁在高流量下是可测量的开销。
func (e *Enricher) Apply(batch []flow.Flow) {
	for i := range batch {
		f := &batch[i]

		if src := net.ParseIP(f.SrcIP); src != nil {
			info := e.asn.Lookup(src)
			f.SrcASN, f.SrcCountry, f.SrcOrg = info.ASN, info.Country, info.Org
		}
		if dst := net.ParseIP(f.DstIP); dst != nil {
			info := e.asn.Lookup(dst)
			f.DstASN, f.DstCountry, f.DstOrg = info.ASN, info.Country, info.Org
		}

		// 城市维度。两个来源:mmdb(MaxMind,精度最高)与 CityDB
		// (db-ip CSV 或纯真文本,可在线同步)。mmdb 优先。
		//
		// 都没加载时这些字段保持为空,界面上对应视图不显示 ——
		// 而不是编一个值出来。
		switch {
		case e.mmdb.Loaded():
			if src := net.ParseIP(f.SrcIP); src != nil {
				c := e.mmdb.Lookup(src)
				f.SrcRegion, f.SrcCity = c.Region, c.City
			}
			if dst := net.ParseIP(f.DstIP); dst != nil {
				c := e.mmdb.Lookup(dst)
				f.DstRegion, f.DstCity = c.Region, c.City
			}
		case e.city.Loaded():
			// 城市库带 ISO 国家码时,**它的 country 覆盖 ASN 库给的那个**。
			//
			// 这与"优先级固定"的初衷不冲突,是对它的修正:验证时发现
			// 114.114.114.114 在 ip2asn 里归 US(那是按 BGP 路由归属,
			// 该前缀确实被一个美国 AS 宣告),而 db-ip 定位到山东济南。
			// 保留 ASN 库的 country 会产出 country=US / city=济南 这种
			// 自相矛盾的行 —— 那比两个库口径不一致更糟,因为矛盾就在
			// 同一行里,用户第一眼就会看到并且无法解释。
			//
			// 取城市库的 country 让 country/region/city 三者始终来自
			// 同一个源、自洽;ASN 与 org 仍然来自 ASN 库(那是它的强项)。
			if v4 := ipv4Key(f.SrcIP); v4 != 0 {
				c := e.city.Lookup(v4)
				f.SrcRegion, f.SrcCity = c.Region, c.City
				if c.Country != "" {
					f.SrcCountry = c.Country
				}
			}
			if v4 := ipv4Key(f.DstIP); v4 != 0 {
				c := e.city.Lookup(v4)
				f.DstRegion, f.DstCity = c.Region, c.City
				if c.Country != "" {
					f.DstCountry = c.Country
				}
			}
		}

		f.Application = Classify(f.Protocol, f.SrcPort, f.DstPort)
	}
}

// ipv4Key 把点分十进制转成 uint32 供 CityDB 查表。非 IPv4 返回 0。
func ipv4Key(s string) uint32 {
	v, ok := parseIPv4ToUint32(s)
	if !ok {
		return 0
	}
	return v
}
