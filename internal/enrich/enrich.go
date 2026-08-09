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
}

func NewEnricher(asnDB *DB, mmdb *MMDB) *Enricher {
	if asnDB == nil {
		asnDB = New()
	}
	if mmdb == nil {
		mmdb = NewMMDB()
	}
	return &Enricher{asn: asnDB, mmdb: mmdb}
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

		// 城市维度只有加载了 mmdb 才有。没加载时这些字段保持为空,
		// 界面上对应视图不显示——而不是编一个值出来。
		if e.mmdb.Loaded() {
			if src := net.ParseIP(f.SrcIP); src != nil {
				c := e.mmdb.Lookup(src)
				f.SrcRegion, f.SrcCity = c.Region, c.City
			}
			if dst := net.ParseIP(f.DstIP); dst != nil {
				c := e.mmdb.Lookup(dst)
				f.DstRegion, f.DstCity = c.Region, c.City
			}
		}

		f.Application = Classify(f.Protocol, f.SrcPort, f.DstPort)
	}
}
