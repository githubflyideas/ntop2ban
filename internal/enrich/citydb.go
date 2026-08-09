package enrich

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// CityDB 是纯 CSV 形态的城市库,与 mmdb 并列的另一条路。
//
// 存在理由:MaxMind GeoLite2 需要注册账号、同意许可、拿 license key 才能
// 下载,不能内置自动同步。db-ip 的 city-lite 是 CSV、免费、无需注册,
// 因此它是唯一能做到"点一下同步就有城市维度"的源 —— 这直接决定了
// Top City 与 Geo Map 能不能作为默认可用的功能,而不是"你自己去注册"。
//
// 与 MMDB 的分工:两者都提供 city/region/经纬度,谁先加载谁生效
// (Enricher 里 mmdb 优先,因为它精度更高)。数据结构刻意与 ip2asn 的 DB
// 一致 —— 排序数组 + 二分,理由见 ip2asn.go。
type CityDB struct {
	mu      sync.RWMutex
	entries []cityEntry
	loaded  bool
	source  string
}

type cityEntry struct {
	start   uint32
	end     uint32
	country string // ISO alpha-2;仅 db-ip 这类带 ISO 码的源填
	region  string
	city    string
	lat     float32
	lon     float32
}

func NewCityDB() *CityDB { return &CityDB{} }

func (d *CityDB) Loaded() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.loaded
}

func (d *CityDB) Size() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.entries)
}

// Source 返回数据来自哪个源,供界面标注归属口径。
func (d *CityDB) Source() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.source
}

// CityInfo 复用 mmdb.go 里的类型,加上 country —— db-ip 的 city 库自带
// ISO 国家码,而 mmdb 那边 country 交给 ip2asn 负责,所以这里多一个字段。
type CityLookup struct {
	Country string
	Region  string
	City    string
	Lat     float32
	Lon     float32
}

// LoadDBIPCity 解析 db-ip city-lite CSV。
//
// 格式(无表头):
//
//	start_ip,end_ip,continent,country,region,city,latitude,longitude
//	1.0.0.0,1.0.0.255,OC,AU,Queensland,"South Brisbane",-27.4767,153.017
//
// 用 encoding/csv 而不是 strings.Split:city 字段带引号且可能含逗号
// ("South Brisbane" 这种还好,但 "Washington, D.C." 会把手写的分割逻辑
// 直接切错),而切错的后果是经纬度串位、城市名被截断。
func (d *CityDB) LoadDBIPCity(r io.Reader) error {
	cr := csv.NewReader(bufio.NewReaderSize(r, 1<<20))
	cr.FieldsPerRecord = -1 // 行宽不一致时不报错,由下面自己校验
	cr.ReuseRecord = true

	entries := make([]cityEntry, 0, 1<<20)
	intern := make(map[string]string, 1<<16)

	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// 单行畸形跳过而不是整个失败:一个上游数据问题不该让富化
			// 完全不可用。但要区分"这一行有问题"与"整个文件不是这个格式"
			// —— 后者由末尾的 len(entries)==0 判断。
			continue
		}
		if len(rec) < 8 {
			continue
		}

		start, ok1 := parseIPv4ToUint32(rec[0])
		end, ok2 := parseIPv4ToUint32(rec[1])
		if !ok1 || !ok2 {
			continue
		}

		country := rec[3]
		// ZZ 是 db-ip 表示"未知"的占位。留着会让 Top Country 里出现一个
		// 叫 ZZ 的巨大条目,那不是一个国家。
		if country == "ZZ" {
			continue
		}

		lat, _ := strconv.ParseFloat(rec[6], 32)
		lon, _ := strconv.ParseFloat(rec[7], 32)

		entries = append(entries, cityEntry{
			start:   start,
			end:     end,
			country: internString(intern, country),
			region:  internString(intern, rec[4]),
			city:    internString(intern, rec[5]),
			lat:     float32(lat),
			lon:     float32(lon),
		})
	}

	if len(entries) == 0 {
		return fmt.Errorf("enrich: db-ip city 数据为空或格式不符" +
			"(期望 8 列 CSV:start,end,continent,country,region,city,lat,lon)")
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].start < entries[j].start })

	d.mu.Lock()
	d.entries, d.loaded, d.source = entries, true, "db-ip city-lite"
	d.mu.Unlock()
	return nil
}

// LoadQQWryText 解析纯真(qqwry)导出的文本形态。
//
// 纯真原始的 qqwry.dat 是自定义二进制格式且是 GBK 编码,解析它需要一套
// 专门的索引寻址逻辑。这里接受的是它常见的文本导出形态:
//
//	start_ip end_ip 地区 运营商
//	1.0.1.0 1.0.3.255 福建省福州市 电信
//
// **纯真不填 country。** 它的输出是自由文本中文串("福建省福州市"),
// 不是 ISO 国家码。country 那一列的口径必须稳定,否则同一批流量的
// Top Country 会因为"装了哪个库"而变化,而那种差异没人能解释。
// 所以纯真只填 region/city/isp 当文本用 —— 国内 IP 的城市与运营商
// 粒度它确实比 db-ip 好,这是它的价值所在。
func (d *CityDB) LoadQQWryText(r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 256*1024), 1<<20)

	entries := make([]cityEntry, 0, 1<<19)
	intern := make(map[string]string, 1<<16)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		start, ok1 := parseIPv4ToUint32(fields[0])
		end, ok2 := parseIPv4ToUint32(fields[1])
		if !ok1 || !ok2 {
			continue
		}

		region := fields[2]
		city := ""
		// "福建省福州市" 这种连写的形态里,省与市粘在一起。拆开让
		// region/city 两个维度都能分组 —— 否则 Top Region 与 Top City
		// 会显示成完全一样的东西。
		if i := strings.Index(region, "省"); i > 0 && i+3 <= len(region) {
			city = region[i+3:]
			region = region[:i+3]
		} else if i := strings.Index(region, "市"); i > 0 {
			city = region[:i+3]
		}

		entries = append(entries, cityEntry{
			start:  start,
			end:    end,
			region: internString(intern, region),
			city:   internString(intern, city),
		})
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("enrich: 读取纯真数据: %w", err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("enrich: 纯真数据为空或格式不符(期望 `起始IP 结束IP 地区 运营商`)")
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].start < entries[j].start })

	d.mu.Lock()
	d.entries, d.loaded, d.source = entries, true, "纯真 qqwry"
	d.mu.Unlock()
	return nil
}

// Lookup 查一个 IPv4 的城市信息。查不到返回零值。
func (d *CityDB) Lookup(ipv4 uint32) CityLookup {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.entries) == 0 {
		return CityLookup{}
	}

	i := sort.Search(len(d.entries), func(i int) bool {
		return d.entries[i].start > ipv4
	})
	if i == 0 {
		return CityLookup{}
	}
	e := d.entries[i-1]
	// 必须验证上界:相邻条目之间有空洞(未分配地址段),只看 start
	// 会把空洞里的 IP 错归到前一条记录 —— 那会让某个城市凭空多出
	// 一堆不属于它的流量。
	if ipv4 > e.end {
		return CityLookup{}
	}
	return CityLookup{
		Country: e.country, Region: e.region, City: e.city,
		Lat: e.lat, Lon: e.lon,
	}
}

// newLineScanner 是带大缓冲的行扫描器。
//
// 默认 64KB 的 bufio.Scanner 会在个别超长行上直接失败(某些 AS
// 描述、某些 RIR 注释行很长),而那种失败会让整个加载中止。
func newLineScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 256*1024), 1<<20)
	return sc
}
