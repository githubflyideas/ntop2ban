// Package enrich 是写入时富化:给每条 flow 打上 ASN、国家、组织、
// 应用分类。
//
// 为什么在写入时做而不是查询时 JOIN(技术设计 §8.1、§34.5):亿级 flow
// 表与 GeoIP 表实时 JOIN 在单机上不可行。代价是 GeoIP 库更新后历史数据
// 保持当时的快照——这是想要的行为:历史应该反映当时的归属,一个 IP
// 去年属于 A 公司今年属于 B 公司,去年的流量不该被改写成 B 的。
//
// 数据源是 iptoasn.com 的 ip2asn TSV:免费、无许可限制、无需注册。
// 它只有 ASN + country + org 三样,**没有 city/region/经纬度**,
// 所以 Top City 与 Geo Map 做不了。flow 表里那几列保留但恒为空,
// 将来接 MaxMind mmdb 就自动有值,不需要迁移。
package enrich

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// entry 是一条 ip2asn 记录。
//
// 起止地址用 uint32 而不是 net.IP:查表是最热的路径(每条 flow 两次),
// 整数比较比 bytes.Compare 快一个数量级,而且二分查找需要有序的可比较值。
type entry struct {
	start   uint32
	end     uint32
	asn     uint32
	country string
	org     string
}

// DB 是 ip2asn 前缀库。
//
// 内部是按起始地址排序的数组 + 二分查找,不是 trie:ip2asn v4 大约
// 50 万条记录,二分是 19 次比较,而 trie 要 32 层且每层一次指针跳转
// (cache miss)。数组还顺带让整个库是一块连续内存,GC 压力小得多。
type DB struct {
	mu      sync.RWMutex
	entries []entry
	// countries/orgs 做字符串去重(interning)。50 万条记录里国家只有
	// 两百多个、org 有几万个重复,不去重的话同一个字符串被复制上万次。
	loaded bool
}

// New 返回一个空库。没加载数据时富化是空操作,不报错——ip2asn 库是
// 可选的,没有它 flow 仍然该被采集与存储,只是缺 ASN/国家维度。
func New() *DB { return &DB{} }

// LoadFile 从 ip2asn TSV 加载。支持 .gz(iptoasn.com 提供的就是 gz)。
//
// TSV 格式:range_start \t range_end \t AS_number \t country_code \t AS_description
func (d *DB) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("enrich: 打开 %s: %w", path, err)
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("enrich: 解压 %s: %w", path, err)
		}
		defer gz.Close()
		r = gz
	}
	return d.Load(r)
}

// Load 从 reader 加载 TSV。
func (d *DB) Load(r io.Reader) error {
	entries := make([]entry, 0, 512*1024)
	intern := make(map[string]string, 64*1024)

	sc := bufio.NewScanner(r)
	// ip2asn 的 org 字段可以很长(某些 AS 描述带一长串公司名)。
	// 默认 64KB 的 buffer 够用,但显式放大避免个别超长行让整个加载失败。
	sc.Buffer(make([]byte, 0, 256*1024), 1024*1024)

	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		if text == "" || text[0] == '#' {
			continue
		}
		fields := strings.Split(text, "\t")
		if len(fields) < 5 {
			// 跳过畸形行而不是整个加载失败:一个上游数据问题不该让
			// 富化完全不可用,那样代价大得多。
			continue
		}

		start, ok1 := parseIPv4ToUint32(fields[0])
		end, ok2 := parseIPv4ToUint32(fields[1])
		if !ok1 || !ok2 {
			continue
		}
		asn, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			continue
		}
		// ASN 0 是 "not routed" 的占位记录,org 写的是
		// "Not routed"。留着会让 Top ASN 里出现一个巨大的 AS0,
		// 那不是一个真实的自治系统。
		if asn == 0 {
			continue
		}

		entries = append(entries, entry{
			start:   start,
			end:     end,
			asn:     uint32(asn),
			country: internString(intern, fields[3]),
			org:     internString(intern, fields[4]),
		})
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("enrich: 读取 ip2asn: %w", err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("enrich: ip2asn 数据为空或格式不符(期望 5 列 TSV)")
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].start < entries[j].start })

	d.mu.Lock()
	d.entries = entries
	d.loaded = true
	d.mu.Unlock()
	return nil
}

// Loaded 表示是否已加载数据。
func (d *DB) Loaded() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.loaded
}

// Size 返回记录条数,供界面展示"富化库有多大"。
func (d *DB) Size() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.entries)
}

// Info 是一次查表的结果。
type Info struct {
	ASN     uint32
	Country string
	Org     string
}

// Lookup 查一个 IP 的 ASN/国家/组织。查不到返回零值。
//
// 私有地址与保留地址不在 ip2asn 里,所以内网流量的这几个字段天然为空。
// 这是对的:给内网 IP 编一个国家出来只会误导。
func (d *DB) Lookup(ip net.IP) Info {
	v4 := ip.To4()
	if v4 == nil {
		// IPv6 不在当前 ip2asn v4 库范围内。返回零值而不是报错:
		// IPv6 流量仍该被采集,只是没有 ASN 维度。
		return Info{}
	}
	key := binary.BigEndian.Uint32(v4)

	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.entries) == 0 {
		return Info{}
	}

	// 找最后一个 start <= key 的条目。
	i := sort.Search(len(d.entries), func(i int) bool {
		return d.entries[i].start > key
	})
	if i == 0 {
		return Info{}
	}
	e := d.entries[i-1]
	// 必须验证上界:相邻条目之间可能有空洞(未分配地址段),
	// 只看 start 会把空洞里的 IP 错归到前一个 AS。
	if key > e.end {
		return Info{}
	}
	return Info{ASN: e.asn, Country: e.country, Org: e.org}
}

// parseIPv4ToUint32 解析点分十进制。
//
// 自己解析而不是 net.ParseIP + To4:加载时要处理 50 万行,
// net.ParseIP 会为每行分配一个 16 字节切片,这里零分配。
func parseIPv4ToUint32(s string) (uint32, bool) {
	var v uint32
	var octet uint32
	var digits, dots int

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			octet = octet*10 + uint32(c-'0')
			if octet > 255 {
				return 0, false
			}
			digits++
		case c == '.':
			if digits == 0 || dots == 3 {
				return 0, false
			}
			v = v<<8 | octet
			octet, digits = 0, 0
			dots++
		default:
			return 0, false
		}
	}
	if dots != 3 || digits == 0 {
		return 0, false
	}
	return v<<8 | octet, true
}

func internString(pool map[string]string, s string) string {
	if v, ok := pool[s]; ok {
		return v
	}
	pool[s] = s
	return s
}
