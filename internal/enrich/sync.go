package enrich

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 内置的在线同步源。
//
// 收录标准:许可清晰、**无需注册**、单文件可直接解析。需要点击同意
// 许可协议或申请 key 的(MaxMind GeoLite2)不内置自动拉取 —— 那样等于
// 替用户接受了他没读过的协议;那类库走界面上传。
//
// 每个源都标明**它能填哪些字段**,因为这直接决定界面上哪些视图可用,
// 而用户最常问的就是"我装了库为什么某一列还是空的"。

// SourceKind 决定同步下来的数据喂给哪个库。
type SourceKind string

const (
	// KindASN 填 asn / org / country(ISO)。
	KindASN SourceKind = "asn"
	// KindCity 填 country(ISO)/ region / city / 经纬度。
	KindCity SourceKind = "city"
)

// Source 是一个可同步的上游。
type Source struct {
	ID      string
	Name    string
	Kind    SourceKind
	License string
	// Fields 人读的"能填哪些字段"说明。
	Fields string
	// Note 归属口径与适用场景的提醒。
	Note string

	// url 生成函数。db-ip 的路径带年月,所以不是常量。
	url func(t time.Time) string
	// fallbackURL 主 URL 404 时的退路(db-ip 月初新文件未就位)。
	fallbackURL func(t time.Time) string
}

// URL 返回当前应该下载的地址。
func (s Source) URL() string { return s.url(time.Now()) }

// FallbackURL 返回退路地址;没有则为空。
func (s Source) FallbackURL() string {
	if s.fallbackURL == nil {
		return ""
	}
	return s.fallbackURL(time.Now())
}

// Sources 内置源列表。
var Sources = []Source{
	{
		ID: "iptoasn", Name: "iptoasn.com ip2asn",
		Kind: KindASN, License: "公共领域(基于 RouteViews)",
		Fields: "ASN、国家(ISO)、组织",
		Note:   "按 BGP 实际路由归属,与注册地可能不同;体积小、每日更新",
		url:    func(time.Time) string { return "https://iptoasn.com/data/ip2asn-v4.tsv.gz" },
	},
	{
		ID: "dbip-asn", Name: "DB-IP ASN Lite",
		Kind: KindASN, License: "CC BY 4.0(需在页面署名)",
		Fields:      "ASN、组织",
		Note:        "组织名比 iptoasn 规整(带公司全称);不含国家码",
		url:         dbipURL("dbip-asn-lite", "csv.gz"),
		fallbackURL: dbipURLPrevMonth("dbip-asn-lite", "csv.gz"),
	},
	{
		ID: "dbip-city", Name: "DB-IP City Lite",
		Kind: KindCity, License: "CC BY 4.0(需在页面署名)",
		Fields:      "国家(ISO)、省/州、城市、经纬度",
		Note:        "唯一免费且无需注册的城市库 —— 装上它 Top City 与地图才可用",
		url:         dbipURL("dbip-city-lite", "csv.gz"),
		fallbackURL: dbipURLPrevMonth("dbip-city-lite", "csv.gz"),
	},
}

func dbipURL(name, ext string) func(time.Time) string {
	return func(t time.Time) string {
		return fmt.Sprintf("https://download.db-ip.com/free/%s-%s.%s",
			name, t.Format("2006-01"), ext)
	}
}

// dbipURLPrevMonth 是上个月的文件。
//
// 必需而不是保险:db-ip 的新月份文件不是 1 号零点就位的,月初几天
// 拉当月的会 404。不处理这个,每个月头几天同步都会失败,而失败原因
// (404)完全指不到"等几天或用上个月的"。
func dbipURLPrevMonth(name, ext string) func(time.Time) string {
	return func(t time.Time) string {
		prev := t.AddDate(0, -1, 0)
		return fmt.Sprintf("https://download.db-ip.com/free/%s-%s.%s",
			name, prev.Format("2006-01"), ext)
	}
}

// SourceByID 查内置源。
func SourceByID(id string) (Source, bool) {
	for _, s := range Sources {
		if s.ID == id {
			return s, true
		}
	}
	return Source{}, false
}

// SyncStatus 同步状态,供界面轮询。
type SyncStatus struct {
	InProgress bool      `json:"in_progress"`
	SourceID   string    `json:"source_id"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Bytes      int64     `json:"bytes"`
	Entries    int       `json:"entries"`
	Err        string    `json:"error,omitempty"`
	UsedURL    string    `json:"used_url,omitempty"`
}

// Syncer 负责下载与加载。
type Syncer struct {
	dataDir string
	asn     *DB
	city    *CityDB

	mu     sync.RWMutex
	status SyncStatus
}

func NewSyncer(dataDir string, asn *DB, city *CityDB) *Syncer {
	return &Syncer{dataDir: dataDir, asn: asn, city: city}
}

func (s *Syncer) Status() SyncStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

// Sync 同步一个源。阻塞执行,调用方决定是否放后台。
//
// 流程刻意是"下载到临时文件 → 解析校验 → 原子替换 → 加载":
// 直接边下边解析的话,网络中断会留下一个半截的库并且已经生效了;
// 而直接覆盖正式文件的话,一个坏文件会毁掉原本能用的库 —— 用户点
// 同步的动机通常是"更新一下",不该因此失去已有能力。
func (s *Syncer) Sync(ctx context.Context, id string) error {
	src, ok := SourceByID(id)
	if !ok {
		return fmt.Errorf("enrich: 未知数据源 %q", id)
	}

	s.begin(id)

	tmp := filepath.Join(s.dataDir, "sync-"+id+".tmp")
	defer os.Remove(tmp)

	n, usedURL, err := s.download(ctx, src, tmp)
	if err != nil {
		s.finish(0, 0, usedURL, err)
		return err
	}

	entries, err := s.loadInto(src, tmp)
	if err != nil {
		s.finish(n, 0, usedURL, err)
		return err
	}

	// 解析成功才落到正式路径,重启后仍能直接加载。
	final := filepath.Join(s.dataDir, "enrich-"+id+datExt(src))
	if err := os.Rename(tmp, final); err != nil {
		// 替换失败不算致命:数据已经加载进内存并生效了,只是重启后
		// 要重新同步。明确说出来而不是静默,否则用户会困惑于
		// "为什么重启后又没了"。
		s.finish(n, entries, usedURL,
			fmt.Errorf("已生效但未能落盘(重启后需重新同步): %w", err))
		return nil
	}

	s.finish(n, entries, usedURL, nil)
	return nil
}

func datExt(src Source) string {
	if strings.HasSuffix(src.URL(), ".gz") {
		return ".gz"
	}
	return ".dat"
}

// download 下载到 path,主 URL 失败时试退路。
func (s *Syncer) download(ctx context.Context, src Source, path string) (int64, string, error) {
	urls := []string{src.URL()}
	if fb := src.FallbackURL(); fb != "" {
		urls = append(urls, fb)
	}

	var lastErr error
	for _, u := range urls {
		n, err := fetchTo(ctx, u, path)
		if err == nil {
			return n, u, nil
		}
		lastErr = err
	}
	return 0, "", fmt.Errorf("enrich: 下载 %s 失败: %w", src.Name, lastErr)
}

func fetchTo(ctx context.Context, url, path string) (int64, error) {
	// 超时给到 10 分钟:city 库有几十 MB,而这个功能常在带宽受限的
	// 机房里用。给太短会让本来能成的同步失败在网络慢上。
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "ntop2ban/enrich-sync")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	// 上限防止上游返回一个异常巨大的文件把磁盘写满。
	const maxSize = 1 << 30 // 1GB
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxSize))
	if err != nil {
		return n, err
	}
	if n == 0 {
		return 0, fmt.Errorf("下载到 0 字节")
	}
	return n, nil
}

// loadInto 按源类型解析并加载进对应的库。
func (s *Syncer) loadInto(src Source, path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(src.URL(), ".gz") || strings.HasSuffix(src.FallbackURL(), ".gz") {
		gz, gzErr := gzip.NewReader(f)
		if gzErr != nil {
			// 上游返回 HTML 错误页时也是 200,但不是 gzip。这个错误
			// 要说清楚,否则用户看到 "gzip: invalid header" 完全不知道
			// 发生了什么。
			return 0, fmt.Errorf("解压失败(上游可能返回了错误页而非数据文件): %w", gzErr)
		}
		defer gz.Close()
		r = gz
	}

	switch src.Kind {
	case KindASN:
		if src.ID == "dbip-asn" {
			if err := s.loadDBIPASN(r); err != nil {
				return 0, err
			}
		} else {
			if err := s.asn.Load(r); err != nil {
				return 0, err
			}
		}
		return s.asn.Size(), nil

	case KindCity:
		if err := s.city.LoadDBIPCity(r); err != nil {
			return 0, err
		}
		return s.city.Size(), nil
	}
	return 0, fmt.Errorf("enrich: 未知源类型 %q", src.Kind)
}

// loadDBIPASN 解析 db-ip ASN CSV:start,end,asn,"org"
//
// 转成 ip2asn 的内部形态复用同一套查表。country 留空 —— db-ip 的 ASN
// 库不含国家码,填一个假的比留空糟。
func (s *Syncer) loadDBIPASN(r io.Reader) error {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true

	entries := make([]entry, 0, 1<<19)
	intern := make(map[string]string, 1<<16)

	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(rec) < 4 {
			continue
		}
		start, ok1 := parseIPv4ToUint32(rec[0])
		end, ok2 := parseIPv4ToUint32(rec[1])
		if !ok1 || !ok2 {
			continue
		}
		asn, err := strconv.ParseUint(rec[2], 10, 32)
		if err != nil || asn == 0 {
			continue
		}
		entries = append(entries, entry{
			start: start, end: end, asn: uint32(asn),
			org: internString(intern, rec[3]),
		})
	}
	if len(entries) == 0 {
		return fmt.Errorf("enrich: db-ip ASN 数据为空或格式不符(期望 4 列 CSV)")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].start < entries[j].start })
	s.asn.replace(entries)
	return nil
}

func (s *Syncer) begin(id string) {
	s.mu.Lock()
	s.status = SyncStatus{InProgress: true, SourceID: id, StartedAt: time.Now()}
	s.mu.Unlock()
}

func (s *Syncer) finish(bytes int64, entries int, usedURL string, err error) {
	s.mu.Lock()
	s.status.InProgress = false
	s.status.FinishedAt = time.Now()
	s.status.Bytes = bytes
	s.status.Entries = entries
	s.status.UsedURL = usedURL
	if err != nil {
		s.status.Err = err.Error()
	} else {
		s.status.Err = ""
	}
	s.mu.Unlock()
}

// LoadCached 启动时加载之前同步过的库。
//
// 让同步过一次的库在重启后仍然生效 —— 否则每次重启都要重新点一遍同步,
// 而用户不会觉得那是"正常操作"。
func (s *Syncer) LoadCached() []string {
	var loaded []string
	for _, src := range Sources {
		path := filepath.Join(s.dataDir, "enrich-"+src.ID+datExt(src))
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if _, err := s.loadInto(src, path); err != nil {
			continue
		}
		loaded = append(loaded, src.Name)
	}
	return loaded
}
