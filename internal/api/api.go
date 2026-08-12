// Package api 是 HTTP 层:认证、查询接口、Dashboard 页面。
//
// 所有查询接口都只接受 Query AST,不接受 SQL(技术设计 §29)。
// Dashboard 的每个卡片、Explorer 的每次下钻,都是一次 AST 请求 ——
// 同一个引擎服务所有视图,而不是给每种图表写一个专用 handler。
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/auth"
	"github.com/githubflyideas/ntop2ban/internal/enrich"
	"github.com/githubflyideas/ntop2ban/internal/query"
	"github.com/githubflyideas/ntop2ban/internal/store"
)

// Server 是 HTTP 服务。
type Server struct {
	st     *store.Store
	au     *auth.Auth
	asn    *enrich.DB
	mmdb   *enrich.MMDB
	city   *enrich.CityDB
	syncer *enrich.Syncer
	log    *log.Logger

	// queries 是保存查询的持久化(DataDir/queries.json)。
	queries *queryStore

	// DataDir 用于存放上传的 mmdb。
	DataDir string

	// Inputs 是当前启用的输入源描述,展示在界面顶部。
	Inputs []string
}

// Config 构造参数。
type Config struct {
	Store   *store.Store
	Auth    *auth.Auth
	ASN     *enrich.DB
	MMDB    *enrich.MMDB
	City    *enrich.CityDB
	Syncer  *enrich.Syncer
	Logger  *log.Logger
	DataDir string
	Inputs  []string
}

func New(cfg Config) *Server {
	lg := cfg.Logger
	if lg == nil {
		lg = log.Default()
	}
	return &Server{
		st: cfg.Store, au: cfg.Auth, asn: cfg.ASN, mmdb: cfg.MMDB,
		city: cfg.City, syncer: cfg.Syncer,
		log: lg, DataDir: cfg.DataDir, Inputs: cfg.Inputs,
		queries: newQueryStore(cfg.DataDir),
	}
}

// Routes 注册全部路由。
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)

	mux.HandleFunc("/", s.authed(s.handleIndex))

	// 嵌入的前端资源(ECharts、世界地图)。不走 authed,原因见 handleStatic。
	mux.HandleFunc("/static/", s.handleStatic)

	// 查询:唯一的数据入口。Dashboard 与 Explorer 都走它。
	mux.HandleFunc("/api/v1/query", s.authed(s.handleQuery))
	mux.HandleFunc("/api/v1/query/explain", s.authed(s.handleExplain))
	mux.HandleFunc("/api/v1/query/fields", s.authed(s.handleFields))

	// 保存查询。存的是界面上的选择而不是编译好的 AST,理由见 savedquery.go。
	mux.HandleFunc("/api/v1/queries", s.authed(s.handleQueriesList))
	mux.HandleFunc("/api/v1/queries/save", s.authed(s.handleQuerySave))
	mux.HandleFunc("/api/v1/queries/delete", s.authed(s.handleQueryDelete))

	mux.HandleFunc("/api/v1/overview", s.authed(s.handleOverview))
	mux.HandleFunc("/api/v1/enrich/mmdb", s.authed(s.handleMMDBUpload))
	mux.HandleFunc("/api/v1/enrich/sources", s.authed(s.handleEnrichSources))
	mux.HandleFunc("/api/v1/enrich/sync", s.authed(s.handleEnrichSync))
}

// authed 包装需要登录的 handler。
func (s *Server) authed(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := s.au.User(r)
		if !ok {
			// API 请求返回 401,页面请求跳登录页。混在一起会让前端
			// 拿到一大段 HTML 当 JSON 解析,报出莫名其妙的错误。
			if isAPI(r.URL.Path) {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "未登录"})
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r, user)
	}
}

func isAPI(p string) bool { return len(p) >= 5 && p[:5] == "/api/" }

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(loginHTML))
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误"})
		return
	}
	if !s.au.Check(body.Username, body.Password) {
		// 不区分"用户不存在"与"密码错误",避免枚举用户名。
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "用户名或密码错误"})
		return
	}
	s.au.Issue(w, body.Username)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.au.Revoke(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request, user string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

// handleQuery 是所有数据视图的入口。
func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request, user string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var q query.Query
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "AST 格式错误: " + err.Error()})
		return
	}

	res, err := s.st.Query(r.Context(), q)
	if err != nil {
		// 校验错误的信息是给用户看的(界面直接展示),所以按 400 返回
		// 而不是笼统的 500 —— 区分"你的查询有问题"与"我这边出错了"。
		status := http.StatusBadRequest
		if errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		}
		writeJSON(w, status, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request, user string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var q query.Query
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "AST 格式错误: " + err.Error()})
		return
	}
	stats, err := s.st.Explain(q)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// handleFields 返回可用字段与运算符。
//
// 界面从这里拿字段列表而不是硬编码一份:硬编码那份迟早与后端不同步,
// 表现为界面上能选的字段查询时报"不支持"。
func (s *Server) handleFields(w http.ResponseWriter, r *http.Request, user string) {
	info := query.Fields()

	// 城市维度需要 mmdb 或城市 CSV 库任一。都没有时从可用列表里去掉,
	// 界面就不会给出一个查出来永远是空的选项 —— 那比不显示更让人困惑。
	if !s.cityAvailable() {
		info.Groupable = withoutCity(info.Groupable)
		filtered := info.Filterable[:0]
		for _, f := range info.Filterable {
			if !isCityField(f.Name) {
				filtered = append(filtered, f)
			}
		}
		info.Filterable = filtered
	}
	writeJSON(w, http.StatusOK, info)
}

// cityAvailable 城市维度是否可用。
func (s *Server) cityAvailable() bool {
	return s.mmdb.Loaded() || s.city.Loaded()
}

func isCityField(name string) bool {
	switch name {
	case "src_city", "dst_city", "src_region", "dst_region":
		return true
	}
	return false
}

func withoutCity(names []string) []string {
	out := names[:0]
	for _, n := range names {
		if !isCityField(n) {
			out = append(out, n)
		}
	}
	return out
}

// handleOverview 返回顶部状态:存储、输入源、富化库。
func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request, user string) {
	out := map[string]any{
		"user":   user,
		"inputs": s.Inputs,
	}

	if st, err := s.st.Stats(r.Context()); err == nil {
		out["storage"] = map[string]any{
			"rows":            st.TotalRows,
			"oldest":          st.Oldest,
			"newest":          st.Newest,
			"compressed_gb":   round2(st.CompressedGB),
			"uncompressed_gb": round2(st.UncompressedGB),
		}
	}

	enrichInfo := map[string]any{
		"asn_loaded":   s.asn.Loaded(),
		"asn_entries":  s.asn.Size(),
		"mmdb_loaded":  s.mmdb.Loaded(),
		"city_loaded":  s.city.Loaded(),
		"city_entries": s.city.Size(),
		"city_source":  s.city.Source(),
		"city_ready":   s.cityAvailable(),
	}
	if path, epoch, nodes, ok := s.mmdb.Info(); ok {
		enrichInfo["mmdb_path"] = filepath.Base(path)
		enrichInfo["mmdb_build"] = time.Unix(int64(epoch), 0).Format("2006-01-02")
		enrichInfo["mmdb_nodes"] = nodes
	}
	out["enrich"] = enrichInfo

	writeJSON(w, http.StatusOK, out)
}

// maxMMDBSize 上传上限。GeoLite2-City 解压后约 70MB,给到 256MB 足够,
// 同时防止一个巨大的文件把磁盘写满。
const maxMMDBSize = 256 << 20

// handleMMDBUpload 接收用户上传的 GeoLite2-City mmdb。
//
// 为什么要支持上传:GeoLite2 需要注册 MaxMind 账号拿 license key,
// 不能随发行包分发。让用户在界面上传比要求他登录服务器 scp 到某个
// 特定路径再重启要顺畅得多,而且上传后立即生效、不用重启。
func (s *Server) handleMMDBUpload(w http.ResponseWriter, r *http.Request, user string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "解析上传失败: " + err.Error()})
		return
	}
	file, hdr, err := r.FormFile("mmdb")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "缺少 mmdb 文件字段"})
		return
	}
	defer file.Close()

	if hdr.Size > maxMMDBSize {
		writeJSON(w, http.StatusRequestEntityTooLarge,
			map[string]any{"error": fmt.Sprintf("文件 %.1f MB 超过上限 %d MB",
				float64(hdr.Size)/(1<<20), maxMMDBSize>>20)})
		return
	}

	// 先写到临时文件再校验,校验通过才替换正式文件。
	//
	// 这个顺序很重要:直接覆盖正式文件的话,上传一个坏文件会把原本
	// 能用的库弄坏 —— 而用户上传的动机通常是"更新一下",不该因此
	// 失去已有的能力。
	if err := os.MkdirAll(s.DataDir, 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	tmp := filepath.Join(s.DataDir, "geoip.mmdb.uploading")
	final := filepath.Join(s.DataDir, "geoip.mmdb")

	dst, err := os.Create(tmp)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	written, copyErr := copyLimited(dst, file, maxMMDBSize)
	closeErr := dst.Close()
	if copyErr != nil || closeErr != nil {
		os.Remove(tmp)
		err := copyErr
		if err == nil {
			err = closeErr
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "写入失败: " + err.Error()})
		return
	}

	// 用一个临时 MMDB 实例校验,不动正在服务的那个。
	probe := enrich.NewMMDB()
	if err := probe.Open(tmp); err != nil {
		os.Remove(tmp)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	probe.Close()

	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "替换失败: " + err.Error()})
		return
	}

	// 热加载:上传后立即生效,不需要重启。
	if err := s.mmdb.Open(final); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "加载失败: " + err.Error()})
		return
	}

	s.log.Printf("[api] %s 上传了 GeoIP 库 %s(%.1f MB),已生效",
		user, hdr.Filename, float64(written)/(1<<20))

	path, epoch, nodes, _ := s.mmdb.Info()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"path":       filepath.Base(path),
		"build_date": time.Unix(int64(epoch), 0).Format("2006-01-02"),
		"nodes":      nodes,
		"note":       "城市与区域维度已可用;历史数据保持当时的快照,不会被回填",
	})
}

// handleEnrichSources 返回内置源列表与当前同步状态。
//
// 每个源都带上"能填哪些字段""许可""归属口径"三项 —— 用户最常问的是
// "我装了库为什么某一列还是空的",这三项就是界面上回答它的依据。
func (s *Server) handleEnrichSources(w http.ResponseWriter, r *http.Request, user string) {
	out := make([]map[string]any, 0, len(enrich.Sources))
	for _, src := range enrich.Sources {
		out = append(out, map[string]any{
			"id": src.ID, "name": src.Name, "kind": string(src.Kind),
			"fields": src.Fields, "license": src.License, "note": src.Note,
			"url": src.URL(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sources": out,
		"status":  s.syncer.Status(),
	})
}

// handleEnrichSync 触发一次同步。
//
// 放后台跑并让界面轮询状态,而不是同步等待:city 库有几十 MB,在带宽
// 受限的机房里可能要几分钟,而反向代理通常在 60 秒就切断连接 ——
// 那时用户看到 504 却不知道后台其实还在下。
func (s *Server) handleEnrichSync(w http.ResponseWriter, r *http.Request, user string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误"})
		return
	}
	if _, ok := enrich.SourceByID(body.ID); !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "未知数据源 " + body.ID})
		return
	}
	if st := s.syncer.Status(); st.InProgress {
		// 同时跑两个同步会让两者争抢同一个库的写锁,而且结果取决于
		// 谁先完成 —— 明确拒绝比让用户猜好。
		writeJSON(w, http.StatusConflict,
			map[string]any{"error": "已有同步在进行中(" + st.SourceID + "),请等它完成"})
		return
	}

	go func() {
		// 不用请求的 context:请求早就返回了,用它会让同步立刻被取消。
		if err := s.syncer.Sync(context.Background(), body.ID); err != nil {
			s.log.Printf("[enrich] 同步 %s 失败: %v", body.ID, err)
		} else {
			st := s.syncer.Status()
			s.log.Printf("[enrich] 同步 %s 完成:%d 条记录,%.1f MB",
				body.ID, st.Entries, float64(st.Bytes)/(1<<20))
		}
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok": true, "note": "同步已在后台开始,可轮询 /api/v1/enrich/sources 看进度",
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func round2(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}
