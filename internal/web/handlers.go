package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strconv"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/knock"
	"github.com/githubflyideas/ntop2ban/internal/model"
	"github.com/githubflyideas/ntop2ban/internal/probe"
	"github.com/githubflyideas/ntop2ban/internal/storage/sqlite"
)

// Store 是 web 层需要的全部存储能力。
//
// 用一个接口把 *sqlite.Store 需要的方法列出来,而不是直接依赖具体类型:
// 让 handler 的测试可以塞进假实现,不必开真库。
type Store interface {
	Append(ctx context.Context, batch []model.Flow) error
	Query(ctx context.Context, q model.Query) (model.Result, error)
	Stats(ctx context.Context) (model.StorageStats, error)

	Authenticate(ctx context.Context, username, password string) (sqlite.User, error)
	ListUsers(ctx context.Context) ([]sqlite.User, error)
	CreateUser(ctx context.Context, username, password, role string) error
	WriteAudit(ctx context.Context, actor, action, target, detail string) error
	ListAudit(ctx context.Context, limit int) ([]sqlite.AuditEntry, error)

	SubmitSequence(ctx context.Context, seq knock.Sequence, requestedBy, note string) (int64, error)
	ApproveSequence(ctx context.Context, id int64, approvedBy string) error
	RejectSequence(ctx context.Context, id int64, approvedBy, note string) error
	ActiveSequence(ctx context.Context) (sqlite.SequenceRecord, error)
	ListSequences(ctx context.Context, limit int) ([]sqlite.SequenceRecord, error)
	ListGrants(ctx context.Context, limit int) ([]sqlite.GrantRecord, error)

	ProbeTargets(ctx context.Context) ([]string, error)
	ProbeRounds(ctx context.Context, target string, since, until time.Time, limit int) ([]probe.Round, error)
}

// Handler 是 ntop2ban 的 Web 层。
type Handler struct {
	store  Store
	apiKey string
	sess   *sessions

	// CookieSecure 在 TLS 后面部署时置为 true。
	CookieSecure bool

	// DataSourceLabel 当前观测数据源的说明(XDP native / generic /
	// AF_PACKET)。展示在界面上——性能差一个数量级,运维需要知道自己
	// 在哪一级上,否则会把"统计偏低"误判成"流量真的少"。
	DataSourceLabel string

	// ProbeHint 非空时表示探测未启用,内容是给用户的具体指引
	// (去哪个文件加目标)。界面据此在探测页显示提示而不是空白图表——
	// 空白图表让人以为程序坏了,明确的提示才能让人知道下一步做什么。
	ProbeHint string

	// OnSequenceApproved 序列审批通过后的回调,用于热更新 XDP 匹配 map
	// 与状态机。为空表示不热更新(需要重启才生效)。
	OnSequenceApproved func(seq knock.Sequence, seqID int64)
}

func NewHandler(store Store, apiKey string) *Handler {
	h := &Handler{store: store, apiKey: apiKey, sess: newSessions()}
	go h.sweepLoop()
	return h
}

func (h *Handler) sweepLoop() {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for range t.C {
		h.sess.sweep()
	}
}

// RegisterRoutes 注册全部路由。
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// 采样上报:走 X-API-Key,不需要会话。保留这个端点是为了兼容
	// 外部采样器(xdp-ban 的 xdp-sampler)——内置采样直接写库,不经过 HTTP。
	mux.HandleFunc("/api/v1/samples", h.receiveSamples)

	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc("/logout", h.handleLogout)

	mux.HandleFunc("/", h.requireAuth(h.handleIndex))

	mux.HandleFunc("/api/v1/overview", h.requireAuth(h.apiOverview))
	mux.HandleFunc("/api/v1/flows/top", h.requireAuth(h.apiTopFlows))
	mux.HandleFunc("/api/v1/probe/targets", h.requireAuth(h.apiProbeTargets))
	mux.HandleFunc("/api/v1/probe/rounds", h.requireAuth(h.apiProbeRounds))
	mux.HandleFunc("/api/v1/knock/sequences", h.requireAuth(h.apiKnockSequences))
	mux.HandleFunc("/api/v1/knock/grants", h.requireAuth(h.apiKnockGrants))
	mux.HandleFunc("/api/v1/audit", h.requireAuth(h.apiAudit))

	// 变更类操作限 admin
	mux.HandleFunc("/api/v1/knock/submit", h.requireAdmin(h.apiKnockSubmit))
	mux.HandleFunc("/api/v1/knock/approve", h.requireAdmin(h.apiKnockApprove))
	mux.HandleFunc("/api/v1/knock/reject", h.requireAdmin(h.apiKnockReject))
	mux.HandleFunc("/api/v1/users", h.requireAdmin(h.apiUsers))
}

func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request, u sessionEntry) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

// apiOverview 首页概览:存储状态、当前数据源、生效的敲门序列。
func (h *Handler) apiOverview(w http.ResponseWriter, r *http.Request, u sessionEntry) {
	ctx := r.Context()

	out := map[string]any{
		"user":        u.username,
		"role":        u.role,
		"data_source": h.DataSourceLabel,
		"probe_hint":  h.ProbeHint,
	}

	if stats, err := h.store.Stats(ctx); err == nil {
		out["storage"] = map[string]any{
			"backend":    stats.Backend,
			"total_rows": stats.TotalRows,
			"oldest":     unixOrZero(stats.OldestRecord),
			"newest":     unixOrZero(stats.NewestRecord),
		}
	}

	if rec, err := h.store.ActiveSequence(ctx); err == nil {
		out["knock"] = map[string]any{
			"id":        rec.ID,
			"steps":     stepsJSON(rec.Sequence),
			"window":    rec.Sequence.Window.String(),
			"open_port": rec.Sequence.OpenPort,
			"open_for":  rec.Sequence.OpenFor.String(),
			// 客户端命令直接给出来,用户复制即可敲门,不用自己拼
			"client_script": rec.Sequence.ClientScript(hostOf(r)),
		}
	} else {
		out["knock"] = nil
	}

	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) apiTopFlows(w http.ResponseWriter, r *http.Request, u sessionEntry) {
	q := r.URL.Query()
	minutes := atoiDefault(q.Get("minutes"), 15)
	limit := atoiDefault(q.Get("limit"), 50)
	orderBy := q.Get("order")
	if orderBy != "packets" {
		orderBy = "bytes"
	}

	until := time.Now()
	since := until.Add(-time.Duration(minutes) * time.Minute)

	res, err := h.store.Query(r.Context(), model.Query{
		Since:   since,
		Until:   until,
		Limit:   limit,
		OrderBy: orderBy,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	rows := make([]map[string]any, 0, len(res.Rows))
	for _, f := range res.Rows {
		rows = append(rows, map[string]any{
			"src_ip":     f.SrcIP,
			"dst_ip":     f.DstIP,
			"src_port":   f.SrcPort,
			"dst_port":   f.DstPort,
			"proto":      f.Proto,
			"pkts":       f.PktCount,
			"bytes":      f.ByteCount,
			"sampling_n": f.SamplingN,
			// 还原后的估算流量:采样窗口内的计数 × 采样率。放在这里算
			// 而不是写入时预乘,这样采样率事后校正不需要重写历史数据。
			"est_bytes": f.ByteCount * int64(maxInt(f.SamplingN, 1)),
			"est_pkts":  f.PktCount * int64(maxInt(f.SamplingN, 1)),
			"device":    f.Device,
			"last_seen": f.LastSeen.Unix(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": rows, "total": res.Total})
}

func (h *Handler) apiProbeTargets(w http.ResponseWriter, r *http.Request, u sessionEntry) {
	names, err := h.store.ProbeTargets(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"targets": names, "hint": h.ProbeHint})
}

// apiProbeRounds 返回某目标的探测轮次,含 RTT 分布与突发标记。
func (h *Handler) apiProbeRounds(w http.ResponseWriter, r *http.Request, u sessionEntry) {
	q := r.URL.Query()
	target := q.Get("target")
	if target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "缺少 target 参数"})
		return
	}
	hours := atoiDefault(q.Get("hours"), 6)

	until := time.Now()
	since := until.Add(-time.Duration(hours) * time.Hour)

	rounds, err := h.store.ProbeRounds(r.Context(), target, since, until, 5000)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	out := make([]map[string]any, 0, len(rounds))
	for _, rd := range rounds {
		d := rd.Distribution()
		out = append(out, map[string]any{
			"t":     rd.At.Unix(),
			"loss":  rd.LossPct(),
			"burst": rd.Burst,
			"z":     rd.ZScore,
			// 分布而不是均值:一半 5ms 一半 500ms 与全部 250ms 在均值上
			// 完全相同,但那是两种体感截然不同的链路。
			"min": d[0], "p50": d[1], "p90": d[2], "p99": d[3], "max": d[4],
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"target": target, "rounds": out})
}

func (h *Handler) apiKnockSequences(w http.ResponseWriter, r *http.Request, u sessionEntry) {
	recs, err := h.store.ListSequences(r.Context(), 50)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	out := make([]map[string]any, 0, len(recs))
	for _, rec := range recs {
		out = append(out, map[string]any{
			"id":            rec.ID,
			"steps":         stepsJSON(rec.Sequence),
			"window":        rec.Sequence.Window.String(),
			"open_port":     rec.Sequence.OpenPort,
			"open_for":      rec.Sequence.OpenFor.String(),
			"state":         rec.State,
			"requested_by":  rec.RequestedBy,
			"approved_by":   rec.ApprovedBy,
			"note":          rec.Note,
			"created_at":    rec.CreatedAt.Unix(),
			"client_script": rec.Sequence.ClientScript(hostOf(r)),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sequences": out})
}

func (h *Handler) apiKnockGrants(w http.ResponseWriter, r *http.Request, u sessionEntry) {
	grants, err := h.store.ListGrants(r.Context(), 200)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	out := make([]map[string]any, 0, len(grants))
	for _, g := range grants {
		out = append(out, map[string]any{
			"src_ip":     g.SourceIP,
			"open_port":  g.OpenPort,
			"granted_at": g.GrantedAt.Unix(),
			"expires_at": g.ExpiresAt.Unix(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": out})
}

// apiKnockSubmit 提交一版新序列(pending,等审批)。
func (h *Handler) apiKnockSubmit(w http.ResponseWriter, r *http.Request, u sessionEntry) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var body struct {
		Steps []struct {
			Kind       string `json:"kind"`
			Port       int    `json:"port"`
			PayloadLen int    `json:"payload_len"`
		} `json:"steps"`
		WindowSec  int    `json:"window_sec"`
		OpenPort   int    `json:"open_port"`
		OpenForSec int    `json:"open_for_sec"`
		Note       string `json:"note"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误"})
		return
	}

	seq := knock.Sequence{
		Window:   time.Duration(body.WindowSec) * time.Second,
		OpenPort: body.OpenPort,
		OpenFor:  time.Duration(body.OpenForSec) * time.Second,
	}
	if seq.Window <= 0 {
		seq.Window = knock.DefaultWindow
	}
	if seq.OpenFor <= 0 {
		seq.OpenFor = knock.DefaultOpenFor
	}
	for _, st := range body.Steps {
		seq.Steps = append(seq.Steps, knock.Step{
			Kind:       knock.StepKind(st.Kind),
			Port:       st.Port,
			PayloadLen: st.PayloadLen,
		})
	}

	ctx := r.Context()
	id, err := h.store.SubmitSequence(ctx, seq, u.username, body.Note)
	if err != nil {
		// 校验失败的原因要原样透出:"相邻两步相同""ICMP 长度会分片"
		// 这些提示本身就是给用户看的,包装成"提交失败"等于把线索丢掉。
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	_ = h.store.WriteAudit(ctx, u.username, "knock_submit", strconv.FormatInt(id, 10), body.Note)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

func (h *Handler) apiKnockApprove(w http.ResponseWriter, r *http.Request, u sessionEntry) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var body struct {
		ID int64 `json:"id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误"})
		return
	}

	ctx := r.Context()
	if err := h.store.ApproveSequence(ctx, body.ID, u.username); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	_ = h.store.WriteAudit(ctx, u.username, "knock_approve", strconv.FormatInt(body.ID, 10), "")

	// 热更新:审批只是配置变更,不该要求重启才生效。
	if h.OnSequenceApproved != nil {
		if rec, err := h.store.ActiveSequence(ctx); err == nil {
			h.OnSequenceApproved(rec.Sequence, rec.ID)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) apiKnockReject(w http.ResponseWriter, r *http.Request, u sessionEntry) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var body struct {
		ID   int64  `json:"id"`
		Note string `json:"note"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误"})
		return
	}
	ctx := r.Context()
	if err := h.store.RejectSequence(ctx, body.ID, u.username, body.Note); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	_ = h.store.WriteAudit(ctx, u.username, "knock_reject", strconv.FormatInt(body.ID, 10), body.Note)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) apiUsers(w http.ResponseWriter, r *http.Request, u sessionEntry) {
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		users, err := h.store.ListUsers(ctx)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		out := make([]map[string]any, 0, len(users))
		for _, usr := range users {
			out = append(out, map[string]any{
				"id": usr.ID, "username": usr.Username, "role": usr.Role,
				"active": usr.Active, "created_at": usr.CreatedAt.Unix(),
				"last_login_at": unixOrZero(derefTime(usr.LastLoginAt)),
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": out})

	case http.MethodPost:
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误"})
			return
		}
		if err := h.store.CreateUser(ctx, body.Username, body.Password, body.Role); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		_ = h.store.WriteAudit(ctx, u.username, "user_create", body.Username, body.Role)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

func (h *Handler) apiAudit(w http.ResponseWriter, r *http.Request, u sessionEntry) {
	entries, err := h.store.ListAudit(r.Context(), 200)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]any{
			"actor": e.Actor, "action": e.Action, "target": e.Target,
			"detail": e.Detail, "at": e.OccurredAt.Unix(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}

// --- 辅助 ---

func stepsJSON(seq knock.Sequence) []map[string]any {
	out := make([]map[string]any, 0, len(seq.Steps))
	for _, st := range seq.Steps {
		m := map[string]any{"kind": string(st.Kind)}
		if st.Kind == knock.StepTCP {
			m["port"] = st.Port
		} else {
			m["payload_len"] = st.PayloadLen
		}
		out = append(out, m)
	}
	return out
}

// hostOf 取请求里的主机名,用于生成客户端敲门命令。
// 用请求的 Host 而不是配置的监听地址:后者常是 0.0.0.0,拼出来的命令
// 用户没法直接用。
func hostOf(r *http.Request) string {
	host := r.Host
	for i := 0; i < len(host); i++ {
		if host[i] == ':' {
			return host[:i]
		}
	}
	if host == "" {
		return "<你的主机>"
	}
	return host
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil || v <= 0 {
		return def
	}
	return v
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
