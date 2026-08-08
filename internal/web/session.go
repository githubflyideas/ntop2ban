package web

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/storage/sqlite"
)

// 会话管理。会话只在内存里,进程重启即全部失效。
//
// 这是刻意的:把会话写库会让每个请求多一次 SQLite 读,而重启后要求
// 重新登录对一个内网工具来说完全可以接受。代价明确、收益明确。
type sessions struct {
	mu  sync.RWMutex
	m   map[string]sessionEntry
	ttl time.Duration
}

type sessionEntry struct {
	username string
	role     string
	expires  time.Time
}

const (
	sessionCookie = "ntop2ban_session"
	sessionTTL    = 12 * time.Hour
)

func newSessions() *sessions {
	s := &sessions{m: make(map[string]sessionEntry), ttl: sessionTTL}
	return s
}

func (s *sessions) issue(username, role string) string {
	tok := randomToken()
	s.mu.Lock()
	s.m[tok] = sessionEntry{username: username, role: role, expires: time.Now().Add(s.ttl)}
	s.mu.Unlock()
	return tok
}

func (s *sessions) lookup(tok string) (sessionEntry, bool) {
	s.mu.RLock()
	e, ok := s.m[tok]
	s.mu.RUnlock()
	if !ok {
		return sessionEntry{}, false
	}
	if time.Now().After(e.expires) {
		s.mu.Lock()
		delete(s.m, tok)
		s.mu.Unlock()
		return sessionEntry{}, false
	}
	return e, true
}

func (s *sessions) revoke(tok string) {
	s.mu.Lock()
	delete(s.m, tok)
	s.mu.Unlock()
}

// sweep 清理过期会话。没有它,长期运行下过期条目会一直留在 map 里。
func (s *sessions) sweep() {
	now := time.Now()
	s.mu.Lock()
	for k, e := range s.m {
		if now.After(e.expires) {
			delete(s.m, k)
		}
	}
	s.mu.Unlock()
}

// currentUser 从请求里取出会话。第二个返回值为 false 表示未登录。
func (h *Handler) currentUser(r *http.Request) (sessionEntry, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return sessionEntry{}, false
	}
	return h.sess.lookup(c.Value)
}

// requireAuth 包装需要登录的 handler。
func (h *Handler) requireAuth(next func(http.ResponseWriter, *http.Request, sessionEntry)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := h.currentUser(r)
		if !ok {
			// API 请求返回 401,页面请求跳登录页。混在一起会让前端
			// 拿到一大段 HTML 当 JSON 解析,报出莫名其妙的错误。
			if isAPIPath(r.URL.Path) {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r, u)
	}
}

// requireAdmin 包装只有 admin 能做的操作。
func (h *Handler) requireAdmin(next func(http.ResponseWriter, *http.Request, sessionEntry)) http.HandlerFunc {
	return h.requireAuth(func(w http.ResponseWriter, r *http.Request, u sessionEntry) {
		if u.role != sqlite.RoleAdmin {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "需要 admin 权限"})
			return
		}
		next(w, r, u)
	})
}

func isAPIPath(p string) bool {
	return len(p) >= 5 && p[:5] == "/api/"
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(loginHTML))
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	u, err := h.store.Authenticate(ctx, body.Username, body.Password)
	if err != nil {
		// 不区分"用户不存在"与"密码错误",避免枚举用户名。
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "用户名或密码错误"})
		return
	}

	tok := h.sess.issue(u.Username, u.Role)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.CookieSecure,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	_ = h.store.WriteAudit(ctx, u.Username, "login", "", "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "role": u.Role})
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		h.sess.revoke(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
