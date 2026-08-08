// Package auth 是极简认证:用户名密码来自启动参数,会话只在内存里。
//
// 做法照搬 pingping:`./ntop2ban user=alice,bob passwd=p1,p2`,
// 没有数据库、没有注册流程、没有密码重置。理由是 v0.2 已经明确
// ntop2ban 是单机工具,而且刚把 SQLite 整个删掉了——为了存几个账号
// 再把数据库拉回来是本末倒置。
//
// 会话在内存里,进程重启即全部失效。对一个单机工具完全可以接受,
// 换来的是每个请求不需要任何 I/O。
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// CookieName 会话 cookie 名。
	CookieName = "ntop2ban_session"
	// SessionTTL 会话有效期。
	SessionTTL = 12 * time.Hour
)

// Auth 持有账号表与会话表。
type Auth struct {
	// creds 是用户名 → 密码。启动后不再变更,因此不需要锁。
	creds map[string]string

	mu   sync.RWMutex
	sess map[string]session

	// Secure 在 TLS 后面部署时置为 true,让 cookie 带 Secure 标记。
	Secure bool
}

type session struct {
	user    string
	expires time.Time
}

// ParseArgs 解析 pingping 风格的尾随参数:user=a,b passwd=x,y。
//
// 为什么不用两个 flag(-user -passwd):多用户时 flag 要么重复出现要么
// 逗号分隔,与这个写法没有本质区别;而沿用 pingping 的写法让熟悉那边的
// 用户不用重新学。
//
// 没有任何参数时返回空 map,调用方据此决定是禁用认证还是生成随机密码。
func ParseArgs(args []string) (map[string]string, error) {
	var users, pws []string
	for _, a := range args {
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			return nil, fmt.Errorf("无法识别的参数 %q(应为 user=... passwd=...)", a)
		}
		switch k {
		case "user", "users":
			users = strings.Split(v, ",")
		case "passwd", "password", "passwords":
			pws = strings.Split(v, ",")
		default:
			return nil, fmt.Errorf("未知参数 %q(可用 user= 与 passwd=)", k)
		}
	}
	if len(users) == 0 && len(pws) == 0 {
		return nil, nil
	}
	// 数量不匹配直接报错而不是按最短的配对:静默丢掉一个账号会让用户
	// 以为自己配好了,登录时才发现进不去。
	if len(users) != len(pws) {
		return nil, fmt.Errorf("用户数(%d)与密码数(%d)不一致", len(users), len(pws))
	}
	m := make(map[string]string, len(users))
	for i := range users {
		u, p := strings.TrimSpace(users[i]), pws[i]
		if u == "" || p == "" {
			return nil, fmt.Errorf("第 %d 组用户名或密码为空", i+1)
		}
		m[u] = p
	}
	return m, nil
}

// New 构造 Auth。creds 为空时会生成一个 admin 账号并返回随机密码,
// 调用方应把它打印到日志里。
//
// 生成随机密码而不是留空放行:这个界面能看到全网流量明细、能改敲门
// 序列,裸奔的代价太大。也不用固定默认密码——那在公网上等于没有密码,
// 而且用户往往不会改。
func New(creds map[string]string) (*Auth, string, error) {
	a := &Auth{sess: make(map[string]session)}

	if len(creds) > 0 {
		a.creds = creds
		return a, "", nil
	}

	pw, err := randomPassword()
	if err != nil {
		return nil, "", err
	}
	a.creds = map[string]string{"admin": pw}
	return a, pw, nil
}

// Users 返回配置的用户名(仅供界面展示"当前登录者")。
func (a *Auth) Users() []string {
	out := make([]string, 0, len(a.creds))
	for u := range a.creds {
		out = append(out, u)
	}
	return out
}

// Check 校验用户名密码。
//
// 用常量时间比较,并且在用户不存在时也走一次比较:直接返回会让
// "用户不存在"比"密码错误"快得多,足以用来枚举用户名。
func (a *Auth) Check(user, pass string) bool {
	want, ok := a.creds[user]
	if !ok {
		// 与一个等长的假密码比一次,保持时间大致恒定。
		subtle.ConstantTimeCompare([]byte(pass), []byte(pass))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(pass), []byte(want)) == 1
}

// Issue 签发会话并写入 cookie。
func (a *Auth) Issue(w http.ResponseWriter, user string) {
	tok := randomToken()

	a.mu.Lock()
	a.sess[tok] = session{user: user, expires: time.Now().Add(SessionTTL)}
	a.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   a.Secure,
		MaxAge:   int(SessionTTL.Seconds()),
	})
}

// User 返回请求对应的登录用户名;未登录时第二个返回值为 false。
func (a *Auth) User(r *http.Request) (string, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return "", false
	}

	a.mu.RLock()
	s, ok := a.sess[c.Value]
	a.mu.RUnlock()
	if !ok {
		return "", false
	}
	if time.Now().After(s.expires) {
		a.mu.Lock()
		delete(a.sess, c.Value)
		a.mu.Unlock()
		return "", false
	}
	return s.user, true
}

// Revoke 注销当前会话。
func (a *Auth) Revoke(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil {
		a.mu.Lock()
		delete(a.sess, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1})
}

// Sweep 清理过期会话。没有它,过期条目会一直留在 map 里。
func (a *Auth) Sweep() {
	now := time.Now()
	a.mu.Lock()
	for k, s := range a.sess {
		if now.After(s.expires) {
			delete(a.sess, k)
		}
	}
	a.mu.Unlock()
}

// SweepLoop 周期清理,直到调用方结束进程。
func (a *Auth) SweepLoop() {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for range t.C {
		a.Sweep()
	}
}

func randomPassword() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: 生成随机密码: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
