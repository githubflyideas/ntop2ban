package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseArgsPingpingStyle(t *testing.T) {
	m, err := ParseArgs([]string{"user=alice,bob", "passwd=p1,p2"})
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if len(m) != 2 || m["alice"] != "p1" || m["bob"] != "p2" {
		t.Errorf("解析结果不符: %v", m)
	}
}

func TestParseArgsEmptyMeansNoCreds(t *testing.T) {
	m, err := ParseArgs(nil)
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if m != nil {
		t.Errorf("无参数应返回 nil, got %v", m)
	}
}

// TestParseArgsCountMismatchIsAnError 数量不匹配必须报错,不能按最短的
// 配对——静默丢掉一个账号会让用户以为配好了,登录时才发现进不去。
func TestParseArgsCountMismatchIsAnError(t *testing.T) {
	if _, err := ParseArgs([]string{"user=a,b,c", "passwd=x,y"}); err == nil {
		t.Error("数量不匹配应报错")
	}
}

func TestParseArgsRejectsUnknownAndEmpty(t *testing.T) {
	if _, err := ParseArgs([]string{"secret=x"}); err == nil {
		t.Error("未知参数应报错")
	}
	if _, err := ParseArgs([]string{"noequals"}); err == nil {
		t.Error("缺少 = 应报错")
	}
	if _, err := ParseArgs([]string{"user=a,", "passwd=x,y"}); err == nil {
		t.Error("空用户名应报错")
	}
}

// TestNewGeneratesRandomPasswordWhenUnconfigured 没配账号时必须生成随机
// 密码,不能裸奔放行:这个界面能看到全网流量明细、能改敲门序列。
// 也不能用固定默认密码——那在公网上等于没有密码。
func TestNewGeneratesRandomPasswordWhenUnconfigured(t *testing.T) {
	a, pw, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if pw == "" {
		t.Fatal("未配置账号时必须生成随机密码")
	}
	if len(pw) < 12 {
		t.Errorf("随机密码太短: %d 字符", len(pw))
	}
	if !a.Check("admin", pw) {
		t.Error("生成的密码应能通过校验")
	}
	if a.Check("admin", "admin") {
		t.Error("不该接受固定弱密码")
	}

	// 两次生成的密码必须不同,否则等于固定默认值
	_, pw2, _ := New(nil)
	if pw == pw2 {
		t.Error("随机密码不该可复现")
	}
}

func TestNewWithCredsDoesNotGenerate(t *testing.T) {
	a, pw, err := New(map[string]string{"alice": "secret"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if pw != "" {
		t.Error("已配置账号时不该生成随机密码")
	}
	if !a.Check("alice", "secret") {
		t.Error("配置的账号应能通过校验")
	}
}

func TestCheckRejectsWrongCreds(t *testing.T) {
	a, _, _ := New(map[string]string{"alice": "secret"})
	if a.Check("alice", "wrong") {
		t.Error("错误密码不该通过")
	}
	if a.Check("nobody", "secret") {
		t.Error("不存在的用户不该通过")
	}
	if a.Check("", "") {
		t.Error("空凭据不该通过")
	}
}

// TestSessionRoundTrip 签发 → 带 cookie 请求 → 认出用户 → 注销 → 失效。
func TestSessionRoundTrip(t *testing.T) {
	a, _, _ := New(map[string]string{"alice": "secret"})

	rec := httptest.NewRecorder()
	a.Issue(rec, "alice")

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != CookieName {
		t.Fatalf("应签发会话 cookie, got %v", cookies)
	}
	// HttpOnly 是必须的:防止 XSS 拿到会话
	if !cookies[0].HttpOnly {
		t.Error("会话 cookie 必须是 HttpOnly")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookies[0])
	user, ok := a.User(req)
	if !ok || user != "alice" {
		t.Fatalf("应认出 alice, got %q ok=%v", user, ok)
	}

	rec2 := httptest.NewRecorder()
	a.Revoke(rec2, req)
	if _, ok := a.User(req); ok {
		t.Error("注销后会话应失效")
	}
}

func TestUserWithoutCookieIsAnonymous(t *testing.T) {
	a, _, _ := New(map[string]string{"alice": "secret"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, ok := a.User(req); ok {
		t.Error("没有 cookie 不该被认为已登录")
	}
}

func TestUserWithBogusTokenIsAnonymous(t *testing.T) {
	a, _, _ := New(map[string]string{"alice": "secret"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "not-a-real-token"})
	if _, ok := a.User(req); ok {
		t.Error("伪造的 token 不该通过")
	}
}

// TestSessionsAreDistinct 两次签发必须得到不同的 token,否则一个用户的
// 会话能被另一个用户复用。
func TestSessionsAreDistinct(t *testing.T) {
	a, _, _ := New(map[string]string{"alice": "a", "bob": "b"})

	r1 := httptest.NewRecorder()
	a.Issue(r1, "alice")
	r2 := httptest.NewRecorder()
	a.Issue(r2, "bob")

	t1 := r1.Result().Cookies()[0].Value
	t2 := r2.Result().Cookies()[0].Value
	if t1 == t2 {
		t.Fatal("两次签发得到了相同的 token")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: t2})
	if u, _ := a.User(req); u != "bob" {
		t.Errorf("token 应对应 bob, got %q", u)
	}
}

func TestSweepRemovesExpired(t *testing.T) {
	a, _, _ := New(map[string]string{"alice": "a"})
	rec := httptest.NewRecorder()
	a.Issue(rec, "alice")
	tok := rec.Result().Cookies()[0].Value

	// 手动把会话改成已过期
	a.mu.Lock()
	s := a.sess[tok]
	s.expires = s.expires.Add(-2 * SessionTTL)
	a.sess[tok] = s
	a.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: tok})
	if _, ok := a.User(req); ok {
		t.Error("过期会话不该通过")
	}

	a.Sweep()
	a.mu.RLock()
	n := len(a.sess)
	a.mu.RUnlock()
	if n != 0 {
		t.Errorf("Sweep 后应清空过期会话, got %d", n)
	}
}
