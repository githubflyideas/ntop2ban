package sqlite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// 用户与审批。ntop2ban 面向小企业,角色只有两级:
//
//   - admin  —— 超级权限,可以审批敲门序列变更、管理用户
//   - viewer —— 只读,看流量与探测图
//
// 刻意不做 xdp-ban 那套四眼原则(提交者与审批者必须不同人):小企业
// 常常只有一个管理员,强制四眼会让他无法完成任何操作。审批在这里的
// 作用是留痕与防手误,不是防内鬼。
const userSchema = `
CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	username      TEXT    NOT NULL UNIQUE,
	pass_hash     TEXT    NOT NULL,
	pass_salt     TEXT    NOT NULL,
	role          TEXT    NOT NULL DEFAULT 'viewer',
	active        INTEGER NOT NULL DEFAULT 1,
	created_at    INTEGER NOT NULL,
	last_login_at INTEGER
);

CREATE TABLE IF NOT EXISTS audit_log (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	actor       TEXT    NOT NULL,
	action      TEXT    NOT NULL,
	target      TEXT    NOT NULL DEFAULT '',
	detail      TEXT    NOT NULL DEFAULT '',
	occurred_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(occurred_at);
`

// User 是一个账号。
type User struct {
	ID          int64
	Username    string
	Role        string
	Active      bool
	CreatedAt   time.Time
	LastLoginAt *time.Time
}

const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

var ErrBadCredentials = errors.New("用户名或密码错误")

// EnsureAdmin 在没有任何用户时创建一个 admin,返回生成的随机密码。
//
// 首次启动时打印随机密码而不是用固定的 admin/admin:固定默认密码在
// 公网上等于没有密码,而且用户往往不会改。随机密码只在首次启动的日志
// 里出现一次,迫使用户记下来或立刻改掉。
func (s *Store) EnsureAdmin(ctx context.Context) (string, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return "", fmt.Errorf("users: 统计用户: %w", err)
	}
	if n > 0 {
		return "", nil
	}
	pw, err := randomPassword()
	if err != nil {
		return "", err
	}
	if err := s.CreateUser(ctx, "admin", pw, RoleAdmin); err != nil {
		return "", err
	}
	return pw, nil
}

func (s *Store) CreateUser(ctx context.Context, username, password, role string) error {
	if username == "" || password == "" {
		return errors.New("users: 用户名与密码不能为空")
	}
	if role != RoleAdmin && role != RoleViewer {
		return fmt.Errorf("users: 未知角色 %q", role)
	}
	salt, hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO users (username, pass_hash, pass_salt, role, active, created_at)
		VALUES (?,?,?,?,1,?)`, username, hash, salt, role, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("users: 创建用户 %q: %w", username, err)
	}
	return nil
}

// Authenticate 校验用户名密码。
//
// 用户不存在与密码错误返回同一个错误:区分开会让攻击者能枚举出哪些
// 用户名存在。
func (s *Store) Authenticate(ctx context.Context, username, password string) (User, error) {
	var (
		u    User
		hash string
		salt string
		last sql.NullInt64
		crt  int64
		act  int
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, username, pass_hash, pass_salt, role, active, created_at, last_login_at
		FROM users WHERE username = ?`, username).
		Scan(&u.ID, &u.Username, &hash, &salt, &u.Role, &act, &crt, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrBadCredentials
	}
	if err != nil {
		return User{}, fmt.Errorf("users: 查询用户: %w", err)
	}
	if act == 0 {
		return User{}, ErrBadCredentials
	}
	if !verifyPassword(password, salt, hash) {
		return User{}, ErrBadCredentials
	}

	u.Active = true
	u.CreatedAt = time.Unix(crt, 0)
	if last.Valid {
		t := time.Unix(last.Int64, 0)
		u.LastLoginAt = &t
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE users SET last_login_at = ? WHERE id = ?`, time.Now().Unix(), u.ID)
	return u, nil
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, username, role, active, created_at, last_login_at
		FROM users ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("users: 列出用户: %w", err)
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		var (
			u    User
			act  int
			crt  int64
			last sql.NullInt64
		)
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &act, &crt, &last); err != nil {
			return nil, err
		}
		u.Active = act != 0
		u.CreatedAt = time.Unix(crt, 0)
		if last.Valid {
			t := time.Unix(last.Int64, 0)
			u.LastLoginAt = &t
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// WriteAudit 写审计日志。只增不改。
func (s *Store) WriteAudit(ctx context.Context, actor, action, target, detail string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_log (actor, action, target, detail, occurred_at)
		VALUES (?,?,?,?,?)`, actor, action, target, detail, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("audit: 写入: %w", err)
	}
	return nil
}

// AuditEntry 是一条审计记录。
type AuditEntry struct {
	ID         int64
	Actor      string
	Action     string
	Target     string
	Detail     string
	OccurredAt time.Time
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, actor, action, target, detail, occurred_at
		FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: 查询: %w", err)
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&e.ID, &e.Actor, &e.Action, &e.Target, &e.Detail, &at); err != nil {
			return nil, err
		}
		e.OccurredAt = time.Unix(at, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- 密码哈希 ---
//
// 用 sha256(salt + password) 的多轮迭代,而不是 bcrypt:bcrypt 在 Go 里
// 是 golang.org/x/crypto 的纯 Go 实现,本来也能用,但引入一个依赖只为
// 一处哈希不值当。迭代次数 —— 见 hashRounds 的说明。
//
// 这不如 bcrypt/argon2 抗 GPU 破解。取舍理由:ntop2ban 是小企业内网
// 工具,账号数量个位数,且密码不是唯一防线(敲门已经把端口藏起来了)。
// 若将来面向公网多租户,这里应该换成 argon2id。

const hashRounds = 200000

func hashPassword(password string) (salt, hash string, err error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("users: 生成 salt: %w", err)
	}
	salt = hex.EncodeToString(b)
	return salt, deriveHash(password, salt), nil
}

func deriveHash(password, salt string) string {
	h := sha256.Sum256([]byte(salt + password))
	for i := 0; i < hashRounds; i++ {
		h = sha256.Sum256(h[:])
	}
	return hex.EncodeToString(h[:])
}

// verifyPassword 用常量时间比较,避免通过响应时间侧信道推断哈希前缀。
func verifyPassword(password, salt, want string) bool {
	got := deriveHash(password, salt)
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func randomPassword() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("users: 生成随机密码: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
