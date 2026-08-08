package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/knock"
)

// 敲门相关的持久化。落在同一个 .db 文件里——ntop2ban 只有一个库,
// 采样流量、敲门序列、成功授权记录都在这里,拷走这个文件就是完整备份。
//
// 数据库在敲门这件事上的职责边界很窄:**它只管序列定义与成功记录**。
// 敲门判定完全在内存状态机里做(见 internal/knock.Matcher),不查库——
// 每个包都查一次库既慢又没必要。审批也不是实时闸门:审批走的是对
// "序列定义"这份配置的变更管理,守护进程始终按当前生效的那条序列工作。

// knockSchema 两张表。
//
// knock_sequences 存历史上每一版序列,而不是只存当前一条。理由是审批
// 与审计需要"谁在什么时候把序列改成了什么"这个事实,一条被覆盖写的
// 记录留不下这个。active 标记当前生效的那版。
//
// knock_grants 只记成功授权。失败的敲门不记(那是互联网噪声,记下来
// 只会淹没有用信息),所以这张表天然是稀疏的、可直接当审计证据看。
const knockSchema = `
CREATE TABLE IF NOT EXISTS knock_sequences (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	steps_json   TEXT    NOT NULL,   -- []knock.Step 的 JSON
	window_sec   INTEGER NOT NULL,
	open_port    INTEGER NOT NULL,
	open_for_sec INTEGER NOT NULL,
	state        TEXT    NOT NULL,   -- pending / active / superseded / rejected
	requested_by TEXT    NOT NULL DEFAULT '',
	approved_by  TEXT    NOT NULL DEFAULT '',
	note         TEXT    NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	activated_at INTEGER
);

-- 同一时刻只允许一条 active。用部分唯一索引在库层面强制,而不是靠
-- 应用代码自律:两条 active 会让守护进程按哪条工作变成不确定的,
-- 这种 bug 在生产上表现为"敲门有时开有时不开",极难排查。
CREATE UNIQUE INDEX IF NOT EXISTS idx_knock_single_active
	ON knock_sequences(state) WHERE state = 'active';

CREATE TABLE IF NOT EXISTS knock_grants (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	source_ip   TEXT    NOT NULL,
	open_port   INTEGER NOT NULL,
	granted_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL,
	sequence_id INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_knock_grants_time ON knock_grants(granted_at);
CREATE INDEX IF NOT EXISTS idx_knock_grants_src  ON knock_grants(source_ip);
`

// SequenceRecord 是一版序列定义及其审批状态。
type SequenceRecord struct {
	ID          int64
	Sequence    knock.Sequence
	State       string
	RequestedBy string
	ApprovedBy  string
	Note        string
	CreatedAt   time.Time
	ActivatedAt *time.Time
}

// ErrNoActiveSequence 表示库里还没有生效的序列。
//
// 单独定义而不是返回 sql.ErrNoRows:调用方需要区分"还没配过敲门"
// (正常的首次启动状态,守护进程应当保持关闭而不是报错退出)与
// "查库出错了"。
var ErrNoActiveSequence = errors.New("knock: 尚无生效的敲门序列")

// SubmitSequence 提交一版新序列,状态为 pending,等待审批。
//
// 这里就做 Validate:不合法的序列不该进库。等到审批时才发现端口越界
// 或相邻步重复,审批人会困惑于"为什么批不过",而问题其实出在提交时。
func (s *Store) SubmitSequence(ctx context.Context, seq knock.Sequence, requestedBy, note string) (int64, error) {
	if err := seq.Validate(); err != nil {
		return 0, fmt.Errorf("knock: 序列不合法: %w", err)
	}
	stepsJSON, err := json.Marshal(seq.Steps)
	if err != nil {
		return 0, fmt.Errorf("knock: 序列化步骤: %w", err)
	}

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO knock_sequences
			(steps_json, window_sec, open_port, open_for_sec, state, requested_by, note, created_at)
		VALUES (?,?,?,?,'pending',?,?,?)`,
		string(stepsJSON), int64(seq.Window.Seconds()), seq.OpenPort, int64(seq.OpenFor.Seconds()),
		requestedBy, note, time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("knock: 提交序列: %w", err)
	}
	return res.LastInsertId()
}

// ApproveSequence 批准某版序列并使其生效,同时把原先生效的那版标记为
// superseded。
//
// 整个操作在一个事务里:两步之间若崩溃,要么出现两条 active(被唯一
// 索引挡住,变成写失败),要么一条都没有(敲门直接失效,把自己锁在外面)。
// 事务让它要么全成要么全不动。
func (s *Store) ApproveSequence(ctx context.Context, id int64, approvedBy string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("knock: begin tx: %w", err)
	}
	defer tx.Rollback()

	var state string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM knock_sequences WHERE id = ?`, id).Scan(&state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("knock: 序列 %d 不存在", id)
		}
		return fmt.Errorf("knock: 查询序列 %d: %w", id, err)
	}
	if state != "pending" {
		return fmt.Errorf("knock: 序列 %d 当前状态为 %q,只有 pending 可以批准", id, state)
	}

	// 先降级旧的 active,再升级新的——顺序反了会撞上唯一索引。
	if _, err := tx.ExecContext(ctx,
		`UPDATE knock_sequences SET state = 'superseded' WHERE state = 'active'`); err != nil {
		return fmt.Errorf("knock: 降级旧序列: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE knock_sequences SET state = 'active', approved_by = ?, activated_at = ? WHERE id = ?`,
		approvedBy, time.Now().Unix(), id); err != nil {
		return fmt.Errorf("knock: 激活序列 %d: %w", id, err)
	}
	return tx.Commit()
}

// RejectSequence 驳回一版待审序列。
func (s *Store) RejectSequence(ctx context.Context, id int64, approvedBy, note string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE knock_sequences SET state = 'rejected', approved_by = ?, note = ?
		WHERE id = ? AND state = 'pending'`, approvedBy, note, id)
	if err != nil {
		return fmt.Errorf("knock: 驳回序列 %d: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("knock: 序列 %d 不存在或不处于 pending 状态", id)
	}
	return nil
}

// ActiveSequence 读取当前生效的序列,供守护进程启动与热更新时加载。
func (s *Store) ActiveSequence(ctx context.Context) (SequenceRecord, error) {
	return s.scanSequence(s.db.QueryRowContext(ctx, `
		SELECT id, steps_json, window_sec, open_port, open_for_sec, state,
		       requested_by, approved_by, note, created_at, activated_at
		FROM knock_sequences WHERE state = 'active'`))
}

func (s *Store) scanSequence(row *sql.Row) (SequenceRecord, error) {
	var (
		rec         SequenceRecord
		stepsJSON   string
		windowSec   int64
		openForSec  int64
		createdAt   int64
		activatedAt sql.NullInt64
	)
	err := row.Scan(&rec.ID, &stepsJSON, &windowSec, &rec.Sequence.OpenPort, &openForSec,
		&rec.State, &rec.RequestedBy, &rec.ApprovedBy, &rec.Note, &createdAt, &activatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return SequenceRecord{}, ErrNoActiveSequence
	}
	if err != nil {
		return SequenceRecord{}, fmt.Errorf("knock: 读取序列: %w", err)
	}
	if err := json.Unmarshal([]byte(stepsJSON), &rec.Sequence.Steps); err != nil {
		return SequenceRecord{}, fmt.Errorf("knock: 解析序列步骤(id=%d): %w", rec.ID, err)
	}
	rec.Sequence.Window = time.Duration(windowSec) * time.Second
	rec.Sequence.OpenFor = time.Duration(openForSec) * time.Second
	rec.CreatedAt = time.Unix(createdAt, 0)
	if activatedAt.Valid {
		t := time.Unix(activatedAt.Int64, 0)
		rec.ActivatedAt = &t
	}
	return rec, nil
}

// ListSequences 返回全部序列版本,最新在前,供审批界面与审计查看。
func (s *Store) ListSequences(ctx context.Context, limit int) ([]SequenceRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, steps_json, window_sec, open_port, open_for_sec, state,
		       requested_by, approved_by, note, created_at, activated_at
		FROM knock_sequences ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("knock: 列出序列: %w", err)
	}
	defer rows.Close()

	var out []SequenceRecord
	for rows.Next() {
		var (
			rec         SequenceRecord
			stepsJSON   string
			windowSec   int64
			openForSec  int64
			createdAt   int64
			activatedAt sql.NullInt64
		)
		if err := rows.Scan(&rec.ID, &stepsJSON, &windowSec, &rec.Sequence.OpenPort, &openForSec,
			&rec.State, &rec.RequestedBy, &rec.ApprovedBy, &rec.Note, &createdAt, &activatedAt); err != nil {
			return nil, fmt.Errorf("knock: 扫描序列行: %w", err)
		}
		if err := json.Unmarshal([]byte(stepsJSON), &rec.Sequence.Steps); err != nil {
			return nil, fmt.Errorf("knock: 解析序列步骤(id=%d): %w", rec.ID, err)
		}
		rec.Sequence.Window = time.Duration(windowSec) * time.Second
		rec.Sequence.OpenFor = time.Duration(openForSec) * time.Second
		rec.CreatedAt = time.Unix(createdAt, 0)
		if activatedAt.Valid {
			t := time.Unix(activatedAt.Int64, 0)
			rec.ActivatedAt = &t
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// RecordGrant 记录一次成功授权。只记成功——失败的敲门不写库。
func (s *Store) RecordGrant(ctx context.Context, sourceIP string, openPort int, grantedAt time.Time, openFor time.Duration, sequenceID int64) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO knock_grants (source_ip, open_port, granted_at, expires_at, sequence_id)
		VALUES (?,?,?,?,?)`,
		sourceIP, openPort, grantedAt.Unix(), grantedAt.Add(openFor).Unix(), sequenceID)
	if err != nil {
		return fmt.Errorf("knock: 记录授权: %w", err)
	}
	return nil
}

// GrantRecord 是一条成功授权记录。
type GrantRecord struct {
	ID         int64
	SourceIP   string
	OpenPort   int
	GrantedAt  time.Time
	ExpiresAt  time.Time
	SequenceID int64
}

// ListGrants 返回最近的成功授权记录,最新在前。
func (s *Store) ListGrants(ctx context.Context, limit int) ([]GrantRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, source_ip, open_port, granted_at, expires_at, sequence_id
		FROM knock_grants ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("knock: 列出授权记录: %w", err)
	}
	defer rows.Close()

	var out []GrantRecord
	for rows.Next() {
		var g GrantRecord
		var granted, expires int64
		if err := rows.Scan(&g.ID, &g.SourceIP, &g.OpenPort, &granted, &expires, &g.SequenceID); err != nil {
			return nil, fmt.Errorf("knock: 扫描授权行: %w", err)
		}
		g.GrantedAt = time.Unix(granted, 0)
		g.ExpiresAt = time.Unix(expires, 0)
		out = append(out, g)
	}
	return out, rows.Err()
}
