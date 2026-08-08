package sqlite

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/probe"
)

// 探测结果的持久化。落在同一个 .db 文件里,与采样流量、敲门序列共用。
//
// 这是"搬 pingping 但不搬它的 store.go"的落点:算法照搬,存储重写成
// modernc.org/sqlite(纯 Go),保住 CGO_ENABLED=0 静态编译。

// probeSchema 探测轮次表。
//
// RTT 样本存成打包的 float32 blob 而不是 JSON 数组:每个样本 4 字节
// 而不是 ~6 个字符,读出来也不需要解析。一轮 20 个包、一分钟一轮、
// 40 天保留,单目标就是 115 万个样本——这个差别不是微优化。
//
// WITHOUT ROWID + (target, at) 主键:按目标与时间查是唯一的访问模式,
// 省掉一层 rowid 间接寻址。
const probeSchema = `
CREATE TABLE IF NOT EXISTS probe_rounds (
	target    TEXT    NOT NULL,
	at        INTEGER NOT NULL,
	sent      INTEGER NOT NULL,
	recv      INTEGER NOT NULL,
	rtts      BLOB,
	burst     INTEGER NOT NULL DEFAULT 0,
	z         REAL    NOT NULL DEFAULT 0,
	PRIMARY KEY (target, at)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_probe_at ON probe_rounds(at);
`

// AppendRound 写入一轮探测结果。
//
// 用 INSERT OR REPLACE:同一目标同一秒重复写(进程重启后立刻探一轮,
// 恰好撞上上次那一秒)不应该报主键冲突把这轮数据丢掉。
func (s *Store) AppendRound(ctx context.Context, r probe.Round) error {
	burst := 0
	if r.Burst {
		burst = 1
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO probe_rounds (target, at, sent, recv, rtts, burst, z)
		VALUES (?,?,?,?,?,?,?)`,
		r.Target, r.At.Unix(), r.Sent, r.Recv, packRTTs(r.RTTs), burst, r.ZScore)
	if err != nil {
		return fmt.Errorf("probe: 写入轮次: %w", err)
	}
	return nil
}

// RecentLoss 返回最近若干轮的丢包数,供突发判定做基线。
func (s *Store) RecentLoss(ctx context.Context, target string, since time.Time, limit int) ([]int, error) {
	if limit <= 0 {
		limit = 240
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT sent - recv FROM probe_rounds
		WHERE target = ? AND at >= ?
		ORDER BY at DESC LIMIT ?`, target, since.Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("probe: 读取基线: %w", err)
	}
	defer rows.Close()

	var out []int
	for rows.Next() {
		var loss int
		if err := rows.Scan(&loss); err != nil {
			return nil, fmt.Errorf("probe: 扫描基线行: %w", err)
		}
		out = append(out, loss)
	}
	return out, rows.Err()
}

// ProbeRounds 返回某目标在时间区间内的轮次,供界面画图。
func (s *Store) ProbeRounds(ctx context.Context, target string, since, until time.Time, limit int) ([]probe.Round, error) {
	if limit <= 0 {
		limit = 5000
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT target, at, sent, recv, rtts, burst, z FROM probe_rounds
		WHERE target = ? AND at >= ? AND at < ?
		ORDER BY at ASC LIMIT ?`, target, since.Unix(), until.Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("probe: 查询轮次: %w", err)
	}
	defer rows.Close()

	var out []probe.Round
	for rows.Next() {
		var (
			r     probe.Round
			at    int64
			blob  []byte
			burst int
		)
		if err := rows.Scan(&r.Target, &at, &r.Sent, &r.Recv, &blob, &burst, &r.ZScore); err != nil {
			return nil, fmt.Errorf("probe: 扫描轮次行: %w", err)
		}
		r.At = time.Unix(at, 0)
		r.RTTs = unpackRTTs(blob)
		r.Burst = burst != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// ProbeTargets 返回库里出现过的目标名。
func (s *Store) ProbeTargets(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT target FROM probe_rounds ORDER BY target`)
	if err != nil {
		return nil, fmt.Errorf("probe: 列出目标: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// ProbeRetention 删除过期的探测轮次。与采样数据共用同一个保留期概念,
// 但是独立的表,所以单独一个方法。
func (s *Store) ProbeRetention(ctx context.Context, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	cutoff := time.Now().Add(-ttl).Unix()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM probe_rounds WHERE at < ?`, cutoff); err != nil {
		return fmt.Errorf("probe: 清理过期轮次: %w", err)
	}
	return nil
}

// packRTTs 把 RTT 样本打包成 float32 小端 blob。
//
// float32 而非 float64:RTT 的有效精度是微秒级(我们记到 0.001ms),
// float32 的 ~7 位有效数字足够表示到几百毫秒,存储却省一半。
func packRTTs(rtts []float64) []byte {
	if len(rtts) == 0 {
		return nil
	}
	b := make([]byte, 4*len(rtts))
	for i, v := range rtts {
		binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(float32(v)))
	}
	return b
}

func unpackRTTs(b []byte) []float64 {
	if len(b) < 4 {
		return nil
	}
	out := make([]float64, 0, len(b)/4)
	for i := 0; i+4 <= len(b); i += 4 {
		out = append(out, float64(math.Float32frombits(binary.LittleEndian.Uint32(b[i:]))))
	}
	return out
}
