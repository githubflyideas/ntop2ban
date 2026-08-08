// Package clickhouse 的集成测试。
//
// 需要连接一个真实的 ClickHouse 实例(native protocol,默认端口 9000)。
// 通过环境变量 NTOP2BAN_CH_TEST_ADDR 显式开启——没设置就跳过,不在
// 普通 `go test ./...` 时因为缺少外部依赖而失败,这与 CI 里跑单元测试
// 和跑集成测试分成两个不同的 make 目标是一致的做法。
package clickhouse

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/model"
)

func testAddr(t *testing.T) string {
	addr := os.Getenv("NTOP2BAN_CH_TEST_ADDR")
	if addr == "" {
		t.Skip("NTOP2BAN_CH_TEST_ADDR 未设置,跳过 ClickHouse 集成测试")
	}
	return addr
}

// openTestStore 每个测试用独立的库名,避免测试之间通过共享 schema
// 互相影响(比如一个测试的 Retention 把另一个测试还需要的数据删了)。
func openTestStore(t *testing.T) *Store {
	t.Helper()
	addr := testAddr(t)

	dbName := "ntop2ban_test_" + sanitizeTestName(t.Name())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	s, err := Open(ctx, Config{
		Addr:               addr,
		Database:           dbName,
		AutoCreateDatabase: true,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		_ = s.Close()
	})
	return s
}

func sanitizeTestName(name string) string {
	out := make([]byte, 0, len(name))
	for _, c := range []byte(name) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

// TestOpen_CreatesSchemaIdempotently 验证 Open 会建好三层 schema,
// 且重复调用(模拟进程重启后重新连接)不报错——ensureSchema 里的
// IF NOT EXISTS 必须真的生效。
func TestOpen_CreatesSchemaIdempotently(t *testing.T) {
	addr := testAddr(t)
	dbName := "ntop2ban_test_" + sanitizeTestName(t.Name())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	s1, err := Open(ctx, Config{Addr: addr, Database: dbName, AutoCreateDatabase: true})
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	defer s1.Close()

	s2, err := Open(ctx, Config{Addr: addr, Database: dbName, AutoCreateDatabase: true})
	if err != nil {
		t.Fatalf("second Open (idempotency): %v", err)
	}
	defer s2.Close()
}

func sampleFlow(srcIP, dstIP string, pkt, bytes int64, at time.Time) model.Flow {
	return model.Flow{
		ReportedAt: at,
		Device:     "eth1",
		SamplingN:  100,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		SrcPort:    51000,
		DstPort:    443,
		Proto:      "tcp",
		PktCount:   pkt,
		ByteCount:  bytes,
		LastSeen:   at,
	}
}

// TestAppendAndQuery_RoundTrips 验证写入的字段在查询时原样返回——
// 这是最基础的契约:接收端点转换出的 model.Flow 经过 Append 再 Query
// 出来,五元组和计数不能有偏差(比如端口的有符号/无符号转换错误、
// 时间戳时区错位)。
func TestAppendAndQuery_RoundTrips(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Second)
	batch := []model.Flow{
		sampleFlow("1.2.3.4", "5.6.7.8", 10, 1500, now),
		sampleFlow("9.9.9.9", "5.6.7.8", 20, 3000, now),
	}
	if err := s.Append(ctx, batch); err != nil {
		t.Fatalf("Append: %v", err)
	}

	res, err := s.Query(ctx, model.Query{
		Since: now.Add(-time.Minute),
		Until: now.Add(time.Minute),
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res.Rows) != 2 {
		t.Fatalf("want 2 rows, got %d", len(res.Rows))
	}

	// 默认按 byte_count 降序,9.9.9.9 那条(3000 bytes)应排第一
	if res.Rows[0].SrcIP != "9.9.9.9" {
		t.Errorf("want first row src_ip=9.9.9.9 (higher bytes), got %s", res.Rows[0].SrcIP)
	}
	if res.Rows[0].PktCount != 20 || res.Rows[0].ByteCount != 3000 {
		t.Errorf("计数未原样返回: pkt=%d byte=%d", res.Rows[0].PktCount, res.Rows[0].ByteCount)
	}
	if res.Rows[0].DstPort != 443 || res.Rows[0].SrcPort != 51000 {
		t.Errorf("端口未原样返回: src_port=%d dst_port=%d", res.Rows[0].SrcPort, res.Rows[0].DstPort)
	}
}

// TestQuery_FiltersBySrcIP 验证按源 IP 过滤生效,这是 Top Clients 视图
// "点进某个 IP 看它的所有流"场景的基础查询路径。
func TestQuery_FiltersBySrcIP(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	if err := s.Append(ctx, []model.Flow{
		sampleFlow("1.1.1.1", "2.2.2.2", 1, 100, now),
		sampleFlow("3.3.3.3", "2.2.2.2", 1, 100, now),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	res, err := s.Query(ctx, model.Query{
		Since: now.Add(-time.Minute),
		Until: now.Add(time.Minute),
		SrcIP: "1.1.1.1",
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("want 1 row filtered by src_ip, got %d", len(res.Rows))
	}
	if res.Rows[0].SrcIP != "1.1.1.1" {
		t.Errorf("want src_ip=1.1.1.1, got %s", res.Rows[0].SrcIP)
	}
}

// TestStats_ReflectsAppendedData 验证 Stats 返回的行数与时间范围
// 跟随 Append 变化——这是运维仪表板判断"数据在正常流入"的依据。
func TestStats_ReflectsAppendedData(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	if err := s.Append(ctx, []model.Flow{sampleFlow("1.1.1.1", "2.2.2.2", 1, 100, now)}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	stats, err := s.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.Backend != "clickhouse" {
		t.Errorf("want backend=clickhouse, got %q", stats.Backend)
	}
	if stats.TotalRows < 1 {
		t.Errorf("want TotalRows >= 1, got %d", stats.TotalRows)
	}
}

// TestRetention_DropsOldPartitionsOnly 验证 Retention 只丢弃早于截止
// 时间的分区,当天写入的数据必须保留——这是最容易出错的边界:如果
// cutoff 分区键的比较方向写反,会把刚写入的数据也删掉。
func TestRetention_DropsOldPartitionsOnly(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	recent := time.Now().Truncate(time.Second)
	old := recent.AddDate(0, 0, -10)

	if err := s.Append(ctx, []model.Flow{
		sampleFlow("1.1.1.1", "2.2.2.2", 1, 100, recent),
		sampleFlow("9.9.9.9", "2.2.2.2", 1, 100, old),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	if err := s.Retention(ctx, model.RetentionPolicy{DetailTTL: 5 * 24 * time.Hour}); err != nil {
		t.Fatalf("Retention: %v", err)
	}

	res, err := s.Query(ctx, model.Query{
		Since: recent.AddDate(0, 0, -30),
		Until: recent.Add(time.Minute),
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("Query after retention: %v", err)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("want 1 row (only recent) survives retention, got %d", len(res.Rows))
	}
	if res.Rows[0].SrcIP != "1.1.1.1" {
		t.Errorf("want surviving row to be the recent one (1.1.1.1), got %s", res.Rows[0].SrcIP)
	}
}

// TestCompact_NoError 只验证 OPTIMIZE TABLE 链路走通,不断言合并
// 后的具体存储形态(那是 ClickHouse 引擎内部行为,不是本项目的契约)。
func TestCompact_NoError(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	if err := s.Append(ctx, []model.Flow{sampleFlow("1.1.1.1", "2.2.2.2", 1, 100, now)}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := s.Compact(ctx); err != nil {
		t.Fatalf("Compact: %v", err)
	}
}
