package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/model"
)

// openTempStore 在每个测试的临时目录里开一个独立的 db 文件,测试之间
// 互不共享状态。t.TempDir() 会在测试结束时自动清理。
func openTempStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "flows.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
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

// TestOpen_EnablesWAL 验证 Open 真的把库切到了 WAL 模式——这个断言
// 存在的理由见 store.go:DSN pragma 名字写错时驱动静默忽略,不验证
// 就会以为开了 WAL 其实没开,并发问题到生产才暴露。
func TestOpen_EnablesWAL(t *testing.T) {
	s := openTempStore(t)
	var mode string
	if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("want journal_mode=wal, got %q", mode)
	}
}

// TestAppendEmpty_NoError 空批次应直接返回 nil,不开事务——接收端点
// 收到不含 flow 的上报(可能发生:采样窗口内无流量)时不应报错。
func TestAppendEmpty_NoError(t *testing.T) {
	s := openTempStore(t)
	if err := s.Append(context.Background(), nil); err != nil {
		t.Fatalf("Append(nil): %v", err)
	}
	if err := s.Append(context.Background(), []model.Flow{}); err != nil {
		t.Fatalf("Append(empty): %v", err)
	}
}

// TestAppendAndQuery_RoundTrips 与 ClickHouse 的同名测试对齐:写入的
// 字段(五元组、计数、时间戳)经 Append 再 Query 出来必须原样返回。
// 两个后端跑等价的往返断言,是"切换后端行为不变"这一契约的保证。
func TestAppendAndQuery_RoundTrips(t *testing.T) {
	s := openTempStore(t)
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
	// 默认按 byte_count 降序,3000 bytes 的 9.9.9.9 排第一
	if res.Rows[0].SrcIP != "9.9.9.9" {
		t.Errorf("want first row src_ip=9.9.9.9, got %s", res.Rows[0].SrcIP)
	}
	if res.Rows[0].PktCount != 20 || res.Rows[0].ByteCount != 3000 {
		t.Errorf("计数未原样返回: pkt=%d byte=%d", res.Rows[0].PktCount, res.Rows[0].ByteCount)
	}
	if res.Rows[0].DstPort != 443 || res.Rows[0].SrcPort != 51000 {
		t.Errorf("端口未原样返回: src=%d dst=%d", res.Rows[0].SrcPort, res.Rows[0].DstPort)
	}
	if !res.Rows[0].ReportedAt.Equal(now) {
		t.Errorf("时间戳未原样返回: want %v got %v", now, res.Rows[0].ReportedAt)
	}
}

// TestQuery_OrderByPackets 验证 OrderBy=packets 时按包数而非字节数
// 排序——两个排序维度对应展示层"按流量"和"按连接数"两种 Top 视图。
func TestQuery_OrderByPackets(t *testing.T) {
	s := openTempStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	// A: 高字节低包数;B: 低字节高包数。按 packets 排序应 B 在前。
	if err := s.Append(ctx, []model.Flow{
		sampleFlow("10.0.0.1", "2.2.2.2", 5, 9000, now),
		sampleFlow("10.0.0.2", "2.2.2.2", 50, 500, now),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	res, err := s.Query(ctx, model.Query{
		Since:   now.Add(-time.Minute),
		Until:   now.Add(time.Minute),
		OrderBy: "packets",
		Limit:   10,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if res.Rows[0].SrcIP != "10.0.0.2" {
		t.Errorf("按包数排序时 want 10.0.0.2 在前, got %s", res.Rows[0].SrcIP)
	}
}

// TestQuery_FiltersBySrcIP 与 ClickHouse 同名测试对齐:按源 IP 过滤。
func TestQuery_FiltersBySrcIP(t *testing.T) {
	s := openTempStore(t)
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
	if len(res.Rows) != 1 || res.Rows[0].SrcIP != "1.1.1.1" {
		t.Fatalf("按 src_ip 过滤失败: got %d rows", len(res.Rows))
	}
}

// TestRetention_DeletesOldRows 验证按时间清理只删过期行、保留新行。
func TestRetention_DeletesOldRows(t *testing.T) {
	s := openTempStore(t)
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
		t.Fatalf("Query: %v", err)
	}
	if len(res.Rows) != 1 || res.Rows[0].SrcIP != "1.1.1.1" {
		t.Fatalf("Retention 后应只剩最近一行, got %d rows", len(res.Rows))
	}
}

// TestStats_EmptyStore 空库时 min/max 为 NULL,Stats 不应报错——
// 服务刚启动、还没收到任何上报时会走这条路径。
func TestStats_EmptyStore(t *testing.T) {
	s := openTempStore(t)
	stats, err := s.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats on empty store: %v", err)
	}
	if stats.TotalRows != 0 {
		t.Errorf("want 0 rows, got %d", stats.TotalRows)
	}
}

// TestStats_ReportsBackendAndRows 替代原先那个 Degraded 断言:
// 现在只有一个后端,没有"降级"概念可言,但 Stats 仍要正确反映
// backend 名与行数——仪表板靠它判断"数据在正常流入"。
func TestStats_ReportsBackendAndRows(t *testing.T) {
	s := openTempStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	if err := s.Append(ctx, []model.Flow{sampleFlow("1.1.1.1", "2.2.2.2", 1, 100, now)}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	stats, err := s.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.Backend != "sqlite" {
		t.Errorf("want backend=sqlite, got %q", stats.Backend)
	}
	if stats.TotalRows != 1 {
		t.Errorf("want TotalRows=1, got %d", stats.TotalRows)
	}
}

// TestOpen_EnablesIncrementalAutoVacuum 守住一个容易静默失效的设置:
// auto_vacuum 只能在建表之前设定,一旦库里有了表就改不动了。若这个
// pragma 没生效,Retention 里的 incremental_vacuum 就是空转,采样文件
// 会一直单调增长——而且不会有任何报错提示。
func TestOpen_EnablesIncrementalAutoVacuum(t *testing.T) {
	s := openTempStore(t)
	var mode int
	if err := s.db.QueryRow("PRAGMA auto_vacuum").Scan(&mode); err != nil {
		t.Fatalf("query auto_vacuum: %v", err)
	}
	// 2 = INCREMENTAL(0=NONE, 1=FULL)
	if mode != 2 {
		t.Errorf("want auto_vacuum=2(INCREMENTAL), got %d —— Retention 的空间回收会静默失效", mode)
	}
}
