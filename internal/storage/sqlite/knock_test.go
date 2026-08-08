package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/knock"
)

func demoSeq() knock.Sequence {
	return knock.Sequence{
		Steps: []knock.Step{
			{Kind: knock.StepTCP, Port: 9001},
			{Kind: knock.StepICMP, PayloadLen: 56},
			{Kind: knock.StepTCP, Port: 9003},
			{Kind: knock.StepICMP, PayloadLen: 90},
		},
		Window:   knock.DefaultWindow,
		OpenPort: 22,
		OpenFor:  knock.DefaultOpenFor,
	}
}

// TestActiveSequence_EmptyStoreReportsNoActive 首次启动时库里没有序列,
// 必须能区分"还没配过"与"查库出错"——守护进程据此决定是保持关闭
// 还是报错退出。
func TestActiveSequence_EmptyStoreReportsNoActive(t *testing.T) {
	s := openTempStore(t)
	_, err := s.ActiveSequence(context.Background())
	if !errors.Is(err, ErrNoActiveSequence) {
		t.Fatalf("want ErrNoActiveSequence, got %v", err)
	}
}

// TestSubmitRejectsInvalidSequence 不合法的序列不该进库。等到审批时
// 才发现问题,审批人会困惑于"为什么批不过"而问题其实出在提交那一刻。
func TestSubmitRejectsInvalidSequence(t *testing.T) {
	s := openTempStore(t)
	bad := demoSeq()
	bad.Steps[1] = bad.Steps[0] // 相邻两步相同

	if _, err := s.SubmitSequence(context.Background(), bad, "alice", ""); err == nil {
		t.Fatal("提交不合法序列应报错")
	}
}

// TestSubmitThenApproveActivates 提交后处于 pending,不生效;批准后
// 才成为 active 并能被守护进程读到。
func TestSubmitThenApproveActivates(t *testing.T) {
	s := openTempStore(t)
	ctx := context.Background()

	id, err := s.SubmitSequence(ctx, demoSeq(), "alice", "上线首版")
	if err != nil {
		t.Fatalf("SubmitSequence: %v", err)
	}

	// 还没批准,不应有 active
	if _, err := s.ActiveSequence(ctx); !errors.Is(err, ErrNoActiveSequence) {
		t.Fatalf("pending 序列不应生效, got %v", err)
	}

	if err := s.ApproveSequence(ctx, id, "admin"); err != nil {
		t.Fatalf("ApproveSequence: %v", err)
	}

	rec, err := s.ActiveSequence(ctx)
	if err != nil {
		t.Fatalf("ActiveSequence after approve: %v", err)
	}
	if rec.ID != id {
		t.Errorf("active id: want %d, got %d", id, rec.ID)
	}
	if rec.ApprovedBy != "admin" {
		t.Errorf("approved_by: want admin, got %q", rec.ApprovedBy)
	}
	if rec.ActivatedAt == nil {
		t.Error("activated_at 应被填上")
	}
	// 序列内容要能原样读回——守护进程按它工作,字段错了敲门就打不开
	if len(rec.Sequence.Steps) != 4 {
		t.Fatalf("want 4 steps, got %d", len(rec.Sequence.Steps))
	}
	if rec.Sequence.Steps[1].PayloadLen != 56 {
		t.Errorf("第 2 步 ICMP 长度: want 56, got %d", rec.Sequence.Steps[1].PayloadLen)
	}
	if rec.Sequence.Window != knock.DefaultWindow {
		t.Errorf("window: want %v, got %v", knock.DefaultWindow, rec.Sequence.Window)
	}
	if rec.Sequence.OpenPort != 22 {
		t.Errorf("open_port: want 22, got %d", rec.Sequence.OpenPort)
	}
}

// TestApproveSupersedesPrevious 批准新版时旧版必须降级,且任何时刻
// 只能有一条 active。两条 active 会让守护进程按哪条工作变成不确定,
// 表现为"敲门有时开有时不开",这种 bug 极难排查,所以库层面就要挡住。
func TestApproveSupersedesPrevious(t *testing.T) {
	s := openTempStore(t)
	ctx := context.Background()

	id1, err := s.SubmitSequence(ctx, demoSeq(), "alice", "v1")
	if err != nil {
		t.Fatalf("submit v1: %v", err)
	}
	if err := s.ApproveSequence(ctx, id1, "admin"); err != nil {
		t.Fatalf("approve v1: %v", err)
	}

	seq2 := demoSeq()
	seq2.Steps[0].Port = 9101
	id2, err := s.SubmitSequence(ctx, seq2, "bob", "换端口")
	if err != nil {
		t.Fatalf("submit v2: %v", err)
	}
	if err := s.ApproveSequence(ctx, id2, "admin"); err != nil {
		t.Fatalf("approve v2: %v", err)
	}

	rec, err := s.ActiveSequence(ctx)
	if err != nil {
		t.Fatalf("ActiveSequence: %v", err)
	}
	if rec.ID != id2 {
		t.Fatalf("active 应为 v2(%d), got %d", id2, rec.ID)
	}
	if rec.Sequence.Steps[0].Port != 9101 {
		t.Errorf("生效的应是新序列, 第 1 步端口 want 9101, got %d", rec.Sequence.Steps[0].Port)
	}

	// 历史版本必须留着——审批与审计需要"谁在何时改成了什么"
	all, err := s.ListSequences(ctx, 10)
	if err != nil {
		t.Fatalf("ListSequences: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("历史版本应保留, want 2 条, got %d", len(all))
	}
	var superseded int
	for _, r := range all {
		if r.State == "superseded" {
			superseded++
		}
	}
	if superseded != 1 {
		t.Errorf("want 1 条 superseded, got %d", superseded)
	}
}

// TestApproveOnlyFromPending 已经生效或已驳回的版本不能再次批准。
func TestApproveOnlyFromPending(t *testing.T) {
	s := openTempStore(t)
	ctx := context.Background()

	id, err := s.SubmitSequence(ctx, demoSeq(), "alice", "")
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if err := s.ApproveSequence(ctx, id, "admin"); err != nil {
		t.Fatalf("first approve: %v", err)
	}
	if err := s.ApproveSequence(ctx, id, "admin"); err == nil {
		t.Error("重复批准同一版本应报错")
	}
}

// TestRejectSequence 驳回后不生效,且不能再批准。
func TestRejectSequence(t *testing.T) {
	s := openTempStore(t)
	ctx := context.Background()

	id, err := s.SubmitSequence(ctx, demoSeq(), "alice", "")
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if err := s.RejectSequence(ctx, id, "admin", "端口与业务冲突"); err != nil {
		t.Fatalf("RejectSequence: %v", err)
	}
	if _, err := s.ActiveSequence(ctx); !errors.Is(err, ErrNoActiveSequence) {
		t.Errorf("驳回的序列不应生效, got %v", err)
	}
	if err := s.ApproveSequence(ctx, id, "admin"); err == nil {
		t.Error("已驳回的版本不应还能批准")
	}
}

// TestRecordAndListGrants 成功授权要能记下来并查出——这是敲门唯一
// 留痕的地方(失败不记),也就是审计要看的东西。
func TestRecordAndListGrants(t *testing.T) {
	s := openTempStore(t)
	ctx := context.Background()

	id, err := s.SubmitSequence(ctx, demoSeq(), "alice", "")
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if err := s.ApproveSequence(ctx, id, "admin"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	now := time.Now().Truncate(time.Second)
	if err := s.RecordGrant(ctx, "203.0.113.7", 22, now, knock.DefaultOpenFor, id); err != nil {
		t.Fatalf("RecordGrant: %v", err)
	}

	grants, err := s.ListGrants(ctx, 10)
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	g := grants[0]
	if g.SourceIP != "203.0.113.7" {
		t.Errorf("source_ip: want 203.0.113.7, got %q", g.SourceIP)
	}
	if g.OpenPort != 22 {
		t.Errorf("open_port: want 22, got %d", g.OpenPort)
	}
	if !g.ExpiresAt.Equal(now.Add(knock.DefaultOpenFor)) {
		t.Errorf("expires_at: want %v, got %v", now.Add(knock.DefaultOpenFor), g.ExpiresAt)
	}
	if g.SequenceID != id {
		t.Errorf("sequence_id: want %d, got %d", id, g.SequenceID)
	}
}
