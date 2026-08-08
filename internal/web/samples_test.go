package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/githubflyideas/ntop2ban/internal/model"
)

var errAppendFailed = errors.New("append failed")

// fakeStorage 是测试用的内存假实现,只实现 Append 记录调用参数,
// 其余方法返回零值——这个测试只关心接收端点的鉴权/解码/转换逻辑,
// 不关心具体存储后端行为(那些由各后端自己的 contract test 覆盖)。
type fakeStorage struct {
	appended  [][]model.Flow
	appendErr error
}

func (f *fakeStorage) Append(ctx context.Context, batch []model.Flow) error {
	f.appended = append(f.appended, batch)
	return f.appendErr
}
func (f *fakeStorage) Query(ctx context.Context, q model.Query) (model.Result, error) {
	return model.Result{}, nil
}
func (f *fakeStorage) Retention(ctx context.Context, p model.RetentionPolicy) error { return nil }
func (f *fakeStorage) Stats(ctx context.Context) (model.StorageStats, error) {
	return model.StorageStats{}, nil
}
func (f *fakeStorage) Close() error { return nil }

func validReport() SampleReport {
	return SampleReport{
		Timestamp: 1710000000,
		Device:    "eth1",
		SamplingN: 100,
		Flows: []FlowSample{
			{SrcIP: "1.2.3.4", DstIP: "5.6.7.8", SrcPort: 443, DstPort: 51000, Proto: "tcp", PktCount: 10, ByteCount: 1500, LastSeen: 1710000005},
		},
	}
}

func postSamples(t *testing.T, h *Handler, apiKey string, body any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/samples", bytes.NewReader(data))
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	rec := httptest.NewRecorder()
	h.receiveSamples(rec, req)
	return rec
}

// TestReceiveSamples_RejectsMissingOrWrongKey 覆盖鉴权路径:
// 未配置密钥的请求、密钥错误的请求都应 401,且不应触达存储层
// (否则一次鉴权失败还会产生一次无意义的存储写入尝试)。
func TestReceiveSamples_RejectsMissingOrWrongKey(t *testing.T) {
	store := &fakeStorage{}
	h := NewHandler(store, "secret123")

	rec := postSamples(t, h, "", validReport())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing key: want 401, got %d", rec.Code)
	}

	rec = postSamples(t, h, "wrong-key", validReport())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key: want 401, got %d", rec.Code)
	}

	if len(store.appended) != 0 {
		t.Fatalf("鉴权失败的请求不应触达存储层, got %d次 Append 调用", len(store.appended))
	}
}

// TestReceiveSamples_HandlerAPIKeyEmpty_AlwaysRejects 覆盖一个容易被
// 忽略的边界:如果部署时忘了配置 apiKey(空字符串),不能因为客户端也
// 没传 X-API-Key 就意外放行——空对空不算匹配。
func TestReceiveSamples_HandlerAPIKeyEmpty_AlwaysRejects(t *testing.T) {
	store := &fakeStorage{}
	h := NewHandler(store, "")

	rec := postSamples(t, h, "", validReport())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("未配置 apiKey 时任何请求都应被拒绝, got %d", rec.Code)
	}
}

// TestReceiveSamples_AcceptsAndConvertsToFlows 验证成功路径:
// 鉴权通过后,上报载荷被正确展开成 []model.Flow 并调用一次 Append,
// 外层字段(Device/SamplingN/ReportedAt)被带到每一条 flow 上。
func TestReceiveSamples_AcceptsAndConvertsToFlows(t *testing.T) {
	store := &fakeStorage{}
	h := NewHandler(store, "secret123")

	rec := postSamples(t, h, "secret123", validReport())
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	if len(store.appended) != 1 {
		t.Fatalf("want 1次 Append 调用, got %d", len(store.appended))
	}
	batch := store.appended[0]
	if len(batch) != 1 {
		t.Fatalf("want 1条 flow, got %d", len(batch))
	}

	f := batch[0]
	if f.Device != "eth1" {
		t.Errorf("Device: want eth1, got %q", f.Device)
	}
	if f.SamplingN != 100 {
		t.Errorf("SamplingN: want 100, got %d", f.SamplingN)
	}
	if f.SrcIP != "1.2.3.4" || f.DstIP != "5.6.7.8" {
		t.Errorf("五元组未正确带入: src=%s dst=%s", f.SrcIP, f.DstIP)
	}
	if f.PktCount != 10 || f.ByteCount != 1500 {
		t.Errorf("计数未正确带入: pkt=%d byte=%d", f.PktCount, f.ByteCount)
	}
}

// TestReceiveSamples_StorageErrorReturns500NotClientError 存储层失败
// 应映射为 5xx(调用方有资格但这次处理失败),不能与鉴权失败的 401
// 混淆——否则 xdp-sampler 侧无法区分"该不该换个密钥重试"。
func TestReceiveSamples_StorageErrorReturns500NotClientError(t *testing.T) {
	store := &fakeStorage{appendErr: errAppendFailed}
	h := NewHandler(store, "secret123")

	rec := postSamples(t, h, "secret123", validReport())
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", rec.Code)
	}
}

// TestReceiveSamples_RejectsNonPOST 确认方法不匹配时明确拒绝,
// 而不是静默按 POST 处理导致读取 body 出错时给出误导性的错误信息。
func TestReceiveSamples_RejectsNonPOST(t *testing.T) {
	store := &fakeStorage{}
	h := NewHandler(store, "secret123")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/samples", nil)
	req.Header.Set("X-API-Key", "secret123")
	rec := httptest.NewRecorder()
	h.receiveSamples(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rec.Code)
	}
}
