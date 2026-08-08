// Package web 提供 NTop2ban 面向 xdp-sampler 的接收端点。
//
// 复用 xdp-ban 现有的上报协议(JSON 结构、X-API-Key 校验方式)——
// 部署时把 xdp-sampler 的 -url 指向本服务即可,不需要改动
// xdp-sampler/xdp-ban 任何代码。这是方案 B(参见项目讨论):
// 借鉴可用代码与协议,不去改造已上线的 xdp-ban/xdp-sampler。
//
// 与 xdp-ban 的 internal/web/samples.go 的关键差异:xdp-ban 收到后只进
// 内存环形缓冲(重启即丢,服务于实时仪表板);这里收到后经 FlowStorage
// 持久化到 ClickHouse/SQLite,服务于 NTop2ban 的历史查询与展示层。
package web

import (
	"log"
	"net/http"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/model"
)

// FlowSample 是单条流统计,字段与 xdp-ban 的 cmd/xdp-sampler.FlowSample
// 逐字段对齐(json tag 相同),这样 xdp-sampler 现有的 JSON 序列化输出
// 可以被本接收端直接反序列化,不需要任何改动。
type FlowSample struct {
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	Proto     string `json:"proto"`
	PktCount  int64  `json:"pkt_count"`
	ByteCount int64  `json:"byte_count"`
	LastSeen  int64  `json:"last_seen_unix"`
}

// SampleReport 是一次上报的完整载荷,对齐 xdp-ban 的
// internal/web/api.go 里的 SampleReport(同一个 xdp-sampler 二进制,
// 同一份上报格式)。
type SampleReport struct {
	Timestamp     int64          `json:"timestamp"`
	Device        string         `json:"device"`
	SamplingN     int            `json:"sampling_n"`
	NetflowTarget string         `json:"netflow_target,omitempty"`
	Flows         []FlowSample   `json:"flows"`
	GlobalStat    map[string]any `json:"global_stat"`
}

// receiveSamples 接收 xdp-sampler 的周期上报,转换为 model.Flow 后
// 批量写入 FlowStorage。
//
// 鉴权失败与后端写入失败的响应码是刻意区分的:401 表示"你没资格调用
// 这个接口",5xx 表示"你有资格,但这次处理失败了"——xdp-sampler 侧
// 如果要做重试/告警区分,需要能分辨这两种情况。
func (h *Handler) receiveSamples(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if h.apiKey == "" || r.Header.Get("X-API-Key") != h.apiKey {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var report SampleReport
	if err := decodeJSON(r, &report); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	batch := fromSampleReport(report)

	ctx := r.Context()
	if err := h.store.Append(ctx, batch); err != nil {
		log.Printf("[samples] Append 失败 device=%s flows=%d: %v", report.Device, len(batch), err)
		http.Error(w, `{"error":"storage append failed"}`, http.StatusInternalServerError)
		return
	}

	log.Printf("[samples] device=%s flows=%d sampling=1/%d", report.Device, len(batch), report.SamplingN)

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "accepted": len(batch)})
}

// fromSampleReport 把一次上报载荷展开成 []model.Flow。
//
// 这里就是"接收即建模"的落点:ReportedAt/Device/SamplingN 是外层
// 上报维度,逐条 flow 展开时一起带上,查询层不需要再做一次 join。
func fromSampleReport(report SampleReport) []model.Flow {
	reportedAt := time.Unix(report.Timestamp, 0)

	flows := make([]model.Flow, 0, len(report.Flows))
	for _, fs := range report.Flows {
		flows = append(flows, model.Flow{
			ReportedAt: reportedAt,
			Device:     report.Device,
			SamplingN:  report.SamplingN,

			SrcIP:   fs.SrcIP,
			DstIP:   fs.DstIP,
			SrcPort: fs.SrcPort,
			DstPort: fs.DstPort,
			Proto:   fs.Proto,

			PktCount:  fs.PktCount,
			ByteCount: fs.ByteCount,
			LastSeen:  time.Unix(fs.LastSeen, 0),
		})
	}
	return flows
}
