// Package storage 定义 NTop2ban 的存储抽象:FlowStorage 接口。
//
// 两种实现见 internal/storage/clickhouse(默认)与 internal/storage/sqlite
// (兜底,功能降级)。上层(接收端、查询 API)只依赖这个接口,不感知
// 具体后端 —— 切换后端只是启动时选一个构造函数,业务代码零改动。
package storage

import (
	"context"

	"github.com/githubflyideas/ntop2ban/internal/model"
)

// FlowStorage 是流量明细的存储抽象。
//
// 方法集对齐 xdp-ban-架构方案 v0.3 第一节给出的接口:
// Append/Query/Aggregate/Retention/Compact/Stats。
//
// 实现须知:
//   - Append 是高频写入路径(接收端每次收到 xdp-sampler 上报即调用一次),
//     实现必须支持批量写入且对瞬时故障(网络抖动、后端短暂不可用)有
//     合理的重试/降级策略——采样数据允许丢,但不应因为存储层报错就让
//     整个接收端点跟着 500,阻塞 xdp-sampler 的上报节奏。
//   - Query 用于展示层(Top Clients/Servers、Country/ASN 视图等),
//     实现应假定调用方会给出合理的时间范围与 Limit,不做无范围全表扫描
//     的防御(那是调用方的责任,不是存储层的责任)。
//   - Aggregate/Compact/Retention 是后台任务的接口,不在请求路径上调用。
type FlowStorage interface {
	// Append 批量写入 flow 记录。batch 为空时应直接返回 nil,不做无意义
	// 的网络往返。
	Append(ctx context.Context, batch []model.Flow) error

	// Query 按筛选条件查询 flow 记录,用于展示层。
	Query(ctx context.Context, q model.Query) (model.Result, error)

	// Aggregate 对指定时间窗口做增量聚合(写入/刷新对应粒度的 rollup)。
	// 由后台调度调用,不在写入或查询的请求路径上。
	Aggregate(ctx context.Context, window model.Window) error

	// Retention 按策略清理过期数据(明细表与各级 rollup 分别处理)。
	Retention(ctx context.Context, policy model.RetentionPolicy) error

	// Compact 触发后端的整理/优化操作(如 ClickHouse 的 OPTIMIZE TABLE)。
	// SQLite 实现可以是空操作(VACUUM 成本较高,不在此自动触发)。
	Compact(ctx context.Context) error

	// Stats 返回当前存储的运行状态,供运维/仪表板展示,也用于前端判断
	// 当前后端是否处于降级模式(见 model.StorageStats.Degraded)。
	Stats(ctx context.Context) (model.StorageStats, error)

	// Close 释放底层连接/资源。
	Close() error
}
