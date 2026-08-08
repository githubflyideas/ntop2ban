// Package storage 定义 NTop2ban 的存储抽象:FlowStorage 接口。
//
// 只有一个实现:internal/storage/sqlite。接口保留下来不是为了将来换
// 后端(ClickHouse 那套已经搬去 xdp-ban 了,ntop2ban 明确不走重存储),
// 而是为了让采样写入路径能在测试里替换成假实现——见 internal/web 的
// fakeStorage。
package storage

import (
	"context"

	"github.com/githubflyideas/ntop2ban/internal/model"
)

// FlowStorage 是流量明细的存储抽象。
//
// 方法集是 v0.3 文档那套接口的瘦身版:去掉了 Aggregate 与 Compact——
// 那两个方法本来只为 ClickHouse 的 rollup 与 OPTIMIZE TABLE 而存在,
// ntop2ban 不做分层聚合,留着就是给唯一的实现强加两个空方法。
//
// 实现须知:
//   - Append 是高频写入路径(采样聚合窗口每到期即调用一次),实现必须
//     支持批量写入。采样数据允许丢:存储层报错不应该让采样循环停下来,
//     调用方记日志继续跑下一个窗口即可。
//   - Query 用于展示层(Top Clients/Servers、Country/ASN 视图等),
//     实现应假定调用方会给出合理的时间范围与 Limit,不做无范围全表扫描
//     的防御(那是调用方的责任,不是存储层的责任)。
//   - Retention 是后台任务的接口,不在请求路径上调用。
type FlowStorage interface {
	// Append 批量写入 flow 记录。batch 为空时应直接返回 nil。
	Append(ctx context.Context, batch []model.Flow) error

	// Query 按筛选条件查询 flow 记录,用于展示层。
	Query(ctx context.Context, q model.Query) (model.Result, error)

	// Retention 按策略清理过期数据。
	Retention(ctx context.Context, policy model.RetentionPolicy) error

	// Stats 返回当前存储的运行状态,供运维/仪表板展示。
	Stats(ctx context.Context) (model.StorageStats, error)

	// Close 释放底层连接/资源。
	Close() error
}
