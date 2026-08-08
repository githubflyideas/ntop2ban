// Command ntop2ban —— 流量可视化服务:接收 xdp-sampler 的采样上报,
// 持久化到存储后端(默认托管一个内嵌 ClickHouse,兜底可用 SQLite),
// 供展示层查询。
//
// 打包形态(v0.3 决策):发布包里 ntop2ban 与官方 clickhouse 静态二进制
// 同目录。默认模式下 ntop2ban 会把 clickhouse 作为子进程拉起并托管其
// 生命周期,用户体验保持"拷贝即用",不需要单独安装 ClickHouse 服务。
//
// 存储后端选择(-storage):
//   - clickhouse(默认):托管内嵌 ClickHouse,完整能力
//   - sqlite:极简兜底,无外部/子进程依赖,功能降级
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/storage"
	"github.com/githubflyideas/ntop2ban/internal/storage/clickhouse"
	"github.com/githubflyideas/ntop2ban/internal/storage/sqlite"
	"github.com/githubflyideas/ntop2ban/internal/web"
)

func main() {
	var (
		addr        = flag.String("addr", ":8090", "HTTP 监听地址")
		storageKind = flag.String("storage", "clickhouse", "存储后端: clickhouse(默认,托管内嵌) | sqlite(兜底)")
		dataDir     = flag.String("data-dir", "./ntop2ban-data", "数据目录(托管 ClickHouse 的库文件 / SQLite 的 .db 都落这里)")
		chBin       = flag.String("clickhouse-bin", "", "clickhouse 静态二进制路径;为空则取 ntop2ban 同目录下的 ./clickhouse")
		apiKey      = flag.String("api-key", "", "xdp-sampler 上报鉴权用的 X-API-Key(必填,不设则拒绝一切上报)")
	)
	flag.Parse()

	if *apiKey == "" {
		// 与接收端点的行为一致:apiKey 为空会拒绝一切请求。这里直接
		// 在启动时拦下,避免服务起来了却永远收不到数据、用户却以为
		// 在正常工作。
		log.Fatal("必须通过 -api-key 指定上报鉴权密钥(与 xdp-sampler 的 -key 一致);留空会拒绝所有上报")
	}

	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		log.Fatalf("创建数据目录 %q 失败: %v", *dataDir, err)
	}

	// 根 context:收到 SIGINT/SIGTERM 时取消,驱动优雅退出。
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, cleanup, err := openStorage(ctx, *storageKind, *dataDir, *chBin)
	if err != nil {
		log.Fatalf("初始化存储后端失败: %v", err)
	}
	defer cleanup()

	// HTTP 服务:接收端点。
	handler := web.NewHandler(store, *apiKey)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("ntop2ban 监听 %s(存储后端: %s,上报端点 POST %s/api/v1/samples)", *addr, *storageKind, *addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP 服务异常退出: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("收到退出信号,正在优雅关闭...")

	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Printf("HTTP 优雅关闭出错(继续收尾存储): %v", err)
	}
}

// openStorage 按 kind 构造存储后端,返回 store 与一个 cleanup 函数
// (cleanup 负责关闭 store 以及——ClickHouse 托管模式下——停止子进程)。
func openStorage(ctx context.Context, kind, dataDir, chBin string) (storage.FlowStorage, func(), error) {
	switch kind {
	case "clickhouse":
		binPath := chBin
		if binPath == "" {
			p, err := clickhouse.DefaultBinPath()
			if err != nil {
				return nil, nil, fmt.Errorf("解析默认 clickhouse 二进制路径: %w", err)
			}
			binPath = p
		}

		managed, err := clickhouse.StartManaged(ctx, clickhouse.ManagedConfig{
			BinPath: binPath,
			DataDir: filepath.Join(dataDir, "clickhouse"),
		})
		if err != nil {
			return nil, nil, err
		}
		log.Printf("已托管内嵌 ClickHouse(native %s)", managed.Addr())

		store, err := clickhouse.Open(ctx, clickhouse.Config{
			Addr:               managed.Addr(),
			Database:           "ntop2ban",
			AutoCreateDatabase: true,
		})
		if err != nil {
			_ = managed.Stop(10 * time.Second)
			return nil, nil, fmt.Errorf("连接托管 ClickHouse: %w", err)
		}

		cleanup := func() {
			_ = store.Close()
			if err := managed.Stop(15 * time.Second); err != nil {
				log.Printf("停止托管 ClickHouse: %v", err)
			} else {
				log.Println("托管 ClickHouse 已停止")
			}
		}
		return store, cleanup, nil

	case "sqlite":
		store, err := sqlite.Open(filepath.Join(dataDir, "flows.db"))
		if err != nil {
			return nil, nil, err
		}
		log.Println("使用 SQLite 兜底存储(功能降级:无历史趋势 / 无多维聚合)")
		return store, func() { _ = store.Close() }, nil

	default:
		return nil, nil, fmt.Errorf("未知存储后端 %q(可选: clickhouse | sqlite)", kind)
	}
}
