// Command ntop2ban —— 小企业向的流量观测与访问控制,单一二进制、单一
// SQLite 文件。
//
// 与 xdp-ban 的分工:xdp-ban 处理大流量镜像分析(ClickHouse 分层聚合在
// 那边),ntop2ban 走轻量路线——采样流量、敲门序列、审批与审计、
// pingping 探测结果都落同一个 .db 文件,拷走那个文件就是完整备份。
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/model"
	"github.com/githubflyideas/ntop2ban/internal/storage/sqlite"
	"github.com/githubflyideas/ntop2ban/internal/web"
)

var version = "dev"

func main() {
	var (
		addr    = flag.String("addr", ":8090", "HTTP 监听地址")
		dataDir = flag.String("data-dir", "./ntop2ban-data", "数据目录(SQLite 库文件落这里)")
		apiKey  = flag.String("api-key", "", "采样上报鉴权用的 X-API-Key(必填)")
		days    = flag.Int("days", 40, "采样数据保留天数")
	)
	flag.Parse()

	if *apiKey == "" {
		// 与接收端点行为一致:apiKey 为空会拒绝一切请求。启动时直接拦下,
		// 避免服务起来了却永远收不到数据、用户却以为在正常工作。
		log.Fatal("必须通过 -api-key 指定上报鉴权密钥;留空会拒绝所有上报")
	}

	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		log.Fatalf("创建数据目录 %q 失败: %v", *dataDir, err)
	}

	store, err := sqlite.Open(filepath.Join(*dataDir, "ntop2ban.db"))
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer store.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	handler := web.NewHandler(store, *apiKey)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go retentionLoop(ctx, store, *days)

	go func() {
		log.Printf("ntop2ban %s 监听 %s(数据 %s,保留 %d 天)", version, *addr, *dataDir, *days)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP 服务异常退出: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("收到退出信号,正在关闭...")
	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Printf("HTTP 关闭出错: %v", err)
	}
}

// retentionLoop 周期清理过期采样数据。
//
// 一小时一次而不是每天一次:每天一次意味着单次要删掉一整天的数据,
// 那一下的 DELETE 会明显卡住写入;每小时删一小部分,代价摊平了。
func retentionLoop(ctx context.Context, store *sqlite.Store, days int) {
	if days <= 0 {
		return
	}
	policy := model.RetentionPolicy{DetailTTL: time.Duration(days) * 24 * time.Hour}
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := store.Retention(ctx, policy); err != nil {
				log.Printf("清理过期数据: %v", err)
			}
		}
	}
}
