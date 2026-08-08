// Command ntop2ban —— 小企业向的流量观测与访问控制,单一二进制、单一
// SQLite 文件。
//
// 与 xdp-ban 的分工:xdp-ban 处理大流量镜像分析(ClickHouse 分层聚合在
// 那边),ntop2ban 走轻量路线——采样流量、敲门序列、审批与审计、
// pingping 探测结果都落同一个 .db 文件,拷走那个文件就是完整备份。
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/knock"
	"github.com/githubflyideas/ntop2ban/internal/model"
	"github.com/githubflyideas/ntop2ban/internal/probe"
	"github.com/githubflyideas/ntop2ban/internal/storage/sqlite"
	"github.com/githubflyideas/ntop2ban/internal/web"
)

var version = "dev"

func main() {
	var (
		addr    = flag.String("addr", ":8090", "HTTP 监听地址")
		dataDir = flag.String("data-dir", "./ntop2ban-data", "数据目录(SQLite 库文件落这里)")
		apiKey  = flag.String("api-key", "", "采样上报鉴权用的 X-API-Key(必填)")
		days    = flag.Int("days", 40, "数据保留天数(采样与探测共用)")
		knockIf = flag.String("knock-iface", "", "敲门抓包的网卡;留空表示所有网卡")
		noKnock = flag.Bool("no-knock", false, "不启动敲门守护(库里已配的序列不会生效)")
		probes  = flag.String("probe", "", "探测目标,逗号分隔。格式 name=host 或 name=host:port(带端口即 TCP 探测)")
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

	if !*noKnock {
		startKnock(ctx, store, *knockIf)
	}

	if targets := parseProbeTargets(*probes); len(targets) > 0 {
		probe.NewRunner(store, nil).Run(ctx, targets)
		log.Printf("链路探测:%d 个目标已启动", len(targets))
	}

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

// parseProbeTargets 解析 -probe 参数。
//
// 格式 name=host 或 name=host:port。带端口即 TCP 探测(用连接建立耗时
// 作为 RTT),否则 ICMP。解析失败的条目跳过并告警,不让整个程序起不来——
// 一个写错的探测目标不该阻止采样与敲门这些更重要的功能。
func parseProbeTargets(spec string) []probe.Target {
	if spec == "" {
		return nil
	}
	var out []probe.Target
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, hostport, ok := strings.Cut(item, "=")
		if !ok || name == "" || hostport == "" {
			log.Printf("探测目标 %q 格式无效(应为 name=host 或 name=host:port),已跳过", item)
			continue
		}
		t := probe.Target{Name: name, Kind: "icmp", Host: hostport}
		if host, portStr, err := net.SplitHostPort(hostport); err == nil {
			port, perr := strconv.Atoi(portStr)
			if perr != nil || port < 1 || port > 65535 {
				log.Printf("探测目标 %q 端口无效,已跳过", item)
				continue
			}
			t.Kind, t.Host, t.Port = "tcp", host, port
		}
		out = append(out, t)
	}
	return out
}

// startKnock 按库里生效的序列启动敲门守护。
//
// 库里还没配序列时只打一行提示就返回,不是错误——首次部署时用户还没
// 提交过序列,这是正常状态。若因此让整个程序退出,用户会以为程序坏了。
func startKnock(ctx context.Context, store *sqlite.Store, iface string) {
	rec, err := store.ActiveSequence(ctx)
	if errors.Is(err, sqlite.ErrNoActiveSequence) {
		log.Println("敲门:尚未配置生效的序列,守护未启动(在界面提交并批准一版序列后重启生效)")
		return
	}
	if err != nil {
		log.Printf("敲门:读取序列失败,守护未启动: %v", err)
		return
	}

	opener := knock.NewNFTOpener()
	d, err := knock.NewDaemon(knock.DaemonConfig{
		Iface:      iface,
		Sequence:   rec.Sequence,
		SequenceID: rec.ID,
		Opener:     opener,
		Recorder:   store,
	})
	if err != nil {
		log.Printf("敲门:守护初始化失败: %v", err)
		return
	}

	log.Printf("敲门:序列 #%d 已加载(%d 步,%s 内完成,放行端口 %d)",
		rec.ID, len(rec.Sequence.Steps), rec.Sequence.Window, rec.Sequence.OpenPort)

	go func() {
		if err := d.Run(ctx); err != nil {
			log.Printf("敲门:守护退出: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		// 退出时撤销所有仍在生效的放行规则。不清理会留下永久放行的
		// 规则,而那时已经没有任何组件会去回收它们。
		if err := opener.Close(); err != nil {
			log.Printf("敲门:清理放行规则: %v", err)
		}
	}()
}

// retentionLoop 周期清理过期数据(采样与探测两张表)。
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
				log.Printf("清理过期采样数据: %v", err)
			}
			if err := store.ProbeRetention(ctx, policy.DetailTTL); err != nil {
				log.Printf("清理过期探测数据: %v", err)
			}
		}
	}
}
