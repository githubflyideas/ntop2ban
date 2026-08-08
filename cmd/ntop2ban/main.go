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
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/datasource"
	"github.com/githubflyideas/ntop2ban/internal/knock"
	"github.com/githubflyideas/ntop2ban/internal/model"
	"github.com/githubflyideas/ntop2ban/internal/probe"
	"github.com/githubflyideas/ntop2ban/internal/storage/sqlite"
	"github.com/githubflyideas/ntop2ban/internal/web"
)

var version = "dev"

func main() {
	var (
		addr     = flag.String("addr", ":8090", "HTTP 监听地址")
		dataDir  = flag.String("data-dir", "./ntop2ban-data", "数据目录(SQLite 库文件落这里)")
		apiKey   = flag.String("api-key", "", "采样上报鉴权用的 X-API-Key(必填)")
		days     = flag.Int("days", 40, "数据保留天数(采样与探测共用)")
		iface    = flag.String("iface", "", "观测网卡。XDP 模式必须指定;留空则只能走 AF_PACKET 兼容模式")
		sampleN  = flag.Int("sampling", 100, "抽样率 1/N;1 表示全量")
		prefer   = flag.String("datasource", "", "强制指定数据源:xdp-native | xdp-generic | af-packet;留空则自动降级")
		noKnock  = flag.Bool("no-knock", false, "不启动敲门守护(库里已配的序列不会生效)")
		probeDir = flag.String("probe-dir", probe.DefaultDir, "探测目标清单目录(ping.list / tcp.list)")
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

	// 首次启动时创建 admin 并打印随机密码。固定默认密码在公网上等于
	// 没有密码,而用户往往不会改;随机密码只在日志里出现一次,迫使
	// 用户记下来或立刻改掉。
	if pw, err := store.EnsureAdmin(ctx); err != nil {
		log.Fatalf("初始化管理员账号失败: %v", err)
	} else if pw != "" {
		log.Printf("已创建管理员账号 admin,初始密码:%s  (仅此一次显示,请立即登录并修改)", pw)
	}

	handler := web.NewHandler(store, *apiKey)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// 观测数据源 + 敲门:两者共用 XDP 程序(采样走 1/N 抽样,敲门走
	// 精确匹配),所以要一起装配。
	startObservation(ctx, store, handler, observeConfig{
		iface:       *iface,
		samplingN:   *sampleN,
		prefer:      datasource.Mode(*prefer),
		enableKnock: !*noKnock,
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go retentionLoop(ctx, store, *days)

	startProbes(ctx, store, handler, *probeDir)

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

// startProbes 从清单文件加载探测目标并启动。
//
// 探测随主程序一起启动,不需要单独的命令或参数——目标写在
// /etc/ntop2ban/{ping.list,tcp.list} 里,`echo host >> ping.list` 就能加
// 一个,这比在界面上点几下或写 SQL 都快。
//
// 清单为空(首次部署、或全部注释掉)时不是错误:界面上不显示探测视图,
// 并提示用户去哪个文件里加目标。让服务因为"还没配探测"起不来是不可
// 接受的。
func startProbes(ctx context.Context, store *sqlite.Store, handler *web.Handler, dir string) {
	created, err := probe.EnsureExampleFiles(dir)
	if err != nil {
		// 目录不可写(比如非 root 跑且 -probe-dir 指向 /etc)不该让服务
		// 起不来:探测只是三个功能之一,流量与敲门仍然有用。
		log.Printf("链路探测:无法准备清单目录 %s(探测不可用): %v", dir, err)
		handler.ProbeHint = "无法读写清单目录 " + dir
		return
	}
	for _, p := range created {
		log.Printf("链路探测:已生成示例清单 %s(默认全部注释,去掉行首 # 并重启即生效)", p)
	}

	targets, warnings, err := probe.LoadTargets(dir)
	if err != nil {
		log.Printf("链路探测:读取清单失败: %v", err)
		handler.ProbeHint = "读取清单失败:" + err.Error()
		return
	}
	for _, w := range warnings {
		log.Printf("链路探测:%s", w)
	}

	if len(targets) == 0 {
		hint := "还没有探测目标。编辑 " + filepath.Join(dir, probe.PingListName) +
			"(ICMP)或 " + filepath.Join(dir, probe.TCPListName) + "(TCP),每行一个,重启生效"
		log.Printf("链路探测:%s", hint)
		handler.ProbeHint = hint
		return
	}

	probe.NewRunner(store, nil).Run(ctx, targets)
	log.Printf("链路探测:%d 个目标已启动(清单目录 %s)", len(targets), dir)
	handler.ProbeHint = ""
}

// observeConfig 观测装配参数。
type observeConfig struct {
	iface       string
	samplingN   int
	prefer      datasource.Mode
	enableKnock bool
}

// startObservation 装配流量观测与敲门。
//
// 两者共用一个 XDP 程序:采样走 1/N 抽样(允许丢,只服务可视化),
// 敲门走精确匹配(一个包都不能漏)。这是同一次包解析的两个输出,
// 但判定与上报路径完全分开——共用 ringbuf 时高流量下敲门事件会被
// 采样事件挤掉,那正是最不能丢的东西。
//
// 降级到 AF_PACKET 时,采样仍然工作,但敲门必须回退到自己的 socket:
// AF_PACKET 的采样过滤器带 1/N 抽样,敲门包会被抽掉。
func startObservation(ctx context.Context, store *sqlite.Store, handler *web.Handler, cfg observeConfig) {
	// 敲门状态机与放行动作。序列没配时 matcher 为 nil,数据源仍然
	// 照常采样——首次部署还没提交序列是正常状态,不该让采样也起不来。
	var (
		feeder   *knock.XDPFeeder
		matcher  *knock.Matcher
		opener   *knock.NFTOpener
		seqRec   sqlite.SequenceRecord
		haveSeq  bool
		tcpPorts []int
		icmpLens []int
	)

	if cfg.enableKnock {
		rec, err := store.ActiveSequence(ctx)
		switch {
		case errors.Is(err, sqlite.ErrNoActiveSequence):
			log.Println("敲门:尚未配置生效的序列(在界面提交并批准一版后即时生效)")
		case err != nil:
			log.Printf("敲门:读取序列失败,敲门未启用: %v", err)
		default:
			seqRec, haveSeq = rec, true
			opener = knock.NewNFTOpener()
			m, f, err := knock.NewMatcherOnly(knock.DaemonConfig{
				Sequence:   rec.Sequence,
				SequenceID: rec.ID,
				Opener:     opener,
				Recorder:   store,
			})
			if err != nil {
				log.Printf("敲门:初始化失败: %v", err)
			} else {
				matcher, feeder = m, f
				tcpPorts = rec.Sequence.TCPPorts()
				icmpLens = rec.Sequence.ICMPLens()
				log.Printf("敲门:序列 #%d 已加载(%d 步,%s 内完成,放行端口 %d)",
					rec.ID, len(rec.Sequence.Steps), rec.Sequence.Window, rec.Sequence.OpenPort)
			}
		}
	}

	var knockSink datasource.KnockSink
	if feeder != nil {
		knockSink = feeder
	}

	src, err := datasource.Open(datasource.Config{
		Iface:         cfg.iface,
		SamplingN:     cfg.samplingN,
		Prefer:        cfg.prefer,
		Sink:          store,
		KnockSink:     knockSink,
		KnockTCPPorts: tcpPorts,
		KnockICMPLens: icmpLens,
	}, nil)
	if err != nil {
		// 观测起不来不该让整个服务退出:界面、审批、探测仍然有用,
		// 而且用户需要能登进界面看到"观测没起来"这个事实。
		log.Printf("流量观测未启动: %v", err)
		handler.DataSourceLabel = "未启动(" + firstLine(err.Error()) + ")"
	} else {
		handler.DataSourceLabel = src.Mode().Label()
		go func() {
			if err := src.Run(ctx); err != nil {
				log.Printf("流量观测退出: %v", err)
			}
		}()
		go func() {
			<-ctx.Done()
			_ = src.Close()
		}()
	}

	// AF_PACKET 模式下敲门要自己开 socket:那一层的采样过滤器带抽样,
	// 敲门包会被抽掉,不能复用。
	if matcher != nil && haveSeq && (src == nil || src.Mode() == datasource.ModeAFPacket) {
		d, err := knock.NewDaemon(knock.DaemonConfig{
			Iface:      cfg.iface,
			Sequence:   seqRec.Sequence,
			SequenceID: seqRec.ID,
			Opener:     opener,
			Recorder:   store,
		})
		if err != nil {
			log.Printf("敲门:兼容模式守护初始化失败: %v", err)
		} else {
			log.Println("敲门:数据源为 AF_PACKET,敲门使用独立的精确捕获 socket")
			go func() {
				if err := d.Run(ctx); err != nil {
					log.Printf("敲门:守护退出: %v", err)
				}
			}()
		}
	}

	// 审批通过后热更新:序列变更是常规操作,不该要求重启。
	handler.OnSequenceApproved = func(seq knock.Sequence, seqID int64) {
		if matcher != nil {
			matcher.SetSequence(seq)
		}
		if u, ok := src.(interface {
			UpdateKnockSets(ports, icmpLens []int) error
		}); ok {
			if err := u.UpdateKnockSets(seq.TCPPorts(), seq.ICMPLens()); err != nil {
				log.Printf("敲门:热更新匹配集合失败(重启后生效): %v", err)
				return
			}
		}
		log.Printf("敲门:序列 #%d 已生效", seqID)
	}

	if opener != nil {
		go func() {
			<-ctx.Done()
			// 退出时撤销所有仍在生效的放行。不清理会留下永久放行的规则,
			// 而那时已经没有组件会去回收它们。
			if err := opener.Close(); err != nil {
				log.Printf("敲门:清理放行规则: %v", err)
			}
		}()
	}
}

// firstLine 取错误信息的第一行,用于在界面上展示"观测未启动"的简短原因。
// 完整原因(逐级降级失败的三条)在日志里,界面上只放一行避免撑破布局。
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
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
