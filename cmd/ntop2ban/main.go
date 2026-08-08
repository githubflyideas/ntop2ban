// Command ntop2ban —— 单机 Flow Analytics 平台。
//
// 采集(XDP/eBPF,后续加 sFlow v5 / NetFlow v5)→ Canonical Flow →
// 富化 → ClickHouse → Query Engine → Web 界面。
//
// 与 xdp-ban 的边界:ntop2ban 负责 Observe / Analyze,xdp-ban 负责
// Decide / Enforce。两者通过 API 协作,封禁逻辑不回流到这里。
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/auth"
	"github.com/githubflyideas/ntop2ban/internal/datasource"
	"github.com/githubflyideas/ntop2ban/internal/knock"
	"github.com/githubflyideas/ntop2ban/internal/store"
)

var version = "dev"

func main() {
	var (
		iface     = flag.String("iface", "", "观测网卡。XDP 模式必须指定;留空只能走 AF_PACKET 兼容模式")
		sampleN   = flag.Int("sampling", 100, "抽样率 1/N;1 表示全量")
		prefer    = flag.String("datasource", "", "强制指定数据源:xdp-native | xdp-generic | af-packet;留空自动降级")
		dataDir   = flag.String("data-dir", "./ntop2ban-data", "数据目录(托管 ClickHouse 的库文件落这里)")
		confDir   = flag.String("config-dir", knock.DefaultConfigDir, "配置清单目录(knock.list)")
		chAddr    = flag.String("clickhouse-addr", "", "外部 ClickHouse 地址 host:port;留空则托管同目录下的 clickhouse 二进制")
		chBin     = flag.String("clickhouse-bin", "", "clickhouse 二进制路径;留空取 ntop2ban 同目录")
		retention = flag.Int("retention-days", 90, "明细数据保留天数")
		noKnock   = flag.Bool("no-knock", false, "不启动敲门")
		showVer   = flag.Bool("version", false, "打印版本")
	)
	flag.Parse()

	if *showVer {
		log.Printf("ntop2ban %s", version)
		return
	}

	// 认证:pingping 风格的尾随参数 user=a,b passwd=x,y。
	// 没有数据库——v0.2 已经把 SQLite 整个删掉了,为了几个账号再拉回来
	// 是本末倒置。
	creds, err := auth.ParseArgs(flag.Args())
	if err != nil {
		log.Fatalf("认证参数无效: %v", err)
	}
	au, genPW, err := auth.New(creds)
	if err != nil {
		log.Fatalf("初始化认证失败: %v", err)
	}
	if genPW != "" {
		log.Printf("未指定账号,已生成 admin 初始密码:%s", genPW)
		log.Printf("  (仅此一次显示。下次可用 ./ntop2ban user=admin passwd=你的密码 指定)")
	}
	go au.SweepLoop()

	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		log.Fatalf("创建数据目录 %q 失败: %v", *dataDir, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, chStop, err := openStore(ctx, *chAddr, *chBin, *dataDir, *retention)
	if err != nil {
		log.Fatalf("初始化存储失败: %v", err)
	}
	defer chStop()
	defer st.Close()

	if s, err := st.Stats(ctx); err == nil {
		log.Printf("存储就绪:flows %d 行,磁盘 %.2f GB(压缩后),保留 %d 天",
			s.TotalRows, s.CompressedGB, *retention)
	}

	startObservation(ctx, st, observeConfig{
		iface:       *iface,
		samplingN:   *sampleN,
		prefer:      datasource.Mode(*prefer),
		confDir:     *confDir,
		enableKnock: !*noKnock,
	})

	<-ctx.Done()
	log.Println("收到退出信号,正在关闭...")
	// 给 ClickHouse 留出刷盘时间:不优雅停止的话下次启动要做 part 恢复,
	// 慢且可能丢掉最后一批写入。
	time.Sleep(500 * time.Millisecond)
}

// openStore 打开存储。
//
// 两种形态:指定 -clickhouse-addr 就连外部实例;否则托管同目录下的
// clickhouse 二进制。托管是默认路径,让部署保持"拷贝即用";外部实例的
// 分支代价很小,却能让不想下 200MB 发行包的人有出路。
func openStore(ctx context.Context, addr, bin, dataDir string, retentionDays int) (*store.Store, func(), error) {
	noop := func() {}

	if addr != "" {
		st, err := store.Open(ctx, store.Config{
			Addr: addr, Database: "ntop2ban",
			AutoCreateDatabase: true, RetentionDays: retentionDays,
		})
		if err != nil {
			return nil, noop, err
		}
		log.Printf("已连接外部 ClickHouse %s", addr)
		return st, noop, nil
	}

	managed, err := store.StartManaged(ctx, store.ManagedConfig{
		BinPath: bin,
		DataDir: filepath.Join(dataDir, "clickhouse"),
	})
	if err != nil {
		return nil, noop, err
	}
	log.Printf("已托管内嵌 ClickHouse(native %s)", managed.Addr())

	st, err := store.Open(ctx, store.Config{
		Addr: managed.Addr(), Database: "ntop2ban",
		AutoCreateDatabase: true, RetentionDays: retentionDays,
	})
	if err != nil {
		_ = managed.Stop(10 * time.Second)
		return nil, noop, err
	}
	return st, func() {
		if err := managed.Stop(20 * time.Second); err != nil {
			log.Printf("停止托管 ClickHouse: %v", err)
		} else {
			log.Println("托管 ClickHouse 已停止")
		}
	}, nil
}

type observeConfig struct {
	iface       string
	samplingN   int
	prefer      datasource.Mode
	confDir     string
	enableKnock bool
}

// startObservation 装配流量观测与敲门。
//
// 两者共用一个 XDP 程序:采样走 1/N 抽样(允许丢,只服务可视化),
// 敲门走精确匹配(一个包都不能漏)。各用独立 ringbuf——共用的话
// 高流量下敲门事件会被采样事件挤掉,而那是最不能丢的东西。
func startObservation(ctx context.Context, st *store.Store, cfg observeConfig) {
	var (
		feeder   *knock.XDPFeeder
		matcher  *knock.Matcher
		opener   *knock.NFTOpener
		seq      knock.Sequence
		haveSeq  bool
		tcpPorts []int
		icmpLens []int
	)

	if cfg.enableKnock {
		created, path, err := knock.EnsureList(cfg.confDir)
		if err != nil {
			log.Printf("敲门:无法准备清单 %s(敲门未启用): %v", cfg.confDir, err)
		} else {
			if created {
				log.Printf("敲门:已生成默认清单 %s(默认序列 tcp 9001 → icmp 123 → tcp 9002 → icmp 145)", path)
			}
			loaded, err := knock.LoadSequence(cfg.confDir)
			switch {
			case errors.Is(err, knock.ErrNoKnockList):
				log.Println("敲门:清单不存在,敲门未启用")
			case err != nil:
				// 清单有问题直接说清楚哪一行:序列就是密码,配错了不该
				// 静默降级成"敲门关闭",那样用户以为门锁着其实开着。
				log.Printf("敲门:清单无效,敲门未启用 —— %v", err)
			default:
				seq, haveSeq = loaded, true
				opener = knock.NewNFTOpener()
				m, f, err := knock.NewMatcherOnly(knock.DaemonConfig{
					Sequence: loaded, Opener: opener,
				})
				if err != nil {
					log.Printf("敲门:初始化失败: %v", err)
				} else {
					matcher, feeder = m, f
					tcpPorts, icmpLens = loaded.TCPPorts(), loaded.ICMPLens()
					log.Printf("敲门:已加载(%d 步,%s 内完成,放行端口 %d %s)",
						len(loaded.Steps), loaded.Window, loaded.OpenPort, loaded.OpenFor)
				}
			}
		}
	}

	var knockSink datasource.KnockSink
	if feeder != nil {
		knockSink = feeder
	}

	var srcMode datasource.Mode
	src, err := datasource.Open(datasource.Config{
		Iface:         cfg.iface,
		SamplingN:     cfg.samplingN,
		Prefer:        cfg.prefer,
		Sink:          st,
		KnockSink:     knockSink,
		KnockTCPPorts: tcpPorts,
		KnockICMPLens: icmpLens,
	}, nil)
	if err != nil {
		// 观测起不来不该让整个服务退出:界面与敲门仍然有用,而且用户
		// 需要能登进界面看到"观测没起来"这个事实。
		log.Printf("流量观测未启动: %v", err)
	} else {
		srcMode = src.Mode()
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
	// 敲门包会被抽掉。
	// srcMode 为空表示观测没起来。这种情况下也要起敲门的独立 socket:
	// 观测挂了不代表敲门也该失效——那会把人直接锁在门外。
	if matcher != nil && haveSeq && (srcMode == "" || srcMode == datasource.ModeAFPacket) {
		d, err := knock.NewDaemon(knock.DaemonConfig{
			Iface: cfg.iface, Sequence: seq, Opener: opener,
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
