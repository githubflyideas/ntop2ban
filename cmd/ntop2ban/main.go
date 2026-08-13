// Command ntop2ban —— 单机 Flow Analytics 平台。
//
// 采集(本机 XDP/AF_PACKET、远端 sFlow v5、远端 NetFlow v5)→
// Canonical Flow → 富化 → ClickHouse → Query Engine → Web 界面。
//
// 与 xdp-ban 的边界:ntop2ban 负责 Observe / Analyze,xdp-ban 负责
// Decide / Enforce。封禁逻辑不在这里。
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

	"github.com/githubflyideas/ntop2ban/internal/api"
	"github.com/githubflyideas/ntop2ban/internal/auth"
	"github.com/githubflyideas/ntop2ban/internal/collector"
	"github.com/githubflyideas/ntop2ban/internal/datasource"
	"github.com/githubflyideas/ntop2ban/internal/enrich"
	"github.com/githubflyideas/ntop2ban/internal/flow"
	"github.com/githubflyideas/ntop2ban/internal/store"
)

var version = "dev"

func main() {
	var (
		addr    = flag.String("addr", ":8090", "Web 监听地址")
		dataDir = flag.String("data-dir", "./ntop2ban-data", "数据目录")

		input = flag.String("input", "local", "输入源:local(本机抓包)| sflow | netflow;逗号分隔可同时启用")

		iface   = flag.String("iface", "", "本机抓包的网卡。XDP 与 macOS 的 BPF 设备都必须指定")
		sampleN = flag.Int("sampling", datasource.DefaultSamplingN,
			"本机抓包的抽样率 1/N;1 表示全量。默认 Linux 上 100(内核里丢包,省 CPU)、"+
				"macOS 上 1(BSD 的 BPF 没有内核随机数扩展,抽样省不下多少却白扣精度)")
		prefer = flag.String("datasource", "", "强制指定本机采集层:xdp-native | xdp-generic | af-packet | bpf-device(macOS)")

		sflowListen   = flag.String("sflow-listen", fmt.Sprintf(":%d", collector.DefaultSFlowPort), "sFlow v5 监听地址")
		netflowListen = flag.String("netflow-listen", fmt.Sprintf(":%d", collector.DefaultNetFlowPort), "NetFlow v5 监听地址")

		chAddr    = flag.String("clickhouse-addr", "", "外部 ClickHouse 地址;留空则托管同目录下的 clickhouse 二进制")
		chBin     = flag.String("clickhouse-bin", "", "clickhouse 二进制路径")
		retention = flag.Int("retention-days", 90, "明细数据保留天数")

		ip2asnPath = flag.String("ip2asn", "", "ip2asn TSV 路径(.tsv 或 .tsv.gz),提供 ASN/国家/组织")
		mmdbPath   = flag.String("mmdb", "", "GeoLite2-City mmdb 路径,额外提供城市与区域;也可在界面上传")

		showVer = flag.Bool("version", false, "打印版本")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("ntop2ban", version)
		return
	}

	modes, err := collector.ParseModes(*input)
	if err != nil {
		log.Fatalf("输入源参数无效: %v", err)
	}

	// 认证:pingping 风格的尾随参数 user=a,b passwd=x,y。
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

	// 富化库。两者都是可选的:没有 ip2asn 就没有 ASN/国家维度,
	// 没有 mmdb 就没有城市维度,但 flow 仍然照常采集与存储。
	asnDB := enrich.New()
	if *ip2asnPath != "" {
		if err := asnDB.LoadFile(*ip2asnPath); err != nil {
			log.Printf("富化:加载 ip2asn 失败(ASN/国家维度不可用): %v", err)
		} else {
			log.Printf("富化:ip2asn 已加载 %d 条前缀", asnDB.Size())
		}
	}

	cityDB := enrich.NewCityDB()
	syncer := enrich.NewSyncer(*dataDir, asnDB, cityDB)
	// 之前同步过的库在重启后仍然生效 —— 否则每次重启都要重新点一遍同步,
	// 而用户不会觉得那是正常操作。
	if loaded := syncer.LoadCached(); len(loaded) > 0 {
		log.Printf("富化:已从缓存加载 %v", loaded)
	}

	// 这句提示必须等到 LoadCached 之后再判断。放在它前面时,缓存里明明
	// 有库,启动日志却先喊一句"ASN/国家维度不可用,去设置页点同步",
	// 紧接着下一行又说"已从缓存加载 [...]" —— 自己打自己的脸,而用户
	// 只会记住前面那句、白跑一趟设置页。
	if !asnDB.Loaded() {
		log.Println("富化:ASN/国家维度不可用 —— 在界面「设置」页点一下同步即可" +
			"(内置 iptoasn 与 DB-IP 两个源,无需注册)")
	}

	mmdb := enrich.NewMMDB()
	// 优先用参数指定的;没指定则看数据目录里有没有之前上传过的。
	// 这样界面上传一次之后重启仍然生效,不需要用户再记一个路径。
	mmdbCandidate := *mmdbPath
	if mmdbCandidate == "" {
		if p := filepath.Join(*dataDir, "geoip.mmdb"); fileExists(p) {
			mmdbCandidate = p
		}
	}
	if mmdbCandidate != "" {
		if err := mmdb.Open(mmdbCandidate); err != nil {
			log.Printf("富化:加载 mmdb 失败(城市维度不可用): %v", err)
		} else {
			_, epoch, _, _ := mmdb.Info()
			log.Printf("富化:GeoLite2-City 已加载(构建于 %s)",
				time.Unix(int64(epoch), 0).Format("2006-01-02"))
		}
	}
	defer mmdb.Close()

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

	// 富化包在存储前面:sink 收到 flow 先富化再写库。
	sink := &enrichingSink{st: st, en: enrich.NewEnricher(asnDB, mmdb, cityDB)}

	var inputLabels []string

	if collector.HasMode(modes, collector.ModeLocal) {
		label := startLocal(ctx, sink, localConfig{
			iface: *iface, samplingN: *sampleN, prefer: datasource.Mode(*prefer),
		})
		inputLabels = append(inputLabels, label)
	}
	if collector.HasMode(modes, collector.ModeSFlow) {
		if l, err := startSFlow(ctx, sink, *sflowListen); err != nil {
			log.Printf("sFlow 未启动: %v", err)
		} else {
			inputLabels = append(inputLabels, l)
		}
	}
	if collector.HasMode(modes, collector.ModeNetFlow) {
		if l, err := startNetFlow(ctx, sink, *netflowListen); err != nil {
			log.Printf("NetFlow 未启动: %v", err)
		} else {
			inputLabels = append(inputLabels, l)
		}
	}

	srv := api.New(api.Config{
		Store: st, Auth: au, ASN: asnDB, MMDB: mmdb,
		City: cityDB, Syncer: syncer,
		DataDir: *dataDir, Inputs: inputLabels,
	})
	mux := http.NewServeMux()
	srv.Routes(mux)

	httpSrv := &http.Server{
		Addr: *addr, Handler: mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("ntop2ban %s 监听 %s(输入:%v)", version, *addr, inputLabels)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP 服务异常退出: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("收到退出信号,正在关闭...")
	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	// 给 ClickHouse 留出刷盘时间:不优雅停止的话下次启动要做 part 恢复。
	time.Sleep(500 * time.Millisecond)
}

// enrichingSink 在写库前做富化。
//
// 放在 sink 这一层而不是各个 collector 里:三种输入都要富化,
// 放在共同的下游只有一处实现,也保证了口径一致。
type enrichingSink struct {
	st *store.Store
	en *enrich.Enricher
}

func (s *enrichingSink) Append(ctx context.Context, batch []flow.Flow) error {
	s.en.Apply(batch)
	return s.st.Append(ctx, batch)
}

type localConfig struct {
	iface     string
	samplingN int
	prefer    datasource.Mode
}

// startLocal 启动本机采集。
//
// 失败不退出:界面与其他输入源仍然有用,而且用户需要能登进界面看到
// "本机采集没起来"这个事实。
func startLocal(ctx context.Context, sink *enrichingSink, cfg localConfig) string {
	src, err := datasource.Open(datasource.Config{
		Iface: cfg.iface, SamplingN: cfg.samplingN, Prefer: cfg.prefer, Sink: sink,
	}, nil)
	if err != nil {
		log.Printf("本机采集未启动: %v", err)
		return "local(未启动)"
	}
	go func() {
		if err := src.Run(ctx); err != nil {
			log.Printf("本机采集退出: %v", err)
		}
	}()
	go func() { <-ctx.Done(); _ = src.Close() }()
	return "local/" + string(src.Mode())
}

func startSFlow(ctx context.Context, sink *enrichingSink, listen string) (string, error) {
	src, err := collector.NewSFlowSource(collector.SFlowConfig{Listen: listen, Sink: sink})
	if err != nil {
		return "", err
	}
	log.Printf("sFlow v5 监听 %s", listen)
	go func() {
		if err := src.Run(ctx); err != nil {
			log.Printf("sFlow 退出: %v", err)
		}
	}()
	go func() { <-ctx.Done(); _ = src.Close() }()
	return "sflow" + listen, nil
}

func startNetFlow(ctx context.Context, sink *enrichingSink, listen string) (string, error) {
	src, err := collector.NewNetFlowSource(collector.NetFlowConfig{Listen: listen, Sink: sink})
	if err != nil {
		return "", err
	}
	log.Printf("NetFlow v5 监听 %s", listen)
	go func() {
		if err := src.Run(ctx); err != nil {
			log.Printf("NetFlow 退出: %v", err)
		}
	}()
	go func() { <-ctx.Done(); _ = src.Close() }()
	return "netflow" + listen, nil
}

// openStore 打开存储。指定 -clickhouse-addr 连外部实例,否则托管子进程。
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
		BinPath: bin, DataDir: filepath.Join(dataDir, "clickhouse"),
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

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}
