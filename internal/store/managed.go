package store

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// Managed 是由 ntop2ban 拉起并托管的 ClickHouse 子进程。
//
// 发行包里 ntop2ban 与官方 clickhouse 静态二进制同目录,启动时自动拉起,
// 用户体验是"拷贝即用"、不需要单独安装数据库。代价明确:发行包会从
// 10MB 变成 ~200MB(压缩后),解开 771MB。这是刻意接受的取舍——
// ClickHouse 现在是唯一存储,没有兜底后端,让用户自己去装数据库就等于
// 放弃了"scp 即跑"这个产品属性。
//
// 不用 go:embed 把二进制塞进 ntop2ban 自身:那会让主二进制接近 1GB,
// 而且每次启动都要往磁盘写几百 MB 解压。
type Managed struct {
	cmd     *exec.Cmd
	dataDir string
	binPath string

	TCPPort  int
	HTTPPort int
}

// ManagedConfig 托管子进程的参数。
type ManagedConfig struct {
	// BinPath clickhouse 二进制路径。空则取 ntop2ban 同目录下的 ./clickhouse。
	BinPath string
	// DataDir 数据与配置落地目录。所有状态都在这里,删除即清空。
	DataDir string
	// TCPPort / HTTPPort 为 0 时用 9000 / 8123。允许自定义是为了避开
	// 与机器上已有 ClickHouse 的端口冲突。
	TCPPort  int
	HTTPPort int
	// MaxMemoryBytes 单查询内存上限。0 用默认。
	MaxMemoryBytes int64
}

// DefaultBinPath 返回与当前可执行文件同目录的 clickhouse 路径。
// 发行包把两个文件放一起,用户在哪解压都能找到。
func DefaultBinPath() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("store: 定位自身可执行文件: %w", err)
	}
	return filepath.Join(filepath.Dir(self), "clickhouse"), nil
}

// StartManaged 生成配置、拉起 clickhouse server,并等到能真正连上才返回。
func StartManaged(ctx context.Context, cfg ManagedConfig) (*Managed, error) {
	if cfg.BinPath == "" {
		p, err := DefaultBinPath()
		if err != nil {
			return nil, err
		}
		cfg.BinPath = p
	}
	if _, err := os.Stat(cfg.BinPath); err != nil {
		return nil, fmt.Errorf("store: 找不到 clickhouse 二进制 %q: %w"+
			"(发行包应在 ntop2ban 同目录下附带该文件;或用 -clickhouse-addr 连接外部实例)",
			cfg.BinPath, err)
	}
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("store: DataDir 不能为空")
	}
	if cfg.TCPPort == 0 {
		cfg.TCPPort = 9000
	}
	if cfg.HTTPPort == 0 {
		cfg.HTTPPort = 8123
	}

	logDir := filepath.Join(cfg.DataDir, "log")
	for _, d := range []string{cfg.DataDir, logDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, fmt.Errorf("store: mkdir %q: %w", d, err)
		}
	}

	configPath := filepath.Join(cfg.DataDir, "config.xml")
	usersPath := filepath.Join(cfg.DataDir, "users.xml")
	if err := os.WriteFile(configPath, []byte(renderServerConfig(cfg, logDir, usersPath)), 0o644); err != nil {
		return nil, fmt.Errorf("store: 写入 config.xml: %w", err)
	}
	if err := os.WriteFile(usersPath, []byte(renderUsersConfig(cfg)), 0o644); err != nil {
		return nil, fmt.Errorf("store: 写入 users.xml: %w", err)
	}

	cmd := exec.Command(cfg.BinPath, "server", "--config-file="+configPath)
	// 独立进程组:优雅退出时给整个组发信号,不会漏掉 clickhouse 内部
	// fork 出的看护进程(clickhouse-watchdog)。漏掉它的话主进程退了
	// watchdog 会把 server 再拉起来,端口一直被占着。
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := os.Create(filepath.Join(logDir, "stdout.log"))
	if err != nil {
		return nil, fmt.Errorf("store: 创建 stdout 日志: %w", err)
	}
	stderr, err := os.Create(filepath.Join(logDir, "stderr.log"))
	if err != nil {
		stdout.Close()
		return nil, fmt.Errorf("store: 创建 stderr 日志: %w", err)
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("store: 启动 clickhouse: %w", err)
	}

	m := &Managed{cmd: cmd, dataDir: cfg.DataDir, binPath: cfg.BinPath,
		TCPPort: cfg.TCPPort, HTTPPort: cfg.HTTPPort}

	if err := m.waitReady(ctx); err != nil {
		_ = m.Stop(5 * time.Second)
		return nil, err
	}
	return m, nil
}

// waitReady 轮询到能建立 native 连接为止。
//
// 用真正的连接而不是"进程还活着"作判据:server 起来到端口开始 accept
// 之间有一段初始化时间(要加载 schema、恢复 part),过早连接会
// connection refused。首次启动在慢磁盘上可能要十几秒,所以给到 60 秒。
func (m *Managed) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(60 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if m.cmd.ProcessState != nil && m.cmd.ProcessState.Exited() {
			return fmt.Errorf("store: clickhouse 在就绪前退出,检查 %s/log/stderr.log", m.dataDir)
		}
		probe, err := Open(ctx, Config{Addr: m.Addr(), Database: "default"})
		if err == nil {
			probe.Close()
			return nil
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("store: 等待 clickhouse 就绪超时(60s),检查 %s/log/stderr.log: %w",
		m.dataDir, lastErr)
}

// Addr 返回 native protocol 地址。
func (m *Managed) Addr() string { return fmt.Sprintf("127.0.0.1:%d", m.TCPPort) }

// Stop 优雅停止:先 SIGTERM 让 ClickHouse 刷盘关连接,超时再 SIGKILL。
//
// 不优雅停止的后果是下次启动要做 part 恢复,慢且可能丢掉最后一批写入。
func (m *Managed) Stop(timeout time.Duration) error {
	if m.cmd == nil || m.cmd.Process == nil {
		return nil
	}

	pgid, pgErr := syscall.Getpgid(m.cmd.Process.Pid)
	if pgErr == nil {
		_ = syscall.Kill(-pgid, syscall.SIGTERM)
	} else {
		_ = m.cmd.Process.Signal(syscall.SIGTERM)
	}

	done := make(chan error, 1)
	go func() { done <- m.cmd.Wait() }()

	select {
	case <-time.After(timeout):
		if pgErr == nil {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		} else {
			_ = m.cmd.Process.Kill()
		}
		<-done
		return fmt.Errorf("store: clickhouse 优雅停止超时,已强制杀死(下次启动会做 part 恢复)")
	case <-done:
		// Wait 对被信号终止的进程返回非 nil error,这是预期的。
		return nil
	}
}

// renderServerConfig 生成最小 config.xml。
//
// 只绑 127.0.0.1:这是随 ntop2ban 本机跑的内嵌存储,不该被外部直接触达。
// 对外的访问控制由 ntop2ban 的 web 层负责。
//
// 移除 mysql/postgresql 兼容端口与 interserver 端口:单机内嵌不需要,
// 少开端口少一分攻击面。注意 interserver_http_port 不能写成空值——
// ClickHouse 解析空字符串会报 ATTEMPT_TO_READ_AFTER_EOF 直接启动失败,
// 必须整个键都不出现。
func renderServerConfig(cfg ManagedConfig, logDir, usersPath string) string {
	return fmt.Sprintf(`<clickhouse>
    <logger>
        <level>warning</level>
        <log>%s/clickhouse-server.log</log>
        <errorlog>%s/clickhouse-server.err.log</errorlog>
        <size>100M</size>
        <count>3</count>
    </logger>
    <path>%s/</path>
    <tmp_path>%s/tmp/</tmp_path>
    <user_files_path>%s/user_files/</user_files_path>
    <listen_host>127.0.0.1</listen_host>
    <tcp_port>%d</tcp_port>
    <http_port>%d</http_port>
    <users_config>%s</users_config>
    <default_profile>default</default_profile>
    <mark_cache_size>2147483648</mark_cache_size>
    <max_server_memory_usage_to_ram_ratio>0.6</max_server_memory_usage_to_ram_ratio>
    <max_concurrent_queries>32</max_concurrent_queries>
</clickhouse>
`, logDir, logDir, cfg.DataDir, cfg.DataDir, cfg.DataDir,
		cfg.TCPPort, cfg.HTTPPort, usersPath)
}

// renderUsersConfig 生成 users.xml。
//
// 默认用户无密码但只允许回环访问,与 config.xml 里只绑 127.0.0.1 一致:
// 内嵌存储的边界防护是"根本连不上",而不是"连上了但要密码"。
//
// max_memory_usage 给上限,避免一条失控查询把整机内存吃光——这个界面
// 允许用户自由组合过滤条件,一次没加时间范围的聚合就可能扫全表。
// Query Engine 那边也强制要求时间范围与 limit,两层防护。
func renderUsersConfig(cfg ManagedConfig) string {
	mem := cfg.MaxMemoryBytes
	if mem <= 0 {
		mem = 4 << 30 // 4GB
	}
	return fmt.Sprintf(`<clickhouse>
    <profiles>
        <default>
            <max_memory_usage>%d</max_memory_usage>
            <max_execution_time>60</max_execution_time>
            <max_bytes_before_external_group_by>%d</max_bytes_before_external_group_by>
        </default>
    </profiles>
    <users>
        <default>
            <password></password>
            <networks>
                <ip>::1</ip>
                <ip>127.0.0.1</ip>
            </networks>
            <profile>default</profile>
            <quota>default</quota>
        </default>
    </users>
    <quotas><default/></quotas>
</clickhouse>
`, mem, mem/2)
}
