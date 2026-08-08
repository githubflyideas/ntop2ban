package clickhouse

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// Managed 是一个由 ntop2ban 拉起并托管其生命周期的 ClickHouse 子进程。
//
// 打包决策(v0.3):ClickHouse 不作为需要用户另行安装的外部服务,而是
// 随 ntop2ban 发布包附带官方静态二进制,由 ntop2ban 负责生成配置、启动、
// 健康检查、退出收尾——用户体验保持 xdp-ban 那种"拷贝即用"。这里只管
// 进程,建表/读写仍由 Store(native protocol 连本地 9000)负责,两者
// 职责分开:Managed 保证"有一个 ClickHouse 在本地跑着",Store 保证
// "schema 正确、能读写"。
type Managed struct {
	cmd     *exec.Cmd
	dataDir string
	binPath string

	TCPPort  int // native protocol 端口,Store 连这个
	HTTPPort int
}

// ManagedConfig 托管子进程所需的最小配置。
type ManagedConfig struct {
	// BinPath 是 clickhouse 静态二进制的路径。发布包里与 ntop2ban 同目录,
	// 默认解析为 <ntop2ban 所在目录>/clickhouse(见 DefaultBinPath)。
	BinPath string
	// DataDir 数据与配置的落地目录。所有状态都在这里,删除即清空。
	DataDir string
	// TCPPort / HTTPPort 为 0 时用默认(9000/8123)。允许自定义是为了
	// 避开与已有 ClickHouse 或其他服务的端口冲突。
	TCPPort  int
	HTTPPort int
}

// DefaultBinPath 返回与当前 ntop2ban 可执行文件同目录下的 clickhouse
// 二进制路径。发布包把两个文件放在一起,用户在哪解压都能找到。
func DefaultBinPath() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate self executable: %w", err)
	}
	return filepath.Join(filepath.Dir(self), "clickhouse"), nil
}

// StartManaged 生成配置、拉起 clickhouse server 子进程,并等待它就绪
// (通过 Store.Open 能成功连接为准,而不是仅仅进程还活着——进程活着
// 不等于端口已经在监听)。
func StartManaged(ctx context.Context, cfg ManagedConfig) (*Managed, error) {
	if cfg.BinPath == "" {
		return nil, fmt.Errorf("clickhouse managed: BinPath 不能为空")
	}
	if _, err := os.Stat(cfg.BinPath); err != nil {
		return nil, fmt.Errorf("clickhouse managed: 找不到 clickhouse 二进制 %q: %w("+
			"发布包应在 ntop2ban 同目录下附带该文件)", cfg.BinPath, err)
	}
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("clickhouse managed: DataDir 不能为空")
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
			return nil, fmt.Errorf("clickhouse managed: mkdir %q: %w", d, err)
		}
	}

	configPath := filepath.Join(cfg.DataDir, "config.xml")
	usersPath := filepath.Join(cfg.DataDir, "users.xml")
	if err := os.WriteFile(configPath, []byte(renderServerConfig(cfg, logDir, usersPath)), 0o644); err != nil {
		return nil, fmt.Errorf("clickhouse managed: write config: %w", err)
	}
	if err := os.WriteFile(usersPath, []byte(usersConfigXML), 0o644); err != nil {
		return nil, fmt.Errorf("clickhouse managed: write users config: %w", err)
	}

	cmd := exec.Command(cfg.BinPath, "server", "--config-file="+configPath)
	// 独立进程组:这样优雅退出时可以给整个组发信号,不会漏掉
	// clickhouse 内部 fork 出的看护进程(clickhouse-watchdog)。
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := os.Create(filepath.Join(logDir, "stdout.log"))
	if err != nil {
		return nil, fmt.Errorf("clickhouse managed: create stdout log: %w", err)
	}
	stderr, err := os.Create(filepath.Join(logDir, "stderr.log"))
	if err != nil {
		stdout.Close()
		return nil, fmt.Errorf("clickhouse managed: create stderr log: %w", err)
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("clickhouse managed: start: %w", err)
	}

	m := &Managed{
		cmd:      cmd,
		dataDir:  cfg.DataDir,
		binPath:  cfg.BinPath,
		TCPPort:  cfg.TCPPort,
		HTTPPort: cfg.HTTPPort,
	}

	if err := m.waitReady(ctx); err != nil {
		// 就绪失败时把已经拉起的进程收掉,不留孤儿。
		_ = m.Stop(5 * time.Second)
		return nil, err
	}
	return m, nil
}

// waitReady 轮询直到能建立 native protocol 连接或超时。用真正的连接
// 而非"进程存活"作为就绪判据:server 进程起来到端口开始 accept 之间
// 有一段初始化时间,过早连接会 connection refused。
func (m *Managed) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		// 进程若已退出,不必再等——直接把日志线索抛出来。
		if m.cmd.ProcessState != nil && m.cmd.ProcessState.Exited() {
			return fmt.Errorf("clickhouse managed: 进程在就绪前退出,检查 %s/log/stderr.log",
				m.dataDir)
		}
		probe, err := Open(ctx, Config{Addr: m.Addr(), Database: "default"})
		if err == nil {
			probe.Close()
			return nil
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("clickhouse managed: 等待就绪超时(30s): %w", lastErr)
}

// Addr 返回 native protocol 连接地址,供 Store.Open 使用。
func (m *Managed) Addr() string {
	return fmt.Sprintf("127.0.0.1:%d", m.TCPPort)
}

// Stop 优雅停止子进程:先 SIGTERM 让 ClickHouse 走正常关闭流程
// (刷盘、关连接),超时后再 SIGKILL 兜底。
func (m *Managed) Stop(timeout time.Duration) error {
	if m.cmd == nil || m.cmd.Process == nil {
		return nil
	}

	// 给整个进程组发 SIGTERM(负 PID),覆盖 clickhouse 的看护子进程。
	pgid, err := syscall.Getpgid(m.cmd.Process.Pid)
	if err == nil {
		_ = syscall.Kill(-pgid, syscall.SIGTERM)
	} else {
		_ = m.cmd.Process.Signal(syscall.SIGTERM)
	}

	done := make(chan error, 1)
	go func() { done <- m.cmd.Wait() }()

	select {
	case <-time.After(timeout):
		if pgid, err := syscall.Getpgid(m.cmd.Process.Pid); err == nil {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		} else {
			_ = m.cmd.Process.Kill()
		}
		<-done
		return fmt.Errorf("clickhouse managed: 优雅停止超时,已强制杀死")
	case err := <-done:
		// Wait 对被信号终止的进程会返回非 nil error,这是预期的,不算失败。
		_ = err
		return nil
	}
}
