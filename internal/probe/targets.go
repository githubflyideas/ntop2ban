package probe

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// 目标清单文件。沿用 pingping 的格式,这样从 pingping 迁过来的用户可以
// 直接拷贝原来的清单文件。
//
// 为什么用文件而不是数据库表:探测目标是运维手写的东西,`echo host >>
// ping.list` 就能加一个,比在界面上点几下或者写 SQL 都快。pingping 当初
// 的判断在这里同样成立,不必因为 ntop2ban 有了数据库就把它改掉。
//
// 目录默认 /etc/ntop2ban/,可用 -probe-dir 覆盖(测试与非 root 部署需要)。

const (
	// DefaultDir 是清单文件的默认目录。
	DefaultDir = "/etc/ntop2ban"
	// PingListName ICMP 目标清单。
	PingListName = "ping.list"
	// TCPListName TCP 目标清单。
	TCPListName = "tcp.list"
)

// LoadTargets 读取目录下的 ping.list 与 tcp.list。
//
// 文件不存在**不是错误**:首次部署时两个文件都还没建,这时应该返回空
// 列表让程序照常启动——界面上不显示探测视图并提示用户去哪个文件里加
// 目标,而不是让整个服务起不来。这也是需求里明确要求的行为。
//
// 单行格式错误也不终止:跳过那行并把原因收集起来交给调用方记日志。
// 一个写错的目标不该让其余正确的目标也探不了。
func LoadTargets(dir string) (targets []Target, warnings []string, err error) {
	if dir == "" {
		dir = DefaultDir
	}

	icmp, w1, err := loadOne(filepath.Join(dir, PingListName), "icmp")
	if err != nil {
		return nil, nil, err
	}
	tcp, w2, err := loadOne(filepath.Join(dir, TCPListName), "tcp")
	if err != nil {
		return nil, nil, err
	}

	targets = append(icmp, tcp...)
	warnings = append(w1, w2...)

	// 名字重复会让界面上两条曲线画到一起、库里的数据互相污染。
	// 保留第一个、跳过后面的,并明确告知——静默合并会让人以为
	// 某个目标"探测结果不对"。
	seen := map[string]bool{}
	deduped := make([]Target, 0, len(targets))
	for _, t := range targets {
		if seen[t.Name] {
			warnings = append(warnings, fmt.Sprintf("目标名 %q 重复,已跳过后一个(名字是库里的主键,重复会让两条曲线混在一起)", t.Name))
			continue
		}
		seen[t.Name] = true
		deduped = append(deduped, t)
	}
	return deduped, warnings, nil
}

func loadOne(path, kind string) ([]Target, []string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil, nil // 文件不存在是正常状态,不是错误
	}
	if err != nil {
		return nil, nil, fmt.Errorf("probe: 打开 %s: %w", path, err)
	}
	defer f.Close()

	var (
		out      []Target
		warnings []string
	)
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		t, err := parseLine(line, kind)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s:%d %v", filepath.Base(path), lineNo, err))
			continue
		}
		out = append(out, t)
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("probe: 读取 %s: %w", path, err)
	}
	return out, warnings, nil
}

// parseLine 解析一行目标定义。
//
// 格式(与 pingping 一致):
//
//	ping.list:  host [name] [pace=fast|slow] [interval=秒]
//	tcp.list:   host:port [name] [pace=...] [interval=秒]
//
// name 省略时用 host 本身。pace 是预设档位,interval 是显式秒数,
// 后者优先——显式给的数字应该赢过档位,否则用户写了 interval 却不生效
// 会很困惑。
func parseLine(line, kind string) (Target, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return Target{}, fmt.Errorf("空行")
	}

	t := Target{Kind: kind}
	hostField := fields[0]

	if kind == "tcp" {
		host, portStr, ok := splitHostPort(hostField)
		if !ok {
			return Target{}, fmt.Errorf("TCP 目标 %q 缺少端口(格式 host:port)", hostField)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return Target{}, fmt.Errorf("TCP 目标 %q 端口无效", hostField)
		}
		t.Host, t.Port = host, port
	} else {
		t.Host = hostField
	}
	t.Name = t.Host
	if kind == "tcp" {
		t.Name = hostField // TCP 默认名带端口,避免同主机不同端口撞名
	}

	var paceInterval time.Duration
	for _, f := range fields[1:] {
		switch {
		case strings.HasPrefix(f, "pace="):
			switch strings.TrimPrefix(f, "pace=") {
			case "fast":
				// fast 档同时把每轮包数提到 30:快节奏链路值得更细的
				// 分布分辨率(沿用 pingping 的取值)。
				paceInterval, t.Packets = 15*time.Second, 30
			case "slow":
				paceInterval = 5 * time.Minute
			case "normal":
				paceInterval = time.Minute
			default:
				return Target{}, fmt.Errorf("未知 pace %q(可选 fast/normal/slow)", f)
			}
		case strings.HasPrefix(f, "interval="):
			sec, err := strconv.Atoi(strings.TrimPrefix(f, "interval="))
			if err != nil || sec <= 0 {
				return Target{}, fmt.Errorf("interval %q 无效", f)
			}
			t.Interval = time.Duration(sec) * time.Second
		default:
			// 不带 = 的字段是名字
			if strings.Contains(f, "=") {
				return Target{}, fmt.Errorf("无法识别的字段 %q", f)
			}
			t.Name = f
		}
	}
	// 显式 interval 优先于 pace 档位
	if t.Interval == 0 {
		t.Interval = paceInterval
	}
	return t, nil
}

// splitHostPort 按**最后**一个冒号切分 host:port。
//
// 为什么按最后一个而不是第一个:IPv6 字面量里有多个冒号
// (如 [2001:db8::1]:443 或裸写的 2001:db8::1:443),按第一个切会把
// 地址切碎,得到一个永远解析不了的主机名。这不是理论问题——用户
// 迟早会写 IPv6 目标。
func splitHostPort(s string) (host, port string, ok bool) {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	host = strings.Trim(s[:i], "[]")
	return host, s[i+1:], true
}

// ExampleFiles 返回首次部署时写入的示例清单内容。
//
// 首次启动生成带注释的示例文件(全部注释掉),用户改一行就能用——
// 比让他去读文档猜格式友好得多。全部注释掉是刻意的:自动开始探测
// 一个示例主机(比如 www.google.com)属于未经同意的外部网络行为。
func ExampleFiles() map[string]string {
	return map[string]string{
		PingListName: `# ICMP 探测目标 —— 每行一个,修改后重启生效
# 格式: host  [名字]  [pace=fast|normal|slow]  [interval=秒]
#
# pace: fast=15秒/轮(每轮30包) normal=60秒/轮 slow=300秒/轮
# interval 显式指定秒数,优先于 pace
#
# 去掉行首的 # 即可启用:
#192.168.1.1      网关        pace=fast
#8.8.8.8          Google-DNS
#203.0.113.10     分支机构     pace=slow
`,
		TCPListName: `# TCP 探测目标 —— 每行一个 host:port,修改后重启生效
# 用连接建立耗时作为 RTT;被 RST 拒绝也算"可达"(目标在线,只是端口关着),
# 与超时(丢包/不可达)区分开——混为一谈会让"服务挂了"和"网络断了"看起来一样。
#
# 格式: host:port  [名字]  [pace=fast|normal|slow]  [interval=秒]
#
# 去掉行首的 # 即可启用:
#10.0.0.5:443     API网关     interval=30
#203.0.113.20:22  备份SSH     pace=slow
`,
	}
}

// EnsureExampleFiles 目录里没有清单文件时写入示例。返回是否创建了文件。
func EnsureExampleFiles(dir string) (created []string, err error) {
	if dir == "" {
		dir = DefaultDir
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("probe: 创建目录 %s: %w", dir, err)
	}
	for name, content := range ExampleFiles() {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			continue // 已存在,绝不覆盖用户的文件
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("probe: 检查 %s: %w", p, err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			return nil, fmt.Errorf("probe: 写入 %s: %w", p, err)
		}
		created = append(created, p)
	}
	return created, nil
}
