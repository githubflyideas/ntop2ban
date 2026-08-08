package knock

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// 敲门序列的清单文件。格式与 pingping 的 ping.list 同一路数:纯文本、
// 一行一步、# 注释、改完重启生效。
//
// 为什么不用数据库:序列就是几行配置,而且 v0.2 已经把审批流删掉了
// (单机单用户,不需要提交/审批/驳回那套生命周期)。放文件里
// `vi /etc/ntop2ban/knock.list` 就能改,比建一张表、写一套 CRUD、
// 再在界面上做表单要直接得多。这也和探测目标清单的做法保持一致,
// 用户只需要记住一个规律:配置都在 /etc/ntop2ban/*.list。

const (
	// KnockListName 是序列清单文件名。
	KnockListName = "knock.list"
)

// DefaultSteps 是默认序列:tcp 9001 → icmp len 123 → tcp 9002 → icmp len 145。
//
// 给一套能直接用的默认值而不是留空:留空的话首次启动敲门就是关闭的,
// 用户得先读文档才知道怎么开;给默认值则装上就能用,想换再改。
// 四步(两 TCP 两 ICMP)也顺带演示了混合序列的写法。
func DefaultSteps() []Step {
	return []Step{
		{Kind: StepTCP, Port: 9001},
		{Kind: StepICMP, PayloadLen: 123},
		{Kind: StepTCP, Port: 9002},
		{Kind: StepICMP, PayloadLen: 145},
	}
}

// DefaultSequence 返回带默认时限与放行参数的完整序列。
func DefaultSequence() Sequence {
	return Sequence{
		Steps:    DefaultSteps(),
		Window:   DefaultWindow,
		OpenPort: 22,
		OpenFor:  DefaultOpenFor,
	}
}

// LoadSequence 从 dir/knock.list 读取序列。
//
// 文件不存在返回 ErrNoKnockList,由调用方决定是写入默认清单还是禁用
// 敲门——这个包不该擅自往用户的 /etc 里写东西。
func LoadSequence(dir string) (Sequence, error) {
	if dir == "" {
		dir = DefaultConfigDir
	}
	path := filepath.Join(dir, KnockListName)

	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return Sequence{}, ErrNoKnockList
	}
	if err != nil {
		return Sequence{}, fmt.Errorf("knock: 打开 %s: %w", path, err)
	}
	defer f.Close()

	seq := Sequence{
		Window:   DefaultWindow,
		OpenPort: 22,
		OpenFor:  DefaultOpenFor,
	}

	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := applyLine(&seq, line); err != nil {
			// 单行错误直接失败而不是跳过:序列的每一步都是必需的,
			// 跳过一步会静默地把 4 步序列变成 3 步——那是个能被更容易
			// 猜到的序列,属于安全问题,不能只记个警告了事。
			return Sequence{}, fmt.Errorf("knock: %s:%d %w", KnockListName, lineNo, err)
		}
	}
	if err := sc.Err(); err != nil {
		return Sequence{}, fmt.Errorf("knock: 读取 %s: %w", path, err)
	}

	if err := seq.Validate(); err != nil {
		return Sequence{}, fmt.Errorf("knock: %s 内容不合法: %w", KnockListName, err)
	}
	return seq, nil
}

// applyLine 解析一行。支持两类:
//
//	步骤行:  tcp 9001        /  icmp 123
//	参数行:  open-port 22    /  window 60   /  open-for 60
//
// 参数用同一个文件而不是单独的配置文件:序列与"敲开什么、开多久"是
// 一件事,分成两个文件只会让人改了一个忘了另一个。
func applyLine(seq *Sequence, line string) error {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return fmt.Errorf("格式应为 `<类型> <值>`,得到 %q", line)
	}
	key, val := strings.ToLower(fields[0]), fields[1]

	switch key {
	case "tcp":
		port, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("TCP 端口 %q 不是数字", val)
		}
		seq.Steps = append(seq.Steps, Step{Kind: StepTCP, Port: port})

	case "icmp":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("ICMP 长度 %q 不是数字", val)
		}
		seq.Steps = append(seq.Steps, Step{Kind: StepICMP, PayloadLen: n})

	case "udp":
		// 明确报错而不是当成未知字段:用户会自然地想试 UDP,
		// 给出理由比"未知类型"有用得多。
		return fmt.Errorf("不支持 UDP 敲门步:很多客户端出口环境发不出 UDP," +
			"而一个静默不到达的敲门步是最难排查的故障")

	case "open-port":
		port, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("open-port %q 不是数字", val)
		}
		seq.OpenPort = port

	case "window":
		sec, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("window %q 不是数字(单位秒)", val)
		}
		seq.Window = time.Duration(sec) * time.Second

	case "open-for":
		sec, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("open-for %q 不是数字(单位秒)", val)
		}
		seq.OpenFor = time.Duration(sec) * time.Second

	default:
		return fmt.Errorf("未知配置项 %q(可用:tcp / icmp / open-port / window / open-for)", key)
	}
	return nil
}

// ExampleList 返回默认清单内容。
//
// 与探测清单不同,这份是**未注释、直接生效**的:敲门默认开启才有意义
// (装上就藏起 SSH 端口),而探测默认去 ping 一个示例主机属于未经同意
// 的外部行为,那个必须注释掉。
func ExampleList() string {
	return `# ntop2ban 敲门序列 —— 改完重启生效
#
# 按顺序依次敲对全部步骤,才会为你的来源 IP 放行 open-port。
# 步骤类型只有两种(不支持 UDP:很多客户端出口环境发不出去,
# 而一个静默不到达的敲门步是最难排查的故障):
#
#   tcp  <端口>      客户端用:nc -z -w1 <主机> <端口>
#   icmp <payload长度>  客户端用:ping -s <长度> -c 1 <主机>
#
# 相邻两步不能相同(网络重传会让判定分不清是下一步还是上一步的重发)。
# ICMP 长度范围 8-1400:再大会在 1500 MTU 链路上分片,而分片后长度
# 改变,必然敲不开且没有任何线索。

tcp  9001
icmp 123
tcp  9002
icmp 145

# 敲开哪个端口、整个序列的时限(秒)、放行多久(秒)
open-port 22
window    60
open-for  60
`
}

// EnsureList 清单不存在时写入默认内容。返回是否创建了文件。
//
// 绝不覆盖已存在的文件:那会把用户配好的序列换成默认的,而默认序列是
// 公开的——等于悄悄把门锁换成了所有人都知道的那把。
func EnsureList(dir string) (created bool, path string, err error) {
	if dir == "" {
		dir = DefaultConfigDir
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, "", fmt.Errorf("knock: 创建目录 %s: %w", dir, err)
	}
	path = filepath.Join(dir, KnockListName)

	if _, err := os.Stat(path); err == nil {
		return false, path, nil
	} else if !os.IsNotExist(err) {
		return false, path, fmt.Errorf("knock: 检查 %s: %w", path, err)
	}

	// 0600 而不是 0644:序列就是密码,不该让机器上的其他用户读到。
	// 探测清单里都是公开的主机名,那个 0644 无所谓,这个不行。
	if err := os.WriteFile(path, []byte(ExampleList()), 0o600); err != nil {
		return false, path, fmt.Errorf("knock: 写入 %s: %w", path, err)
	}
	return true, path, nil
}
