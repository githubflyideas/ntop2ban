// Package knock 实现单向"敲门"授权:客户端按预设顺序发出几个探测包,
// 全部命中后守护进程为该来源 IP 临时放行受保护端口(如 SSHd)。
//
// 设计要点与被否决的替代方案:
//
//   - **混合序列,只用 TCP 与 ICMP,不用 UDP。** 一个序列可以是
//     "TCP 9001 → ICMP 长度 56 → TCP 9003 → ICMP 长度 90"。用户在平台上
//     自行设定。不用 UDP 是因为很多客户端环境发不出去(出口设备直接丢)。
//     这样敲门只需要系统自带的 telnet/nc 与 ping,不需要任何自制客户端。
//
//   - **暗号固定,不做轮换。** 曾设计过按 30 秒时间窗用 HMAC 轮换 ICMP
//     包长,被否决:用户得先去某处查当前值才能敲门,而那个"某处"往往也
//     在敲门保护之后,鸡生蛋。接受的代价是被抓包后可重放——但真正要防的
//     是全网扫描器,它永远猜不中这个序列;而能在链路上抓包的对手已经是
//     中间人,敲门本来也救不了,那时靠的是 SSH 自身的密钥认证。
//
//   - **不走 eBPF 采样路径。** 采样是 1/N 的,大部分敲门包根本不会被采到。
//     安全判定必须走精确捕获的独立数据路径,这与"采样只服务可视化"是
//     同一条原则。
//
//   - **只记成功,不记失败。** 失败的敲门就是互联网噪声,记下来只会淹没
//     审计日志;成功授权才是需要追溯的事实。
package knock

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// StepKind 是一步敲门的类型。
type StepKind string

const (
	// StepTCP 对某个端口发起 TCP 连接(只看 SYN,不需要对端接受)。
	// 客户端用 `telnet host port` 或 `nc -z host port` 即可。
	StepTCP StepKind = "tcp"
	// StepICMP 发一个特定 payload 长度的 ICMP echo。
	// 客户端用 `ping -s <len> -c 1 host`。
	StepICMP StepKind = "icmp"
)

// Step 是序列中的一步。
//
// TCP 步用 Port;ICMP 步用 PayloadLen。两者互斥,由 Kind 决定看哪个字段。
type Step struct {
	Kind StepKind `json:"kind"`
	// Port 仅 StepTCP 使用:要敲的目的端口。
	Port int `json:"port,omitempty"`
	// PayloadLen 仅 StepICMP 使用:ping 的 payload 字节数,
	// 即 `ping -s` 的参数值。
	PayloadLen int `json:"payload_len,omitempty"`
}

func (s Step) String() string {
	switch s.Kind {
	case StepTCP:
		return "tcp/" + strconv.Itoa(s.Port)
	case StepICMP:
		return "icmp/len=" + strconv.Itoa(s.PayloadLen)
	default:
		return "invalid"
	}
}

// ClientHint 返回这一步对应的客户端命令,直接显示在界面上供复制。
// 让用户看到"要敲什么"而不必理解协议细节。
func (s Step) ClientHint(host string) string {
	switch s.Kind {
	case StepTCP:
		return fmt.Sprintf("nc -z -w1 %s %d", host, s.Port)
	case StepICMP:
		return fmt.Sprintf("ping -s %d -c 1 %s", s.PayloadLen, host)
	default:
		return ""
	}
}

// Sequence 是一次完整的敲门序列定义。
type Sequence struct {
	Steps []Step `json:"steps"`

	// Window 是整个序列必须完成的时限。超时则该来源的进度清零,
	// 必须从第一步重来。
	Window time.Duration `json:"window"`

	// OpenPort 敲门成功后为来源 IP 放行的端口(通常是 22)。
	OpenPort int `json:"open_port"`

	// OpenFor 放行持续时间。够建立连接即可——连接建立之后的会话不受
	// 影响(放行只针对新建连接),所以这个值不需要覆盖整个会话时长。
	OpenFor time.Duration `json:"open_for"`
}

// DefaultConfigDir 是配置清单的默认目录。与探测清单同一个目录,
// 用户只需要记住"配置都在 /etc/ntop2ban/*.list"。
const DefaultConfigDir = "/etc/ntop2ban"

// ErrNoKnockList 表示清单文件不存在。单独定义以便调用方区分
// "还没配置"(正常的首次启动状态)与"配置有问题"。
var ErrNoKnockList = errors.New("knock: 清单文件不存在")

// DefaultWindow 是序列的默认完成时限。
//
// 一分钟:够手工敲完四五步(每步一条命令),又短到让重放窗口没有实际
// 价值。设长了没有额外便利,只是让半途而废的进度在内存里多留一会儿。
const DefaultWindow = time.Minute

// DefaultOpenFor 默认放行时长。60 秒够 SSH 完成 TCP 握手与认证。
const DefaultOpenFor = 60 * time.Second

// Validate 检查序列定义是否可用。
//
// 这些限制不是形式主义,每条都对应一种会让敲门在生产上出问题的配置:
func (seq Sequence) Validate() error {
	if len(seq.Steps) < 2 {
		return fmt.Errorf("序列至少需要 2 步(1 步等于把端口直接暴露给任何扫到它的人)")
	}
	if len(seq.Steps) > 8 {
		return fmt.Errorf("序列最多 8 步,当前 %d 步(手工敲门步数过多容易出错,且无助于安全)", len(seq.Steps))
	}

	for i, st := range seq.Steps {
		switch st.Kind {
		case StepTCP:
			if st.Port < 1 || st.Port > 65535 {
				return fmt.Errorf("第 %d 步:TCP 端口 %d 越界", i+1, st.Port)
			}
			if st.Port == seq.OpenPort {
				return fmt.Errorf("第 %d 步:敲门端口不能等于要放行的端口 %d"+
					"(否则敲门本身就在访问被保护端口,自相矛盾)", i+1, seq.OpenPort)
			}
		case StepICMP:
			// ping -s 的下限:低于 8 字节放不下时间戳,各平台行为不一;
			// 上限留在 1400 以内,避免在常见 1500 MTU 链路上分片——
			// 分片后的 ICMP 到达时长度已变,敲门必然失败且极难排查。
			if st.PayloadLen < 8 || st.PayloadLen > 1400 {
				return fmt.Errorf("第 %d 步:ICMP payload 长度 %d 超出可用范围 8-1400"+
					"(过小各平台行为不一致,过大会在 1500 MTU 链路上分片,分片后长度改变必然敲不开)",
					i+1, st.PayloadLen)
			}
		default:
			return fmt.Errorf("第 %d 步:未知类型 %q(只支持 tcp 与 icmp;"+
				"不支持 udp,因为很多客户端出口环境发不出 UDP)", i+1, st.Kind)
		}
	}

	// 相邻两步完全相同会让状态机无法区分"第二步到了"还是"第一步重发了"——
	// 网络重传很常见,这种序列在真实链路上行为不可预测。
	for i := 1; i < len(seq.Steps); i++ {
		if seq.Steps[i] == seq.Steps[i-1] {
			return fmt.Errorf("第 %d 步与第 %d 步完全相同(%s):"+
				"网络重传会让状态机无法分辨是下一步还是上一步的重发,请改成不同的端口或长度",
				i, i+1, seq.Steps[i])
		}
	}

	if seq.OpenPort < 1 || seq.OpenPort > 65535 {
		return fmt.Errorf("放行端口 %d 越界", seq.OpenPort)
	}
	if seq.Window <= 0 {
		return fmt.Errorf("序列完成时限必须为正数")
	}
	if seq.OpenFor <= 0 {
		return fmt.Errorf("放行时长必须为正数")
	}
	return nil
}

// ClientScript 返回完整的敲门操作步骤,供界面展示给用户复制执行。
func (seq Sequence) ClientScript(host string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 依次执行,%s 内完成:\n", seq.Window)
	for i, st := range seq.Steps {
		fmt.Fprintf(&b, "%s          # 第 %d 步\n", st.ClientHint(host), i+1)
	}
	fmt.Fprintf(&b, "# 成功后 %s 内可连接端口 %d\n", seq.OpenFor, seq.OpenPort)
	return b.String()
}
