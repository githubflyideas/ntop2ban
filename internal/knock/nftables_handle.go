package knock

import (
	"bufio"
	"net"
	"os/exec"
	"strings"
)

// findHandle 查出某条放行规则的 handle。
//
// nftables 删除规则必须按 handle,不能像 iptables 那样按匹配内容删
// (`iptables -D` 可以重复匹配串,`nft delete rule` 只接受 handle)。
// 所以这里 list 出链内容,找出匹配 saddr+dport 的那一行再取其 handle。
func (o *NFTOpener) findHandle(src net.IP, port int) (string, error) {
	bin := o.NFTPath
	if bin == "" {
		bin = "nft"
	}
	out, err := exec.Command(bin, "-a", "list", "chain", "inet", o.Table, o.Chain).Output()
	if err != nil {
		return "", err
	}
	return scanHandle(string(out), src.String(), port), nil
}

// scanHandle 从 `nft -a list chain` 的输出里找出目标规则的 handle。
//
// 拆成独立函数是为了能在没有 nft 的机器上测试解析逻辑——nft 输出格式
// 的解析是这段代码最容易出错也最难在生产上发现问题的地方:handle 取错
// 会删掉别人的规则,取不到则规则永久残留。
func scanHandle(nftOutput, srcIP string, port int) string {
	sc := bufio.NewScanner(strings.NewReader(nftOutput))
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, srcIP) || !hasDPort(line, port) {
			continue
		}
		if !strings.Contains(line, "ntop2ban-knock") {
			// 只删自己打了标记的规则。没有这个检查,用户手工加的
			// 恰好同源同端口的规则会被我们删掉。
			continue
		}
		if h := handleOf(line); h != "" {
			return h
		}
	}
	return ""
}

// hasDPort 判断这一行的 dport 是否恰好等于 port。
//
// 不能用裸的 strings.Contains("dport 22"):那会匹配到 "dport 2222",
// 于是删规则时删错一条——被删的是另一个端口的放行规则,而目标规则
// 永久残留。所以必须检查数字后面是边界(空白或行尾)。
func hasDPort(line string, port int) bool {
	tok := "dport " + itoa(port)
	i := strings.Index(line, tok)
	if i < 0 {
		return false
	}
	rest := line[i+len(tok):]
	if rest == "" {
		return true
	}
	c := rest[0]
	return c == ' ' || c == '\t'
}

func handleOf(line string) string {
	const marker = "# handle "
	i := strings.Index(line, marker)
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(line[i+len(marker):])
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
