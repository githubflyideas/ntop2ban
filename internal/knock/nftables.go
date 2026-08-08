package knock

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

// NFTOpener 用 nftables 实现放行:敲门成功后插一条 accept 规则,
// 到期删掉。
//
// 为什么这里用 nftables 而不是 XDP/eBPF map(xdp-ban 封禁走的是那条路):
// 那条结论说的是**大流量攻击的丢包路径**,性能敏感,XDP 在驱动层丢包
// 的优势不可替代。敲门放行是完全不同的量级——每分钟最多几次规则增删,
// nftables 完全够用,而且不需要任何内核编程、不占用网卡的 XDP 挂载点
// (那个位置在同机部署时属于 xdp-ban)。
//
// 规则放在自建的 table/chain 里,不碰用户已有的规则集:直接往
// filter/INPUT 里插会与用户自己的防火墙管理(firewalld/ufw/ansible)
// 打架——它们 reload 时会把我们的规则冲掉,而且冲掉时不会有任何提示。
type NFTOpener struct {
	// Table/Chain 自建的表与链名。
	Table string
	Chain string

	// nft 可执行文件路径。留空则从 PATH 查找。
	NFTPath string

	mu      sync.Mutex
	timers  map[string]*time.Timer
	ensured bool
}

// NewNFTOpener 构造 nftables 放行器。
func NewNFTOpener() *NFTOpener {
	return &NFTOpener{
		Table:  "ntop2ban",
		Chain:  "knock",
		timers: make(map[string]*time.Timer),
	}
}

func (o *NFTOpener) nft(args ...string) error {
	bin := o.NFTPath
	if bin == "" {
		bin = "nft"
	}
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %v: %w: %s", args, err, string(out))
	}
	return nil
}

// EnsureChain 建表建链。幂等,可重复调用。
//
// 链的 policy 是 accept 而不是 drop:这条链只负责"额外放行"敲门通过的
// 来源,不负责阻断。如果 policy 设成 drop,那么在敲门守护进程挂掉或
// 规则没建好的瞬间,所有流量都会被这条链吞掉——一个观测/授权组件
// 不该有把整机网络打死的能力。真正的默认阻断由用户自己的防火墙负责。
func (o *NFTOpener) EnsureChain() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.ensured {
		return nil
	}
	if err := o.nft("add", "table", "inet", o.Table); err != nil {
		return err
	}
	// priority 用 -10:比常规 filter(0)更早,这样放行在用户的 drop
	// 规则之前生效。否则用户 INPUT 里先 drop 掉,我们的 accept 永远轮不到。
	if err := o.nft("add", "chain", "inet", o.Table, o.Chain,
		"{ type filter hook input priority -10 ; policy accept ; }"); err != nil {
		return err
	}
	o.ensured = true
	return nil
}

// Open 为 src 放行 port,持续 d。
//
// 同一个来源重复敲门时重置计时器而不是叠加规则:叠加会让规则表随着
// 敲门次数无限增长,而且删除时容易删错一条留下另一条。
func (o *NFTOpener) Open(src net.IP, port int, d time.Duration) error {
	if err := o.EnsureChain(); err != nil {
		return err
	}

	key := src.String() + "/" + strconv.Itoa(port)

	o.mu.Lock()
	if t, ok := o.timers[key]; ok {
		// 已经放行过:重置到期时间,不再插重复规则。
		t.Reset(d)
		o.mu.Unlock()
		return nil
	}
	o.mu.Unlock()

	if err := o.addRule(src, port); err != nil {
		return err
	}

	o.mu.Lock()
	o.timers[key] = time.AfterFunc(d, func() {
		o.mu.Lock()
		delete(o.timers, key)
		o.mu.Unlock()
		if err := o.delRule(src, port); err != nil {
			// 删除失败要显眼:规则残留意味着这个来源被长期放行,
			// 是个安全问题,不能静默。
			fmt.Printf("[knock] 警告:回收放行规则失败 src=%s port=%d: %v\n", src, port, err)
		}
	})
	o.mu.Unlock()
	return nil
}

// ruleArgs 构造规则的匹配部分。带 comment 便于运维在 `nft list ruleset`
// 里认出这是谁加的——没有注释的临时规则会让人不敢删。
func (o *NFTOpener) ruleArgs(src net.IP, port int) []string {
	family := "ip"
	if src.To4() == nil {
		family = "ip6"
	}
	return []string{
		family, "saddr", src.String(),
		"tcp", "dport", strconv.Itoa(port),
		"accept",
		"comment", "\"ntop2ban-knock\"",
	}
}

func (o *NFTOpener) addRule(src net.IP, port int) error {
	args := append([]string{"add", "rule", "inet", o.Table, o.Chain}, o.ruleArgs(src, port)...)
	return o.nft(args...)
}

// delRule 删除规则。nft 没有"按内容删除"的直接语法,需要先查 handle
// 再按 handle 删——这是 nftables 与 iptables 的一个显著差异,
// iptables 可以 -D 同样的匹配串,nft 不行。
func (o *NFTOpener) delRule(src net.IP, port int) error {
	handle, err := o.findHandle(src, port)
	if err != nil {
		return err
	}
	if handle == "" {
		return nil // 已经不在了,视为成功
	}
	return o.nft("delete", "rule", "inet", o.Table, o.Chain, "handle", handle)
}

// Close 撤销所有仍在生效的放行,并删掉自建的表。
//
// 进程退出时必须清理:残留的 accept 规则会让某个来源在服务停止后
// 仍然被永久放行——而那时已经没有任何组件会去回收它了。
func (o *NFTOpener) Close() error {
	o.mu.Lock()
	for k, t := range o.timers {
		t.Stop()
		delete(o.timers, k)
	}
	ensured := o.ensured
	o.mu.Unlock()

	if !ensured {
		return nil
	}
	// 直接删整张表:比逐条删规则更可靠,也顺带清掉任何因为崩溃残留的规则。
	return o.nft("delete", "table", "inet", o.Table)
}
