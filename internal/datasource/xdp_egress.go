//go:build linux

package datasource

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// 出向采集。
//
// XDP 只挂在接收路径上,发出去的包压根不经过它 —— 只挂 XDP 的话上传流量
// 会系统性缺失,而且不报错,图上只是看着比实际空闲。出向要另找钩子,
// 内核给的两个都不完美:
//
//   - TCX(clsact egress):按网卡挂,语义与 XDP 对称,转发的包也看得见。
//     但要内核 >= 6.6,而 Debian 12 是 6.1、Ubuntu 22.04 是 5.15。
//   - cgroup_skb/egress:内核 >= 4.10,几乎哪都能挂。但它挂在 cgroup 上、
//     在 IP 层,只看得见**本机进程发出**的包(转发的看不见),而且所有网卡
//     的包都会经过,得自己按 ifindex 过滤。
//
// 所以先试 TCX,不行退到 cgroup。两个都不行只警告不退出:入向数据仍然
// 是完整的,少一半方向也比整个采集起不来强 —— 但必须说清楚,不然用户
// 拿着一张只有下载没有上传的图去做判断。
const (
	egressHookTCX    = "TCX"
	egressHookCgroup = "cgroup_skb/egress"
)

// attachEgress 挂出向程序,返回挂上的钩子名。
//
// 返回的 error 供调用方打警告,不作为致命错误 —— 见上面的说明。
func (s *xdpSource) attachEgress(ifIndex int) (string, error) {
	tcProg := s.coll.Programs["tc_egress_sampler"]
	cgProg := s.coll.Programs["cgroup_egress_sampler"]

	var errs []error

	if tcProg != nil {
		lnk, err := link.AttachTCX(link.TCXOptions{
			Program:   tcProg,
			Attach:    ebpf.AttachTCXEgress,
			Interface: ifIndex,
		})
		if err == nil {
			s.egressLnk = lnk
			return egressHookTCX, nil
		}
		errs = append(errs, fmt.Errorf("TCX: %w(内核 <6.6 不支持)", err))
	} else {
		errs = append(errs, errors.New("TCX: bytecode 里没有 tc_egress_sampler 程序"))
	}

	if cgProg != nil {
		root, err := cgroup2Root()
		if err != nil {
			errs = append(errs, fmt.Errorf("cgroup: %w", err))
			return "", errors.Join(errs...)
		}
		// ifindex 必须在 attach 之前写进 map:cgroup 程序对所有网卡的出向
		// 包都会被调用,map 里是 0 时它什么都不采。反过来说,先 attach 再
		// 写会漏掉中间那一小段,不致命但没必要。
		if err := s.setEgressIfindex(ifIndex); err != nil {
			errs = append(errs, fmt.Errorf("cgroup: %w", err))
			return "", errors.Join(errs...)
		}
		lnk, err := link.AttachCgroup(link.CgroupOptions{
			Path:    root,
			Attach:  ebpf.AttachCGroupInetEgress,
			Program: cgProg,
		})
		if err == nil {
			s.egressLnk = lnk
			return egressHookCgroup, nil
		}
		errs = append(errs, fmt.Errorf("cgroup(%s): %w", root, err))
	} else {
		errs = append(errs, errors.New("cgroup: bytecode 里没有 cgroup_egress_sampler 程序"))
	}

	return "", errors.Join(errs...)
}

func (s *xdpSource) setEgressIfindex(ifIndex int) error {
	m := s.coll.Maps["egress_ifindex"]
	if m == nil {
		return errors.New("bytecode 缺少 egress_ifindex map(与本程序版本不匹配)")
	}
	var idx uint32
	if err := m.Put(idx, uint32(ifIndex)); err != nil {
		return fmt.Errorf("写入出向 ifindex: %w", err)
	}
	return nil
}

// cgroup2Root 找 cgroup v2 的挂载点。
//
// 不写死 /sys/fs/cgroup:多数发行版是那里(统一层级),但混合层级下
// cgroup2 会挂在 /sys/fs/cgroup/unified,而纯 cgroup v1 的机器上根本
// 没有 cgroup2 —— 那时要给出"你的系统没有 cgroup2"这种能看懂的原因,
// 而不是一个 ENOENT。
func cgroup2Root() (string, error) {
	const mounts = "/proc/self/mounts"
	b, err := os.ReadFile(mounts)
	if err != nil {
		return "", fmt.Errorf("读 %s: %w", mounts, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		// 格式:device mountpoint fstype options ...
		if len(f) >= 3 && f[2] == "cgroup2" {
			return f[1], nil
		}
	}
	return "", errors.New("系统里没有挂载 cgroup2(纯 cgroup v1 的内核用不了这条退路)")
}

// loadCollection 加载 bytecode,并在 verifier 拒掉出向程序时逐级降级。
//
// ebpf.NewCollection 是全有全无的:三个程序里任何一个过不了 verifier,
// 整个 collection 都建不起来,连入向 XDP 一起陪葬。而出向那两个程序恰恰
// 是最可能被拒的 —— gso_segs 要 5.8、sched_cls 的字段可访问范围各版本
// 不同、cgroup_skb 允许读的字段更窄。为了不让"多采一个方向"这件事有
// 机会打掉本来能用的入向采集,这里按 完整 -> 去掉 cgroup -> 再去掉 tc
// 的顺序重试,每一级都重新 loadSpec,因为 NewCollection 会改写 spec、
// 用过的 spec 不能再用第二次。
func loadCollection(lg *log.Logger) (*ebpf.Collection, error) {
	// 每一级要去掉的程序,按"先舍弃谁"排序。
	tiers := [][]string{
		nil,
		{"cgroup_egress_sampler"},
		{"cgroup_egress_sampler", "tc_egress_sampler"},
	}

	var firstErr error
	for _, drop := range tiers {
		spec, err := loadSpec()
		if err != nil {
			return nil, err
		}
		for _, name := range drop {
			delete(spec.Programs, name)
		}
		coll, err := ebpf.NewCollection(spec)
		if err == nil {
			if len(drop) > 0 {
				lg.Printf("[flow] 内核拒绝加载出向程序(%s),已跳过它继续:%v",
					strings.Join(drop, "、"), firstErr)
			}
			return coll, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, fmt.Errorf("加载 eBPF 程序: %w", firstErr)
}

// attachEgressOrWarn 挂出向程序,失败只警告。
//
// 不作为致命错误:入向数据是完整的,少一个方向也比整个采集起不来强。
// 但警告必须说清后果和两条出路,否则用户会拿着一张只有下载没有上传的
// 图去判断带宽。
func (s *xdpSource) attachEgressOrWarn(iface string) {
	ifi, err := interfaceByName(iface)
	if err != nil {
		s.log.Printf("[flow] 出向采集未启用:%v", err)
		return
	}
	hook, err := s.attachEgress(ifi.Index)
	if err != nil {
		s.log.Printf("[flow] 出向采集未启用,统计里只有下载、没有上传。原因:%v。"+
			"两条出路:把内核升到 6.6 以上用 TCX,或改用 -datasource af-packet"+
			"(双向都看得见,代价是没有 XDP 那样的内核态抽样)", err)
		return
	}
	s.egressHook = hook
	s.log.Printf("[flow] 出向采集已挂到 %s(%s)", iface, hook)
}
