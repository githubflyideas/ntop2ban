//go:build darwin

package datasource

import (
	"errors"
	"log"
)

// supportedModes 是本平台可用的观测层级。
//
// macOS 只有一级,不存在降级:XDP 需要内核里的可编程快路径,而 macOS
// 没有这种东西,也没有 AF_PACKET。保留与 Linux 相同的"尝试列表"结构而
// 不是特例化,是为了让 Open 的日志、错误汇总、-prefer 参数在两个平台上
// 表现一致——用户不需要为了看懂一条日志先知道自己在哪个系统上。
var supportedModes = []Mode{ModeBPFDevice}

var errNoSink = errors.New("datasource: 必须提供 Sink")

// Open 在 macOS 上打开 /dev/bpf 抓包。
func Open(cfg Config, lg *log.Logger) (Source, error) {
	if lg == nil {
		lg = log.Default()
	}
	if cfg.Sink == nil {
		return nil, errNoSink
	}

	var failures []error
	for _, mode := range attemptOrder(cfg.Prefer) {
		if mode != ModeBPFDevice {
			failures = append(failures, &ErrUnavailable{Mode: mode,
				Reason: errors.New("macOS 上不存在这一层级(XDP 与 AF_PACKET 是 Linux 内核接口)")})
			continue
		}
		src, err := openBPFDevice(cfg, lg)
		if err == nil {
			lg.Printf("[flow] 数据源:%s", mode.Label())
			return src, nil
		}
		failures = append(failures, err)
	}
	return nil, describeAttempts(failures)
}
