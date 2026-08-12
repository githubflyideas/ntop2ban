//go:build linux

package datasource

import (
	"errors"
	"log"
)

// supportedModes 是本平台可用的观测层级,按优先级从高到低。
var supportedModes = []Mode{ModeXDPNative, ModeXDPGeneric, ModeAFPacket}

var errNoSink = errors.New("datasource: 必须提供 Sink")

// Open 按 native → generic → af-packet 顺序尝试,返回第一个可用的数据源。
//
// 降级只发生在启动时,一次决定、之后不变。不做运行时自动切换:切换会让
// 同一时间窗口内混入两种口径的数据,流量曲线上出现无法解释的跳变,
// 而排查时没人会想到是数据源换了。
//
// 每一级失败的原因都会记录并在全部失败时一起报出——用户需要知道
// "native 因为驱动不支持、generic 因为权限不足",而不只是最后那条
// "AF_PACKET 打不开"。
func Open(cfg Config, lg *log.Logger) (Source, error) {
	if lg == nil {
		lg = log.Default()
	}
	if cfg.Sink == nil {
		return nil, errNoSink
	}

	var failures []error
	for _, mode := range attemptOrder(cfg.Prefer) {
		var (
			src Source
			err error
		)
		switch mode {
		case ModeXDPNative, ModeXDPGeneric:
			src, err = openXDP(mode, cfg, lg)
		case ModeAFPacket:
			src, err = openAFPacket(cfg, lg)
		}
		if err == nil {
			if mode != ModeXDPNative {
				// 降级要显眼:用户以为自己在跑 XDP native,实际上在
				// generic 或 AF_PACKET 上,性能差一个数量级。
				lg.Printf("[flow] 数据源降级为 %s", mode.Label())
				for _, f := range failures {
					lg.Printf("[flow]   上一级失败原因:%v", f)
				}
			} else {
				lg.Printf("[flow] 数据源:%s", mode.Label())
			}
			return src, nil
		}
		failures = append(failures, err)
	}
	return nil, describeAttempts(failures)
}
