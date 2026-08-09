package collector

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/flow"
)

// NetFlow v5 解码器。
//
// v5 是固定长度的二进制格式,没有模板协商(那是 v9/IPFIX 才有的),
// 所以解码器很短:24 字节包头 + N × 48 字节记录。自己写而不引第三方库,
// 因为引进来的那些库大多带着 v9/IPFIX 的模板缓存机制,而技术设计 §4.3
// 明确第一阶段不做 v9/IPFIX。
//
// 关键的坑是时间戳:v5 记录里的 first/last 是**设备启动以来的毫秒数**
// (sysUptime),不是绝对时间。要用包头里的 unix_secs + sysUptime 换算,
// 否则所有 flow 的时间会落在 1970 年附近——那种错误在图上表现为
// "什么数据都没有",很难想到是时间戳的问题。

const (
	netflowV5HeaderLen = 24
	netflowV5RecordLen = 48
)

// NetFlowSource 监听 UDP 收 NetFlow v5。
type NetFlowSource struct {
	conn *net.UDPConn
	sink Sink
	log  *log.Logger

	// batch 累积待写入的 flow。UDP 每个包最多 30 条记录,逐包写库会让
	// ClickHouse 收到大量小批次,产生过多小 part。
	batch    []flow.Flow
	batchCap int
	flushAt  time.Time
	flushInt time.Duration

	// 解码错误日志限流:版本配错(把 v9 发到 v5 端口)会让每个包都
	// 解码失败,不限流的话日志会以上报速率增长。
	lastLog    time.Time
	suppressed int
}

// NetFlowConfig 配置。
type NetFlowConfig struct {
	// Listen 监听地址,如 ":2055" 或 "10.0.0.5:2055"。
	Listen string
	Sink   Sink
	Logger *log.Logger
	// FlushInterval 批量写入间隔。
	FlushInterval time.Duration
	// BatchSize 批量上限。
	BatchSize int
}

func NewNetFlowSource(cfg NetFlowConfig) (*NetFlowSource, error) {
	if cfg.Sink == nil {
		return nil, errors.New("collector: NetFlow 需要 Sink")
	}
	if cfg.Listen == "" {
		cfg.Listen = fmt.Sprintf(":%d", DefaultNetFlowPort)
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 4096
	}

	addr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("collector: 解析 NetFlow 监听地址 %q: %w", cfg.Listen, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("collector: 监听 NetFlow %s 失败: %w"+
			"(端口可能被其他 collector 占用,用 -netflow-listen 换一个)", cfg.Listen, err)
	}

	// 放大接收缓冲:突发上报时内核缓冲区满了会静默丢包,而 NetFlow 是
	// UDP,丢了就没了。8MB 对应几万个包的缓冲。
	_ = conn.SetReadBuffer(8 << 20)

	return &NetFlowSource{
		conn:     conn,
		sink:     cfg.Sink,
		log:      cfg.Logger,
		batch:    make([]flow.Flow, 0, cfg.BatchSize),
		batchCap: cfg.BatchSize,
		flushInt: cfg.FlushInterval,
	}, nil
}

func (s *NetFlowSource) Name() string { return "netflow-v5" }

func (s *NetFlowSource) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *NetFlowSource) Run(ctx context.Context) error {
	buf := make([]byte, 65535)
	s.flushAt = time.Now().Add(s.flushInt)

	for {
		if ctx.Err() != nil {
			s.flush(context.Background())
			return nil
		}

		// 读超时让循环能定期检查退出信号与刷批次 —— 一个没有流量的
		// collector 不该卡在 read 上,那样进程退不掉、攒着的批次也刷不出去。
		_ = s.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, src, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if isTimeout(err) {
				s.maybeFlush(ctx)
				continue
			}
			if ctx.Err() != nil {
				s.flush(context.Background())
				return nil
			}
			return fmt.Errorf("collector: NetFlow 读取失败: %w", err)
		}

		flows, err := DecodeNetFlowV5(buf[:n], src.IP)
		if err != nil {
			// 单个畸形包不终止 collector:上游设备可能发了别的版本
			// (v9/IPFIX 发到同一个端口很常见)。记一次日志就够,
			// 每包都记会在版本配错时刷满磁盘。
			s.logOnce(err)
			continue
		}
		s.batch = append(s.batch, flows...)
		s.maybeFlush(ctx)
	}
}

func (s *NetFlowSource) maybeFlush(ctx context.Context) {
	if len(s.batch) >= s.batchCap || time.Now().After(s.flushAt) {
		s.flush(ctx)
	}
}

func (s *NetFlowSource) flush(ctx context.Context) {
	s.flushAt = time.Now().Add(s.flushInt)
	if len(s.batch) == 0 {
		return
	}
	if err := s.sink.Append(ctx, s.batch); err != nil {
		// 写失败记日志继续:采样数据允许丢,但 collector 停下来就
		// 再也没有数据了。
		s.log.Printf("[netflow] 写入 %d 条失败: %v", len(s.batch), err)
	}
	s.batch = s.batch[:0]
}

// logOnce 限流的错误日志。
func (s *NetFlowSource) logOnce(err error) {
	now := time.Now()
	if now.Sub(s.lastLog) < 30*time.Second {
		s.suppressed++
		return
	}
	if s.suppressed > 0 {
		s.log.Printf("[netflow] 解码失败: %v(另有 %d 条同类错误被抑制)", err, s.suppressed)
	} else {
		s.log.Printf("[netflow] 解码失败: %v", err)
	}
	s.lastLog, s.suppressed = now, 0
}

// DecodeNetFlowV5 解码一个 NetFlow v5 UDP 包。
//
// exporter 是上报设备的地址,用来填 Canonical Flow 的 DeviceID ——
// v5 包头里没有设备标识,只能靠源地址区分是哪台设备报的。
func DecodeNetFlowV5(pkt []byte, exporter net.IP) ([]flow.Flow, error) {
	if len(pkt) < netflowV5HeaderLen {
		return nil, fmt.Errorf("包长 %d 小于 v5 头长 %d", len(pkt), netflowV5HeaderLen)
	}

	version := binary.BigEndian.Uint16(pkt[0:2])
	if version != 5 {
		return nil, fmt.Errorf("版本 %d 不是 NetFlow v5(v9/IPFIX 当前不支持)", version)
	}

	count := int(binary.BigEndian.Uint16(pkt[2:4]))
	if count == 0 {
		return nil, nil
	}
	// v5 每包最多 30 条记录。超过这个数说明包损坏或不是 v5,
	// 不检查会让下面按 count 循环时越界。
	if count > 30 {
		return nil, fmt.Errorf("记录数 %d 超过 v5 上限 30", count)
	}
	need := netflowV5HeaderLen + count*netflowV5RecordLen
	if len(pkt) < need {
		return nil, fmt.Errorf("包长 %d 不足以容纳 %d 条记录(需要 %d)", len(pkt), count, need)
	}

	sysUptime := binary.BigEndian.Uint32(pkt[4:8])   // 设备启动至今毫秒
	unixSecs := binary.BigEndian.Uint32(pkt[8:12])   // 导出时刻秒
	unixNsecs := binary.BigEndian.Uint32(pkt[12:16]) // 导出时刻纳秒残余
	samplingRaw := binary.BigEndian.Uint16(pkt[22:24])

	// 采样率在低 14 位,高 2 位是采样模式。模式 0 表示未采样。
	samplingMode := samplingRaw >> 14
	samplingRate := uint32(samplingRaw & 0x3fff)
	if samplingMode == 0 || samplingRate == 0 {
		samplingRate = 1
	}

	// 导出时刻的绝对时间,作为换算 sysUptime 的基准。
	exportTime := time.Unix(int64(unixSecs), int64(unixNsecs))
	deviceID := ipToDeviceID(exporter)

	out := make([]flow.Flow, 0, count)
	for i := 0; i < count; i++ {
		r := pkt[netflowV5HeaderLen+i*netflowV5RecordLen:][:netflowV5RecordLen]

		f := flow.Flow{
			SrcIP:    net.IPv4(r[0], r[1], r[2], r[3]).String(),
			DstIP:    net.IPv4(r[4], r[5], r[6], r[7]).String(),
			Packets:  uint64(binary.BigEndian.Uint32(r[16:20])),
			Bytes:    uint64(binary.BigEndian.Uint32(r[20:24])),
			SrcPort:  binary.BigEndian.Uint16(r[32:34]),
			DstPort:  binary.BigEndian.Uint16(r[34:36]),
			Protocol: r[38],
			TCPFlags: uint16(r[37]),

			InputInterface:  uint32(binary.BigEndian.Uint16(r[12:14])),
			OutputInterface: uint32(binary.BigEndian.Uint16(r[14:16])),

			SamplingRate: samplingRate,
			SourceType:   flow.SourceNetFlow,
			DeviceID:     deviceID,
		}

		// first/last 是 sysUptime 相对值,换算成绝对时间。
		first := binary.BigEndian.Uint32(r[24:28])
		last := binary.BigEndian.Uint32(r[28:32])
		f.Start = uptimeToAbs(exportTime, sysUptime, first)
		f.End = uptimeToAbs(exportTime, sysUptime, last)

		// NetFlow 上报的计数已经是设备侧的实测值。按采样率还原成估算值,
		// 同时保留实测值 —— 与本机采集走同一套语义(见 flow.ApplySampling)。
		f.ApplySampling()

		out = append(out, f)
	}
	return out, nil
}

// uptimeToAbs 把 sysUptime 相对毫秒换算成绝对时间。
//
// exportTime 是包导出时刻,exportUptime 是那一刻的 sysUptime,
// 所以 (exportUptime - ts) 就是"这个事件发生在导出前多久"。
//
// 处理 uptime 回绕:sysUptime 是 uint32 毫秒,约 49.7 天就回绕一次。
// 回绕后 ts 会大于 exportUptime,直接相减得到一个巨大的正数,让 flow
// 的时间落到未来几十天。判断出这种情况就退回用导出时刻,宁可时间略有
// 偏差也不要一个明显错误的时间戳。
func uptimeToAbs(exportTime time.Time, exportUptime, ts uint32) time.Time {
	if ts == 0 || ts > exportUptime {
		return exportTime
	}
	return exportTime.Add(-time.Duration(exportUptime-ts) * time.Millisecond)
}

// ipToDeviceID 把上报设备的 IP 压成一个 uint32 作为 DeviceID。
//
// v5 包头没有设备标识,用源 IP 区分是唯一办法。IPv4 直接用 4 字节值;
// IPv6 取后 4 字节 —— 会有碰撞可能,但 device_metadata 表里存的是
// IP 到设备的映射,展示时按那张表还原,DeviceID 只是个内部键。
func ipToDeviceID(ip net.IP) uint32 {
	if ip == nil {
		return 0
	}
	if v4 := ip.To4(); v4 != nil {
		return binary.BigEndian.Uint32(v4)
	}
	b := ip.To16()
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b[12:16])
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
