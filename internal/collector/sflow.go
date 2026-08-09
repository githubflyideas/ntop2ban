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

// sFlow v5 解码器。
//
// 与 NetFlow 的本质区别:sFlow 送的是**采样到的原始包头**,不是设备侧
// 聚合好的 flow 记录。所以解码流程是"拆 sFlow 封装 → 拿到以太网帧 →
// 用 internal/flow 那份共用解析拆出五元组"。这也是为什么包解析要提到
// 公共位置:sFlow 与本机 AF_PACKET 抓到的东西在这一步之后完全同构。
//
// sFlow 的结构是嵌套的:datagram → samples → flow records → raw packet
// header。每一层都有长度字段,而且都是 XDR 编码(4 字节对齐、大端)。
// 逐层校验长度不是防御性编程,是必需的——上游设备的实现质量差异很大,
// 而一个长度字段读错会让后面所有偏移全错。

const (
	sflowV5Version = 5

	// sample_type 的枚举值。
	sflowFlowSample         = 1
	sflowCounterSample      = 2
	sflowFlowSampleExpanded = 3

	// flow record 的 format 值。
	sflowRawPacketHeader = 1

	// header_protocol 的枚举值。
	sflowHeaderEthernet = 1
	sflowHeaderIPv4     = 11
)

// SFlowSource 监听 UDP 收 sFlow v5。
type SFlowSource struct {
	conn *net.UDPConn
	sink Sink
	log  *log.Logger

	batch    []flow.Flow
	batchCap int
	flushAt  time.Time
	flushInt time.Duration

	lastLog    time.Time
	suppressed int
}

// SFlowConfig 配置。
type SFlowConfig struct {
	Listen        string
	Sink          Sink
	Logger        *log.Logger
	FlushInterval time.Duration
	BatchSize     int
}

func NewSFlowSource(cfg SFlowConfig) (*SFlowSource, error) {
	if cfg.Sink == nil {
		return nil, errors.New("collector: sFlow 需要 Sink")
	}
	if cfg.Listen == "" {
		cfg.Listen = fmt.Sprintf(":%d", DefaultSFlowPort)
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
		return nil, fmt.Errorf("collector: 解析 sFlow 监听地址 %q: %w", cfg.Listen, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("collector: 监听 sFlow %s 失败: %w"+
			"(端口可能被其他 collector 占用,用 -sflow-listen 换一个)", cfg.Listen, err)
	}
	_ = conn.SetReadBuffer(8 << 20)

	return &SFlowSource{
		conn:     conn,
		sink:     cfg.Sink,
		log:      cfg.Logger,
		batch:    make([]flow.Flow, 0, cfg.BatchSize),
		batchCap: cfg.BatchSize,
		flushInt: cfg.FlushInterval,
	}, nil
}

func (s *SFlowSource) Name() string { return "sflow-v5" }

func (s *SFlowSource) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *SFlowSource) Run(ctx context.Context) error {
	buf := make([]byte, 65535)
	s.flushAt = time.Now().Add(s.flushInt)

	for {
		if ctx.Err() != nil {
			s.flush(context.Background())
			return nil
		}
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
			return fmt.Errorf("collector: sFlow 读取失败: %w", err)
		}

		flows, err := DecodeSFlowV5(buf[:n], src.IP)
		if err != nil {
			s.logOnce(err)
			continue
		}
		s.batch = append(s.batch, flows...)
		s.maybeFlush(ctx)
	}
}

func (s *SFlowSource) maybeFlush(ctx context.Context) {
	if len(s.batch) >= s.batchCap || time.Now().After(s.flushAt) {
		s.flush(ctx)
	}
}

func (s *SFlowSource) flush(ctx context.Context) {
	s.flushAt = time.Now().Add(s.flushInt)
	if len(s.batch) == 0 {
		return
	}
	if err := s.sink.Append(ctx, s.batch); err != nil {
		s.log.Printf("[sflow] 写入 %d 条失败: %v", len(s.batch), err)
	}
	s.batch = s.batch[:0]
}

func (s *SFlowSource) logOnce(err error) {
	now := time.Now()
	if now.Sub(s.lastLog) < 30*time.Second {
		s.suppressed++
		return
	}
	if s.suppressed > 0 {
		s.log.Printf("[sflow] 解码失败: %v(另有 %d 条同类错误被抑制)", err, s.suppressed)
	} else {
		s.log.Printf("[sflow] 解码失败: %v", err)
	}
	s.lastLog, s.suppressed = now, 0
}

// reader 是 XDR 风格的顺序读取器。
//
// 自己写而不是 binary.Read + 结构体:sFlow 是变长嵌套的,记录长度决定
// 下一个记录从哪开始,固定结构体表达不了。而且每次读都要检查剩余长度,
// 集中在一个类型里比散在各处的 if len(b) < n 可靠。
type reader struct {
	b   []byte
	off int
}

func (r *reader) remaining() int { return len(r.b) - r.off }

func (r *reader) u32() (uint32, bool) {
	if r.remaining() < 4 {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v, true
}

func (r *reader) skip(n int) bool {
	if n < 0 || r.remaining() < n {
		return false
	}
	r.off += n
	return true
}

// bytes 取 n 字节。返回的是原切片的视图,调用方不能持有它超过本次解码。
func (r *reader) bytes(n int) ([]byte, bool) {
	if n < 0 || r.remaining() < n {
		return nil, false
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v, true
}

// DecodeSFlowV5 解码一个 sFlow v5 datagram。
func DecodeSFlowV5(pkt []byte, exporter net.IP) ([]flow.Flow, error) {
	r := &reader{b: pkt}

	version, ok := r.u32()
	if !ok {
		return nil, errors.New("包过短,读不到版本号")
	}
	if version != sflowV5Version {
		return nil, fmt.Errorf("版本 %d 不是 sFlow v5", version)
	}

	// agent address:1 = IPv4(4 字节),2 = IPv6(16 字节)。
	agentType, ok := r.u32()
	if !ok {
		return nil, errors.New("读不到 agent 地址类型")
	}
	agentLen := 4
	if agentType == 2 {
		agentLen = 16
	}
	agentIP, ok := r.bytes(agentLen)
	if !ok {
		return nil, errors.New("读不到 agent 地址")
	}

	// sub_agent_id, datagram_sequence, uptime
	if !r.skip(12) {
		return nil, errors.New("包过短,读不到 datagram 头")
	}

	numSamples, ok := r.u32()
	if !ok {
		return nil, errors.New("读不到 sample 数量")
	}
	// 上限防止损坏的长度字段导致一个巨大的循环。一个 datagram 里
	// 上千个 sample 已经不正常。
	if numSamples > 1024 {
		return nil, fmt.Errorf("sample 数量 %d 不合理", numSamples)
	}

	// DeviceID 优先用 agent address —— 那是设备自报的身份,比 UDP 源地址
	// 可靠(源地址可能是 NAT 后的)。agent 地址无效时退回源地址。
	deviceID := ipToDeviceID(net.IP(agentIP))
	if deviceID == 0 {
		deviceID = ipToDeviceID(exporter)
	}

	now := time.Now()
	var out []flow.Flow

	for i := uint32(0); i < numSamples; i++ {
		sampleType, ok := r.u32()
		if !ok {
			break // 样本数量字段可能虚高,读完就停,不算错误
		}
		sampleLen, ok := r.u32()
		if !ok {
			break
		}
		body, ok := r.bytes(int(sampleLen))
		if !ok {
			return nil, fmt.Errorf("第 %d 个 sample 声明长度 %d 超出剩余数据", i+1, sampleLen)
		}

		switch sampleType {
		case sflowFlowSample, sflowFlowSampleExpanded:
			fs, err := decodeFlowSample(body, sampleType == sflowFlowSampleExpanded, deviceID, now)
			if err != nil {
				// 单个 sample 解不出来不影响同一个 datagram 里的其他 sample。
				continue
			}
			out = append(out, fs...)
		case sflowCounterSample:
			// Counter sample 是接口计数器快照,技术设计 §4.2 把它列为
			// 后续版本。跳过而不是报错:设备通常同时发两种,报错会让
			// 一半的包被记成解码失败。
			continue
		}
	}
	return out, nil
}

// decodeFlowSample 解一个 flow sample。
func decodeFlowSample(b []byte, expanded bool, deviceID uint32, now time.Time) ([]flow.Flow, error) {
	r := &reader{b: b}

	// sequence_number
	if _, ok := r.u32(); !ok {
		return nil, errors.New("flow sample 过短")
	}

	var inputIf, outputIf uint32
	if expanded {
		// expanded 格式:source_id_type + source_id_index 各 4 字节,
		// input/output 也各是 8 字节(type + index)。
		if !r.skip(8) {
			return nil, errors.New("expanded sample 过短")
		}
		if _, ok := r.u32(); !ok { // input format
			return nil, errors.New("读不到 input format")
		}
		v, ok := r.u32()
		if !ok {
			return nil, errors.New("读不到 input index")
		}
		inputIf = v
		if _, ok := r.u32(); !ok { // output format
			return nil, errors.New("读不到 output format")
		}
		v, ok = r.u32()
		if !ok {
			return nil, errors.New("读不到 output index")
		}
		outputIf = v
	} else {
		// 标准格式:source_id 4 字节。
		if !r.skip(4) {
			return nil, errors.New("sample 过短")
		}
	}

	samplingRate, ok := r.u32()
	if !ok {
		return nil, errors.New("读不到采样率")
	}
	if samplingRate == 0 {
		samplingRate = 1
	}

	// sample_pool, drops
	if !r.skip(8) {
		return nil, errors.New("sample 过短")
	}

	if !expanded {
		v, ok := r.u32()
		if !ok {
			return nil, errors.New("读不到 input interface")
		}
		inputIf = v
		v, ok = r.u32()
		if !ok {
			return nil, errors.New("读不到 output interface")
		}
		outputIf = v
	}

	numRecords, ok := r.u32()
	if !ok {
		return nil, errors.New("读不到 record 数量")
	}
	if numRecords > 64 {
		return nil, fmt.Errorf("record 数量 %d 不合理", numRecords)
	}

	var out []flow.Flow
	for i := uint32(0); i < numRecords; i++ {
		format, ok := r.u32()
		if !ok {
			break
		}
		recLen, ok := r.u32()
		if !ok {
			break
		}
		rec, ok := r.bytes(int(recLen))
		if !ok {
			return out, fmt.Errorf("record %d 声明长度 %d 超出剩余数据", i+1, recLen)
		}

		// format 的低 12 位是 record type,高 20 位是企业号(0 = 标准)。
		if format&0xfff != sflowRawPacketHeader {
			// 扩展记录(extended_switch/router/gateway 等)当前不用。
			continue
		}

		f, err := decodeRawPacketHeader(rec)
		if err != nil {
			continue
		}
		f.SamplingRate = samplingRate
		f.SourceType = flow.SourceSFlow
		f.DeviceID = deviceID
		f.InputInterface = inputIf
		f.OutputInterface = outputIf
		// sFlow 不带 flow 的起止时间,只有采样时刻。用收包时刻作为
		// 两端 —— 这是单个包的采样,持续时间本来就是 0。
		f.Start, f.End = now, now

		// 一个采样包代表 samplingRate 个包。ApplySampling 把实测的
		// 1 个包/N 字节还原成估算值,同时保留实测值。
		f.Packets = 1
		f.ApplySampling()

		out = append(out, f)
	}
	return out, nil
}

// decodeRawPacketHeader 解 raw packet header 记录,拆出五元组。
func decodeRawPacketHeader(b []byte) (flow.Flow, error) {
	var f flow.Flow
	r := &reader{b: b}

	headerProto, ok := r.u32()
	if !ok {
		return f, errors.New("读不到 header protocol")
	}
	frameLength, ok := r.u32()
	if !ok {
		return f, errors.New("读不到 frame length")
	}
	// stripped
	if _, ok := r.u32(); !ok {
		return f, errors.New("读不到 stripped")
	}
	headerLen, ok := r.u32()
	if !ok {
		return f, errors.New("读不到 header length")
	}
	header, ok := r.bytes(int(headerLen))
	if !ok {
		return f, fmt.Errorf("header 声明长度 %d 超出剩余数据", headerLen)
	}

	var p flow.Packet
	var err error
	switch headerProto {
	case sflowHeaderEthernet:
		p, err = flow.ParseEthernet(header)
	case sflowHeaderIPv4:
		p, err = flow.ParseIPv4(header)
	default:
		return f, fmt.Errorf("不支持的 header protocol %d", headerProto)
	}
	if err != nil {
		return f, err
	}

	f.SrcIP = p.SrcIP.String()
	f.DstIP = p.DstIP.String()
	f.SrcPort, f.DstPort = p.SrcPort, p.DstPort
	f.Protocol = p.Protocol
	f.TCPFlags = p.TCPFlags
	f.SrcMAC, f.DstMAC = p.SrcMAC, p.DstMAC
	f.VLAN = p.VLAN

	// 字节数优先用 sFlow 自报的 frame_length,而不是包解析出的 IP
	// total length。
	//
	// 理由:frame_length 是设备看到的**链路层帧长**(含以太网头),
	// 而 sFlow 只截取了前 128/256 字节,IP 头里的 total length 虽然
	// 也是完整长度,但对于被截断到只剩以太网头的极端情况(某些设备
	// 的 header_size 配得很小),IP 头可能根本不完整。frame_length
	// 总是可靠的。
	if frameLength > 0 {
		f.Bytes = uint64(frameLength)
	} else {
		f.Bytes = uint64(p.Length)
	}
	return f, nil
}
