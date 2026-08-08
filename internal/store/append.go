package store

import (
	"context"
	"fmt"
	"net"

	"github.com/githubflyideas/ntop2ban/internal/flow"
)

// Append 批量写入 flow。
//
// 用 PrepareBatch 而不是逐行 INSERT:ClickHouse 的写入模型是"少量大
// 批次",逐行插入会在服务端产生大量小 part,拖慢后续 merge 与查询。
// 上游(采集侧的聚合窗口)已经天然分批,这里直接复用那个批次边界。
func (s *Store) Append(ctx context.Context, batch []flow.Flow) error {
	if len(batch) == 0 {
		return nil
	}

	b, err := s.conn.PrepareBatch(ctx, "INSERT INTO flows")
	if err != nil {
		return fmt.Errorf("store: prepare batch: %w", err)
	}

	for i := range batch {
		f := &batch[i]
		src, dst := parseIP(f.SrcIP), parseIP(f.DstIP)
		if err := b.Append(
			f.Start,
			f.End,
			src,
			dst,
			f.SrcPort,
			f.DstPort,
			f.Protocol,
			f.Packets,
			f.Bytes,
			f.ObservedPackets,
			f.ObservedBytes,
			f.SamplingRate,
			f.TCPFlags,
			f.SrcMAC,
			f.DstMAC,
			f.InputInterface,
			f.OutputInterface,
			f.VLAN,
			f.InnerVLAN,
			f.DurationMS(),
			string(f.SourceType),
			f.SensorID,
			f.DeviceID,
			f.SiteID,
			f.Application,
			f.SrcCountry,
			f.DstCountry,
			f.SrcRegion,
			f.DstRegion,
			f.SrcCity,
			f.DstCity,
			f.SrcASN,
			f.DstASN,
			f.SrcOrg,
			f.DstOrg,
		); err != nil {
			return fmt.Errorf("store: append row: %w", err)
		}
	}

	if err := b.Send(); err != nil {
		return fmt.Errorf("store: send batch (%d rows): %w", len(batch), err)
	}
	return nil
}

// parseIP 把字符串 IP 转成 net.IP 供 ClickHouse 的 IPv6 列使用。
//
// 解析失败返回 :: 而不是报错整批失败:一条 flow 的 IP 字段异常
// (采集侧解析出了畸形包)不该让同批次的其他几千条正常记录一起丢掉。
// 采样数据允许有损,而完整丢一批的代价大得多。
func parseIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return net.IPv6zero
	}
	// IPv4 统一转成 16 字节表示。ClickHouse 的 IPv6 列接受 net.IP,
	// 但 4 字节与 16 字节混用时驱动的处理不一致,显式归一避免踩这个坑。
	if v4 := ip.To4(); v4 != nil {
		return v4.To16()
	}
	return ip
}

// Stats 是存储层的运行状态,供界面展示"数据在正常流入"。
type Stats struct {
	TotalRows      uint64
	Oldest         string
	Newest         string
	DiskBytes      uint64
	CompressedGB   float64
	UncompressedGB float64
}

// Stats 查询 flows 表的行数、时间范围与磁盘占用。
//
// 磁盘占用从 system.parts 取而不是估算:用户最关心的运维问题是
// "这东西会不会把盘吃满",给一个估算值不如给真实值。
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats

	row := s.conn.QueryRow(ctx, `
		SELECT count(),
		       toString(min(timestamp)),
		       toString(max(timestamp))
		FROM flows`)
	if err := row.Scan(&st.TotalRows, &st.Oldest, &st.Newest); err != nil {
		return Stats{}, fmt.Errorf("store: stats: %w", err)
	}

	// 空表时 min/max 返回零值时间,展示层据此判断"还没有数据"。
	var compressed, uncompressed uint64
	row = s.conn.QueryRow(ctx, `
		SELECT sum(bytes_on_disk), sum(data_uncompressed_bytes)
		FROM system.parts
		WHERE database = currentDatabase() AND table = 'flows' AND active`)
	if err := row.Scan(&compressed, &uncompressed); err == nil {
		st.DiskBytes = compressed
		st.CompressedGB = float64(compressed) / (1 << 30)
		st.UncompressedGB = float64(uncompressed) / (1 << 30)
	}
	return st, nil
}
