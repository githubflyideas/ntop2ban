package clickhouse

import (
	"context"
	"fmt"

	"github.com/githubflyideas/ntop2ban/internal/model"
)

// Append 批量写入明细表。使用 clickhouse-go 的批量插入(PrepareBatch)
// 而不是逐行 Exec INSERT——ClickHouse 的写入吞吐模型是"少量大批次"
// 而非"高频小批次",逐行 INSERT 会在服务端产生大量小 part,拖慢后续
// 的 merge 与查询。上游(接收端点)已经按上报周期天然分批,这里直接
// 复用那个批次边界,不做二次缓冲。
func (s *Store) Append(ctx context.Context, batch []model.Flow) error {
	if len(batch) == 0 {
		return nil
	}

	b, err := s.conn.PrepareBatch(ctx, "INSERT INTO flows")
	if err != nil {
		return fmt.Errorf("clickhouse: prepare batch: %w", err)
	}

	for _, f := range batch {
		if err := b.Append(
			f.ReportedAt,
			f.Device,
			uint32(f.SamplingN),
			f.SrcIP,
			f.DstIP,
			uint16(f.SrcPort),
			uint16(f.DstPort),
			f.Proto,
			f.PktCount,
			f.ByteCount,
			f.LastSeen,
			f.SrcCountry,
			f.DstCountry,
			f.SrcASN,
			f.DstASN,
			f.ServiceName,
		); err != nil {
			return fmt.Errorf("clickhouse: append row to batch: %w", err)
		}
	}

	if err := b.Send(); err != nil {
		return fmt.Errorf("clickhouse: send batch (%d rows): %w", len(batch), err)
	}
	return nil
}
