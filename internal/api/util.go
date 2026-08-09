package api

import (
	"fmt"
	"io"
)

// copyLimited 拷贝但不超过 limit 字节。
//
// 用它而不是 io.Copy + MaxBytesReader:后者在超限时返回的错误信息是
// "http: request body too large",无法区分是 mmdb 太大还是别的字段太大。
// 这里能给出确切的字节数。
func copyLimited(dst io.Writer, src io.Reader, limit int64) (int64, error) {
	n, err := io.Copy(dst, io.LimitReader(src, limit+1))
	if err != nil {
		return n, err
	}
	if n > limit {
		return n, fmt.Errorf("文件超过 %d MB 上限", limit>>20)
	}
	return n, nil
}
