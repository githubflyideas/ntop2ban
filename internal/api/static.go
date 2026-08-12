package api

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
)

// 前端资源以 gzip 形式嵌入,而不是原文。
//
// ECharts 原文 1.0MB、世界地图 GeoJSON 1.0MB,两者压缩后合计约 0.6MB。
// 嵌入压缩版让二进制少长 1.4MB,而浏览器本来就都支持 gzip,绝大多数请求
// 可以把这份字节原样发出去、完全不解压 —— 既省二进制体积又省 CPU。
//
// 不用 CDN 是明确的设计决定:ntop2ban 常常部署在没有出网的内网机房,
// 一个取不到的 CDN 会让整个界面变成白屏。
//
//go:embed static/echarts.min.js.gz static/world.json.gz
var staticFS embed.FS

// asset 是一份嵌入资源的元信息。ETag 在启动时算一次,之后浏览器带
// If-None-Match 来就直接回 304,不再重传这 0.6MB。
type asset struct {
	gz          []byte
	contentType string
	etag        string
}

var assets = map[string]*asset{}

func init() {
	register("echarts.min.js", "application/javascript; charset=utf-8")
	register("world.json", "application/json; charset=utf-8")
}

func register(name, ct string) {
	b, err := staticFS.ReadFile("static/" + name + ".gz")
	if err != nil {
		// 嵌入资源缺失是编译期就该发现的问题,不是运行期可恢复的错误。
		panic("api: 嵌入资源 " + name + " 缺失: " + err.Error())
	}
	sum := sha256.Sum256(b)
	assets[name] = &asset{gz: b, contentType: ct, etag: `"` + hex.EncodeToString(sum[:8]) + `"`}
}

// handleStatic 提供嵌入的前端资源。
//
// 故意不要求登录:这里只有第三方库和公开的国界数据,没有任何本站信息。
// 放在认证后面反而有害 —— 会话过期时浏览器会拿到一段登录页 HTML 当
// JavaScript 执行,报出与真实原因毫无关系的语法错误。
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	a, ok := assets[name]
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", a.contentType)
	w.Header().Set("ETag", a.etag)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Vary", "Accept-Encoding")

	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, a.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(a.gz)
		return
	}

	// 少见的退路:客户端声明不接受 gzip 时现场解压。curl 默认就是这种,
	// 所以这条路径必须真的能用,不能只当摆设。
	zr, err := gzip.NewReader(bytes.NewReader(a.gz))
	if err != nil {
		http.Error(w, "解压嵌入资源失败", http.StatusInternalServerError)
		return
	}
	defer zr.Close()
	_, _ = io.Copy(w, zr)
}
