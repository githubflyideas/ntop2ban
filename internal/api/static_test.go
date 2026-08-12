package api

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// get 发起一次 /static/ 请求。handleStatic 不碰 Server 的任何字段,
// 所以这里用零值 Server 就够,不必拉起 ClickHouse。
func get(t *testing.T, path string, hdr map[string]string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	(&Server{}).handleStatic(w, req)
	return w.Result()
}

func TestStaticServesGzipVerbatim(t *testing.T) {
	for name := range assets {
		res := get(t, "/static/"+name, map[string]string{"Accept-Encoding": "gzip, deflate"})
		if res.StatusCode != 200 {
			t.Fatalf("%s: 状态码 %d", name, res.StatusCode)
		}
		if got := res.Header.Get("Content-Encoding"); got != "gzip" {
			t.Fatalf("%s: Content-Encoding = %q,应为 gzip", name, got)
		}
		body, _ := io.ReadAll(res.Body)
		if len(body) != len(assets[name].gz) {
			t.Fatalf("%s: 发出 %d 字节,嵌入 %d 字节,没有原样发送", name, len(body), len(assets[name].gz))
		}
		// 浏览器要能解开,否则原样发送就是发了一堆废字节。
		zr, err := gzip.NewReader(strings.NewReader(string(body)))
		if err != nil {
			t.Fatalf("%s: 发出的字节不是合法 gzip: %v", name, err)
		}
		if _, err := io.Copy(io.Discard, zr); err != nil {
			t.Fatalf("%s: gzip 内容损坏: %v", name, err)
		}
	}
}

// 不声明接受 gzip 的客户端(curl 默认就是)必须拿到解压后的原文。
func TestStaticGunzipsWhenNotAccepted(t *testing.T) {
	res := get(t, "/static/echarts.min.js", nil)
	if res.StatusCode != 200 {
		t.Fatalf("状态码 %d", res.StatusCode)
	}
	if got := res.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q,不该声明压缩", got)
	}
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "echarts") {
		t.Fatalf("解压结果里找不到 echarts,前 80 字节: %q", body[:min(80, len(body))])
	}
	if len(body) < 500_000 {
		t.Fatalf("解压后只有 %d 字节,像是被截断了", len(body))
	}
}

func TestStaticETagRoundTrip(t *testing.T) {
	res := get(t, "/static/world.json", nil)
	etag := res.Header.Get("ETag")
	if etag == "" {
		t.Fatal("没有 ETag")
	}
	res2 := get(t, "/static/world.json", map[string]string{"If-None-Match": etag})
	if res2.StatusCode != http.StatusNotModified {
		t.Fatalf("带 If-None-Match 仍返回 %d,缓存没生效", res2.StatusCode)
	}
	if res.Header.Get("Vary") != "Accept-Encoding" {
		t.Fatal("缺少 Vary: Accept-Encoding,压缩与非压缩两种响应会被缓存串味")
	}
}

func TestStaticUnknownIs404(t *testing.T) {
	// 路径穿越也走同一条路:名字不在白名单里就是 404。
	for _, p := range []string{"/static/nope.js", "/static/../api.go", "/static/"} {
		if res := get(t, p, nil); res.StatusCode != http.StatusNotFound {
			t.Fatalf("%s 返回 %d,应为 404", p, res.StatusCode)
		}
	}
}

// 底图的 name 必须是 ClickHouse 里存的 ISO alpha-2,不是国家名。
// 名字对不上时地图只是少涂一块颜色,不报错,靠肉眼极难发现。
func TestWorldMapKeyedByISOAlpha2(t *testing.T) {
	res := get(t, "/static/world.json", nil)
	var geo struct {
		Type     string `json:"type"`
		Features []struct {
			Properties struct {
				Name string `json:"name"`
				ZH   string `json:"zh"`
			} `json:"properties"`
			Geometry json.RawMessage `json:"geometry"`
		} `json:"features"`
	}
	if err := json.NewDecoder(res.Body).Decode(&geo); err != nil {
		t.Fatalf("底图不是合法 GeoJSON: %v", err)
	}
	if geo.Type != "FeatureCollection" {
		t.Fatalf("type = %q", geo.Type)
	}
	if len(geo.Features) < 200 {
		t.Fatalf("只有 %d 个国家/地区,50m 数据应有 230+", len(geo.Features))
	}
	alpha2 := regexp.MustCompile(`^[A-Z]{2}$`)
	seen := map[string]bool{}
	for _, f := range geo.Features {
		n := f.Properties.Name
		if !alpha2.MatchString(n) {
			t.Fatalf("feature name = %q,不是 ISO alpha-2", n)
		}
		if seen[n] {
			t.Fatalf("%s 出现两次,registerMap 会只留一个", n)
		}
		seen[n] = true
		if f.Properties.ZH == "" {
			t.Fatalf("%s 缺中文名", n)
		}
		if len(f.Geometry) == 0 {
			t.Fatalf("%s 没有几何数据", n)
		}
	}
	// 这几个是流量里最常见、又最容易被低精度底图丢掉的。
	for _, c := range []string{"CN", "TW", "HK", "SG", "US", "JP", "KR", "RU", "DE", "NL"} {
		if !seen[c] {
			t.Fatalf("底图缺 %s", c)
		}
	}
}

// 明确的设计约束:界面不许引用任何外部地址。内网机房取不到 CDN
// 会直接白屏,所以这条用测试钉住,而不是靠记性。
func TestIndexHasNoExternalAssets(t *testing.T) {
	if !strings.Contains(indexHTML, `src="/static/echarts.min.js"`) {
		t.Fatal("界面没有引用本地 echarts")
	}
	bad := regexp.MustCompile(`(?i)(src|href)\s*=\s*["']?(https?:)?//`)
	if m := bad.FindString(indexHTML); m != "" {
		t.Fatalf("界面里出现外部资源引用: %q", m)
	}
	for _, kw := range []string{"cdn.", "unpkg", "jsdelivr", "googleapis"} {
		if strings.Contains(strings.ToLower(indexHTML), kw) {
			t.Fatalf("界面里出现 %q,禁止使用 CDN", kw)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
