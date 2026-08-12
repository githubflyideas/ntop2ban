# 嵌入的前端资源

这里的文件由 `internal/api/static.go` 用 `go:embed` 编进二进制,通过
`/static/<name>` 提供。**不用 CDN**:ntop2ban 常部署在没有出网的内网机房,
一个取不到的 CDN 会让整个界面变成白屏。

以 gzip 形式提交而不是原文:两者原文合计约 2.5MB、压缩后 0.4MB,而浏览器
本来就都支持 gzip,绝大多数请求可以把这份字节原样发出去、完全不解压。

| 文件 | 来源 | 许可 |
|---|---|---|
| `echarts.min.js.gz` | [Apache ECharts](https://echarts.apache.org/) 5.5.1 | Apache-2.0 |
| `world.json.gz` | Natural Earth 50m 国界,经 `tools/genworld` 处理 | public domain |

## 升级 ECharts

```sh
curl -sSL -o /tmp/echarts.min.js https://cdn.jsdelivr.net/npm/echarts@<版本>/dist/echarts.min.js
gzip -9 -c /tmp/echarts.min.js > internal/api/static/echarts.min.js.gz
```

## 重新生成底图

只在升级底图时才需要。`world.json` 的 feature 名是 ISO alpha-2 码而不是
国家名 —— 与 ClickHouse 里 `src_country`/`dst_country` 的取值对齐,这样
前端着色是精确匹配。理由与坑详见 `tools/genworld/main.go` 顶部注释。

```sh
curl -sSLO https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_50m_admin_0_countries.geojson
go run ./tools/genworld -in ne_50m_admin_0_countries.geojson -out internal/api/static/world.json
gzip -9 -f internal/api/static/world.json
```

中文国名取 Natural Earth 的 `NAME_ZH`,少数正式国名过长的用
`tools/genworld/main.go` 里的 `zhOverride` 换成常用简称。
