// Command genworld 把 Natural Earth 的国界数据转成界面地图用的精简 GeoJSON。
//
// 为什么要转而不是直接用现成的 world.json:ClickHouse 里存的 country 是
// ISO alpha-2 码(ip2asn 与城市库都给码,见 internal/enrich),而通行的
// world.json 用国家英文名当 feature 名。拿名字去对码就得在前端维护一张
// 两百多条的映射表,还得处理 "W. Sahara" 这类简写 —— 一旦对不上,地图上
// 那个国家就悄悄变成空白,没有任何报错。
//
// 所以这里反过来:把 feature 名直接设成 ISO alpha-2,前端拿查询结果的
// country 值当键去着色,是精确匹配,对不上会立刻显现为整张图都没颜色。
// 中英文国名作为附加属性带上,只用于 tooltip 显示。
//
// 用法(资源已提交进仓库,只有升级底图时才需要重跑):
//
//	curl -sSLO https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_50m_admin_0_countries.geojson
//	go run ./tools/genworld -in ne_50m_admin_0_countries.geojson -out internal/api/static/world.json
//	gzip -9 -f internal/api/static/world.json
//
// 数据来源:Natural Earth(public domain),50m 精度。用 50m 而不是更小的
// 110m:110m 会整体省掉新加坡、香港、澳门这类面积极小的地区,而它们恰好
// 是流量榜上的常客 —— 底图上没有它们的多边形,那部分流量就无声地消失了。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
)

type feature struct {
	Type       string          `json:"type"`
	Properties json.RawMessage `json:"properties"`
	Geometry   json.RawMessage `json:"geometry"`
}

type collection struct {
	Type     string    `json:"type"`
	Features []feature `json:"features"`
}

type props struct {
	ISOA2   string `json:"ISO_A2"`
	ISOA2EH string `json:"ISO_A2_EH"`
	NameEN  string `json:"NAME_EN"`
	NameZH  string `json:"NAME_ZH"`
	Name    string `json:"NAME"`
}

// outProps 只留三项。底图占了嵌入资源的一半体积,Natural Earth 原始的
// 九十多个属性字段(人口、GDP、各语言译名…)一个都用不上。
type outProps struct {
	Name string `json:"name"` // ISO alpha-2,与 ClickHouse 的 country 列对齐
	ZH   string `json:"zh,omitempty"`
	EN   string `json:"en,omitempty"`
}

// coordDigits 坐标保留的小数位。110m 底图上 0.01° 约合 1km,
// 比这更精细的数字只是在放大文件体积。
const coordDigits = 2

func main() {
	in := flag.String("in", "", "Natural Earth ne_110m_admin_0_countries.geojson")
	out := flag.String("out", "", "输出的精简 GeoJSON")
	flag.Parse()
	if *in == "" || *out == "" {
		log.Fatal("用法: genworld -in ne_110m_admin_0_countries.geojson -out world.json")
	}

	raw, err := os.ReadFile(*in)
	if err != nil {
		log.Fatal(err)
	}
	var fc collection
	if err := json.Unmarshal(raw, &fc); err != nil {
		log.Fatal(err)
	}

	kept := make([]feature, 0, len(fc.Features))
	var skipped []string
	// index 记录每个 ISO 码在 kept 里的下标,用于把同码的多条 feature 合并。
	index := map[string]int{}
	for _, f := range fc.Features {
		var p props
		if err := json.Unmarshal(f.Properties, &p); err != nil {
			log.Fatal(err)
		}
		// Natural Earth 的 ISO_A2 有两类不能直接用的值:"-99" 表示"没有
		// 公认的 ISO 码"(北塞浦路斯、索马里兰),以及带归属前缀的写法
		// —— 台湾在这份数据里是 "CN-TW"。两者都不会等于 ip2asn 给出的
		// 两字母码,所以统一要求"恰好两个大写字母",不合格就退到
		// ISO_A2_EH(Natural Earth 给的事实归属码,台湾在那里是 "TW")。
		//
		// 这条校验是必须的:早先只判 "-99" 的版本让台湾拿到 "CN-TW",
		// 结果地图上台湾永远不着色,而查询结果里明明有 TW 的流量。
		code := p.ISOA2
		if !isAlpha2(code) {
			code = p.ISOA2EH
		}
		if !isAlpha2(code) {
			// 仍然没有码就丢掉:留着也永远匹配不到任何查询结果。
			name := p.NameEN
			if name == "" {
				name = p.Name
			}
			skipped = append(skipped, name)
			continue
		}

		geom, err := roundGeometry(f.Geometry)
		if err != nil {
			log.Fatal(err)
		}
		zh := p.NameZH
		if v, ok := zhOverride[code]; ok {
			zh = v
		}
		// 同一个 ISO 码可能对应多个 feature:Natural Earth 把澳大利亚本土、
		// 阿什莫尔和卡捷群岛、珊瑚海群岛拆成三条,ISO_A2 都是 AU。留成三条
		// 的话 echarts.registerMap 里 AU 这个名字重复,只有一条能被着色和
		// 点中,是哪一条还取决于遍历顺序 —— 表现为"某块地方莫名没颜色"。
		// 所以按码合并成一个 MultiPolygon。
		if i, ok := index[code]; ok {
			merged, err := mergeGeom(kept[i].Geometry, geom)
			if err != nil {
				log.Fatal(err)
			}
			kept[i].Geometry = merged
			continue
		}

		op := outProps{Name: code, ZH: zh, EN: p.NameEN}
		pj, err := json.Marshal(op)
		if err != nil {
			log.Fatal(err)
		}
		index[code] = len(kept)
		kept = append(kept, feature{Type: "Feature", Properties: pj, Geometry: geom})
	}

	body, err := json.Marshal(collection{Type: "FeatureCollection", Features: kept})
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, body, 0o644); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("写出 %s:%d 个国家/地区,%.0f KB\n", *out, len(kept), float64(len(body))/1024)
	if len(skipped) > 0 {
		fmt.Printf("跳过 %d 个没有 ISO 码的地区(地图上会是空白):%v\n", len(skipped), skipped)
	}
}

// zhOverride 覆盖 Natural Earth 的部分中文名。
//
// NAME_ZH 给的是正式国名(CN 是"中华人民共和国"、KR 是"大韩民国"),
// 在只有几十像素宽的 tooltip 和榜单里太长,而中文习惯用法本来就是简称。
// 这张表只做"长名换常用简称",不改变任何归属判断 —— 需要调整措辞的话
// 改这里一处即可,不用碰底图数据。
var zhOverride = map[string]string{
	"CN": "中国",
	"KR": "韩国",
	"KP": "朝鲜",
	"TW": "台湾",
	"US": "美国",
	"GB": "英国",
	"RU": "俄罗斯",
	"AE": "阿联酋",
	"LA": "老挝",
	"VE": "委内瑞拉",
	"TZ": "坦桑尼亚",
	"CD": "刚果(金)",
	"CG": "刚果(布)",
}

// isAlpha2 判断是否是规范的 ISO alpha-2 码。
func isAlpha2(s string) bool {
	if len(s) != 2 {
		return false
	}
	for i := 0; i < 2; i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}

// mergeGeom 把两份 geometry 合成一个 MultiPolygon。
//
// GeoJSON 里 Polygon 的 coordinates 是"环的数组",MultiPolygon 的是
// "多边形的数组",所以合并前要先把 Polygon 多包一层,否则外环会被当成
// 另一个多边形,地图上出现莫名其妙的连片色块。
func mergeGeom(a, b json.RawMessage) (json.RawMessage, error) {
	polys, err := asPolygons(a)
	if err != nil {
		return nil, err
	}
	pb, err := asPolygons(b)
	if err != nil {
		return nil, err
	}
	out := struct {
		Type   string        `json:"type"`
		Coords []interface{} `json:"coordinates"`
	}{Type: "MultiPolygon", Coords: append(polys, pb...)}
	return json.Marshal(out)
}

// asPolygons 把任意 Polygon / MultiPolygon 统一成"多边形的数组"。
func asPolygons(raw json.RawMessage) ([]interface{}, error) {
	var g struct {
		Type   string        `json:"type"`
		Coords []interface{} `json:"coordinates"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		return nil, err
	}
	switch g.Type {
	case "Polygon":
		return []interface{}{g.Coords}, nil
	case "MultiPolygon":
		return g.Coords, nil
	default:
		return nil, fmt.Errorf("无法合并的几何类型 %q", g.Type)
	}
}

// roundGeometry 递归地把 geometry 里所有坐标数字降到 coordDigits 位小数。
//
// 直接对 JSON 树做,而不是按 Polygon/MultiPolygon 分别解析:GeoJSON 的
// 坐标嵌套深度随几何类型变化,按类型写会漏掉某一种,而漏掉的那种会以
// 原始精度写出去 —— 体积异常但看不出错。
func roundGeometry(raw json.RawMessage) (json.RawMessage, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return json.Marshal(roundAny(v))
}

func roundAny(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, sub := range t {
			t[k] = roundAny(sub)
		}
		return t
	case []any:
		for i, sub := range t {
			t[i] = roundAny(sub)
		}
		return t
	case float64:
		p := math.Pow(10, coordDigits)
		return math.Round(t*p) / p
	default:
		return v
	}
}
