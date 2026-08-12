package api

import (
	"regexp"
	"strconv"
	"testing"
)

// 排版下限。整个界面原本是按 11~13px 排的,在 4K 屏和 NAS 接的电视上
// 眼睛受不了 —— 这类机器上人离屏幕远,不是坐在笔记本前面。所以定一个
// 下限钉住:界面上不许再出现小于 13px 的字号。
//
// 检查用正则扫模板字符串而不是渲染后的 DOM:字号散落在 <style> 里、
// 元素的 style 属性里、以及 JS 拼 HTML 的字符串里,只有扫源码才能
// 一网打尽。ECharts 的 fontSize 是数字不带 px,单独扫。
const minFontPx = 13.0

var (
	cssFontRe   = regexp.MustCompile(`font-size:\s*([\d.]+)px`)
	shortFontRe = regexp.MustCompile(`font:\s*([\d.]+)px/`)
	jsFontRe    = regexp.MustCompile(`fontSize:\s*([\d.]+)`)
)

func TestNoTinyFontsInTemplates(t *testing.T) {
	for name, tpl := range map[string]string{"index": indexHTML, "login": loginHTML} {
		for _, re := range []*regexp.Regexp{cssFontRe, shortFontRe, jsFontRe} {
			for _, m := range re.FindAllStringSubmatch(tpl, -1) {
				px, err := strconv.ParseFloat(m[1], 64)
				if err != nil {
					t.Fatalf("%s: 解析字号 %q: %v", name, m[1], err)
				}
				if px < minFontPx {
					t.Errorf("%s: %q 小于下限 %gpx", name, m[0], minFontPx)
				}
			}
		}
	}
}

// LOGO 必须明显大于正文,而不是跟着正文一起等比放大 —— 它是这个页面
// 上唯一的品牌元素,与正文同级会整页都糊成一片。
func TestLogoIsLargerThanBodyText(t *testing.T) {
	body := shortFontRe.FindStringSubmatch(indexHTML)
	if body == nil {
		t.Fatal("index 里找不到 body 的 font 简写")
	}
	bodyPx, _ := strconv.ParseFloat(body[1], 64)

	logoRe := regexp.MustCompile(`header \.logo\{font-size:([\d.]+)px`)
	logo := logoRe.FindStringSubmatch(indexHTML)
	if logo == nil {
		t.Fatal("index 里找不到 header .logo 的字号")
	}
	logoPx, _ := strconv.ParseFloat(logo[1], 64)

	if logoPx < bodyPx*1.4 {
		t.Errorf("LOGO %gpx 相对正文 %gpx 不够突出", logoPx, bodyPx)
	}
}
