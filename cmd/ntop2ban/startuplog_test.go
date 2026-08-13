package main

import (
	"os"
	"strings"
	"testing"
)

// 富化提示必须排在 LoadCached 之后。
//
// 这条测试盯的是**语句顺序**,不是某个函数的返回值 —— 因为 bug 就在顺序上。
// 提示原本写在 syncer.LoadCached() 前面,于是缓存里明明有库,启动日志还是
// 先喊一句"ASN/国家维度不可用,去设置页点同步",下一行紧接着"已从缓存
// 加载 [iptoasn.com ip2asn DB-IP ASN Lite DB-IP City Lite]"。两句话互相
// 打脸,而用户只会照着前一句白跑一趟设置页。
//
// 用扫源码的办法钉住(和 internal/api/typography_test.go 一个路子):这里
// 是 main 的接线逻辑,没有可以单独调用的函数,把它拆出来只为了测反而更绕。
func TestEnrichHintComesAfterCacheLoad(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("读 main.go: %v", err)
	}
	s := string(src)

	load := strings.Index(s, "syncer.LoadCached()")
	if load < 0 {
		t.Fatal("main.go 里找不到 syncer.LoadCached()")
	}
	hint := strings.Index(s, "富化:ASN/国家维度不可用")
	if hint < 0 {
		t.Fatal("main.go 里找不到那句富化提示")
	}
	if hint < load {
		t.Error("那句「ASN/国家维度不可用」排在 LoadCached 之前," +
			"缓存里有库时会先打一句自相矛盾的提示")
	}
}
