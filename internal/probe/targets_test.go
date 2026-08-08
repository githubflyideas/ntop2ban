package probe

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeList(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("写入 %s: %v", name, err)
	}
}

// TestLoadTargetsMissingFilesIsNotAnError 首次部署时两个文件都不存在,
// 必须返回空列表而不是报错——否则整个服务起不来,而用户只是还没配探测。
// 这是需求明确要求的行为。
func TestLoadTargetsMissingFilesIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	targets, warnings, err := LoadTargets(dir)
	if err != nil {
		t.Fatalf("文件不存在不应报错: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("want 0 targets, got %d", len(targets))
	}
	if len(warnings) != 0 {
		t.Errorf("文件不存在不该产生警告, got %v", warnings)
	}
}

// TestLoadTargetsAllCommentedIsEmpty 示例文件全部注释掉时应得到空列表。
// 界面据此不显示探测视图并提示用户去改文件。
func TestLoadTargetsAllCommentedIsEmpty(t *testing.T) {
	dir := t.TempDir()
	for name, content := range ExampleFiles() {
		writeList(t, dir, name, content)
	}
	targets, warnings, err := LoadTargets(dir)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("示例文件应全部注释掉,不自动探测任何外部主机, got %d 个目标", len(targets))
	}
	if len(warnings) != 0 {
		t.Errorf("纯注释文件不该产生警告, got %v", warnings)
	}
}

func TestLoadICMPTargets(t *testing.T) {
	dir := t.TempDir()
	writeList(t, dir, PingListName, `
# 注释行
192.168.1.1      网关      pace=fast
8.8.8.8
203.0.113.10     分支      pace=slow
10.0.0.9         自定义     interval=45
`)
	targets, warnings, err := LoadTargets(dir)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("不该有警告: %v", warnings)
	}
	if len(targets) != 4 {
		t.Fatalf("want 4 targets, got %d", len(targets))
	}

	byName := map[string]Target{}
	for _, tg := range targets {
		byName[tg.Name] = tg
	}

	if g := byName["网关"]; g.Host != "192.168.1.1" || g.Interval != 15*time.Second || g.Packets != 30 {
		t.Errorf("pace=fast 应为 15 秒/30 包: %+v", g)
	}
	// 省略名字时用 host 本身
	if g, ok := byName["8.8.8.8"]; !ok || g.Kind != "icmp" {
		t.Errorf("省略名字应以 host 为名: %+v", g)
	}
	if g := byName["分支"]; g.Interval != 5*time.Minute {
		t.Errorf("pace=slow 应为 5 分钟: %v", g.Interval)
	}
	if g := byName["自定义"]; g.Interval != 45*time.Second {
		t.Errorf("interval=45 应为 45 秒: %v", g.Interval)
	}
}

// TestExplicitIntervalBeatsPace 显式给的秒数要赢过 pace 档位。
// 反过来的话用户写了 interval 却不生效,会以为程序没读他的配置。
func TestExplicitIntervalBeatsPace(t *testing.T) {
	dir := t.TempDir()
	writeList(t, dir, PingListName, "1.1.1.1 t pace=slow interval=20\n")
	targets, _, err := LoadTargets(dir)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if targets[0].Interval != 20*time.Second {
		t.Errorf("显式 interval 应优先于 pace: got %v", targets[0].Interval)
	}
}

func TestLoadTCPTargets(t *testing.T) {
	dir := t.TempDir()
	writeList(t, dir, TCPListName, `
10.0.0.5:443     API网关   interval=30
203.0.113.20:22
`)
	targets, warnings, err := LoadTargets(dir)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("不该有警告: %v", warnings)
	}
	if len(targets) != 2 {
		t.Fatalf("want 2 targets, got %d", len(targets))
	}
	for _, tg := range targets {
		if tg.Kind != "tcp" {
			t.Errorf("%s 应为 tcp: %+v", tg.Name, tg)
		}
	}
	byName := map[string]Target{}
	for _, tg := range targets {
		byName[tg.Name] = tg
	}
	if g := byName["API网关"]; g.Host != "10.0.0.5" || g.Port != 443 || g.Interval != 30*time.Second {
		t.Errorf("解析错误: %+v", g)
	}
	// 省略名字时 TCP 目标默认名带端口,避免同主机不同端口撞名
	if g, ok := byName["203.0.113.20:22"]; !ok || g.Port != 22 {
		t.Errorf("TCP 默认名应带端口: %+v", g)
	}
}

// TestTCPTargetNeedsPort 缺端口的 TCP 目标要被跳过并给出原因,
// 而不是当成主机名去 DNS 解析(那会得到一个莫名其妙的解析失败)。
func TestTCPTargetNeedsPort(t *testing.T) {
	dir := t.TempDir()
	writeList(t, dir, TCPListName, "10.0.0.5   没端口\n10.0.0.6:443  好的\n")
	targets, warnings, err := LoadTargets(dir)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("只有一个合法目标, got %d", len(targets))
	}
	if len(warnings) != 1 {
		t.Fatalf("want 1 warning, got %v", warnings)
	}
	if !contains(warnings[0], "缺少端口") {
		t.Errorf("警告应说明缺端口: %s", warnings[0])
	}
}

// TestIPv6TargetSplitsOnLastColon IPv6 字面量里有多个冒号,按第一个切
// 会把地址切碎、得到一个永远解析不了的主机名。
func TestIPv6TargetSplitsOnLastColon(t *testing.T) {
	dir := t.TempDir()
	writeList(t, dir, TCPListName, "[2001:db8::1]:443  v6\n")
	targets, warnings, err := LoadTargets(dir)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("不该有警告: %v", warnings)
	}
	if len(targets) != 1 {
		t.Fatalf("want 1 target, got %d", len(targets))
	}
	if targets[0].Host != "2001:db8::1" || targets[0].Port != 443 {
		t.Errorf("IPv6 解析错误: host=%q port=%d", targets[0].Host, targets[0].Port)
	}
}

// TestBadLineDoesNotKillTheRest 一行写错不该让其余正确的目标也探不了。
func TestBadLineDoesNotKillTheRest(t *testing.T) {
	dir := t.TempDir()
	writeList(t, dir, PingListName, `
1.1.1.1  好的
2.2.2.2  坏的 pace=飞快
3.3.3.3  也好
4.4.4.4  坏的2 interval=abc
5.5.5.5  还好
`)
	targets, warnings, err := LoadTargets(dir)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if len(targets) != 3 {
		t.Fatalf("want 3 合法目标, got %d: %+v", len(targets), targets)
	}
	if len(warnings) != 2 {
		t.Fatalf("want 2 warnings, got %v", warnings)
	}
	// 警告要带文件名与行号,否则用户不知道去改哪一行
	for _, w := range warnings {
		if !contains(w, PingListName) {
			t.Errorf("警告应带文件名: %s", w)
		}
	}
}

// TestDuplicateNamesAreSkipped 名字是库里的主键,重复会让两条曲线画到
// 一起、数据互相污染。跳过后一个并明确告知,而不是静默合并。
func TestDuplicateNamesAreSkipped(t *testing.T) {
	dir := t.TempDir()
	writeList(t, dir, PingListName, "1.1.1.1 同名\n2.2.2.2 同名\n")
	targets, warnings, err := LoadTargets(dir)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("重名应只保留一个, got %d", len(targets))
	}
	if targets[0].Host != "1.1.1.1" {
		t.Errorf("应保留第一个, got %s", targets[0].Host)
	}
	if len(warnings) != 1 || !contains(warnings[0], "重复") {
		t.Errorf("应告知重名: %v", warnings)
	}
}

// TestICMPAndTCPListsCombine 两个文件的目标合并成一个列表。
func TestICMPAndTCPListsCombine(t *testing.T) {
	dir := t.TempDir()
	writeList(t, dir, PingListName, "1.1.1.1 ping目标\n")
	writeList(t, dir, TCPListName, "2.2.2.2:443 tcp目标\n")
	targets, _, err := LoadTargets(dir)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("want 2, got %d", len(targets))
	}
	kinds := map[string]string{}
	for _, tg := range targets {
		kinds[tg.Name] = tg.Kind
	}
	if kinds["ping目标"] != "icmp" || kinds["tcp目标"] != "tcp" {
		t.Errorf("类型错误: %v", kinds)
	}
}

// TestEnsureExampleFilesNeverOverwrites 已存在的文件绝不能被覆盖——
// 那会把用户配好的探测目标清空,而且没有任何提示。
func TestEnsureExampleFilesNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	mine := "9.9.9.9 我的目标\n"
	writeList(t, dir, PingListName, mine)

	created, err := EnsureExampleFiles(dir)
	if err != nil {
		t.Fatalf("EnsureExampleFiles: %v", err)
	}
	// 只应创建缺失的那个
	if len(created) != 1 || !contains(created[0], TCPListName) {
		t.Errorf("只应创建缺失的 tcp.list, got %v", created)
	}

	got, err := os.ReadFile(filepath.Join(dir, PingListName))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != mine {
		t.Error("已存在的文件被覆盖了 —— 这会清空用户配好的目标")
	}
}

func TestEnsureExampleFilesCreatesBoth(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub", "dir")
	created, err := EnsureExampleFiles(dir)
	if err != nil {
		t.Fatalf("EnsureExampleFiles: %v", err)
	}
	if len(created) != 2 {
		t.Fatalf("want 2 created, got %v", created)
	}
	// 创建出来的文件必须能被 LoadTargets 读且得到空列表(全注释)
	targets, warnings, err := LoadTargets(dir)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if len(targets) != 0 || len(warnings) != 0 {
		t.Errorf("示例文件应产出空列表无警告, got %d 目标 %v", len(targets), warnings)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
