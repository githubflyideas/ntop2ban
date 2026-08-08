package knock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDefaultSequenceIsValidAndFourSteps 默认序列必须直接可用:
// tcp 9001 → icmp 123 → tcp 9002 → icmp 145。
//
// 装上就能用是刻意的:留空的话敲门默认关闭,用户得先读文档才知道
// 怎么开。四步(两 TCP 两 ICMP)顺带演示了混合序列的写法。
func TestDefaultSequenceIsValidAndFourSteps(t *testing.T) {
	seq := DefaultSequence()
	if err := seq.Validate(); err != nil {
		t.Fatalf("默认序列必须合法: %v", err)
	}
	if len(seq.Steps) != 4 {
		t.Fatalf("默认应为 4 步, got %d", len(seq.Steps))
	}
	want := []Step{
		{Kind: StepTCP, Port: 9001},
		{Kind: StepICMP, PayloadLen: 123},
		{Kind: StepTCP, Port: 9002},
		{Kind: StepICMP, PayloadLen: 145},
	}
	for i := range want {
		if seq.Steps[i] != want[i] {
			t.Errorf("第 %d 步: want %v, got %v", i+1, want[i], seq.Steps[i])
		}
	}
	if seq.OpenPort != 22 {
		t.Errorf("默认放行端口应为 22, got %d", seq.OpenPort)
	}
	if seq.Window != time.Minute {
		t.Errorf("默认时限应为 1 分钟, got %v", seq.Window)
	}
}

// TestLoadSequenceMissingFileIsDistinguishable 文件不存在要能被区分出来,
// 调用方据此决定"写入默认清单"还是"报错"——这个包不该擅自往用户的
// /etc 里写东西。
func TestLoadSequenceMissingFileIsDistinguishable(t *testing.T) {
	_, err := LoadSequence(t.TempDir())
	if !errors.Is(err, ErrNoKnockList) {
		t.Fatalf("want ErrNoKnockList, got %v", err)
	}
}

func writeKnock(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, KnockListName), []byte(content), 0o600); err != nil {
		t.Fatalf("写入清单: %v", err)
	}
}

// TestExampleListParsesToDefaultSequence 生成的默认清单必须能被自己解析
// 回默认序列。这条测试守住的是"示例文件写错了但没人发现"——它是用户
// 看到的第一份配置,格式示范错了会误导所有后续修改。
func TestExampleListParsesToDefaultSequence(t *testing.T) {
	dir := t.TempDir()
	writeKnock(t, dir, ExampleList())

	seq, err := LoadSequence(dir)
	if err != nil {
		t.Fatalf("示例清单应能被解析: %v", err)
	}
	def := DefaultSequence()
	if len(seq.Steps) != len(def.Steps) {
		t.Fatalf("步数不符: want %d, got %d", len(def.Steps), len(seq.Steps))
	}
	for i := range def.Steps {
		if seq.Steps[i] != def.Steps[i] {
			t.Errorf("第 %d 步: want %v, got %v", i+1, def.Steps[i], seq.Steps[i])
		}
	}
	if seq.OpenPort != def.OpenPort || seq.Window != def.Window || seq.OpenFor != def.OpenFor {
		t.Errorf("参数不符: %+v vs %+v", seq, def)
	}
}

func TestLoadSequenceParsesStepsAndParams(t *testing.T) {
	dir := t.TempDir()
	writeKnock(t, dir, `
# 注释
tcp  10001
icmp 200
tcp  10002

open-port 2222
window    30
open-for  15
`)
	seq, err := LoadSequence(dir)
	if err != nil {
		t.Fatalf("LoadSequence: %v", err)
	}
	if len(seq.Steps) != 3 {
		t.Fatalf("want 3 steps, got %d", len(seq.Steps))
	}
	if seq.Steps[0] != (Step{Kind: StepTCP, Port: 10001}) {
		t.Errorf("第 1 步: %v", seq.Steps[0])
	}
	if seq.Steps[1] != (Step{Kind: StepICMP, PayloadLen: 200}) {
		t.Errorf("第 2 步: %v", seq.Steps[1])
	}
	if seq.OpenPort != 2222 {
		t.Errorf("open-port: want 2222, got %d", seq.OpenPort)
	}
	if seq.Window != 30*time.Second {
		t.Errorf("window: want 30s, got %v", seq.Window)
	}
	if seq.OpenFor != 15*time.Second {
		t.Errorf("open-for: want 15s, got %v", seq.OpenFor)
	}
}

// TestLoadSequenceRejectsUDPWithReason 用户会自然地想试 UDP,
// 给出理由比"未知类型"有用得多。
func TestLoadSequenceRejectsUDPWithReason(t *testing.T) {
	dir := t.TempDir()
	writeKnock(t, dir, "udp 9001\ntcp 9002\n")
	_, err := LoadSequence(dir)
	if err == nil {
		t.Fatal("UDP 步应报错")
	}
	if !contains(err.Error(), "UDP") {
		t.Errorf("错误信息应说明为什么不支持 UDP: %v", err)
	}
}

// TestLoadSequenceFailsOnBadLineRatherThanSkipping 单行错误必须直接失败。
//
// 跳过会静默地把 4 步序列变成 3 步 —— 那是个更容易被猜到的序列,
// 属于安全问题,不能只记个警告了事。这与探测清单的处理刻意不同:
// 那边跳过一个坏目标只是少监控一条链路。
func TestLoadSequenceFailsOnBadLineRatherThanSkipping(t *testing.T) {
	dir := t.TempDir()
	writeKnock(t, dir, "tcp 9001\nicmp 一百二十三\ntcp 9002\nicmp 145\n")
	_, err := LoadSequence(dir)
	if err == nil {
		t.Fatal("坏行应导致加载失败,而不是被跳过")
	}
	// 错误要带行号,否则用户不知道去改哪一行
	if !contains(err.Error(), ":2") {
		t.Errorf("错误应带行号: %v", err)
	}
}

// TestLoadSequenceValidatesResult 清单能解析不代表序列合法。
// 相邻两步相同、只有一步这类问题必须在加载时就拦住。
func TestLoadSequenceValidatesResult(t *testing.T) {
	cases := map[string]string{
		"只有一步":     "tcp 9001\nopen-port 22\n",
		"相邻两步相同":   "tcp 9001\ntcp 9001\nopen-port 22\n",
		"敲门端口等于放行": "tcp 22\nicmp 100\nopen-port 22\n",
		"ICMP会分片":  "tcp 9001\nicmp 2000\nopen-port 22\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeKnock(t, dir, content)
			if _, err := LoadSequence(dir); err == nil {
				t.Error("应在加载时就被 Validate 拦住")
			}
		})
	}
}

func TestLoadSequenceRejectsUnknownKey(t *testing.T) {
	dir := t.TempDir()
	writeKnock(t, dir, "tcp 9001\nicmp 123\nsecret hunter2\n")
	_, err := LoadSequence(dir)
	if err == nil {
		t.Fatal("未知配置项应报错")
	}
	if !contains(err.Error(), "未知配置项") {
		t.Errorf("错误应指出未知配置项: %v", err)
	}
}

// TestEnsureListNeverOverwrites 绝不覆盖已存在的清单。
//
// 覆盖会把用户配好的序列换成默认的,而默认序列是公开的 —— 等于悄悄
// 把门锁换成了所有人都知道的那把。
func TestEnsureListNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	mine := "tcp 11111\nicmp 222\nopen-port 22\n"
	writeKnock(t, dir, mine)

	created, _, err := EnsureList(dir)
	if err != nil {
		t.Fatalf("EnsureList: %v", err)
	}
	if created {
		t.Error("已存在时不该报告创建")
	}
	got, err := os.ReadFile(filepath.Join(dir, KnockListName))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != mine {
		t.Error("用户的清单被覆盖了 —— 等于把序列换成公开的默认值")
	}
}

func TestEnsureListCreatesWithTightPermissions(t *testing.T) {
	dir := t.TempDir()
	created, path, err := EnsureList(dir)
	if err != nil {
		t.Fatalf("EnsureList: %v", err)
	}
	if !created {
		t.Fatal("空目录应创建清单")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// 序列就是密码,不该让机器上的其他用户读到
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("清单权限应为 0600(序列即密码), got %o", perm)
	}
	// 创建出来的必须立刻可用
	if _, err := LoadSequence(dir); err != nil {
		t.Errorf("新建的清单应能直接加载: %v", err)
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
