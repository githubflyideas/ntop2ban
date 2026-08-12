package api

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/githubflyideas/ntop2ban/internal/query"
)

// 界面的 JavaScript 全在 indexHTML 这个字符串里,go build 不会看它一眼:
// 一个拼错的变量名要等到有人打开浏览器才暴露。这里把其中几个纯函数抠出来
// 交给 node 跑真值检查,把它们纳入 go test ./... 的覆盖范围。
//
// 挑这几个函数不是随手挑的 —— 它们的错误都不会报错,只会静静给出错的图:
// pivot 补不齐时间点就让堆叠面积图的高度全错,coerce 不转类型就让端口过滤
// 报 ClickHouse 类型错,localInput 切错时区就让自定义区间整体偏移。
//
// 没有 node 时跳过而不是失败:node 只是开发期的校验工具,不是构建依赖。
func TestUIPureFunctions(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("没有 node,跳过界面 JS 检查")
	}

	dir := t.TempDir()

	// 被测函数从 indexHTML 里按名字抠出来,而不是在测试里复制一份 ——
	// 复制的那份会跟界面慢慢走散,测试照样全绿。
	var b strings.Builder
	b.WriteString(mustSnippet(t, "const PROTO = ", true))
	for _, fn := range []string{"protoLabel", "coerce", "isIntField", "pivot", "localInput"} {
		b.WriteString("\n\n")
		b.WriteString(mustSnippet(t, "function "+fn+"(", false))
	}
	b.WriteString("\n\nmodule.exports={protoLabel,coerce,isIntField,pivot,localInput,PROTO};\n")
	write(t, filepath.Join(dir, "ui.js"), b.String())

	// FIELDS 用后端真实的字段表,不手写:coerce 判类型完全依赖它,
	// 手写一份就等于把"前后端不同步"这个真正的风险从测试里剔掉了。
	fields, err := json.Marshal(query.Fields())
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "fields.json"), string(fields))

	src, err := os.ReadFile("testdata/ui_test.js")
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "ui_test.js"), string(src))

	cmd := exec.Command(node, "ui_test.js")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	t.Logf("node 输出:\n%s", out)
	if err != nil {
		t.Fatalf("界面 JS 检查失败: %v", err)
	}
}

// 界面脚本必须先能被解析。语法错误在 go build 里是完全看不见的。
func TestUIScriptParses(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("没有 node,跳过界面 JS 语法检查")
	}
	i := strings.Index(indexHTML, "<script>")
	j := strings.LastIndex(indexHTML, "</script>")
	if i < 0 || j <= i {
		t.Fatal("indexHTML 里找不到内联 <script>")
	}
	js := indexHTML[i+len("<script>") : j]
	if len(js) < 10_000 {
		t.Fatalf("抠出来只有 %d 字节,像是取错了范围", len(js))
	}
	path := filepath.Join(t.TempDir(), "index.js")
	write(t, path, js)
	if out, err := exec.Command(node, "--check", path).CombinedOutput(); err != nil {
		t.Fatalf("界面脚本语法错误: %v\n%s", err, out)
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// mustSnippet 从 indexHTML 里截出一段声明。
//
// line 为真时截到行尾(用于 const 表),否则按花括号配对截出整个函数体。
// 花括号计数对字符串里的 { 会算错,但这几个函数体里没有带花括号的字符串,
// 真出现的时候测试会直接语法错误报出来,不会静默取错。
func mustSnippet(t *testing.T, start string, line bool) string {
	t.Helper()
	i := strings.Index(indexHTML, "\n"+start)
	if i < 0 {
		t.Fatalf("indexHTML 里找不到 %q —— 函数被改名或删掉了,测试需要同步", start)
	}
	i++
	if line {
		// const 表可能跨多行,截到分号结尾的那一行。
		end := strings.Index(indexHTML[i:], ";\n")
		if end < 0 {
			t.Fatalf("%q 没有以分号结尾", start)
		}
		return indexHTML[i : i+end+1]
	}
	depth := 0
	for j := i; j < len(indexHTML); j++ {
		switch indexHTML[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return indexHTML[i : j+1]
			}
		}
	}
	t.Fatal(fmt.Sprintf("%q 的花括号不配对", start))
	return ""
}
