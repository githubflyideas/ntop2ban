package datasource_test

import (
	"os/exec"
	"testing"
)

// TestBuildsForDarwin 守住"整个程序在 macOS 上编译得过"这条约束。
//
// 本包用的 AF_PACKET 与 XDP 都是 Linux 内核接口,很容易随手写出一个只在
// Linux 上编译得过的文件,而这会连带把 cmd/ntop2ban 整个拖下水——哪怕
// Mac 用户只想收 NetFlow、根本不碰本机抓包。这种破坏在 Linux 上跑
// go build ./... 是发现不了的,所以必须显式跨编译一次。
//
// 编译目标是 cmd/ntop2ban 而不是本包:约束的实质是"程序能在 Mac 上出
// 二进制",只测本包会漏掉调用方(比如 main 里对 Open 返回值的用法)。
func TestBuildsForDarwin(t *testing.T) {
	if testing.Short() {
		t.Skip("跨平台编译要拉 darwin 的标准库对象,-short 下跳过")
	}
	for _, arch := range []string{"arm64", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			cmd := exec.Command("go", "build", "-o", t.TempDir()+"/ntop2ban",
				"github.com/githubflyideas/ntop2ban/cmd/ntop2ban")
			cmd.Env = append(cmd.Environ(),
				"GOOS=darwin", "GOARCH="+arch, "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("darwin/%s 编译失败: %v\n%s", arch, err, out)
			}
		})
	}
}
