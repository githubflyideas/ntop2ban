//go:build linux

package datasource

import _ "embed"

// samplerBytecode 是编译好的 XDP 采样程序。
//
// 与 xdp-ban 的做法不同:这里的 .o **提交进版本库**。理由是交付承诺——
// ntop2ban 的最终用户应该 `go build` 一步出二进制、不需要装 clang。
// 只有改动 bpf/sampler.c 的维护者才需要 clang 与 `make bpf`。
//
// 代价是 .o 与 .c 可能漂移(改了 C 忘了重编)。这个风险由 `make bpf-verify`
// 兜住:重新编译并与库里的 .o 比对,不一致就失败。CI 跑这个目标。
//
// 库里必须始终有一份**真的** .o。曾经这里放的是一个 0 字节占位文件:
// embed 一个空文件是合法的,go build 与全部测试都是绿的,而每一个发行
// 二进制启动时都会打"内嵌 eBPF bytecode 为空"并降级到 AF_PACKET ——
// XDP 那条路从没通过,却没有任何一处会红。现在由 embed_test.go 的
// TestEmbeddedBytecodeIsRealProgram 钉住:bytecode 必须能解析成
// collection 且带着 xdp_sampler 与两个 map。
//
// openXDP 里对空 bytecode 的判断仍然留着 —— 那是兜底,不是常态。
//
//go:embed obj/sampler.o
var samplerBytecode []byte
