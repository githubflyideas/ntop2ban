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
// 文件不存在时 embed 会导致编译失败,所以库里始终有一份(哪怕是占位的
// 空文件)。空 bytecode 会在 openXDP 里被识别为"不可用"并降级到
// AF_PACKET,而不是抛出一个难懂的 verifier 错误。
//
//go:embed obj/sampler.o
var samplerBytecode []byte
