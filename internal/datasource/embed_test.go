//go:build linux

package datasource

import "testing"

// 库里的 obj/sampler.o 曾经是一个 0 字节的占位文件,于是每一个发行二进制
// 都必然在启动时打出"内嵌 eBPF bytecode 为空"然后降级到 AF_PACKET ——
// XDP 那条路等于从来没通过。占位文件不会让 go build 失败(embed 一个空
// 文件是合法的),也不会让任何测试变红,所以它藏了很久。
//
// 这条测试就是那个缺口的补丁:bytecode 必须真的在,而且必须是 cilium/ebpf
// 认得的 collection,里面得有用户态按名字取用的那三个符号。改了
// bpf/sampler.c 忘了跑 make bpf,或者把 .o 又清成空文件,这里都会红。
func TestEmbeddedBytecodeIsRealProgram(t *testing.T) {
	if len(samplerBytecode) == 0 {
		t.Fatal("obj/sampler.o 是空的 —— 需要 make bpf 并把产物提交进库")
	}

	spec, err := loadSpec()
	if err != nil {
		t.Fatalf("解析内嵌 bytecode: %v", err)
	}
	// xdp_sampler 只管入向。出向那两个程序缺一个都意味着上传流量在某类
	// 内核上会静默丢失:tc_egress_sampler 是 6.6+ 的正路,
	// cgroup_egress_sampler 是老内核的退路。少了退路的话,Debian 12 这种
	// 6.1 的机器上出向就彻底没有了,而日志只会说"没挂上",看不出是
	// 编译时漏了程序。
	for _, prog := range []string{"xdp_sampler", "tc_egress_sampler", "cgroup_egress_sampler"} {
		if _, ok := spec.Programs[prog]; !ok {
			t.Errorf("bytecode 里没有 %s 程序,attach 时会失败", prog)
		}
	}
	for _, m := range []string{"sampling_rate", "sample_events", "egress_ifindex"} {
		if _, ok := spec.Maps[m]; !ok {
			t.Errorf("bytecode 里没有 %s map,configure/openReaders 时会失败", m)
		}
	}
}
