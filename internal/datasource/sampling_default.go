package datasource

import "runtime"

// DefaultSamplingN 是 -sampling 的默认值,按平台分。
//
// Linux 上默认 1/100:抽样判定由 cBPF 的 ExtRand 扩展在内核里做,没被选中
// 的包连拷都不拷,所以抽样是实打实省 CPU 的,默认开着划算。
//
// macOS 上默认全量。BSD 的 BPF 解释器没有随机数扩展,判定只能等包拷到用户
// 态之后再做(见 bpfdev_darwin.go 顶上的说明),抽样省下的只有解析和聚合那
// 一小段,内核过滤、拷贝、缓冲区占用、read 系统调用这几笔每个包都照付。于是
// -sampling 100 在 macOS 上几乎不省 CPU,却把统计精度砍掉了一大截——误差按
// 1/sqrt(实际计入的包数) 走,流量越小越难看,而家里那台 Mac 的流量本来就小。
// 更糟的是内核缓冲区一旦溢出,丢掉的包会被外推乘上 N,偏差跟着放大 100 倍。
//
// 换句话说:Linux 上抽样是省钱,macOS 上抽样是白扣精度。默认值就该不一样。
var DefaultSamplingN = defaultSamplingFor(runtime.GOOS)

func defaultSamplingFor(goos string) int {
	if goos == "darwin" {
		return 1
	}
	return 100
}
