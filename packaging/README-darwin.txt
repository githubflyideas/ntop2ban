ntop2ban —— 解压即跑(macOS)
============================

这个目录里有两个可执行文件:ntop2ban 本身,和它要用的 clickhouse。
不需要 brew,不需要 docker。

先解除 Gatekeeper 隔离 —— 这一步必须做
--------------------------------------

从浏览器下载的压缩包会被打上 com.apple.quarantine 标记,解压出来的两个
二进制都带着它,直接运行会被系统拦下(clickhouse 那个尤其明显,因为它
没有签名也没有公证)。在这个目录的上一层执行:

    xattr -dr com.apple.quarantine ntop2ban-darwin-arm64

(Intel 机器上把目录名换成 ntop2ban-darwin-amd64。)

跑起来
------

    sudo ./ntop2ban -iface en0 -sampling 1

然后浏览器打开 http://localhost:8090

第一次启动会慢一点:clickhouse 是自解压二进制,首次运行要把自己展开,
需要大约 1GB 的空闲磁盘,耗时几十秒。

macOS 上与 Linux 的三点差异
---------------------------

1) -iface 必须给。macOS 走 /dev/bpf 抓包,BPF 设备没有"监听所有网卡"
   这个语义,必须绑定一块。en0 是无线/有线主网卡,lo0 是本机回环,
   utun* 是 VPN 隧道。ifconfig -l 可以列出来。

2) 建议 -sampling 1(全量)。抽样在 macOS 上只能在用户态做——BSD 的 BPF
   没有内核随机数扩展——所以内核该拷的包照拷,省下来的只有解析和聚合那
   一点 CPU,却要付上统计精度的代价。Mac 上的流量本来就不大,不值当。

3) 需要 sudo。/dev/bpf* 默认只有 root 可读。想免 sudo 就装 Wireshark 的
   ChmodBPF,或者自己给这些设备加个属于你的用户组。

XDP 是 Linux 内核接口,macOS 上没有,所以这里只有一级采集层可用;
抓包本身、界面、查询、存储与 Linux 完全一样。

ntop2ban 只做观测与统计,不封禁任何东西。

完整文档:https://github.com/githubflyideas/ntop2ban
