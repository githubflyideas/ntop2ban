ntop2ban —— 解压即跑
====================

这个目录里有两个可执行文件:ntop2ban 本身,和它要用的 clickhouse。
不需要安装任何东西,不需要 docker,不需要 root 之外的权限配置。

跑起来
------

    sudo ./ntop2ban -iface eth0

把 eth0 换成你要看的网卡名(ip -br link 可以列出来)。然后浏览器打开

    http://<这台机器的地址>:8090

第一次启动会慢一点:clickhouse 是自解压二进制,首次运行要把自己展开,
需要大约 1GB 的空闲磁盘,耗时几十秒。之后每次启动就快了。

常用参数
--------

  -sampling 1        全量统计,不抽样。默认是 1/100 抽样,流量不大的机器
                     (家用 NAS、单台服务器)建议直接用 1,数字才准。
  -addr :8090        改 Web 监听地址。
  -data-dir DIR      数据落在哪,默认 ./ntop2ban-data。整个目录删掉就是清空。
  -retention-days 90 明细数据保留天数。
  -clickhouse-addr HOST:9000
                     机器上已经有 ClickHouse 实例的话用这个连过去,
                     包里的 clickhouse 就不会被启动。
  -input sflow       不抓本机网卡,改收交换机导出的 sFlow(默认端口 6343);
                     netflow 同理(2055)。

为什么要 root:抓本机流量要 XDP 或 AF_PACKET,这两个都要
CAP_NET_RAW/CAP_NET_ADMIN。只收 sFlow/NetFlow 的话不需要 root。

ntop2ban 只做观测与统计,不封禁任何东西。封禁是 xdp-ban 的事。

完整文档:https://github.com/githubflyideas/ntop2ban
