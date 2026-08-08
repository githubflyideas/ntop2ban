# ntop2ban

**Watch the Top, Ban the Bad.**

小企业向的流量观测与访问控制。一个二进制,一个 SQLite 文件,scp 上去就能跑。

---

## 这是什么

ntop2ban 把三件事装进同一个程序:

- **流量观测** —— eBPF 采样,看清谁在打你的主机
- **敲门授权(knock)** —— 按预设序列敲门才放行 SSH,让扫描器看不到端口
- **链路探测** —— 周期性 ICMP/TCP 探测,延迟与丢包的分布图(源自 [pingping](https://github.com/githubflyideas/pingping))

配上审批与审计:序列的变更需要走审批,成功授权全部留痕。

与 [xdp-ban](https://github.com/githubflyideas/xdp-ban) 的分工:xdp-ban 处理大流量镜像分析
(ClickHouse 分层聚合在那边),ntop2ban 走轻量路线。采样流量、敲门序列、
审批审计、探测结果都落**同一个 `.db` 文件**,拷走那个文件就是完整备份。

## 快速开始

```bash
./ntop2ban -api-key <你的密钥>
# 监听 :8090,数据落 ./ntop2ban-data/,采样保留 40 天
```

## 敲门(knock)

序列由用户在平台上设定,混合 TCP 与 ICMP,**不用 UDP**——很多客户端出口
环境发不出 UDP。整个序列必须在 **1 分钟内**完成。

一个典型序列 `TCP 9001 → ICMP 56 → TCP 9003 → ICMP 90`,敲门就是四条
系统自带命令,不需要任何自制客户端:

```bash
nc -z -w1 <host> 9001      # 第 1 步
ping -s 56 -c 1 <host>     # 第 2 步
nc -z -w1 <host> 9003      # 第 3 步
ping -s 90 -c 1 <host>     # 第 4 步
# 成功后 60 秒内可连接 SSH,只对你这个来源 IP 放行
```

界面直接给出可复制的命令,不用自己拼。

设计取舍值得说明:**暗号是固定的,不做轮换。** 曾经设计过按时间窗
用 HMAC 轮换 ICMP 包长,否决了——你得先去某处查当前值才能敲门,而那个
"某处"往往也在敲门保护之后,鸡生蛋。接受的代价是被抓包后可重放,但真正
要防的是全网扫描器,它永远猜不中这个序列;而能在链路上抓包的对手已经是
中间人,敲门本来也救不了,那时靠的是 SSH 自身的密钥认证。

**只记成功,不记失败。** 敲错的包就是互联网噪声,记下来只会淹没审计日志。

审批不是实时闸门:它管的是"序列定义"这份配置的变更(改哪些端口、
哪些 ICMP 长度),守护进程始终按当前生效的那版工作,不会卡在等审批上。

## 敲门(knock)是怎么实现的

捕获层**不走 XDP**。一张网卡同时只能挂一个 XDP 程序,而同机部署时那个
位置属于 xdp-ban 的封禁程序——敲门也必须在生产网卡上看包,直接冲突。
而且敲门一分钟就几个包,XDP 的线速处理能力毫无用处,换来的却是
clang + libbpf 构建链和网卡驱动兼容性问题。

实际用的是:

- **TCP 步** —— AF_PACKET socket + cBPF 过滤器,只看目的端口在集合内的
  纯 SYN。不用 `net.Listen` 监听那几个端口,因为那样端口在扫描器眼里是
  **开着的**,暴露了"这台机器有几个奇怪端口在听";旁听则让端口保持关闭、
  内核照常回 RST,扫描器看到的就是普通关闭端口。
- **ICMP 步** —— raw ICMP socket,读 echo request 的 payload 长度。
  **不影响内核照常回 ping**,普通 ping 该通还是通。
- **放行** —— nftables,插一条 accept 规则,到期删掉。规则放在自建的
  `inet ntop2ban` 表里、带 `ntop2ban-knock` 注释,不碰用户已有规则集。
  这里用 nftables 而不是 eBPF map:xdp-ban"封禁走 XDP"那条结论说的是
  大流量丢包路径,性能敏感;敲门放行是每分钟几次规则增删,量级完全不同。

cBPF 而非 eBPF 的好处是字节码可以用纯 Go 在运行时汇编出来
(`golang.org/x/net/bpf`),不需要编译期的 clang,`go build` 一步出二进制。

## 链路探测

周期性 ICMP/TCP 探测,记录每轮的 RTT 分布与丢包,画延迟/丢包图。
算法搬自 [pingping](https://github.com/githubflyideas/pingping),
但**没有搬它的存储层**——那边用 cgo 驱动,带进来会毁掉静态编译。
探测结果落 ntop2ban 已有的那一个库,只是多几张表。

```bash
./ntop2ban -api-key k1 -probe 'idc-a=10.0.0.1,dns=8.8.8.8,web=example.com:443'
# 不带端口 = ICMP 探测;带端口 = TCP 探测(用连接建立耗时作为 RTT)
```

保留 pingping 的核心取舍:**存分布而不是均值**。一轮 20 个包,记下
min/p50/p90/p99/max。均值会把"一半包 5ms、一半包 500ms"和"所有包 250ms"
画成同一条线,而这两种链路的体感完全不同。丢包突发用 robust z-score
(中位数 + MAD)判定,对异常值不敏感——用均值加标准差的话,历史上的
大丢包会把基线自己抬高,变成"以前抖过,现在抖就不算异常"。

## 启动参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-api-key` | —(必填) | 采样上报鉴权密钥。留空会拒绝一切上报,因此启动时直接报错退出,而不是静默起来收不到数据 |
| `-addr` | `:8090` | HTTP 监听地址 |
| `-data-dir` | `./ntop2ban-data` | 数据目录 |
| `-days` | `40` | 数据保留天数(采样与探测共用) |
| `-probe` | 空 | 探测目标,逗号分隔。`name=host` 走 ICMP,`name=host:port` 走 TCP |
| `-knock-iface` | 空(所有网卡) | 敲门抓包的网卡 |
| `-no-knock` | 关 | 不启动敲门守护 |

## 从源码构建

```bash
make build     # 构建 ./ntop2ban
make test      # 全部测试
make check     # vet + test
make release   # 交叉编译 linux/{amd64,arm64} 到 dist/
```

`CGO_ENABLED=0` 是硬约束:SQLite 用 `modernc.org/sqlite`(纯 Go),
所以能静态编译、拷过去就跑。

## 路线图

- [x] 采样存储层(SQLite)与接收端点
- [x] 敲门序列状态机与持久化(序列版本 + 成功授权记录)
- [x] 敲门捕获层(AF_PACKET + cBPF / raw ICMP)与 nftables 放行
- [x] 链路探测(ICMP/TCP,分布存储,突发判定)
- [ ] 内化 eBPF 采样(目前接收 xdp-sampler 上报;目标是自己 attach 网卡)
- [ ] 审批流与角色权限(借鉴 xdp-ban 的四眼/审计设计,admin 超级权限)
- [ ] Web 界面(敲门序列配置与审批、Top Clients/Servers、流量趋势、探测分布图;点击 IP 发起封禁)

## License

Apache-2.0
