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

## 启动参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-api-key` | —(必填) | 采样上报鉴权密钥。留空会拒绝一切上报,因此启动时直接报错退出,而不是静默起来收不到数据 |
| `-addr` | `:8090` | HTTP 监听地址 |
| `-data-dir` | `./ntop2ban-data` | 数据目录 |
| `-days` | `40` | 采样数据保留天数 |

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
- [ ] 敲门捕获层(AF_PACKET raw socket + cBPF 过滤,纯 Go,不需要 clang)与放行动作
- [ ] 内化 eBPF 采样(目前接收 xdp-sampler 上报;目标是自己 attach 网卡)
- [ ] 审批流与角色权限(借鉴 xdp-ban 的四眼/审计设计,admin 超级权限)
- [ ] pingping 探测能力搬入(丢弃其 cgo 存储层,共用同一个库)
- [ ] 展示层(Top Clients/Servers、流量趋势、探测分布图;点击 IP 发起封禁)

## License

Apache-2.0
