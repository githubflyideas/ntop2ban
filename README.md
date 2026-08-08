# ntop2ban

**Watch the Top, Ban the Bad.**

单机 Flow Analytics 平台。XDP/eBPF 采集 + ClickHouse 存储 + 灵活查询。

---

## 这是什么

以 ClickHouse 为核心,在单机部署场景下实现接近 ElastiFlow 核心 Flow
Analytics 的能力:Top Talker / Conversation / ASN / Country / Port /
Protocol / 时间序列 / 下钻,输入支持本机 XDP、远端 sFlow v5、远端
NetFlow v5。

与 [xdp-ban](https://github.com/githubflyideas/xdp-ban) 的边界很清楚:

```
ntop2ban              xdp-ban
Observe               Decide
Analyze      ──→      Approve
Understand            Enforce / Audit
```

ntop2ban 不做封禁,只在发现可疑源时把事件推给 xdp-ban,由那边决定
放行/阻断/待审批。封禁逻辑不回流到这里。

顺带集成了两件事:**敲门(knock)**——按预设序列敲对了才放行 SSH,让
扫描器看不到端口;**链路探测**——不自己实现,界面上是指向你单独跑的
[pingping](https://github.com/githubflyideas/pingping) 的入口。

## 快速开始

```bash
sudo ./ntop2ban -iface eth0 user=admin passwd=你的密码
# 监听 :8090。不带 user=/passwd= 会生成一个随机密码打到日志里
```

需要 root(或 `CAP_NET_ADMIN` + `CAP_NET_RAW`):挂 XDP、抓包、写
nftables 规则。

发行包里 `ntop2ban` 与官方 `clickhouse` 静态二进制同目录,启动时自动
拉起并托管生命周期,不需要单独装数据库:

```
ntop2ban-linux-amd64/
├── ntop2ban      # 主程序
└── clickhouse    # 官方静态二进制,由 ntop2ban 托管
```

已经有 ClickHouse 的话用 `-clickhouse-addr host:9000` 连过去,不拉子进程。

## 认证

照搬 pingping 的做法:用户名密码放启动参数,没有数据库、没有注册流程。

```bash
./ntop2ban user=alice,bob passwd=p1,p2
```

会话只在内存里,重启即失效——单机工具完全可以接受,换来每个请求零 I/O。
不带账号参数时生成随机密码而不是裸奔放行:这个界面能看全网流量明细、
能改敲门序列,代价太大;也不用固定默认密码,那在公网上等于没密码。

## 敲门(knock)

序列写在 `/etc/ntop2ban/knock.list`,格式与 pingping 的 `ping.list`
同一路数,改完重启生效。默认值装上就能用:

```
tcp  9001
icmp 123
tcp  9002
icmp 145

open-port 22
window    60
open-for  60
```

敲门就是四条系统自带命令,不需要任何客户端工具:

```bash
nc -z -w1 <host> 9001
ping -s 123 -c 1 <host>
nc -z -w1 <host> 9002
ping -s 145 -c 1 <host>
# 成功后 60 秒内可连 SSH,只对你这个来源 IP 放行
```

**不支持 UDP**:很多客户端出口环境发不出 UDP,而一个静默不到达的敲门步
是最难排查的故障。**暗号固定不轮换**:曾设计过按时间窗用 HMAC 轮换
ICMP 包长,否决了——你得先去某处查当前值才能敲门,而那个页面往往也在
敲门保护之后,鸡生蛋。接受的代价是被抓包后可重放,但真正要防的是全网
扫描器,它猜不中序列;能在链路上抓包的对手已经是中间人,敲门本来也
救不了。**只记成功不记失败**:失败的敲门是互联网噪声,记下来只会淹没
真正需要看的东西。

清单文件权限是 0600 —— 序列就是密码。已存在的清单绝不会被覆盖,
否则等于悄悄把门锁换成公开的默认值。

## 数据面:XDP 优先,自动降级

流量采样与敲门捕获共用**一个 XDP 程序**(`bpf/sampler.c`),一次包解析
两个输出:采样走 1/N 抽样(允许丢,只服务可视化),敲门走精确匹配
(一个包都不能漏)。两者用各自的 ringbuf——共用一个的话,高流量下
敲门事件会被采样事件挤掉,而那是最不能丢的东西。

XDP 程序永远 `XDP_PASS`,只观测不拦截。封禁在 nftables 那边(netfilter
hook,与 XDP 不同层次),所以不存在网卡挂载点冲突。

挂不上 XDP 时按 native → generic → af-packet 逐级降级:

| 层级 | 说明 |
|---|---|
| **xdp-native** | 驱动层处理,性能最佳。需要网卡驱动支持 |
| **xdp-generic** | 内核在 `netif_receive_skb` 处模拟。任何网卡都能挂,但已在 `sk_buff` 分配之后。veth、容器、部分云主机常只能走这级 |
| **af-packet** | 完全不用 XDP。内核太老、XDP 被占用或权限受限时的退路。抽样判定仍在内核侧完成(cBPF 的 `ExtRand`) |

**三级产出完全相同的 Canonical Flow**,用的是同一份包解析
(`internal/flow`)与同一个聚合器。三处各写一份解析迟早会在"长度算不算
以太网头""分片怎么处理"这类细节上分叉,而分叉的表现是同一份流量在
不同输入方式下显示出不同数字,没有任何报错。

降级只发生在启动时,一次决定、之后不变。运行时切换会让同一时间窗口内
混入两种口径的数据,曲线上出现无法解释的跳变。用 `-datasource` 可强制
指定某一级(排查用)。

## 数据模型

Canonical Flow 是整个系统最重要的接口:**Input 可替换,Flow Model 不变。**
将来加 NetFlow v9 / IPFIX 只需要新增一个 Normalizer,ClickHouse 表结构与
Query Engine 一行都不用改。

计数保留双份:`packets`/`bytes` 是按采样率还原的**估算值**,
`observed_packets`/`observed_bytes` 是采样器真正看到的**实测值**。
只存估算值的话采样率事后发现配错就回不去了;只存实测值的话每次查询都
要乘一遍,而采样率是逐流可变的,那要求把采样率带进 GROUP BY,聚合基数
会暴涨。界面上两者分开展示。

长度统一取 IP 头声明的 total length,不是抓到的字节数——sFlow 只带包头
前 128/256 字节,用抓到的长度统计会让所有数字系统性缩水,而且完全静默。

## 存储

ClickHouse 是**唯一**存储,没有兜底后端。之前那套 `FlowStorage` 接口 +
SQLite 兜底已删除:维护两个后端的代价没有换来对应价值,SQLite 版本永远
做不到分层聚合与亿级明细查询,而那正是这个产品的核心能力。

- `flows` —— Raw Flow,MergeTree,按天分区,TTL 可配(`-retention-days`)
- `flows_1m` —— 分钟级聚合,SummingMergeTree + 物化视图自动填充,供时间
  序列与长期趋势(TTL 更长)
- `ip_metadata` —— IP 维度权威源,ReplacingMergeTree

`ORDER BY` 目前是 `(timestamp, src_ip, dst_ip, src_port, dst_port)`,
对应最高频的"最近 1h/24h + 某个 IP"。这是**草案**——最终必须通过真实
query benchmark 决定,而不是凭经验。

富化在写入时做,把 country/ASN/org 快照到 flow 行上,查询时不 JOIN
(禁止让亿级 flow 实时 JOIN GeoIP 表)。代价是 GeoIP 库更新后历史数据
保持当时快照,这是想要的行为:历史应该反映当时的归属。

## 启动参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-iface` | 空 | 观测网卡。XDP 模式必须指定 |
| `-sampling` | `100` | 抽样率 1/N;`1` 表示全量 |
| `-datasource` | 空(自动降级) | 强制 `xdp-native` / `xdp-generic` / `af-packet` |
| `-data-dir` | `./ntop2ban-data` | 数据目录 |
| `-config-dir` | `/etc/ntop2ban` | 配置清单目录(`knock.list`) |
| `-clickhouse-addr` | 空(托管子进程) | 外部 ClickHouse 地址 |
| `-clickhouse-bin` | 同目录 `./clickhouse` | clickhouse 二进制路径 |
| `-retention-days` | `90` | 明细数据保留天数 |
| `-no-knock` | 关 | 不启动敲门 |
| `user=` `passwd=` | 无(生成随机密码) | 逗号分隔的多账号 |

## 从源码构建

```bash
make build       # 构建 ./ntop2ban
make check       # vet + 全部测试
make release     # 交叉编译 linux/{amd64,arm64} 到 dist/
```

**最终用户不需要 clang。** 编译好的 eBPF 目标文件已提交进版本库。
只有改动 `bpf/sampler.c` 的维护者才需要:

```bash
make bpf         # 需要 clang + libbpf-dev,产物要一并提交
make bpf-verify  # 重新编译并与库里的 .o 比对(CI 跑这个)
```

`bpf-verify` 挡住的是"改了 C 忘了重编"——那样 `.o` 与 `.c` 会静默漂移,
运行时行为与源码不符,极难排查。

`CGO_ENABLED=0` 是硬约束,所以能静态编译、拷过去就跑。

## 当前进度

- [x] Canonical Flow 模型 + 共用包解析(三种输入口径统一)
- [x] ClickHouse 存储层(flows / flows_1m / ip_metadata,托管子进程)
- [x] 数据面:XDP 采样 + 敲门精确匹配,三级降级
- [x] 敲门:清单文件配置,nftables 放行
- [x] 认证:启动参数 + 内存会话
- [ ] sFlow v5 / NetFlow v5 Collector 与 Normalizer
- [ ] 写入时富化(ip2asn:ASN / country / org)
- [ ] Query AST 与查询引擎(字段白名单、强制时间范围与 limit)
- [ ] Dashboard / Explorer 界面(汇总、Top N、时间序列、下钻)

### 已知限制

**Top City 与 Geo Map 做不了。** 富化数据源用的是 iptoasn.com 的
ip2asn TSV(免费、无许可限制),它只有 ASN + country + org,没有
city/region/经纬度。`flows` 表里那几列保留但恒为空,将来接 MaxMind
GeoLite2 mmdb 就自动有值;界面上 city 相关视图在没有数据时直接不显示,
而不是显示一片空白让人以为坏了。

## License

Apache-2.0
