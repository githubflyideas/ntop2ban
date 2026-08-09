# ntop2ban

**Watch the Top, Ban the Bad.**

单机 Flow Analytics 平台。XDP/eBPF 采集 + ClickHouse 存储 + 灵活查询。

一个二进制,拷过去就跑。不需要 Elasticsearch、不需要装数据库、不需要
Docker、不需要 Java。

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
放行/阻断/待审批。链路探测也不在这里,那是
[pingping](https://github.com/githubflyideas/pingping) 的事。
这个程序只做一件事:把流量看清楚。

## 下载

```bash
# x86_64
curl -L -o ntop2ban.tar.gz https://github.com/githubflyideas/ntop2ban/releases/latest/download/ntop2ban-linux-amd64.tar.gz
tar xzf ntop2ban.tar.gz && cd ntop2ban-linux-amd64
sudo ./ntop2ban -iface eth0 user=admin passwd=你的密码
```

arm64 把 URL 里的 `amd64` 换成 `arm64`。包里有两个文件:

```
ntop2ban-linux-amd64/
├── ntop2ban      # 主程序 ~14MB
└── clickhouse    # 官方静态二进制,由 ntop2ban 自动拉起托管
```

压缩包约 208MB(clickhouse 那个文件本身 176MB,首次运行时自解压到 771MB)。
这是"不装数据库"的代价:ClickHouse 是唯一存储,没有兜底后端,所以它必须
在包里。

包里的 clickhouse 用的是官方 **amd64compat** 构建(纯 SSE2),不是默认的
amd64 构建。后者要求 x86-64-v2(SSE4.2/POPCNT),在较老的物理机和屏蔽了
这些指令的虚拟机上一执行就 `Illegal instruction (core dumped)` —— 而那个
错误完全指不到"换个 clickhouse 构建"这个方向。牺牲一点性能换普遍可运行,
对单机部署是正确的取舍。

不想下这么大的话,单独下主程序(9MB)接外部 ClickHouse:

```bash
curl -L -o ntop2ban https://github.com/githubflyideas/ntop2ban/releases/latest/download/ntop2ban-linux-amd64
chmod +x ntop2ban
sudo ./ntop2ban -iface eth0 -clickhouse-addr 127.0.0.1:9000 user=admin passwd=xxx
```

也可以从源码构建(见文末),`go build` 一步出二进制,不需要 clang。

## 快速开始

```bash
sudo ./ntop2ban -iface eth0 user=admin passwd=你的密码
# 监听 :8090。默认只抓本机,不开任何 UDP 端口
```

需要 root(或 `CAP_NET_ADMIN` + `CAP_NET_RAW`)才能挂 XDP 与抓包。
发行包里 `ntop2ban` 与官方 `clickhouse` 静态二进制同目录,启动时自动
拉起并托管,不需要单独装数据库。已经有 ClickHouse 的话用
`-clickhouse-addr host:9000` 连过去。

## 输入源

三种输入,由 `-input` 选择。**默认只有 `local`,不开任何 UDP 端口** ——
默认监听 UDP 意味着任何装上这程序的机器凭空多两个对外端口,而绝大多数
用户只想看本机流量。要收远端数据必须显式打开,那时你知道自己在开什么。

```bash
./ntop2ban -iface eth0                     # 只抓本机(默认)
./ntop2ban -input sflow                    # 只收 sFlow,不抓本机
./ntop2ban -input netflow -netflow-listen :9995   # 只收 NetFlow,换端口
./ntop2ban -input local,sflow -iface eth0  # 同时启用:本机 + 交换机镜像
```

最后那种组合是有实际场景的:一台机器既跑业务(本机流量)又收汇聚交换机
的 sFlow。三种输入产出同一套 Canonical Flow,进同一张表,查询时用
`source_type` 区分。

| 输入 | 适用 | 说明 |
|---|---|---|
| `local` | 单机、NAS、家用 | XDP/eBPF 抓本机网卡,不需要交换机配合 |
| `sflow` | IDC、企业交换网络 | 远端设备 UDP 送采样包头,默认 6343 |
| `netflow` | 同上 | NetFlow v5,默认 2055 |

sFlow 送的是**采样到的原始包头**(不是聚合好的 flow 记录),所以它复用
本机抓包那份包解析 —— 解出来的东西完全同构,这是"Input 可替换,
Flow Model 不变"的落点。

## 认证

照搬 pingping 的做法:用户名密码放启动参数,没有数据库、没有注册流程。

```bash
./ntop2ban user=alice,bob passwd=p1,p2
```

会话只在内存里,重启即失效——单机工具完全可以接受,换来每个请求零 I/O。
不带账号参数时生成随机密码而不是裸奔放行:这个界面能看全网流量明细、
能看到内网拓扑,代价太大;也不用固定默认密码,那在公网上等于没密码。

## 数据面:XDP 优先,自动降级

本机采集用一个 XDP 程序(`bpf/sampler.c`)做 1/N 抽样,命中的包经
ringbuf 送到用户态聚合。抽样判定在内核完成,不命中的包根本不会拷上来。

XDP 程序永远 `XDP_PASS`,只观测不拦截 —— ntop2ban 的职责是
Observe/Analyze,所以它不需要跟任何封禁程序争抢网卡挂载点。

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

## 富化

写入时富化,不在查询时 JOIN —— 亿级 flow 表与 GeoIP 表实时 JOIN 在单机上
不可行。代价是 GeoIP 库更新后历史数据保持当时的快照,这是想要的行为:
一个 IP 去年属于 A 公司今年属于 B,去年的流量不该被改写成 B 的。

**ip2asn(必备底线)** —— 免费、无许可、无需注册:

```bash
curl -O https://iptoasn.com/data/ip2asn-v4.tsv.gz
./ntop2ban -ip2asn ./ip2asn-v4.tsv.gz -iface eth0
```

提供 ASN / 国家 / 组织。查表是排序数组 + 二分而不是 trie:50 万条记录
二分只需 19 次整数比较,trie 要 32 层指针跳转。

**GeoLite2-City(可选叠加)** —— 补城市、区域、经纬度。需要在 MaxMind
注册拿 license key,不能随发行包分发,所以支持在界面「设置」页上传,
**上传后立即生效、无需重启**。也可以 `-mmdb /path/to/GeoLite2-City.mmdb`。

两个库刻意不重叠覆盖 country:以 ip2asn 为准,mmdb 只补 city/region。
否则同一批流量的 Top Country 会因为"有没有加载 mmdb"而变化,那种差异
没人能解释。

没有 mmdb 时城市相关字段从 `/api/v1/query/fields` 里去掉,界面不会给出
一个查出来永远是空的选项 —— 那比不显示更让人困惑。

## 界面

五个视图:

| 视图 | 内容 |
|---|---|
| **Dashboard** | KPI 卡片(总流量/包/流/活跃源 IP/目的端口)、流量趋势(堆叠面积)、Top Talkers / Destinations / 端口 / ASN、应用与协议构成(甜甜圈) |
| **Hosts** | Top 源/目的主机,点 IP 下钻到该主机的对端、端口、应用、国家、ASN、协议 |
| **Conversations** | 源 ↔ 目的 的流量对,两端都可点击下钻 |
| **ASN / Country** | 源/目的国家、ASN、组织、城市(需 GeoLite2) |
| **Explorer** | 查询构造器:选字段、运算符、值,提交 AST;可查看生成的 SQL |

所有数据都走 `POST /api/v1/query` 提交 Query AST,每个卡片、每次下钻
都是一次 AST 请求 —— 同一个引擎服务所有视图。

图表是手写 SVG,不引 ECharts:1MB 的 JS 嵌进单一二进制会让体积翻倍,
而堆叠面积、横向条形、甜甜圈用 SVG 各几十行就够;更重要的是内网部署时
CDN 拉不到会直接白屏。

Explorer 是查询构造器:选字段、选运算符、填值,提交 AST。可以点「查看
SQL」看后端究竟生成了什么 —— 组合出复杂查询而结果不对时,没有这个入口
只能靠日志猜。

KPI 卡片把**估算值与实测值并列**展示,让人能判断这个数字是量出来的还是
算出来的。

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
| `-addr` | `:8090` | Web 监听地址 |
| `-input` | `local` | 输入源:`local` / `sflow` / `netflow`,逗号分隔 |
| `-iface` | 空 | 本机抓包的网卡。XDP 模式必须指定 |
| `-sampling` | `100` | 本机抓包抽样率 1/N;`1` 表示全量 |
| `-datasource` | 空(自动降级) | 强制 `xdp-native` / `xdp-generic` / `af-packet` |
| `-sflow-listen` | `:6343` | sFlow v5 监听地址 |
| `-netflow-listen` | `:2055` | NetFlow v5 监听地址 |
| `-data-dir` | `./ntop2ban-data` | 数据目录 |
| `-clickhouse-addr` | 空(托管子进程) | 外部 ClickHouse 地址 |
| `-clickhouse-bin` | 同目录 `./clickhouse` | clickhouse 二进制路径 |
| `-retention-days` | `90` | 明细数据保留天数 |
| `-ip2asn` | 空 | ip2asn TSV 路径(`.tsv` 或 `.tsv.gz`) |
| `-mmdb` | 空 | GeoLite2-City mmdb 路径;也可在界面上传 |
| `user=` `passwd=` | 无(生成随机密码) | 逗号分隔的多账号 |

## API

| 端点 | 说明 |
|---|---|
| `POST /api/v1/query` | 提交 Query AST,返回 columns + rows + 执行统计 |
| `POST /api/v1/query/explain` | 返回将要执行的 SQL,不真正执行 |
| `GET /api/v1/query/fields` | 可用字段、运算符、指标(界面据此构造查询器) |
| `GET /api/v1/overview` | 存储状态、输入源、富化库状态 |
| `POST /api/v1/enrich/mmdb` | 上传 GeoLite2-City,立即生效 |

Query AST 示例:

```json
{
  "time_range": {"from": "2026-08-01T00:00:00Z", "to": "2026-08-01T01:00:00Z"},
  "filters": {"op": "AND", "conditions": [
    {"field": "src_country", "operator": "eq", "value": "JP"},
    {"field": "dst_port", "operator": "in", "value": [443, 8443]}
  ]},
  "group_by": ["dst_ip"],
  "metrics": ["bytes", "packets", "flows"],
  "sort": {"field": "bytes", "desc": true},
  "limit": 100
}
```

时间范围、limit、timeout 三样都是强制的:缺任何一个都能让一次误操作
变成一次故障 —— 没时间范围的聚合在单机上一次就能把 ClickHouse 打满。
字段与运算符都有白名单,而且运算符是**逐字段**限制的:`src_ip` 不给
`like`(在 IPv6 列上做字符串匹配能跑但结果反直觉),`bytes` 不给 `cidr`。

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
- [x] 本机采集:XDP 优先,三级降级
- [x] sFlow v5 / NetFlow v5 Collector 与 Normalizer
- [x] 写入时富化(ip2asn + 可选 GeoLite2-City,IANA 服务名分类)
- [x] Query AST 与查询引擎(字段白名单、强制时间范围与 limit)
- [x] Dashboard / Hosts / Conversations / ASN-Country / Explorer
- [x] 认证:启动参数 + 内存会话
- [ ] Saved Query / Dashboard 自定义
- [ ] 向 xdp-ban 推送可疑事件(`POST /api/v1/security/events`)
- [ ] Benchmark 定稿 `ORDER BY`

### 已知限制

**城市维度需要自备 GeoLite2。** ip2asn 只有 ASN + country + org。
上传 GeoLite2-City 后城市与区域可用,但 Geo Map(地图可视化)还没做 ——
经纬度已经在解析里取出来了,缺的是地图组件。

**`ORDER BY` 是草案。** 当前 `(timestamp, src_ip, dst_ip, src_port,
dst_port)` 对应最高频的"最近 1h/24h + 某个 IP"。设计文档明确要求最终
必须由真实 query benchmark 决定,而不是凭经验 —— 这件事还没做。

**eBPF 字节码是占位空文件。** 构建环境装不上 clang,所以库里的
`sampler.o` 是空的,XDP 两级会自动降级到 AF_PACKET。要用上 XDP 请在
有 `clang` + `libbpf-dev` 的机器上 `make bpf && make build`。

## License

Apache-2.0
