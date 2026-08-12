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

四个平台各有一个这样的"解压即跑"包,把 URL 里的 `linux-amd64` 换掉即可:
`linux-amd64`、`linux-arm64`、`darwin-arm64`、`darwin-amd64`。包里三个文件:

```
ntop2ban-linux-amd64/
├── ntop2ban      # 主程序 ~10MB
├── clickhouse    # 官方静态二进制,由 ntop2ban 自动拉起托管
└── README.txt    # 这一页的浓缩版,离线也能看
```

压缩包 160~185MB(clickhouse 那个文件占了几乎全部;它是自解压的,首次
运行时会把自己展开到 770MB 左右,所以目标机上要留出约 1GB 空闲磁盘)。
`clickhouse` 必须在包里 —— ClickHouse 是唯一存储,没有兜底后端,这是
"不装数据库"的代价。

macOS 上是同样的流程,只多一步解除 Gatekeeper 隔离:

```bash
curl -L -o ntop2ban.tar.gz https://github.com/githubflyideas/ntop2ban/releases/latest/download/ntop2ban-darwin-arm64.tar.gz
tar xzf ntop2ban.tar.gz
xattr -dr com.apple.quarantine ntop2ban-darwin-arm64     # 这一步必须做
cd ntop2ban-darwin-arm64
sudo ./ntop2ban -iface en0 user=admin passwd=你的密码
```

`xattr -dr` 不能省。浏览器下载的压缩包会被打上 `com.apple.quarantine`,
解压出来的两个二进制都继承这个标记,包里的 `clickhouse` 既没签名也没公证,
直接运行会被系统拦下,而报错信息指不到隔离标记这个原因上。Intel 机器把
`darwin-arm64` 换成 `darwin-amd64`。

macOS 上三种输入都能用,包括 `-input local`:本机抓包走 `/dev/bpf`,也就是
libpcap 在 Mac 上用的那套设施 —— BPF 本来就是 BSD 的东西,Linux 的
AF_PACKET + cBPF 是后来的仿制。纯 Go 实现,不需要 cgo。

两点与 Linux 不同,都会影响你看到的数字:

**必须指定 `-iface`。** `BIOCSETIF` 是打开 BPF 设备的必要一步,没有
"监听全部网卡"这个语义。`ifconfig` 看名字,通常是 `en0`。

**抽样在用户态做,所以 macOS 上 `-sampling` 默认就是 1(全量),不用自己
写。** Linux 侧靠
cBPF 的 `ExtRand` 扩展在内核里就丢掉 (N-1)/N 的包;BSD 的 BPF 解释器没有
随机数扩展,判定只能等包拷到用户态之后。于是内核那侧的过滤、按 caplen 的
拷贝、缓冲区占用、read 系统调用,每个包都照付,N 是多少都一样 —— 抽样省
下来的只有头部解析与聚合那部分 CPU,而代价是短流会成片消失、且内核缓冲
溢出丢的包会被乘回 N 倍放大。Mac 与家用 NAS 的绝对包速本来就不高,这笔
交换不值当,所以默认值直接按平台分开:Linux 100、macOS 1。真要在 Mac 上
抽样,显式给 `-sampling N` 仍然生效,启动时会打一行日志说明它是在用户态
完成的。

还需要 root:`/dev/bpf*` 默认是 `root:wheel 0600`(Wireshark 装那个
ChmodBPF 启动项就是为这个)。不想用 `sudo` 就把设备属主改成当前用户。

macOS 上唯一真正缺的是 XDP —— 内核里没有可编程快路径这种东西,`-datasource
xdp-native` 之类在 Mac 上不存在,只有 `bpf-device` 一级。

`linux-amd64` 包里的 clickhouse 用的是官方 **amd64compat** 构建(纯 SSE2),
不是默认的 amd64 构建。后者要求 x86-64-v2(SSE4.2/POPCNT),在较老的物理机和屏蔽了
这些指令的虚拟机上一执行就 `Illegal instruction (core dumped)` —— 而那个
错误完全指不到"换个 clickhouse 构建"这个方向。牺牲一点性能换普遍可运行,
对单机部署是正确的取舍。

**每个 release 里只有这四个包加一个 `SHA256SUMS`,没有别的。** 早先还
同时发四个裸二进制,结果一个 release 页面上八个文件,下载的人第一件事是
先搞清楚该点哪个 —— 那本身就是设计失败。已经有 ClickHouse 实例的话照样
下大包,无视里面那个 `clickhouse`、启动时加上 `-clickhouse-addr` 即可:

```bash
sudo ./ntop2ban -iface eth0 -clickhouse-addr 127.0.0.1:9000 user=admin passwd=xxx
```

嫌大也可以从源码构建(见文末),`go build` 一步出 10MB 的二进制,不需要
clang,也不需要下 clickhouse。

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
| `local` | 单机、NAS、家用 | 抓本机网卡,不需要交换机配合。Linux 走 XDP/eBPF,macOS 走 `/dev/bpf` |
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
| **bpf-device** | macOS/BSD 上唯一的一级,`/dev/bpf` + cBPF。不与上面三级构成降级关系:XDP 在 macOS 上不存在,而 BPF 是 BSD 原生设施。抽样在用户态 |

**各级产出完全相同的 Canonical Flow**,用的是同一份包解析
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

**在界面「设置」页一键同步**,内置这些源,全部免费、无需注册:

| 源 | 类型 | 填充字段 | 许可 |
|---|---|---|---|
| iptoasn.com ip2asn | ASN | ASN、国家(ISO)、组织 | 公共领域 |
| DB-IP ASN Lite | ASN | ASN、组织(公司全称更规整) | CC BY 4.0 |
| **DB-IP City Lite** | 城市 | 国家、省/州、城市、经纬度 | CC BY 4.0 |

列表里只留能真正下下来的源。APNIC 的分配记录与纯真的文本导出都曾在列表
里,现在删掉了:`ftp.apnic.net` 在不少家宽出口上直接超时,而纯真那个文本
导出的仓库早已不再更新、URL 也时好时坏。摆一个点了必然失败的按钮比不摆
更糟 —— 用户会先怀疑自己的网络或这个程序。

也可以用 `-ip2asn ./ip2asn-v4.tsv.gz` 指定本地文件。同步过的库存在数据
目录里,重启后自动加载,不用每次重新点。

**DB-IP City Lite 让城市维度成为默认可用的功能** —— 它是唯一免费且无需
注册的城市库,装上之后 Top City 与经纬度就有了,不再必须去 MaxMind 注册。
MaxMind GeoLite2 精度更高但需要 license key,所以只能手动下载后从界面上传,
不内置自动同步(那等于替用户接受了他没读过的许可协议)。

字段优先级是定死的,因为"我装了库为什么某一列还是空的"是最常见的疑问:

- `asn` / `org` 来自 ASN 类源
- `country` / `region` / `city` / 经纬度**同时**来自城市类源 —— 城市库带
  ISO 码时它的 country 覆盖 ASN 库给的那个

城市库覆盖 country 是实测逼出来的:`114.114.114.114`
在 ip2asn 里归 US(按 BGP 路由归属,该前缀确实被一个美国 AS 宣告),而
db-ip 定位到山东济南 —— 保留 ASN 库的 country 会产出
`country=US / city=济南` 这种自相矛盾的行,而矛盾就在同一行里,用户第一眼
就会看到且无法解释。让 country/region/city 三者来自同一个源才自洽。

## 界面

五个视图:

| 视图 | 内容 |
|---|---|
| **Dashboard** | KPI 卡片(总流量/包/流/活跃源 IP/目的端口)、流量趋势(堆叠面积)、Top Talkers / Destinations / 端口 / ASN、应用与协议构成(甜甜圈) |
| **Hosts** | Top 源/目的主机,点 IP 下钻到该主机的对端、端口、应用、国家、ASN、协议 |
| **Conversations** | 源 ↔ 目的 的流量对,两端都可点击下钻 |
| **ASN / Country** | 源/目的国家、ASN、组织、城市(需 GeoLite2) |
| **Geo Map** | 世界地图按国家着色(源/目的 × 流量/包/流),点国家下钻 |
| **Explorer** | 查询构造器:选字段、运算符、值,提交 AST;可查看生成的 SQL;查询条件可保存复用 |

所有数据都走 `POST /api/v1/query` 提交 Query AST,每个卡片、每次下钻
都是一次 AST 请求 —— 同一个引擎服务所有视图。

图表用 ECharts,**资源 `go:embed` 进二进制,不引 CDN**。内网机房拉不到
CDN 会直接白屏,而这种故障从二进制本身完全看不出原因,所以宁可让二进制
多 1MB。世界地图底图同样入库(Natural Earth 50m,feature 名就是 ISO
alpha-2 码,与 `src_country` 精确对应,不做国名模糊匹配),由 `/static/`
服务:入库的是预压缩资源,浏览器接受 gzip 就原样吐字节,ETag 命中走 304。

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
| `-sampling` | Linux `100` / macOS `1` | 本机抓包抽样率 1/N;`1` 表示全量。macOS 默认全量的理由见上文 |
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
| `GET /api/v1/queries` | 已保存的查询列表 |
| `POST /api/v1/queries/save` | 保存一条查询(存界面选择,不是 SQL/AST) |
| `POST /api/v1/queries/delete` | 删除一条已保存的查询 |
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
make release     # 交叉编译 {linux,darwin}/{amd64,arm64} 到 dist/(package 的输入)
make package     # 上面四个再各配一个 clickhouse 打成 tar.gz(要联网下 ~660MB)
                 # 产物就是全部发行资产:四个 tar.gz + SHA256SUMS
make verify-packages  # 用 file(1) 复核包里两个二进制的架构对得上
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
- [x] 写入时富化(ip2asn / DB-IP 一键在线同步,IANA 服务名分类)
- [x] Query AST 与查询引擎(字段白名单、强制时间范围与 limit)
- [x] Dashboard / Hosts / Conversations / ASN-Country / Geo Map / Explorer
- [x] 认证:启动参数 + 内存会话
- [x] Saved Query(查询条件保存复用)
- [ ] Dashboard 自定义(卡片增删与布局)
- [ ] 向 xdp-ban 推送可疑事件(`POST /api/v1/security/events`)
- [ ] Benchmark 定稿 `ORDER BY`

### 已知限制

**`ORDER BY` 是草案。** 当前 `(timestamp, src_ip, dst_ip, src_port,
dst_port)` 对应最高频的"最近 1h/24h + 某个 IP"。设计文档明确要求最终
必须由真实 query benchmark 决定,而不是凭经验 —— 这件事还没做。

**eBPF 字节码是占位空文件。** 构建环境装不上 clang,所以库里的
`sampler.o` 是空的,XDP 两级会自动降级到 AF_PACKET。要用上 XDP 请在
有 `clang` + `libbpf-dev` 的机器上 `make bpf && make build`。

## License

Apache-2.0
