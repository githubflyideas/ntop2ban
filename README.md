# ntop2ban

**Watch the Top, Ban the Bad.**

接收 eBPF 采样上报，持久化到内嵌 ClickHouse，做流量可视化与一键封禁。

---

## 这是什么

ntop2ban 是 [xdp-ban](https://github.com/githubflyideas/xdp-ban) 的流量可视化子项目。
xdp-ban 的 `xdp-sampler` 在镜像口上做 1/N 采样，把聚合后的流记录周期性上报；
xdp-ban 自己只把这些数据放在内存环形缓冲里（重启即丢，够实时仪表板用），
ntop2ban 则把同一份上报**持久化**下来，支撑历史查询、趋势图与多维分析。

协议层面完全复用 xdp-ban 现有的上报格式（`POST /api/v1/samples`，`X-API-Key` 鉴权），
**不需要修改 xdp-ban / xdp-sampler 任何代码**——把 `xdp-sampler -url` 指向 ntop2ban 即可。

## 部署形态：拷贝即用

ClickHouse 不是需要你另行安装的外部服务。发布包里 `ntop2ban` 与官方
`clickhouse` 静态二进制放在同一目录，ntop2ban 启动时把它作为**子进程**
拉起并托管其生命周期（生成配置、健康检查、退出收尾），数据落在本地目录。

```
ntop2ban-linux-amd64/
├── ntop2ban      # 主程序(~19MB)
└── clickhouse    # 官方静态二进制,由 ntop2ban 托管
```

```bash
./ntop2ban -api-key <与 sampler 一致的密钥>
# 默认监听 :8090,数据落 ./ntop2ban-data/
```

然后让采样器把数据打过来：

```bash
sudo ./xdp-sampler -d eth1 -url http://<ntop2ban 主机>:8090/api/v1/samples -n 4096 -key <API_KEY>
```

## 启动参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-api-key` | —（必填） | 上报鉴权密钥，须与 `xdp-sampler -key` 一致。留空会拒绝一切上报，因此启动时直接报错退出而不是静默起来收不到数据 |
| `-addr` | `:8090` | HTTP 监听地址 |
| `-storage` | `clickhouse` | 存储后端：`clickhouse`（托管内嵌）或 `sqlite`（兜底） |
| `-data-dir` | `./ntop2ban-data` | 数据目录。托管 ClickHouse 的库文件、SQLite 的 `.db` 都落这里 |
| `-clickhouse-bin` | 同目录 `./clickhouse` | clickhouse 静态二进制路径 |

## 两种存储后端

| 模式 | 能力 | 适用 |
|---|---|---|
| **clickhouse**（默认） | 完整：三层 schema（明细表 + 分钟级物化视图 + 小时/天 rollup）、多维聚合、历史趋势 | 推荐，开箱即用，无需单独装服务 |
| **sqlite** | 降级：能收能存能做基础 Top-N 与按时间清理，无 rollup / 无多维聚合 | 连一个托管子进程都不想要的场景 |

两者实现同一个 `FlowStorage` 接口（`Append`/`Query`/`Aggregate`/`Retention`/`Compact`/`Stats`），
切换后端时上层业务代码零改动。SQLite 后端的 `Stats()` 会返回 `Degraded: true`，
前端据此隐藏依赖聚合能力的展示入口。

> 注意：这里的 SQLite 是**流量存储**的兜底后端，与 xdp-ban 审批流（Circulate）
> 用的那个 SQLite 库是两回事，互不影响。

## 从源码构建

```bash
make build              # 构建 ntop2ban 到 bin/
make test               # 单元测试(不需要 ClickHouse)
make fetch-clickhouse   # 下载 clickhouse 静态二进制到 bin/
make test-integration   # 集成测试(自动用 bin/clickhouse 起一个实例)
make release            # 交叉编译 linux/{amd64,arm64} 到 dist/
```

集成测试通过环境变量显式开启，没设置就跳过，这样普通 `go test ./...`
不会因为缺少外部依赖而失败：

```bash
NTOP2BAN_CH_TEST_ADDR=127.0.0.1:9000 go test ./internal/storage/clickhouse/...
```

## 路线图

本仓库对应 xdp-ban 架构方案 v0.3 的阶段二至阶段四：

- [x] 阶段二：`FlowStorage` 接口 + ClickHouse 实现 + 采样接收端点
- [ ] 阶段三：写入时富化（GeoIP / ASN / IANA 服务名）
- [ ] 阶段四：展示层（Top Clients/Servers、Services 分布、Traffic Timeline、Country/ASN 视图；点击 IP 直接发起封禁申请）

## License

Apache-2.0
