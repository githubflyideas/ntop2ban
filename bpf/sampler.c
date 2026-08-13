/* sampler.c —— ntop2ban 的内核数据面:1/N 流量采样,入向 + 出向。
 *
 * 永远放行:这些程序只观测,不拦截。ntop2ban 的职责是 Observe / Analyze,
 * 封禁与执行是 xdp-ban 的事(见 README 的边界说明)。因此这里不需要与
 * 任何封禁程序争抢网卡挂载点。
 *
 * 三个程序,共用同一组 map 与同一个采样/解析函数:
 *
 *   xdp_sampler            SEC("xdp")               入向
 *   tc_egress_sampler      SEC("tc")                出向,内核 >= 6.6 走 TCX
 *   cgroup_egress_sampler  SEC("cgroup_skb/egress") 出向,老内核的退路
 *
 * 为什么出向要单独一个程序:XDP 只挂在**接收**路径上,发出去的包压根不
 * 经过它。只挂 XDP 的话上传流量会系统性缺失,而且不会有任何报错——图上
 * 只是看着比实际空闲。v0.6.0 及以前正是这个状态,只不过那时 sampler.o 是
 * 空文件、实际跑在双向可见的 AF_PACKET 上,一个缺陷把另一个盖住了。
 *
 * 编译(需要 clang + libbpf-dev):
 *   make bpf
 * 产物 internal/datasource/obj/sampler.o 提交进库,这样最终用户 go build
 * 一步出二进制、不需要 clang;只有改动本文件的维护者才需要。
 * CI 会重新编译并比对,防止 .o 与 .c 漂移。
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* 故意不 include <linux/icmp.h>:它经由 linux/if.h 拉进 glibc 的
 * sys/socket.h,而 -target bpf 不定义 __x86_64__,于是 features.h
 * 走 32 位分支去找 gnu/stubs-32.h、编译直接失败。这里只需要
 * IPPROTO_ICMP,那个常量在 linux/in.h 里已经有了。 */

/* 同理不 include <linux/pkt_cls.h>,只要一个常量。TC 程序返回
 * TC_ACT_OK(0) 表示"照常走后面的流程"。
 *
 * 这个 0 与 cgroup_skb 的约定正好相反:cgroup_skb/egress 里 return 0 是
 * **丢包**、return 1 才是放行。两个程序都写在这个文件里,搞混的后果是
 * 整机断网,所以每个 return 都注明了含义。 */
#define TC_ACT_OK 0
#define CGROUP_SKB_PASS 1

/* 方向标记,与 Go 侧 Observation.Egress 对应。 */
#define DIR_INGRESS 0
#define DIR_EGRESS  1

/* ---- 采样配置 ---- */

/* 抽样率 1/N。用户态启动时写入,运行期不改(改采样率要重启,
 * 让进程管理器的重启记录成为变更记录)。 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} sampling_rate SEC(".maps");

/* 出向要观测的网卡 ifindex,只有 cgroup_skb 那条退路会读它。
 *
 * TCX 是按网卡挂的,挂上就只看得见那块网卡;而 cgroup_skb/egress 挂在
 * cgroup 上,机器上**所有**网卡的出向包都会经过,包括 lo。不过滤的话
 * ntop2ban 自己往 127.0.0.1:9000 灌 ClickHouse 的流量会被当成网络流量
 * 记下来,越忙越多,自己喂自己。 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} egress_ifindex SEC(".maps");

/* 采样事件 ringbuf。1/N 命中的包送这里。 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);   /* 1MB */
} sample_events SEC(".maps");

struct sample_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 pkt_len;
    __u8  proto;
    __u8  dir;      /* DIR_INGRESS / DIR_EGRESS */
    __u16 segs;     /* 这一个 skb 实际会变成几个网线包,见下文 TSO */
    __u16 _pad;
};

/* 布局是与 Go 侧的跨语言契约,internal/datasource/event.go 按固定偏移解析。
 * Go 侧有测试盯住字段顺序,但盯不住 C 编译器插进来的对齐填充:加一个
 * __u8 字段就可能让 sizeof 从 20 变 24,而 Go 侧照旧按 20 解析、每条事件
 * 都错位,不报错只出垃圾数据。所以在 C 侧把大小钉死。 */
_Static_assert(sizeof(struct sample_event) == 20,
               "sample_event 大小变了,internal/datasource/event.go 的偏移量必须同步改");

/* ---- 全局计数,供界面展示"采样器在正常工作" ---- */
struct global_stats {
    __u64 total_packets;
    __u64 total_bytes;
    __u64 sampled_packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct global_stats);
    __uint(max_entries, 1);
} global_stats SEC(".maps");

/* 简单 LCG 伪随机。抽样不需要密码学强度的随机性,只需要分布均匀。 */
static __always_inline __u32 prng(__u32 seed) {
    return seed * 1103515245 + 12345;
}

/* sample_ipv4 是三个程序共用的解析 + 抽样 + 上报。
 *
 * 提到一个函数里不只是为了少写两遍:入向和出向必须产出口径完全一致的
 * 观测,否则同一条连接的上行和下行会按不同规则统计,而表现只是"上传和
 * 下载的数字对不上",不会有任何报错。
 *
 * wire_len 只用于全局计数(入向是整帧长,出向没有可靠的"网线长度",
 * 传 IP 总长即可);流量统计用的是 IP 头里声明的 tot_len。
 * mix 是给随机种子加的熵:XDP 有 rx_queue_index,TC/cgroup 没有,
 * 给什么都行,只要同一时刻不同包算出来的数不一样。
 */
static __always_inline void sample_ipv4(struct iphdr *ip, void *data_end,
                                        __u32 wire_len, __u32 mix,
                                        __u8 dir, __u16 segs)
{
    if ((void *)(ip + 1) > data_end)
        return;

    /* IP 头长度可变(带 option 时 >20),必须按 ihl 定位传输层头。
     * 写死 20 会在带 option 的包上读错端口。 */
    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(struct iphdr))
        return;
    void *l4 = (void *)ip + ihl;
    if (l4 > data_end)
        return;

    __u32 zero = 0;
    struct global_stats *gs = bpf_map_lookup_elem(&global_stats, &zero);
    if (gs) {
        __sync_fetch_and_add(&gs->total_packets, 1);
        __sync_fetch_and_add(&gs->total_bytes, (__u64)wire_len);
    }

    /* 分片包的后续片没有传输层头,按偏移读端口读到的是载荷数据。
     * 0x1fff 掩掉 flags 只留 fragment offset。 */
    if ((ip->frag_off & __constant_htons(0x1fff)) != 0)
        return;

    __u16 src_port = 0, dst_port = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return;
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);

    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return;
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);

    } else {
        /* ICMP 与其余无端口协议不进采样:只会产生 port=0 的伪流,
         * 占据 Top N 的位置却说明不了"谁在打我"。 */
        return;
    }

    /* ---- 1/N 抽样 ---- */
    __u32 *rate_ptr = bpf_map_lookup_elem(&sampling_rate, &zero);
    __u32 rate = (rate_ptr && *rate_ptr > 0) ? *rate_ptr : 100;

    /* 种子混入包内容,而不是只用队列号/CPU 号:只用后者的话同一队列上
     * 每个包算出的随机数完全相同,结果是"整队列全采或全不采",
     * 采样率形同虚设。 */
    __u32 seed = mix ^ ip->saddr ^ ip->daddr
                 ^ ((__u32)src_port << 16 | dst_port)
                 ^ (__u32)bpf_ktime_get_ns();

    if (rate > 1 && (prng(seed) % rate) != 0)
        return;

    struct sample_event *ev =
        bpf_ringbuf_reserve(&sample_events, sizeof(*ev), 0);
    if (ev) {
        ev->src_ip = ip->saddr;
        ev->dst_ip = ip->daddr;
        ev->src_port = src_port;
        ev->dst_port = dst_port;
        /* 用 IP 头声明的总长,而不是抓到的字节数:抓包可能被截断,
         * 用截断长度统计会让流量图系统性缩水,且不会有任何报错。 */
        ev->pkt_len = bpf_ntohs(ip->tot_len);
        ev->proto = ip->protocol;
        ev->dir = dir;
        ev->segs = segs;
        ev->_pad = 0;
        bpf_ringbuf_submit(ev, 0);
        if (gs)
            __sync_fetch_and_add(&gs->sampled_packets, 1);
    }
}

/* ---- 入向:XDP ---- */

SEC("xdp")
int xdp_sampler(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 包长 = data_end - data。不要用 ctx->data_meta,那是 XDP 程序间
     * 传递自定义元数据的区域,与包长无关,用它算长度会得到垃圾值。 */
    __u32 wire_len = (__u32)(data_end - data);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;   /* 仅 IPv4:IPv6 头部处理不同,不在当前范围 */

    /* 入向的包已经是网线上的样子,一个包就是一个包,segs 恒为 1。 */
    sample_ipv4((void *)(eth + 1), data_end, wire_len,
                ctx->rx_queue_index, DIR_INGRESS, 1);

    return XDP_PASS;   /* 只观测,永不拦截 */
}

/* ---- 出向之一:TC(clsact egress),内核 >= 6.6 由用户态用 TCX 挂上 ---- */

SEC("tc")
int tc_egress_sampler(struct __sk_buff *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* TSO/GSO:到这个钩子时大块发送还没有被切片,一个 skb 可能对应网线上
     * 几十个包,IP 头里的 tot_len 也是那个没切之前的大长度。字节数因此仍
     * 然基本是对的(差的是多出来的那几十份 IP+TCP 头,约 3%),但"包数"会少算几十倍——上传的 pps 会明显低于下载,而这种
     * 不对称看起来完全像是采集坏了。gso_segs 就是切片后的包数,拿它来当
     * 这次观测的包数。非 GSO 的普通包 gso_segs 是 0,按 1 算。 */
    __u16 segs = ctx->gso_segs;
    if (segs == 0)
        segs = 1;

    sample_ipv4((void *)(eth + 1), data_end, ctx->len,
                bpf_get_smp_processor_id(), DIR_EGRESS, segs);

    return TC_ACT_OK;   /* 0 = 照常发出去 */
}

/* ---- 出向之二:cgroup_skb/egress,给挂不上 TCX 的老内核 ---- */

SEC("cgroup_skb/egress")
int cgroup_egress_sampler(struct __sk_buff *ctx)
{
    __u32 zero = 0;
    __u32 *want = bpf_map_lookup_elem(&egress_ifindex, &zero);
    if (!want || *want == 0 || ctx->ifindex != *want)
        return CGROUP_SKB_PASS;

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 这个钩子在 IP 层,skb 里还没有以太网头 —— data 直接指向 IP 头。
     * 照 TC 那样先跳 14 字节的话会从 IP 头中间开始解析,读出来的
     * 地址和端口全是错的,而且不会报错。 */
    if (data + sizeof(struct iphdr) > data_end)
        return CGROUP_SKB_PASS;
    struct iphdr *ip = data;
    if (ip->version != 4)
        return CGROUP_SKB_PASS;

    /* 这里不取 gso_segs:cgroup_skb 能访问的 __sk_buff 字段比 sched_cls
     * 少,取不该取的字段会在加载时被 verifier 拒掉,而那会连带让整个
     * collection 加载失败、把入向的 XDP 一起拖下水。老内核上出向的包数
     * 因此会少算,字节数是对的。 */
    sample_ipv4(ip, data_end, ctx->len,
                bpf_get_smp_processor_id(), DIR_EGRESS, 1);

    return CGROUP_SKB_PASS;   /* 1 = 放行。这里写 0 是丢包,会断网 */
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
