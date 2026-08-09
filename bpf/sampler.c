/* sampler.c —— ntop2ban 的 XDP 数据面:1/N 流量采样。
 *
 * 永远 XDP_PASS:这个程序只观测,不拦截。ntop2ban 的职责是
 * Observe / Analyze,封禁与执行是 xdp-ban 的事(见 README 的边界说明)。
 * 因此这里不需要与任何封禁程序争抢网卡挂载点。
 *
 * 编译(需要 clang + libbpf-dev):
 *   make bpf
 * 产物 cmd/ntop2ban/obj/sampler.o 提交进库,这样最终用户 go build
 * 一步出二进制、不需要 clang;只有改动本文件的维护者才需要。
 * CI 会重新编译并比对,防止 .o 与 .c 漂移。
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>

/* ---- 采样配置 ---- */

/* 抽样率 1/N。用户态启动时写入,运行期不改(改采样率要重启,
 * 让进程管理器的重启记录成为变更记录)。 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} sampling_rate SEC(".maps");

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
    __u8  _pad;
};

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

SEC("xdp")
int xdp_sampler(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 包长 = data_end - data。不要用 ctx->data_meta,那是 XDP 程序间
     * 传递自定义元数据的区域,与包长无关,用它算长度会得到垃圾值。 */
    __u32 pkt_len = (__u32)(data_end - data);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;   /* 仅 IPv4:IPv6 头部处理不同,不在当前范围 */

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* IP 头长度可变(带 option 时 >20),必须按 ihl 定位传输层头。
     * 写死 20 会在带 option 的包上读错端口。 */
    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(struct iphdr))
        return XDP_PASS;
    void *l4 = (void *)ip + ihl;
    if (l4 > data_end)
        return XDP_PASS;

    __u32 zero = 0;
    struct global_stats *gs = bpf_map_lookup_elem(&global_stats, &zero);
    if (gs) {
        __sync_fetch_and_add(&gs->total_packets, 1);
        __sync_fetch_and_add(&gs->total_bytes, (__u64)pkt_len);
    }

    /* 分片包的后续片没有传输层头,按偏移读端口读到的是载荷数据。
     * 0x1fff 掩掉 flags 只留 fragment offset。 */
    int is_fragment = (ip->frag_off & __constant_htons(0x1fff)) != 0;

    __u16 src_port = 0, dst_port = 0;

    if (!is_fragment && ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);

    } else if (!is_fragment && ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    } else if (!is_fragment && ip->protocol == IPPROTO_ICMP) {
        /* ICMP 不进采样:无端口协议只会产生 port=0 的伪流,
         * 占据 Top N 的位置却说明不了"谁在打我"。 */
        return XDP_PASS;
    } else {
        return XDP_PASS;
    }

    if (is_fragment)
        return XDP_PASS;

    /* ---- 1/N 抽样 ---- */
    __u32 *rate_ptr = bpf_map_lookup_elem(&sampling_rate, &zero);
    __u32 rate = (rate_ptr && *rate_ptr > 0) ? *rate_ptr : 100;

    /* 种子混入包内容,而不是只用队列号:只用 rx_queue_index 的话
     * 同一队列上每个包算出的随机数完全相同,结果是"整队列全采或全不采",
     * 采样率形同虚设。 */
    __u32 seed = ctx->rx_queue_index ^ ip->saddr ^ ip->daddr
                 ^ ((__u32)src_port << 16 | dst_port)
                 ^ (__u32)bpf_ktime_get_ns();

    if (rate > 1 && (prng(seed) % rate) != 0)
        return XDP_PASS;

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
        ev->_pad = 0;
        bpf_ringbuf_submit(ev, 0);
        if (gs)
            __sync_fetch_and_add(&gs->sampled_packets, 1);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
