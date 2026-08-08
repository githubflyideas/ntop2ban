/* sampler.c —— ntop2ban 的 XDP 数据面:1/N 流量采样 + 敲门精确匹配。
 *
 * 一个程序两个输出,是刻意的设计:
 *
 *   - 采样走 1/N 抽样。目的是控制开销,允许丢包,只服务可视化。
 *   - 敲门走精确匹配,一个包都不能漏。抽样会漏掉绝大部分敲门包,
 *     所以安全判定必须有自己的数据路径——这条原则在架构文档里就定了。
 *
 * 两者共用一次包解析,但判定与上报路径完全分开。做成两个 XDP 程序不行:
 * 一张网卡只能挂一个。
 *
 * 永远 XDP_PASS:这个程序只观测,不拦截。封禁下发到 nftables,那是
 * netfilter hook,与 XDP 不同层次,因此不存在挂载点冲突——这正是
 * "采样用 XDP 拿性能、封禁用 nftables 避冲突"这个组合的由来。
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

/* ---- 敲门配置 ---- */

/* 敲门关心的 TCP 端口集合。key 是主机字节序端口号,value 恒为 1。
 * 序列审批通过后由用户态刷新——这就是"审批只是配置变更,不是实时闸门"
 * 的落点:守护进程始终按 map 里当前的内容工作。 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, 16);
} knock_ports SEC(".maps");

/* 敲门关心的 ICMP payload 长度集合(即 ping -s 的值)。 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, 16);
} knock_icmp_lens SEC(".maps");

/* 敲门事件 ringbuf。与采样分开,避免抽样噪声把敲门事件挤掉——
 * 共用一个 ringbuf 时,高流量下敲门事件会因为缓冲区被采样事件占满而
 * 丢失,那正是最不能丢的东西。 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);   /* 64KB,敲门量极小 */
} knock_events SEC(".maps");

struct knock_event {
    __u32 src_ip;
    __u16 value;    /* TCP 步:端口号;ICMP 步:payload 长度 */
    __u8  kind;     /* 1 = tcp, 2 = icmp */
    __u8  _pad;
};

/* ---- 全局计数,供界面展示"采样器在正常工作" ---- */
struct global_stats {
    __u64 total_packets;
    __u64 total_bytes;
    __u64 sampled_packets;
    __u64 knock_hits;
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

        /* 敲门:只认纯 SYN。SYN+ACK 是本机主动连出去的回包方向,
         * 算进来会让本机自己的出站连接凑出敲门序列。 */
        if (tcp->syn && !tcp->ack) {
            __u8 *hit = bpf_map_lookup_elem(&knock_ports, &dst_port);
            if (hit) {
                struct knock_event *ev =
                    bpf_ringbuf_reserve(&knock_events, sizeof(*ev), 0);
                if (ev) {
                    ev->src_ip = ip->saddr;
                    ev->value = dst_port;
                    ev->kind = 1;
                    ev->_pad = 0;
                    bpf_ringbuf_submit(ev, 0);
                    if (gs)
                        __sync_fetch_and_add(&gs->knock_hits, 1);
                }
            }
        }
    } else if (!is_fragment && ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    } else if (!is_fragment && ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = l4;
        if ((void *)(icmp + 1) > data_end)
            return XDP_PASS;

        /* 只认 echo request。echo reply 是本机 ping 别人的回包,
         * 算进来会让本机的健康检查不停地"敲自己的门"。 */
        if (icmp->type == ICMP_ECHO) {
            /* payload 长度 = IP 总长 - IP 头 - ICMP 头(8)。
             * 这个值必须与用户在界面上看到的 `ping -s N` 的 N 相同,
             * 否则用户照提示敲永远敲不开,而且日志里差 8 字节没人想得到。 */
            __u16 total = bpf_ntohs(ip->tot_len);
            if (total >= ihl + 8) {
                __u16 payload_len = total - ihl - 8;
                __u8 *hit = bpf_map_lookup_elem(&knock_icmp_lens, &payload_len);
                if (hit) {
                    struct knock_event *ev =
                        bpf_ringbuf_reserve(&knock_events, sizeof(*ev), 0);
                    if (ev) {
                        ev->src_ip = ip->saddr;
                        ev->value = payload_len;
                        ev->kind = 2;
                        ev->_pad = 0;
                        bpf_ringbuf_submit(ev, 0);
                        if (gs)
                            __sync_fetch_and_add(&gs->knock_hits, 1);
                    }
                }
            }
        }
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
