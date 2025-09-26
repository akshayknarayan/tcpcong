#include <net/inet_sock.h>

struct flow {
    __u16 family;
    __u8 saddr[16];
    __u8 daddr[16];
    __u16 sport;
    __u16 dport;
};

struct cong_event {
    struct flow flow;
    __u32 snd_cwnd;
    __u32 srtt;
};

BPF_HASH(flows, struct flow, struct cong_event, 32);

static inline int fill_addr(__u16 family, __u8 addr[28], __u8 slot[16]) {
    if (family == AF_INET6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6*) addr;
        memcpy(slot, &(s->sin6_addr.in6_u.u6_addr8), 16);
    } else if (family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in*) addr;
        memcpy(slot, &(s->sin_addr.s_addr), 4);
    } else {
        return -1;
    }

    return 0;
}

/* tcp_probe format from /sys/kernel/debug/tracing/events/tcp/tcp_probe/format 
 * format:
*      field:unsigned short  common_type;           offset:0;   size:2;  signed:0;  
*      field:unsigned char   common_flags;          offset:2;   size:1;  signed:0;  
*      field:unsigned char   common_preempt_count;  offset:3;   size:1;  signed:0;  
*      field:int             common_pid;            offset:4;   size:4;  signed:1;               
*                                                                                                  
*      field:__u8            saddr[28];             offset:8;   size:28; signed:0;               
*      field:__u8            daddr[28];             offset:36;  size:28; signed:0;               
*      field:__u16           sport;                 offset:64;  size:2;  signed:0;               
*      field:__u16           dport;                 offset:66;  size:2;  signed:0;               
*      field:__u16           family;                offset:68;  size:2;  signed:0;               
*      field:__u32           mark;                  offset:72;  size:4;  signed:0;               
*      field:__u16           data_len;              offset:76;  size:2;  signed:0;               
*      field:__u32           snd_nxt;               offset:80;  size:4;  signed:0;               
*      field:__u32           snd_una;               offset:84;  size:4;  signed:0;               
*      field:__u32           snd_cwnd;              offset:88;  size:4;  signed:0;               
*      field:__u32           ssthresh;              offset:92;  size:4;  signed:0;               
*      field:__u32           snd_wnd;               offset:96;  size:4;  signed:0;               
*      field:__u32           srtt;                  offset:100; size:4;  signed:0;               
*      field:__u32           rcv_wnd;               offset:104; size:4;  signed:0;               
*      field:__u64           sock_cookie;           offset:112; size:8;  signed:0;               
*      field:const void*     skbaddr;               offset:120; size:8;  signed:0;
*      field:const void*     skaddr;                offset:128; size:8;  signed:0;
 * 
 * print fmt: "family=%s src=%pISpc dest=%pISpc mark=%#x data_len=%d snd_nxt=%#x snd_una=%#x snd_cwnd=%u ssthresh=%u snd_wnd=%u srtt=%u rcv_wnd=%u sock_cookie=%llx skbaddr=%p skaddr=%p", __print_symbolic(REC->family, { 2, "AF_INET" }, { 10, "AF_INET6" }), REC->saddr, REC->daddr, REC->mark, REC->data_len, REC->snd_nxt, REC->snd_una, REC->snd_cwnd, REC->ssthresh, REC->snd_wnd, REC->srtt, REC->rcv_wnd, REC->sock_cookie, REC->skbaddr, REC->skaddr
 *
 */
TRACEPOINT_PROBE(tcp, tcp_probe) {
    struct cong_event zero;
    struct cong_event *entry = NULL;
    struct flow f = {
        .saddr = 0,
        .daddr = 0,
        .sport = args->sport,
        .dport = args->dport,
        .family = args->family,
    };
    int i = 0;
    memset(&zero, 0, sizeof(struct cong_event));

    if (0 != fill_addr(args->family, args->saddr, f.saddr)) {
        return 0;
    }
    if (0 != fill_addr(args->family, args->daddr, f.daddr)) {
        return 0;
    }
    
    // replaced at runtime with conditions on f
    MATCH_FLOW

    entry = flows.lookup_or_try_init(&f, &zero);
    if (((void*) entry) != NULL) {
        entry->snd_cwnd = args->snd_cwnd;
        entry->srtt = args->srtt;
    }

    return 0;
};
