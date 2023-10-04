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
