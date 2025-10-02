// see https://github.com/iovisor/bcc/issues/5388:
#define BPF_LOAD_ACQ	0x100	/* load-acquire */
#define BPF_STORE_REL	0x110	/* store-release */

#include <net/inet_sock.h>
#include <net/tcp.h>

struct flow {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct cong_event {
    struct flow flow;
    __u32 snd_cwnd;
    __u32 bytes_acked;
    __u32 packet_loss;
};

// the flows we're interested in.
#define CFG_ARRAY_ITEMS 1
BPF_ARRAY(cfg, struct flow, CFG_ARRAY_ITEMS);

// cong_events for the flows in `cfg`
BPF_HASH(flows, struct flow, struct cong_event, 32);

int cctrace_read_tcp_state(
    const struct sock *sk,
    __u32 _ack,
    __u32 _acked
) {
    struct cong_event zero;
    struct cong_event *entry = NULL;
    struct flow *cfg_f = NULL;
    int i = 0;
    // need to get addr info from struct sock *sk
    //const struct tcp_sock *tp = (struct tcp_sock*) sk;
    const struct tcp_sock *tp = tcp_sk(sk);
    const struct inet_sock *inet = (struct inet_sock *)(sk);
    if (!sk) {
        return -1;
    }

    struct flow f = {
	    .daddr = sk->sk_daddr,
	    .dport = sk->sk_dport,
        .sport = sk->sk_dport, //inet->inet_sport,
        .saddr = sk->sk_daddr, //inet->inet_saddr,
    };
    memset(&zero, 0, sizeof(struct cong_event));
    
    cfg_f = cfg.lookup(&i);
    if (cfg_f == NULL) {
        bpf_trace_printk("no rule installed");
        return 0;
    }

    if (cfg_f != NULL && 
        (cfg_f->sport & f.sport) == f.sport &&
        (cfg_f->dport & f.dport) == f.dport) {
        entry = flows.lookup_or_try_init(&f, &zero);
        if (((void*) entry) != NULL) {
            entry->snd_cwnd = tp->snd_cwnd;
            // tp->bytes_acked is cumulative: userspace needs to do the diff itself
            entry->bytes_acked = tp->bytes_acked;
            // rs->losses refers to marginal events: in this case, *new* packets marked lost upon the most recent ACK
            entry->packet_loss = tp->lost;
        }
    }

    return 0;
}
