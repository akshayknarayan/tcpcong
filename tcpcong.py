import time
import socket
import ipaddress
import sys
import argparse
from bcc import BPF

def flow_rule(src_port, dst_port):
    rule = []
    if src_port != None:
        rule.append(f"(f.sport == {src_port})")
    if dst_port != None:
        rule.append(f"(f.dport == {dst_port})")
    return '(' + ' && '.join(rule) + ')'

def load(flows):
    bpf_template = None
    with open("./tcpcong.c", 'r') as f:
        bpf_template = f.read()
    assert bpf_template != None

    if len(flows) > 0:
        rule = ' || '.join(flow_rule(*f) for f in flows)
        cond = f"if (!({rule})) {{ return 0; }}"
        bpf = bpf_template.replace('MATCH_FLOW', cond)
    else:
        bpf = bpf_template.replace('MATCH_FLOW', '')
    bpf = BPF(text=bpf)
    #bpf.attach_tracepoint(tp="tcp:tcp_probe", fn_name="tracepoint__tcp__tcp_probe")
    return bpf

class FlowGraph:
    def __init__(self, flowid):
        self.flowid = flowid
        self.data = []

    def observation(self, cwnd: int, rtt: float):
        now = time.time()
        self.data.append((now, cwnd, rtt))
        if len(self.data) > 10:
            while self.data[-1][0] - self.data[0][0] > 10:
                self.data = self.data[1:]

    def cwnd_graph(self, fn):
        now = time.time()
        times, cwnds, _ = zip(*self.data)
        times = [t - now for t in times]
        return fn(xs=times, ys=cwnds, lines=True, title=self.flowid + " cwnd")

    def print_cwnd_graph(self):
        from uniplot import plot
        self.cwnd_graph(plot)

    def get_cwnd_graph(self) -> [str]:
        from uniplot import plot_to_string
        return self.cwnd_graph(plot_to_string)

    def rtt_graph(self, fn):
        now = time.time()
        times, _, rtts = zip(*self.data)
        times = [t - now for t in times]
        return fn(xs=times, ys=rtts, lines=True, title=self.flowid + " RTT")

    def print_rtt_graph(self):
        from uniplot import plot
        return self.rtt_graph(plot)

    def get_rtt_graph(self) -> [str]:
        from uniplot import plot_to_string
        return self.rtt_graph(plot_to_string)

def get_addr(addr_bytes, family):
    if family == socket.AF_INET:
        return ipaddress.IPv4Address(addr_bytes[:4])
    elif family == socket.AF_INET6:
        return ipaddress.IPv6Address(addr_bytes)
    else:
        raise Exception("unsupported address family")

def poll(bpf, flow_hist):
    from json import JSONDecodeError
    try:
        flows = bpf["flows"]
        for k, v in flows.items():
            saddr = get_addr(bytes(k.saddr), k.family)
            daddr = get_addr(bytes(k.daddr), k.family)
            #print(f"[{saddr}:{k.sport} -> {daddr}:{k.dport}] cwnd {v.snd_cwnd} srtt {v.srtt}")
            flowid = f"{saddr}:{k.sport} -> {daddr}:{k.dport}"
            if flowid not in flow_hist:
                flow_hist[flowid] = FlowGraph(flowid)
            flow_hist[flowid].observation(v.snd_cwnd, v.srtt)
    except JSONDecodeError as e:
        print(e)
        print('failed', e.doc)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--flow', type=str, required=True, action='append')
    parser.add_argument('--file', type=str, required=False)
    args = parser.parse_args()
    rules = []
    for f in args.flow:
        src, dst = f.split('->')
        src = src.strip()
        dst = dst.strip()
        if src == '*' and dst == '*':
            rules = []
            break
        rules.append((int(src) if src != '*' else None, int(dst) if dst != '*' else None))
    bpf = load(rules)

    flows = {}
    last_print = time.time()
    last_write = time.time()
    if args.file == None:
        args.file = '/dev/null'
        last_write = None
    with open(args.file, 'w') as outf:
        if last_write != None:
            outf.write("time,src,dst,cwnd,rtt\n")
        while True:
            time.sleep(0.1)
            poll(bpf, flows)
            if last_write != None:
                for f in flows:
                    src, dst = f.split('->')
                    for (t, cwnd, rtt) in [d for d in flows[f].data if d[0] > last_write]:
                        outf.write(f"{t},{src.strip()},{dst.strip()},{cwnd},{rtt}\n")
                last_write = time.time()
            if time.time() - last_print > 5:
                for f in flows:
                    flows[f].print_cwnd_graph()
                    flows[f].print_rtt_graph()
                last_print = time.time()
