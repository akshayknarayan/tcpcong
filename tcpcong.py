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

def get_addr(addr_bytes, family):
    if family == socket.AF_INET:
        return ipaddress.IPv4Address(addr_bytes[:4])
    elif family == socket.AF_INET6:
        return ipaddress.IPv6Address(addr_bytes)
    else:
        raise Exception("unsupported address family")

def poll(bpf):
    from json import JSONDecodeError
    try:
        flows = bpf["flows"]
        for k, v in flows.items():
            saddr = get_addr(bytes(k.saddr), k.family)
            daddr = get_addr(bytes(k.daddr), k.family)
            print(f"[{saddr}:{k.sport} -> {daddr}:{k.dport}] cwnd {v.snd_cwnd} srtt {v.srtt}")
    except JSONDecodeError as e:
        print(e)
        print('failed', e.doc)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--flow', type=str, required=True, action='append')
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

    while True:
        time.sleep(1)
        poll(bpf)
