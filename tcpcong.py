import time
import socket
import ipaddress
import socket
import argparse
from ctypes import *
from bcc import BPF

#struct flow {
#    __u16 family;
#    __u8 saddr[16];
#    __u8 daddr[16];
#    __u16 sport;
#    __u16 dport;
#};
class Flow(Structure):
    _fields_ = [
        ("family", c_uint16),
        ("saddr", c_uint8 * 16),
        ("daddr", c_uint8 * 16),
        ("sport", c_uint16),
        ("dport", c_uint16),
    ]

def load(rule):
    src_port, dst_port = rule
    ip_mask = ipaddress.ip_address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
    family = socket.AF_INET
    if src_port == None:
        src_port = 0xffff
    if dst_port == None:
        dst_port = 0xffff
    AddrType = c_uint8 * 16
    flow = Flow(
        family = family,
        saddr = AddrType.from_buffer_copy(ip_mask.packed),
        daddr = AddrType.from_buffer_copy(ip_mask.packed),
        sport = int(src_port),
        dport = int(dst_port))

    bpf = BPF(src_file=b"./tcpcong.c")
    cfg = bpf["cfg"]
    cfg[0] = flow

    bpf.attach_tracepoint(tp=b"tcp:tcp_probe", fn_name=b"tracepoint_tcp_probe")
    return bpf

def get_addr(addr_bytes, family):
    if family == socket.AF_INET:
        return ipaddress.IPv4Address(addr_bytes[:4])
    elif family == socket.AF_INET6:
        return ipaddress.IPv6Address(addr_bytes)
    else:
        raise Exception("unsupported address family")

class Entry:
    def __init__(self, src, dst, cwnd, rtt, snd_nxt, snd_una) -> None:
        self.src = src
        self.dst = dst
        self.cwnd = int(cwnd)
        self.rtt = int(rtt) >> 3 # srtt is << 3 in the kernel
        self.snd_nxt = int(snd_nxt)
        self.snd_una = int(snd_una)

    def __str__(self):
        return f"[{self.src} -> {self.dst}] cwnd {self.cwnd} srtt {self.rtt} snd_nxt {self.snd_nxt} snd_una {self.snd_una}"

    def __repr__(self):
        return f"<[{self.src} -> {self.dst}] cwnd {self.cwnd} srtt {self.rtt} snd_nxt {self.snd_nxt} snd_una {self.snd_una}>"

    def flowid(self):
        return f"{self.src} -> {self.dst}"

def poll(bpf, entries):
    from json import JSONDecodeError
    try:
        flows = bpf["flows"]
        for k, v in flows.items():
            saddr = get_addr(bytes(k.saddr), k.family)
            daddr = get_addr(bytes(k.daddr), k.family)
            src = f"{saddr}:{k.sport}"
            dst = f"{daddr}:{k.dport}"
            e = Entry(src, dst, v.snd_cwnd, v.srtt, v.snd_nxt, v.snd_una)
            if e.flowid() not in entries or entries[e.flowid()].snd_nxt != e.snd_nxt:
                print(e)
                entries[e.flowid()] = e
            return entries
    except JSONDecodeError as e:
        print(e)
        print('failed', e.doc)
    finally:
        return {}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--flow', type=str, required=True, action='store')
    parser.add_argument('--file', type=str, required=False)
    args = parser.parse_args()
    src, dst = args.flow.split('->')
    src = src.strip()
    dst = dst.strip()
    rule = (int(src) if src != '*' else None, int(dst) if dst != '*' else None)
    bpf = load(rule)

    last_write = time.time()
    flows = {}
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
                    for e in flows[f]:
                        outf.write(f"{e.src.strip()},{e.dst.strip()},{e.cwnd},{e.rtt},{e.snd_nxt},{e.snd_una}\n")
                last_write = time.time()
