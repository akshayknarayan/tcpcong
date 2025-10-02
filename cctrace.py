import time
import socket
import ipaddress
import socket
import argparse
from ctypes import *
from bcc import BPF

#struct flow {
#    __u32 saddr;
#    __u32 daddr;
#    __u16 sport;
#    __u16 dport;
#};
class Flow(Structure):
    _fields_ = [
        ("saddr", c_uint32),
        ("daddr", c_uint32),
        ("sport", c_uint16),
        ("dport", c_uint16),
    ]

def load(rule):
    src_port, dst_port = rule
    family = socket.AF_INET
    if src_port == None:
        src_port = 0xffff
    if dst_port == None:
        dst_port = 0xffff
    flow = Flow(
        family = family,
        saddr = int(0xffff_ffff),
        daddr = int(0xffff_ffff),
        sport = int(src_port),
        dport = int(dst_port))

    bpf = BPF(src_file=b"./cctrace.c")
    cfg = bpf["cfg"]
    cfg[0] = flow

    bpf.attach_kprobe(fn_name=b"cctrace_read_tcp_state", event=b"cubictcp_cong_avoid")
    return bpf

class Entry:
    def __init__(self, src, dst, cwnd, bytes_acked, packet_loss) -> None:
        self.src = src
        self.dst = dst
        self.cwnd = int(cwnd)
        self.bytes_acked = int(bytes_acked)
        self.packet_loss = int(packet_loss)

    def __str__(self):
        return f"[{self.src} -> {self.dst}] cwnd {self.cwnd} bytes_acked {self.bytes_acked} packet_loss {self.packet_loss}"

    def __repr__(self):
        return f"<[{self.src} -> {self.dst}] cwnd {self.cwnd} bytes_acked {self.bytes_acked} packet_loss {self.packet_loss}>"

    def flowid(self):
        return f"{self.src} -> {self.dst}"

def poll(bpf, entries):
    from json import JSONDecodeError
    try:
        flows = bpf["flows"]
        for k, v in flows.items():
            saddr = ipaddress.IPv4Address(k.saddr)
            daddr = ipaddress.IPv4Address(k.daddr)
            src = f"{saddr}:{k.sport}"
            dst = f"{daddr}:{k.dport}"
            e = Entry(src, dst, v.snd_cwnd, v.bytes_acked, v.packet_loss)
            if e.flowid() not in entries or entries[e.flowid()].bytes_acked != e.bytes_acked:
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
            outf.write("time,src,dst,cwnd,bytes_acked,packet_loss\n")
        while True:
            time.sleep(0.1)
            poll(bpf, flows)
            if last_write != None:
                for f in flows:
                    for e in flows[f]:
                        outf.write(f"{e.src.strip()},{e.dst.strip()},{e.cwnd},{e.bytes_acked},{e.packet_loss}\n")
                last_write = time.time()
