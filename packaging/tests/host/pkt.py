#!/usr/bin/env python3
"""Packet and socket helper of the host-hardening attack tests (packaging/tests/host/attacks.sh).

Standard library only, so it runs on a bare CI runner. Raw sockets need root; every
subcommand prints one result line that the shell script asserts on.

    pkt.py listen   --addr A --port P [--echo]           TCP listener (holds or echoes)
    pkt.py connect  --dst D --port P [--src S] [--sport SP] [--echo] [--hold T]
                                                         one connect: connected|echoed|refused|timeout|error:<errno>
                                                         (--sport: bind that source port first; --hold: keep it T s)
    pkt.py hold     --dst D --port P --src S -n N        N concurrent connects, one outcome per line
    pkt.py reload   --dst D --port P --cmd CMD           echo, run CMD, echo again on the same connection
    pkt.py udp      --dst D --port P                     refused (ICMP came back) | timeout
    pkt.py syn      --dst D --dport P (--src S | --src-net CIDR) -n N [--mss M] [--flags S|A]
    pkt.py ping     --dst D --src S -n N                 raw ICMP echo requests
    pkt.py icmp-error --dst D --src S --inner-src A --inner-dst B --sport P --dport Q --mtu M
                                                         one "fragmentation needed" (IPv4) or "packet too
                                                         big" (IPv6) quoting the TCP segment A:P -> B:Q
    pkt.py sniff    --iface I --seconds T --what synack|rst|echo-reply [--dst-net CIDR]
                                                         prints "<total> <unique>" (unique: by port/id)
"""

import argparse
import errno
import ipaddress
import os
import random
import socket
import struct
import subprocess
import sys
import threading
import time

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def tcp_segment(src, dst, sport, dport, flags, mss):
    options = struct.pack("!BBH", 2, 4, mss) if mss else b""
    offset = (20 + len(options)) // 4
    flag_bits = {"S": 0x02, "A": 0x10}[flags]
    seq = random.getrandbits(32)
    ack = random.getrandbits(32) if flags == "A" else 0
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, offset << 4, flag_bits, 64240, 0, 0)
    segment = header + options
    if src.version == 4:
        pseudo = src.packed + dst.packed + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(segment))
    else:
        pseudo = src.packed + dst.packed + struct.pack("!I3xB", len(segment), socket.IPPROTO_TCP)
    csum = checksum(pseudo + segment)
    return segment[:16] + struct.pack("!H", csum) + segment[18:]


def ip_packet(src, dst, proto, payload):
    if src.version == 4:
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), random.getrandbits(16), 0, 64,
                             proto, 0, src.packed, dst.packed)
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        return header + payload
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), proto, 64, src.packed, dst.packed) + payload


def raw_socket(version):
    if version == 4:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    else:
        # IPPROTO_RAW on IPv6 implies that the header is included.
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
    return s


def sources(args, n):
    if args.src:
        return [ipaddress.ip_address(args.src)] * n
    net = ipaddress.ip_network(args.src_net)
    span = net.num_addresses - 2 if net.version == 4 else min(net.num_addresses - 1, 2**62)
    return [net.network_address + 1 + random.randrange(span) for _ in range(n)]


def cmd_syn(args):
    dst = ipaddress.ip_address(args.dst)
    srcs = sources(args, args.n)
    s = raw_socket(dst.version)
    base = random.randrange(10000, 50000)
    for i, src in enumerate(srcs):
        segment = tcp_segment(src, dst, base + i, args.dport, args.flags, args.mss)
        s.sendto(ip_packet(src, dst, socket.IPPROTO_TCP, segment), (str(dst), 0))
    print(f"sent {len(srcs)}")


def cmd_ping(args):
    src, dst = ipaddress.ip_address(args.src), ipaddress.ip_address(args.dst)
    s = raw_socket(4)
    ident = random.getrandbits(16)
    for seq in range(args.n):
        body = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + b"tcn-host-test"
        body = body[:2] + struct.pack("!H", checksum(body)) + body[4:]
        s.sendto(ip_packet(src, dst, socket.IPPROTO_ICMP, body), (str(dst), 0))
    print(f"sent {args.n}")


def cmd_icmp_error(args):
    src, dst = ipaddress.ip_address(args.src), ipaddress.ip_address(args.dst)
    a, b = ipaddress.ip_address(args.inner_src), ipaddress.ip_address(args.inner_dst)
    # The quoted packet: an IP header and the first 8 bytes of a TCP segment (ports, sequence).
    inner_tcp = struct.pack("!HHI", args.sport, args.dport, random.getrandbits(32))
    if src.version == 4:
        inner = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 1500, 0, 0x4000, 64, socket.IPPROTO_TCP, 0, a.packed, b.packed)
        inner = inner[:10] + struct.pack("!H", checksum(inner)) + inner[12:]
        body = struct.pack("!BBHHH", 3, 4, 0, 0, args.mtu) + inner + inner_tcp
        body = body[:2] + struct.pack("!H", checksum(body)) + body[4:]
        proto = socket.IPPROTO_ICMP
    else:
        inner = struct.pack("!IHBB16s16s", 6 << 28, 1440, socket.IPPROTO_TCP, 64, a.packed, b.packed)
        body = struct.pack("!BBHI", 2, 0, 0, args.mtu) + inner + inner_tcp
        pseudo = src.packed + dst.packed + struct.pack("!I3xB", len(body), socket.IPPROTO_ICMPV6)
        body = body[:2] + struct.pack("!H", checksum(pseudo + body)) + body[4:]
        proto = socket.IPPROTO_ICMPV6
    s = raw_socket(dst.version)
    s.sendto(ip_packet(src, dst, proto, body), (str(dst), 0))
    print("sent 1")


def cmd_sniff(args):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((args.iface, 0))
    s.settimeout(0.2)
    want = ipaddress.ip_network(args.dst_net) if args.dst_net else None
    total, unique = 0, set()
    deadline = time.monotonic() + args.seconds
    # Tell the caller that the socket is bound: packets sent after this line are seen.
    print("ready", file=sys.stderr, flush=True)
    while time.monotonic() < deadline:
        try:
            frame, addr = s.recvfrom(65535)
        except socket.timeout:
            continue
        if addr[2] == PACKET_OUTGOING:
            continue
        ethertype = struct.unpack("!H", frame[12:14])[0]
        packet = frame[14:]
        if ethertype == 0x0800:
            ihl = (packet[0] & 0x0F) * 4
            proto, dst = packet[9], ipaddress.ip_address(packet[16:20])
            payload = packet[ihl:]
        elif ethertype == 0x86DD:
            proto, dst = packet[6], ipaddress.ip_address(packet[24:40])
            payload = packet[40:]
        else:
            continue
        if want is not None and dst not in want:
            continue
        if proto == socket.IPPROTO_TCP and len(payload) >= 14:
            flags = payload[13]
            key = struct.unpack("!H", payload[2:4])[0]
            if args.what == "synack" and flags & 0x12 == 0x12:
                total += 1
                unique.add(key)
            elif args.what == "rst" and flags & 0x04:
                total += 1
                unique.add(key)
        elif proto == socket.IPPROTO_ICMP and args.what == "echo-reply" and payload[:1] == b"\0":
            total += 1
            unique.add(struct.unpack("!H", payload[6:8])[0])
    print(f"{total} {len(unique)}")


def outcome(exc):
    if isinstance(exc, socket.timeout):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, OSError) and exc.errno is not None:
        return f"error:{errno.errorcode.get(exc.errno, exc.errno)}"
    return f"error:{type(exc).__name__}"


def family(addr):
    return socket.AF_INET6 if ipaddress.ip_address(addr).version == 6 else socket.AF_INET


def dial(args):
    s = socket.socket(family(args.dst), socket.SOCK_STREAM)
    s.settimeout(args.timeout)
    sport = getattr(args, "sport", None)
    if sport:
        # What code inside the relay could do: bind the relay port, then dial.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if args.src or sport:
        any_addr = "::" if family(args.dst) == socket.AF_INET6 else "0.0.0.0"
        s.bind((args.src or any_addr, sport or 0))
    s.connect((args.dst, args.port))
    return s


def echo_once(s, payload=b"tcn-host-test\n"):
    s.sendall(payload)
    got = b""
    while len(got) < len(payload):
        chunk = s.recv(len(payload) - len(got))
        if not chunk:
            break
        got += chunk
    return got == payload


def cmd_connect(args):
    try:
        s = dial(args)
    except Exception as exc:  # noqa: BLE001 - every outcome is a result line
        print(outcome(exc))
        return
    if args.echo:
        try:
            print("echoed" if echo_once(s) else "connected-no-echo")
        except Exception as exc:  # noqa: BLE001
            print("connected-" + outcome(exc))
    else:
        print("connected", flush=True)
    if args.hold:
        time.sleep(args.hold)
    s.close()


def cmd_hold(args):
    held = []
    for _ in range(args.n):
        try:
            s = dial(args)
            # A reset arrives right after the handshake: give it a moment, then read.
            s.settimeout(0.3)
            try:
                data = s.recv(1)
                print("connected" if data else "closed")
            except socket.timeout:
                print("connected")
            except ConnectionResetError:
                print("reset")
            held.append(s)
        except ConnectionResetError:
            print("reset")
        except Exception as exc:  # noqa: BLE001
            print(outcome(exc))
    for s in held:
        s.close()


def cmd_reload(args):
    try:
        s = dial(args)
        first = echo_once(s)
        rc = subprocess.run(args.cmd, shell=True, check=False).returncode
        second = echo_once(s)
        print(f"before={'echoed' if first else 'lost'} reload_rc={rc} after={'echoed' if second else 'lost'}")
    except Exception as exc:  # noqa: BLE001
        print(outcome(exc))


def cmd_udp(args):
    s = socket.socket(family(args.dst), socket.SOCK_DGRAM)
    s.settimeout(args.timeout)
    s.connect((args.dst, args.port))
    try:
        s.send(b"probe")
        s.recv(16)
        print("answered")
    except Exception as exc:  # noqa: BLE001
        print(outcome(exc))


def serve(conn, echo):
    with conn:
        while True:
            try:
                data = conn.recv(4096)
            except OSError:
                return
            if not data:
                return
            if echo:
                conn.sendall(data)


def cmd_listen(args):
    s = socket.socket(family(args.addr), socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((args.addr, args.port))
    s.listen(4096)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=serve, args=(conn, args.echo), daemon=True).start()


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="action", required=True)
    for name in ("connect", "hold", "reload"):
        c = sub.add_parser(name)
        c.add_argument("--dst", required=True)
        c.add_argument("--port", type=int, required=True)
        c.add_argument("--src")
        c.add_argument("--timeout", type=float, default=2.0)
        c.add_argument("--echo", action="store_true")
        c.add_argument("-n", type=int, default=1)
        c.add_argument("--cmd", default="true")
        c.add_argument("--sport", type=int)
        c.add_argument("--hold", type=float, default=0.0)
    c = sub.add_parser("udp")
    c.add_argument("--dst", required=True)
    c.add_argument("--port", type=int, required=True)
    c.add_argument("--timeout", type=float, default=2.0)
    c = sub.add_parser("syn")
    c.add_argument("--dst", required=True)
    c.add_argument("--dport", type=int, required=True)
    c.add_argument("--src")
    c.add_argument("--src-net")
    c.add_argument("-n", type=int, default=1)
    c.add_argument("--mss", type=int, default=1460)
    c.add_argument("--flags", choices=["S", "A"], default="S")
    c = sub.add_parser("ping")
    c.add_argument("--dst", required=True)
    c.add_argument("--src", required=True)
    c.add_argument("-n", type=int, default=1)
    c = sub.add_parser("icmp-error")
    c.add_argument("--dst", required=True)
    c.add_argument("--src", required=True)
    c.add_argument("--inner-src", required=True)
    c.add_argument("--inner-dst", required=True)
    c.add_argument("--sport", type=int, required=True)
    c.add_argument("--dport", type=int, required=True)
    c.add_argument("--mtu", type=int, default=1280)
    c = sub.add_parser("sniff")
    c.add_argument("--iface", required=True)
    c.add_argument("--seconds", type=float, required=True)
    c.add_argument("--what", choices=["synack", "rst", "echo-reply"], required=True)
    c.add_argument("--dst-net")
    c = sub.add_parser("listen")
    c.add_argument("--addr", required=True)
    c.add_argument("--port", type=int, required=True)
    c.add_argument("--echo", action="store_true")
    args = p.parse_args()
    if args.action == "syn" and not (args.src or args.src_net):
        p.error("syn needs --src or --src-net")
    {
        "connect": cmd_connect, "hold": cmd_hold, "reload": cmd_reload, "udp": cmd_udp, "syn": cmd_syn,
        "ping": cmd_ping, "icmp-error": cmd_icmp_error, "sniff": cmd_sniff, "listen": cmd_listen,
    }[args.action](args)


if __name__ == "__main__":
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    main()
