#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aegis-probe.py — разведка канала между твоими RU- и EU-узлами.
Методика воспроизводит измерения из статьи Хабр 1105268 (09.11.2026):
какие L3/L4-протоколы проходят при точечной IP-блокировке, направленная
асимметрия и «штрафная скамейка» по частоте. ТОЛЬКО для своих серверов.

Запуск на ОТПРАВЛЯЮЩЕМ узле (root):
  python3 aegis-probe.py TARGET_IP [--ports 22,80,443] [--rate 3] [--json out.json]
На ПРИЁМНОМ узле параллельно:
  tcpdump -Q in -nli eth0 "ip and src SENDER_IP" -w /tmp/probe.pcap
Скрипт ничего не меняет в системе, шлёт низкочастотные пробы и печатает отчёт.
"""
import argparse, json, socket, struct, sys, time, os

def tcp_check(ip, port, timeout=4):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port)); s.close(); return "open"
    except socket.timeout:
        return "silent-drop"
    except ConnectionRefusedError:
        return "refused(RST)"
    except OSError as e:
        return f"error:{e.errno}"

def udp_send(ip, ports, count, gap):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for p in ports:
        for i in range(count):
            u.sendto(b"aegis-probe-udp-%d" % i, (ip, p)); time.sleep(gap)
    u.close()

def icmp_send(ip, count, gap, payload=64):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        return "no-root"
    s.settimeout(1.0)
    ident = os.getpid() & 0xFFFF
    ok = 0
    for i in range(count):
        pkt = struct.pack("!BBHHH", 8, 0, 0, ident, i) + b"aegis-icmp" + b"x" * payload
        chk = checksum(pkt)
        pkt = struct.pack("!BBHHH", 8, 0, chk, ident, i) + b"aegis-icmp" + b"x" * payload
        try:
            s.sendto(pkt, (ip, 0))
            data, _ = s.recvfrom(2048)
            if data[20:24] == pkt[:4] or data[20] == 0:
                ok += 1
        except socket.timeout:
            pass
        time.sleep(gap)
    s.close()
    return f"{ok}/{count} echo-reply"

def checksum(data):
    if len(data) % 2: data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF); s += s >> 16
    return (~s) & 0xFFFF

def raw_proto(ip, proto, count, gap, payload=b"aegis-raw-probe"):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
    except PermissionError:
        return "no-root"
    except OSError as e:
        return f"unsupported:{e.errno}"
    for i in range(count):
        try:
            s.sendto(payload + b"-%d" % i, (ip, 0))
        except OSError as e:
            s.close(); return f"send-error:{e.errno}"
        time.sleep(gap)
    s.close()
    return "sent (проверь tcpdump на приёмнике)"

def gre_variant(ip, kind, count, gap):
    # GRE: flags=0; protocol: 0x0800 IPv4, 0x86DD IPv6, 0x6558 Ethernet
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 47)
    except (PermissionError, OSError) as e:
        return f"no-root/unsupported:{e}"
    inner6 = struct.pack("!IHBB16s16s", 0x60000000, 8, 17, 64, b"\xfd" + b"\x00"*15, b"\xfd" + b"\x00"*14 + b"\x02") + b"aegis6"
    inner4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 1, 0, 64, 17, 0, socket.inet_aton("10.0.0.1"), socket.inet_aton("10.0.0.2")) + b"aegis4"
    eth = b"\x00"*12 + struct.pack("!H", 0x0800) + inner4
    ptype, inner = {"gre-ipv4": (0x0800, inner4), "gre-ipv6": (0x86DD, inner6), "gre-eth": (0x6558, eth)}[kind]
    hdr = struct.pack("!HH", 0, ptype)
    for i in range(count):
        try:
            s.sendto(hdr + inner, (ip, 0))
        except OSError as e:
            s.close(); return f"send-error:{e.errno}"
        time.sleep(gap)
    s.close()
    return "sent (проверь tcpdump на приёмнике)"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--ports", default="22,80,443")
    ap.add_argument("--rate", type=int, default=3, help="пакетов на пробу (низкая частота!)")
    ap.add_argument("--gap", type=float, default=0.05)
    ap.add_argument("--json", default="")
    a = ap.parse_args()
    if os.geteuid() != 0:
        print("❌ Нужен root (raw sockets)"); sys.exit(1)
    ip = a.target
    ports = [int(p) for p in a.ports.split(",") if p.strip()]
    rep = {"target": ip, "ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "tcp": {}, "udp": "sent", "icmp": "", "raw": {}}
    print(f"== AEGIS probe -> {ip} (методика Хабр 1105268) ==")
    print("На приёмнике: tcpdump -Q in -nli eth0 'ip and src <этот_узел>'")
    for p in ports:
        rep["tcp"][p] = tcp_check(ip, p)
        print(f"TCP {p}: {rep['tcp'][p]}")
    udp_send(ip, [53, 123, 443, 500, 1194, 3478, 4500, 51820], a.rate, a.gap)
    print("UDP 53/123/443/500/1194/3478/4500/51820: sent (смотри tcpdump)")
    rep["icmp"] = icmp_send(ip, a.rate, a.gap)
    print(f"ICMP echo: {rep['icmp']}")
    for proto, name in [(50, "esp"), (51, "ah"), (4, "ipip"), (41, "6in4"), (132, "sctp"), (253, "exp253")]:
        rep["raw"][name] = raw_proto(ip, proto, a.rate, a.gap)
        print(f"{name.upper()} (proto {proto}): {rep['raw'][name]}")
    for kind in ("gre-ipv4", "gre-ipv6", "gre-eth"):
        rep["raw"][kind] = gre_variant(ip, kind, a.rate, a.gap)
        print(f"{kind}: {rep['raw'][kind]}")
    print("\nИнтерпретация: silent-drop по TCP/UDP + проходящий ICMP = точечная IP-блокировка.")
    print("Если GRE-IPv6/GRE-Ethernet/ESP доходят (tcpdump приёмника) — есть «непонятный протокол»-канал,")
    print("но помни про штрафную скамейку по частоте: держи низкий bitrate, это резерв для SSH/сигнализации, не для видео.")
    print("Направленная асимметрия (в РФ не блокируют) — основа для раздельного пути вход/выход.")
    if a.json:
        with open(a.json, "w") as f: json.dump(rep, f, ensure_ascii=False, indent=2)
        print(f"JSON-отчёт: {a.json}")

if __name__ == "__main__":
    main()
