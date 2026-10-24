"""Deterministic synthetic traffic for evaluating Lattice.

Everything is generated from a seeded ``random.Random`` and written to ordinary
PCAP files, so the same seed always yields byte-identical captures. No packet is
ever sent on a network; these are files only.

Scenarios (each = 120 s of ordinary background traffic, plus one injected
behaviour starting at t = 60 s):

* ``normal``             background only; no events expected
* ``rate_spike``         one client suddenly sends ~400 pkt/s of HTTPS data for 10 s
* ``syn_flood``          one source opens 180 connections to a single port in 5 s
* ``port_scan``          one source SYN-probes 60 distinct ports in 3 s
* ``host_sweep``         one source SYN-probes 30 distinct destination hosts
* ``unexpected_protocol`` IP protocol 47 (GRE) from one host
* ``unexpected_port``    TCP traffic to port 31337 from one host
* ``unexpected_traffic`` combined unexpected-port and GRE traffic

Addresses are RFC 1918 / RFC 5737 documentation ranges.

Usage::

    python -m scripts.traffic_gen --out samples
"""
from __future__ import annotations

import argparse
import logging
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

T0 = 1_700_000_000.0          # multiple of 5 s, so scenario times line up with window edges
DURATION = 120
INJECT_AT = 60

CLIENTS = [f"192.168.1.{n}" for n in range(10, 15)]
WEB, DNS, NTP, GATEWAY = "10.0.0.2", "10.0.0.53", "10.0.0.123", "192.168.1.1"
ATTACKER_FLOOD, ATTACKER_SCAN, ATTACKER_SWEEP = "203.0.113.50", "203.0.113.60", "203.0.113.70"
ODD_HOST = "192.168.1.12"


@dataclass(frozen=True)
class Incident:
    """Ground truth: Lattice is expected to raise ``rule`` for this interval."""

    rule: str
    start: float                    # seconds relative to T0
    end: float
    src_ip: Optional[str] = None    # None: any source / window-wide
    note: str = ""


@dataclass
class Scenario:
    name: str
    description: str
    packets: list[Any] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)


def _eth() -> Any:
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def _stamp(pkt: Any, ts: float) -> Any:
    pkt.time = ts
    return pkt


def tcp(ts: float, src: str, dst: str, sport: int, dport: int, flags: str, payload: int = 0) -> Any:
    pkt = _eth() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        pkt = pkt / Raw(b"\0" * payload)
    return _stamp(pkt, ts)


def udp(ts: float, src: str, dst: str, sport: int, dport: int, payload: int) -> Any:
    return _stamp(_eth() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(b"\0" * payload), ts)


def icmp(ts: float, src: str, dst: str) -> Any:
    return _stamp(_eth() / IP(src=src, dst=dst) / ICMP() / Raw(b"\0" * 32), ts)


def background(rng: random.Random, seconds: int, start: float = T0) -> list[Any]:
    """Ordinary small-office traffic: web, DNS, NTP, pings; 16-24 pkt/s, nothing unexpected."""
    packets: list[Any] = []
    for second in range(seconds):
        offsets = sorted(rng.random() for _ in range(rng.randint(16, 24)))
        for offset in offsets:
            ts = start + second + offset
            client = rng.choice(CLIENTS)
            sport = rng.randint(32768, 60999)
            roll = rng.random()
            if roll < 0.40:
                packets.append(tcp(ts, client, WEB, sport, 443, "A", rng.randint(100, 1200)))
            elif roll < 0.65:
                packets.append(tcp(ts, WEB, client, 443, sport, "A", rng.randint(100, 1400)))
            elif roll < 0.73:
                packets.append(tcp(ts, client, WEB, sport, 443, "S"))
            elif roll < 0.86:
                packets.append(udp(ts, client, DNS, sport, 53, rng.randint(30, 60)))
            elif roll < 0.93:
                packets.append(udp(ts, DNS, client, 53, sport, rng.randint(60, 200)))
            elif roll < 0.97:
                packets.append(udp(ts, client, NTP, sport, 123, 48))
            else:
                packets.append(icmp(ts, client, GATEWAY))
    return packets


def build_scenarios(seed: int = 1234) -> list[Scenario]:
    scenarios: list[Scenario] = []

    def new(name: str, description: str) -> tuple[Scenario, random.Random]:
        rng = random.Random(f"{seed}:{name}")
        sc = Scenario(name, description, background(rng, DURATION))
        scenarios.append(sc)
        return sc, rng

    at = INJECT_AT + T0

    new("normal", "120 s of ordinary traffic; no events expected.")

    sc, rng = new("rate_spike", "A client sends ~400 pkt/s of HTTPS data for 10 s (t=60-70).")
    sc.packets += [tcp(at + i / 400, CLIENTS[0], WEB, 50000, 443, "A", 1000) for i in range(4000)]
    sc.incidents.append(Incident("traffic_spike", 60, 70, None, "pkt/s and B/s far above the moving average"))

    sc, rng = new("syn_flood", "One source sends 180 SYNs to port 443 in 5 s (t=60-65).")
    sc.packets += [tcp(at + i / 36, ATTACKER_FLOOD, WEB, 20000 + i, 443, "S") for i in range(180)]
    sc.incidents.append(Incident("excessive_connection_attempts", 60, 65, ATTACKER_FLOOD,
                                 "180 SYN-without-ACK vs limit 100"))

    sc, rng = new("port_scan", "One source SYN-probes ports 1-60 of one host in 3 s (t=60-63).")
    sc.packets += [tcp(at + i / 20, ATTACKER_SCAN, WEB, 41000, port, "S") for i, port in enumerate(range(1, 61))]
    sc.incidents.append(Incident("possible_port_scan", 60, 65, ATTACKER_SCAN, "60 distinct ports vs limit 20"))
    sc.incidents.append(Incident("unexpected_protocol_or_port", 60, 65, ATTACKER_SCAN,
                                 "co-detection: probed ports are outside the allowlist"))

    sc, rng = new("host_sweep", "One source SYN-probes port 443 on 30 hosts in 3 s (t=60-63).")
    sc.packets += [tcp(at + i / 10, ATTACKER_SWEEP, f"198.51.100.{i + 1}", 42000, 443, "S")
                   for i in range(30)]
    sc.incidents.append(Incident("possible_port_scan", 60, 65, ATTACKER_SWEEP,
                                 "30 distinct hosts vs limit 20"))

    sc, rng = new("unexpected_protocol", "A host sends 20 GRE packets (IP protocol 47) (t=60-64).")
    sc.packets += [_stamp(_eth() / IP(src=ODD_HOST, dst=WEB, proto=47) / Raw(b"\0" * 40), at + i / 5)
                   for i in range(20)]
    sc.incidents.append(Incident("unexpected_protocol_or_port", 60, 65, ODD_HOST,
                                 "20 packets use an unexpected IP protocol vs limit 10"))

    sc, rng = new("unexpected_port", "A host sends 20 TCP packets to port 31337 (t=60-64).")
    sc.packets += [tcp(at + i / 5, ODD_HOST, WEB, 50100, 31337, "A", 80) for i in range(20)]
    sc.incidents.append(Incident("unexpected_protocol_or_port", 60, 65, ODD_HOST,
                                 "20 packets use an unexpected TCP port vs limit 10"))

    sc, rng = new("unexpected_traffic", "A host sends TCP to port 31337 and GRE (IP protocol 47) (t=60-65).")
    sc.packets += [tcp(at + i / 10, ODD_HOST, WEB, 50100, 31337, "A", 80) for i in range(40)]
    sc.packets += [_stamp(_eth() / IP(src=ODD_HOST, dst=WEB, proto=47) / Raw(b"\0" * 40), at + 0.05 + i / 5)
                   for i in range(20)]
    sc.incidents.append(Incident("unexpected_protocol_or_port", 60, 65, ODD_HOST,
                                 "60 packets outside the allowlists vs limit 10"))

    for sc in scenarios:
        sc.packets.sort(key=lambda p: float(p.time))
    return scenarios


def build_load(packets: int, seed: int = 1234) -> list[Any]:
    """Background traffic scaled to roughly ``packets`` packets, for a throughput measurement."""
    rng = random.Random(f"{seed}:load")
    seconds = max(1, packets // 20)
    return background(rng, seconds)[:packets]


def write_scenarios(out_dir: Path, seed: int = 1234) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {}
    for sc in build_scenarios(seed):
        path = out_dir / f"{sc.name}.pcap"
        wrpcap(str(path), sc.packets)
        paths[sc.name] = path
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default="samples", help="output directory (default: samples)")
    parser.add_argument("--seed", type=int, default=1234)
    args = parser.parse_args()
    for name, path in write_scenarios(Path(args.out), args.seed).items():
        print(f"{name:20s} {path} ({path.stat().st_size / 1024:.0f} KiB)")


if __name__ == "__main__":
    main()
