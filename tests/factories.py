"""Builders for synthetic packets, records and windows used across the test suite."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable, Optional

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

from lattice.config import Config, parse_config  # noqa: E402
from lattice.models import PacketRecord, SourceStats, WindowStats  # noqa: E402


def eth(**kw: Any) -> Any:
    """Ethernet header with fixed MACs so building never consults this machine's routing table."""
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02", **kw)


def stamp(pkt: Any, ts: float) -> Any:
    pkt.time = ts
    return pkt


def tcp_packet(ts: float, src: str = "10.0.0.1", dst: str = "10.0.0.2", sport: int = 40000,
               dport: int = 443, flags: Any = "S", payload: int = 0) -> Any:
    pkt = eth() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        pkt = pkt / Raw(b"x" * payload)
    return stamp(pkt, ts)


def udp_packet(ts: float, src: str = "10.0.0.1", dst: str = "10.0.0.2", sport: int = 40000,
               dport: int = 53, payload: int = 20) -> Any:
    return stamp(eth() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(b"x" * payload), ts)


def icmp_packet(ts: float, src: str = "10.0.0.1", dst: str = "10.0.0.2") -> Any:
    return stamp(eth() / IP(src=src, dst=dst) / ICMP(), ts)


def ipv6_tcp_packet(ts: float, src: str = "2001:db8::1", dst: str = "2001:db8::2",
                    sport: int = 40000, dport: int = 443, flags: Any = "S") -> Any:
    return stamp(eth() / IPv6(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags), ts)


def write_pcap(path: Path, packets: Iterable[Any]) -> Path:
    wrpcap(str(path), list(packets))
    return path


def record(ts: float, src: Optional[str] = "10.0.0.1", dst: Optional[str] = "10.0.0.2",
           protocol: str = "TCP", length: int = 100, sport: Optional[int] = 40000,
           dport: Optional[int] = 443, flags: Optional[int] = 0x02) -> PacketRecord:
    return PacketRecord(timestamp=ts, length=length, protocol=protocol, src_ip=src, dst_ip=dst,
                        src_port=sport, dst_port=dport, tcp_flags=flags, ip_version=4)


def make_config(overrides: Optional[dict] = None) -> Config:
    """Defaults merged with nested ``overrides``, validated like a real config file."""
    return parse_config(overrides or {})


def window(start: float = 0.0, length: float = 5.0, *, pps: float = 0.0, bps: float = 0.0,
           sources: Optional[dict[str, SourceStats]] = None, **extra: Any) -> WindowStats:
    return WindowStats(start=start, end=start + length, packets=int(pps * length),
                       bytes=int(bps * length), packets_per_second=pps, bytes_per_second=bps,
                       sources=sources or {}, **extra)


def source(syn: int = 0, ports: Iterable[int] = (), hosts: Iterable[str] = (),
           packets: int = 1) -> SourceStats:
    return SourceStats(packets=packets, bytes=packets * 60, syn_attempts=syn,
                       dst_ports=set(ports), dst_hosts=set(hosts))
