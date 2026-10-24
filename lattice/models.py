"""Shared data models passed between Lattice pipeline stages.

Nothing here depends on Scapy, SQLite or Streamlit, so every stage can be tested
with plain Python objects.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# TCP flag bits (RFC 793 / RFC 3168).
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


class Severity(str, Enum):
    """Event severity. Assigned from observed/threshold ratio (see detector.py)."""

    INFO = "INFO"
    WARNING = "WARNING"
    HIGH = "HIGH"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {Severity.INFO: 0, Severity.WARNING: 1, Severity.HIGH: 2}


@dataclass(frozen=True)
class PacketRecord:
    """Header-level view of one packet. No payload bytes are retained.

    Optional fields are ``None`` when the packet has no such field. A ``None``
    port is "not applicable"; a port of ``0`` is a real (if unusual) value.
    Likewise ``tcp_flags`` is ``None`` for non-TCP packets and ``0`` for a TCP
    packet with no flags set (a "NULL" packet).
    """

    timestamp: float
    length: int
    protocol: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[int] = None
    ip_version: Optional[int] = None

    @property
    def is_syn_attempt(self) -> bool:
        """TCP SYN without ACK: the first packet of a connection attempt.

        Retransmitted SYNs are indistinguishable at header level and count again.
        """
        flags = self.tcp_flags
        return flags is not None and bool(flags & TCP_SYN) and not flags & TCP_ACK


@dataclass
class SourceStats:
    """Per-source aggregates inside one window.

    ``syn_attempts``, ``dst_ports`` and ``dst_hosts`` only reflect TCP
    SYN-without-ACK packets (connection attempts). Counting every packet would
    make servers replying to many clients look like port scanners.
    """

    packets: int = 0
    bytes: int = 0
    syn_attempts: int = 0
    dst_ports: set[int] = field(default_factory=set)
    dst_hosts: set[str] = field(default_factory=set)

    @property
    def distinct_ports(self) -> int:
        return len(self.dst_ports)

    @property
    def distinct_hosts(self) -> int:
        return len(self.dst_hosts)


@dataclass
class WindowStats:
    """Finalized statistics for one fixed time window ``[start, end)``.

    Rates divide by the configured window length, not by the span of observed
    packets, so a partially filled final window reports a lower rate.
    """

    start: float
    end: float
    packets: int = 0
    bytes: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    protocol_counts: dict[str, int] = field(default_factory=dict)
    sources: dict[str, SourceStats] = field(default_factory=dict)
    # Packets from sources beyond max_sources_per_window (counted in totals only).
    untracked_packets: int = 0
    # Packets that arrived with a timestamp before this window and were folded in.
    late_packets: int = 0
    # Packets outside the protocol/port allowlists, keyed by reason, e.g. "port:TCP/31337".
    unexpected_total: int = 0
    unexpected_breakdown: dict[str, int] = field(default_factory=dict)
    unexpected_sources: dict[str, int] = field(default_factory=dict)
    # True when a gap too large to fill with empty windows precedes this window.
    after_gap: bool = False

    def top_sources(self, n: int) -> list[tuple[str, SourceStats]]:
        """Top ``n`` sources by packet count (ties broken by IP string)."""
        ranked = sorted(self.sources.items(), key=lambda kv: (-kv[1].packets, kv[0]))
        return ranked[:n]


@dataclass(frozen=True)
class Event:
    """A detection event. An indicator of unusual behaviour, not proof of attack."""

    timestamp: float
    rule: str
    severity: Severity
    observed: float
    threshold: float
    explanation: str
    window_start: float
    window_end: float
    metric: str = ""
    src_ip: Optional[str] = None
    dst_info: Optional[str] = None


@dataclass
class IngestStats:
    """Counts for the capture/parse stage so skipped packets are never hidden."""

    seen: int = 0
    parsed: int = 0
    malformed: int = 0
    dropped: int = 0  # live capture only: queue overflow
    read_error: Optional[str] = None

    @property
    def skipped(self) -> int:
        return self.malformed + self.dropped


@dataclass
class RunSummary:
    """Outcome of processing one PCAP file or one live session."""

    run_id: int
    source: str
    mode: str
    status: str
    packets: int = 0
    bytes: int = 0
    skipped_packets: int = 0
    windows: int = 0
    events: int = 0
    suppressed_events: int = 0
    storage_errors: int = 0
    elapsed_seconds: float = 0.0
    duplicate: bool = False
    note: str = ""

    @property
    def packets_per_second_processed(self) -> float:
        return self.packets / self.elapsed_seconds if self.elapsed_seconds > 0 else 0.0
