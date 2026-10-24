"""Fixed-window feature extraction and traffic aggregation.

Terminology (kept explicit throughout Lattice):

* **packet**: one captured frame that parsed successfully.
* **connection attempt**: a TCP packet with SYN set and ACK clear. Retransmitted
  SYNs and duplicate SYNs are *not* de-duplicated (no per-flow state is kept), so
  each counts as an attempt.
* **established connection**: never inferred; Lattice does no session tracking.

Windows are ``[start, end)`` and aligned to multiples of the window length on the
packet-timestamp axis, so offline replay never consults the machine clock. A
packet whose timestamp precedes the open window (out-of-order live traffic) is
folded into the open window and counted in ``late_packets``.

State is bounded: per-window source tables are capped, and everything is dropped
as soon as a window is finalized.
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Optional

from .config import AllowList, WindowConfig
from .models import PacketRecord, SourceStats, WindowStats

MAX_HOSTS_PER_SOURCE = 65536
MAX_UNEXPECTED_KEYS = 64
MAX_UNEXPECTED_SOURCES = 256
OTHER_KEY = "other"


class _Window:
    """Mutable accumulator for the currently open window."""

    __slots__ = ("packets", "bytes", "protocols", "sources", "untracked", "late",
                 "unexpected", "unexpected_sources", "after_gap")

    def __init__(self, after_gap: bool = False) -> None:
        self.packets = 0
        self.bytes = 0
        self.protocols: Counter[str] = Counter()
        self.sources: dict[str, SourceStats] = {}
        self.untracked = 0
        self.late = 0
        self.unexpected: Counter[str] = Counter()
        self.unexpected_sources: Counter[str] = Counter()
        self.after_gap = after_gap


class Aggregator:
    """Groups :class:`PacketRecord` objects into :class:`WindowStats`.

    Every method that can close a window returns the list of finalized windows
    in chronological order.
    """

    def __init__(self, window: WindowConfig, allowlist: Optional[AllowList] = None) -> None:
        self._cfg = window
        self._len = window.seconds
        self._allow = allowlist
        self._idx: Optional[int] = None
        self._open: Optional[_Window] = None
        self.late_packets_total = 0

    # -- public API ---------------------------------------------------------

    def add(self, rec: PacketRecord) -> list[WindowStats]:
        done: list[WindowStats] = []
        idx = self._index(rec.timestamp)
        late = False
        if self._idx is None:
            self._start(idx)
        elif idx > self._idx:
            done = self._move_to(idx)
        elif idx < self._idx:
            late = True
        assert self._open is not None
        self._accumulate(self._open, rec, late)
        return done

    def advance(self, now: float) -> list[WindowStats]:
        """Close windows that ended before ``now`` (live mode, driven by the clock)."""
        idx = self._index(now)
        if self._idx is None:
            self._start(idx)
            return []
        return self._move_to(idx) if idx > self._idx else []

    def flush(self) -> list[WindowStats]:
        """Finalize the open window if it holds packets, then reset all state."""
        out: list[WindowStats] = []
        if self._idx is not None and self._open is not None and self._open.packets > 0:
            out.append(self._finalize())
        self._idx = None
        self._open = None
        return out

    # -- internals ----------------------------------------------------------

    def _index(self, ts: float) -> int:
        return math.floor(ts / self._len)

    def _start(self, idx: int, after_gap: bool = False) -> None:
        self._idx = idx
        self._open = _Window(after_gap)

    def _move_to(self, idx: int) -> list[WindowStats]:
        assert self._idx is not None
        done = [self._finalize()]
        gap = idx - self._idx - 1
        if gap <= self._cfg.max_gap_windows:
            for missing in range(self._idx + 1, idx):
                self._start(missing)
                done.append(self._finalize())
            self._start(idx)
        else:
            self._start(idx, after_gap=True)
        return done

    def _accumulate(self, win: _Window, rec: PacketRecord, late: bool) -> None:
        win.packets += 1
        win.bytes += rec.length
        win.protocols[rec.protocol] += 1
        if late:
            win.late += 1
            self.late_packets_total += 1

        if rec.src_ip is not None:
            stats = win.sources.get(rec.src_ip)
            if stats is None and len(win.sources) < self._cfg.max_sources_per_window:
                stats = win.sources[rec.src_ip] = SourceStats()
            if stats is None:
                win.untracked += 1
            else:
                stats.packets += 1
                stats.bytes += rec.length
                if rec.is_syn_attempt:
                    stats.syn_attempts += 1
                    if rec.dst_port is not None:
                        stats.dst_ports.add(rec.dst_port)
                    if rec.dst_ip is not None and len(stats.dst_hosts) < MAX_HOSTS_PER_SOURCE:
                        stats.dst_hosts.add(rec.dst_ip)

        if self._allow is not None:
            reason = self._allow.violation(rec)
            if reason is not None:
                if reason not in win.unexpected and len(win.unexpected) >= MAX_UNEXPECTED_KEYS:
                    reason = OTHER_KEY
                win.unexpected[reason] += 1
                if rec.src_ip is not None and (
                        rec.src_ip in win.unexpected_sources
                        or len(win.unexpected_sources) < MAX_UNEXPECTED_SOURCES):
                    win.unexpected_sources[rec.src_ip] += 1

    def _finalize(self) -> WindowStats:
        assert self._idx is not None and self._open is not None
        win = self._open
        start = self._idx * self._len
        stats = WindowStats(
            start=start,
            end=start + self._len,
            packets=win.packets,
            bytes=win.bytes,
            packets_per_second=win.packets / self._len,
            bytes_per_second=win.bytes / self._len,
            protocol_counts=dict(sorted(win.protocols.items())),
            sources=win.sources,
            untracked_packets=win.untracked,
            late_packets=win.late,
            unexpected_total=sum(win.unexpected.values()),
            unexpected_breakdown=dict(sorted(win.unexpected.items())),
            unexpected_sources=dict(sorted(win.unexpected_sources.items())),
            after_gap=win.after_gap,
        )
        # Release the accumulator; callers own the returned stats from here on.
        self._open = None
        return stats
