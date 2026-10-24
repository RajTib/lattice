"""Traffic input: offline PCAP reading and authorized live capture.

Lattice is passive. It only reads packets; it never sends, blocks or modifies
traffic. Only capture on interfaces and networks you are authorized to monitor.
"""
from __future__ import annotations

import logging
import os
import platform
import queue
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from scapy.error import Scapy_Exception
from scapy.utils import PcapReader

from .models import IngestStats, PacketRecord
from .parser import PacketParseError, parse_packet

log = logging.getLogger(__name__)


class CaptureError(RuntimeError):
    """Raised when packets cannot be read or a live capture cannot start."""


# ---------------------------------------------------------------- offline ---

_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<", b"\x4d\x3c\xb2\xa1": "<",  # little-endian, microsecond / nanosecond
    b"\xa1\xb2\xc3\xd4": ">", b"\xa1\xb2\x3c\x4d": ">",  # big-endian
}
_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"
_PCAPNG_BYTE_ORDER = 0x1A2B3C4D
_MAX_RECORD_BYTES = 256 * 1024 * 1024  # no real capture record is anywhere near this


def _check_capture_framing(file: Path) -> Optional[str]:
    """Walk record/block framing without reading packet data.

    Scapy silently accepts a file cut off in the middle of a record (classic
    PCAP) or drops the final block (PCAPNG) without reporting anything, so a
    truncated or still-being-written capture would otherwise look complete.
    Returns a description of the first framing problem, ``None`` if the framing is
    intact or the file is not a recognised capture (Scapy then reports that), and
    raises :class:`CaptureError` if the file claims to be a capture but its
    header is invalid.
    """
    size = file.stat().st_size
    with open(file, "rb") as fh:
        magic = fh.read(4)
        if magic in _PCAP_MAGICS:
            return _check_pcap_framing(fh, size, _PCAP_MAGICS[magic], file)
        if magic == _PCAPNG_SHB:
            return _check_pcapng_framing(fh, size, file)
    return None


def _check_pcap_framing(fh: Any, size: int, endian: str, file: Path) -> Optional[str]:
    header = fh.read(20)
    if len(header) < 20:
        return None  # too short to be a capture; Scapy reports "not a supported capture file"
    major = struct.unpack(endian + "H", header[:2])[0]
    if major != 2:
        raise CaptureError(f"cannot open {file} as a PCAP file: unsupported format version {major}")
    pos, number = 24, 0
    while pos < size:
        number += 1
        fh.seek(pos)
        record = fh.read(16)
        if len(record) < 16:
            return f"record {number} at byte {pos} has an incomplete header"
        caplen = struct.unpack(endian + "I", record[8:12])[0]
        end = pos + 16 + caplen
        if caplen > _MAX_RECORD_BYTES or end > size:
            present = max(0, size - pos - 16)
            return (f"record {number} at byte {pos} is incomplete "
                    f"({caplen} captured bytes declared, {present} present)")
        pos = end
    return None


def _check_pcapng_framing(fh: Any, size: int, file: Path) -> Optional[str]:
    pos, number, endian = 0, 0, "<"
    while pos < size:
        number += 1
        fh.seek(pos)
        head = fh.read(12)
        if len(head) < 12:
            return f"block {number} at byte {pos} has an incomplete header"
        if head[:4] == _PCAPNG_SHB:  # each section may use its own byte order
            order = struct.unpack("<I", head[8:12])[0]
            if order == _PCAPNG_BYTE_ORDER:
                endian = "<"
            elif order == struct.unpack(">I", struct.pack("<I", _PCAPNG_BYTE_ORDER))[0]:
                endian = ">"
            else:
                raise CaptureError(f"cannot open {file} as a PCAPNG file: invalid byte-order magic")
        elif number == 1:
            raise CaptureError(f"cannot open {file} as a PCAPNG file: missing section header")
        total = struct.unpack(endian + "I", head[4:8])[0]
        if total < 12 or total % 4:
            return f"block {number} at byte {pos} has an invalid length {total}"
        if pos + total > size:
            return (f"block {number} at byte {pos} is incomplete "
                    f"({total} bytes declared, {size - pos} present)")
        fh.seek(pos + total - 4)
        if struct.unpack(endian + "I", fh.read(4))[0] != total:
            return f"block {number} at byte {pos} has inconsistent length fields"
        pos += total
    return None


def iter_pcap_records(path: str | Path, stats: IngestStats) -> Iterator[PacketRecord]:
    """Yield parsed records from a PCAP/PCAPNG file in file order.

    Malformed packets are counted in ``stats.malformed`` and skipped. A file that
    is truncated or has broken record framing sets ``stats.read_error`` (packets
    that could be read are still yielded). A file that cannot be opened raises
    :class:`CaptureError`.
    """
    file = Path(path)
    if not file.is_file():
        raise CaptureError(f"PCAP file not found: {file}")
    try:
        framing_problem = _check_capture_framing(file)
        reader = PcapReader(str(file))
    except (Scapy_Exception, OSError, struct.error, EOFError) as exc:
        raise CaptureError(f"cannot open {file} as a PCAP/PCAPNG file: {exc}") from exc
    if framing_problem:
        stats.read_error = framing_problem
        log.warning("%s is incomplete: %s", file, framing_problem)
    with reader:
        while True:
            try:
                pkt = next(reader)
            except StopIteration:
                return
            except (Scapy_Exception, EOFError, struct.error, OSError) as exc:
                stats.read_error = stats.read_error or f"{type(exc).__name__}: {exc}"
                log.warning("stopped reading %s early: %s", file, stats.read_error)
                return
            stats.seen += 1
            try:
                record = parse_packet(pkt)
            except PacketParseError as exc:
                stats.malformed += 1
                log.debug("skipping malformed packet #%d in %s: %s", stats.seen, file, exc)
                continue
            stats.parsed += 1
            yield record


def load_pcap_records(path: str | Path, stats: IngestStats) -> list[PacketRecord]:
    """Read a whole PCAP and return records sorted by timestamp.

    The sort is stable, so packets with equal timestamps keep file order and
    replay is deterministic. Memory use is proportional to the packet count
    (header fields only), which is fine for the small captures Lattice targets.
    """
    records = list(iter_pcap_records(path, stats))
    records.sort(key=lambda r: r.timestamp)
    return records


# ------------------------------------------------------------------- live ---

@dataclass(frozen=True)
class InterfaceInfo:
    name: str
    description: str


@dataclass(frozen=True)
class LiveStatus:
    available: bool
    message: str


def list_interfaces() -> list[InterfaceInfo]:
    """Interfaces Scapy can see. Returns an empty list if enumeration fails."""
    from scapy.config import conf

    try:
        return [InterfaceInfo(str(i.name), str(getattr(i, "description", "") or ""))
                for i in conf.ifaces.values()]
    except Exception as exc:  # enumeration is OS-specific and best-effort
        log.warning("could not enumerate interfaces: %s", exc)
        return []


def _is_elevated() -> Optional[bool]:
    try:
        if platform.system() == "Windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return None


def live_capture_status() -> LiveStatus:
    """Best-effort check of whether live capture can be attempted on this machine."""
    from scapy.config import conf

    system = platform.system()
    elevated = _is_elevated()
    if system == "Windows" and not conf.use_pcap:
        return LiveStatus(False, "Npcap was not found. Install Npcap (https://npcap.com) and "
                                 "restart, then run Lattice from an Administrator terminal.")
    if elevated is False:
        return LiveStatus(True, "Not running with elevated privileges. Capture usually needs "
                                "Administrator (Windows), root or CAP_NET_RAW (Linux) or "
                                "access to /dev/bpf* (macOS); it will fail if they are missing.")
    return LiveStatus(True, "Live capture can be attempted. Capture only networks you are authorized to monitor.")


class LiveCapture:
    """Background sniffer feeding parsed records into a bounded queue.

    ``stop()`` is idempotent and joins the sniffer thread, so no capture thread
    outlives it. When the queue is full new packets are dropped and counted in
    ``stats.dropped`` rather than blocking the sniffer.
    """

    def __init__(self, interface: Optional[str], bpf_filter: Optional[str] = None,
                 queue_size: int = 20000,
                 sniffer_factory: Optional[Callable[..., Any]] = None) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.records: "queue.Queue[PacketRecord]" = queue.Queue(maxsize=queue_size)
        self.stats = IngestStats()
        self._lock = threading.Lock()
        self._sniffer: Any = None
        self._error: Optional[str] = None
        self._factory = sniffer_factory

    def _on_packet(self, pkt: Any) -> None:
        try:
            record = parse_packet(pkt)
        except PacketParseError as exc:
            log.debug("skipping malformed live packet: %s", exc)
            with self._lock:
                self.stats.seen += 1
                self.stats.malformed += 1
            return
        try:
            self.records.put_nowait(record)
        except queue.Full:
            with self._lock:
                self.stats.seen += 1
                self.stats.dropped += 1
            return
        with self._lock:
            self.stats.seen += 1
            self.stats.parsed += 1

    def snapshot_stats(self) -> IngestStats:
        with self._lock:
            return IngestStats(self.stats.seen, self.stats.parsed, self.stats.malformed,
                               self.stats.dropped, self.stats.read_error)

    @property
    def error(self) -> Optional[str]:
        """Last sniffer-thread failure, still available after ``stop()``."""
        exc = getattr(self._sniffer, "exception", None) if self._sniffer is not None else None
        if exc:
            self._error = f"{type(exc).__name__}: {exc}"
        return self._error

    @property
    def running(self) -> bool:
        return bool(self._sniffer is not None and getattr(self._sniffer, "running", False))

    def start(self, startup_timeout: float = 3.0, settle_seconds: float = 0.25) -> None:
        """Begin capturing. Raises :class:`CaptureError` if the sniffer cannot start.

        Scapy flips ``running`` to True *before* it opens its sockets, so a bad
        interface or missing privilege only surfaces moments later as
        ``sniffer.exception``. After ``running`` is seen we therefore watch the
        sniffer for ``settle_seconds`` before declaring success.
        """
        if self._sniffer is not None:
            raise CaptureError("capture already started")
        factory = self._factory
        if factory is None:
            from scapy.sendrecv import AsyncSniffer
            factory = AsyncSniffer
        kwargs: dict[str, Any] = {"prn": self._on_packet, "store": False}
        if self.interface:
            kwargs["iface"] = self.interface
        if self.bpf_filter:
            kwargs["filter"] = self.bpf_filter
        try:
            sniffer = factory(**kwargs)
            self._sniffer = sniffer
            sniffer.start()
        except (OSError, Scapy_Exception, RuntimeError, ValueError) as exc:
            self._sniffer = None
            raise CaptureError(self._hint(exc)) from exc

        deadline = time.monotonic() + startup_timeout
        settled_at: Optional[float] = None
        while time.monotonic() < deadline:
            failure = getattr(sniffer, "exception", None)
            thread = getattr(sniffer, "thread", None)
            if failure is not None or (settled_at is not None and thread is not None
                                       and not thread.is_alive()):
                self.stop()
                raise CaptureError(self._hint(failure or RuntimeError("sniffer thread exited")))
            if getattr(sniffer, "running", False):
                settled_at = settled_at or time.monotonic()
                if time.monotonic() - settled_at >= settle_seconds:
                    log.info("live capture started on %s (filter=%r)",
                             self.interface or "default", self.bpf_filter)
                    return
            time.sleep(0.02)
        self.stop()
        raise CaptureError("live capture did not start within "
                           f"{startup_timeout:.0f}s; check the interface name and privileges")

    def stop(self, join_timeout: float = 5.0) -> None:
        if self._sniffer is None:
            return
        _ = self.error  # latch any sniffer-thread exception before dropping the sniffer
        sniffer, self._sniffer = self._sniffer, None
        try:
            if getattr(sniffer, "running", False):
                sniffer.stop(join=True)
        except Exception as exc:  # Scapy re-raises whatever killed the sniffer thread
            log.warning("sniffer reported an error while stopping: %s: %s", type(exc).__name__, exc)
        thread = getattr(sniffer, "thread", None)
        if thread is not None and thread.is_alive():
            thread.join(join_timeout)
            if thread.is_alive():
                log.error("sniffer thread did not exit within %.0fs", join_timeout)
        log.info("live capture stopped")

    @staticmethod
    def _hint(exc: BaseException) -> str:
        text = f"{type(exc).__name__}: {exc}"
        if platform.system() == "Windows":
            return (f"{text}. On Windows live capture needs Npcap (https://npcap.com) and an "
                    "Administrator terminal. Use PCAP replay if Npcap is unavailable.")
        return (f"{text}. Live capture usually needs root or CAP_NET_RAW "
                "(e.g. sudo, or setcap cap_net_raw+eip on the Python binary). "
                "Check the interface name with `python -m lattice interfaces`.")
