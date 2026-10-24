"""Configuration loading and validation.

``config.json`` is merged over built-in defaults. Unknown keys and wrongly typed
values are rejected with a message naming the offending key, so a typo such as
``"max_syn_per_sorce"`` fails loudly instead of silently using a default.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional

from .models import PacketRecord

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"


class ConfigError(ValueError):
    """Raised for a missing, unreadable or invalid configuration."""


@dataclass(frozen=True)
class WindowConfig:
    seconds: float = 5.0
    # Empty windows are emitted for gaps up to this many windows; longer gaps are skipped.
    max_gap_windows: int = 12
    top_talkers: int = 10
    max_sources_per_window: int = 5000


@dataclass(frozen=True)
class SeverityConfig:
    warning_ratio: float = 2.0
    high_ratio: float = 5.0


@dataclass(frozen=True)
class TrafficSpikeConfig:
    enabled: bool = True
    pps_threshold: Optional[float] = 1000.0
    bps_threshold: Optional[float] = 1_000_000.0
    moving_average_multiplier: Optional[float] = 4.0
    baseline_windows: int = 6
    min_baseline_windows: int = 3
    min_baseline_pps: float = 1.0
    min_baseline_bps: float = 100.0


@dataclass(frozen=True)
class ConnectionAttemptConfig:
    enabled: bool = True
    max_syn_per_source: int = 100


@dataclass(frozen=True)
class PortScanConfig:
    enabled: bool = True
    max_distinct_ports: int = 20
    max_distinct_hosts: Optional[int] = 20


@dataclass(frozen=True)
class UnexpectedTrafficConfig:
    enabled: bool = True
    max_packets: int = 10
    allowed_protocols: tuple[str, ...] = ("TCP", "UDP", "ICMP", "ICMPv6", "ARP")
    # Entries are ints ("443") or inclusive ranges ("8000-8100").
    allowed_ports: tuple[Any, ...] = (22, 53, 80, 123, 443)


@dataclass(frozen=True)
class DetectionConfig:
    cooldown_seconds: float = 30.0
    severity: SeverityConfig = field(default_factory=SeverityConfig)
    traffic_spike: TrafficSpikeConfig = field(default_factory=TrafficSpikeConfig)
    connection_attempts: ConnectionAttemptConfig = field(default_factory=ConnectionAttemptConfig)
    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    unexpected_traffic: UnexpectedTrafficConfig = field(default_factory=UnexpectedTrafficConfig)


@dataclass(frozen=True)
class CaptureConfig:
    interface: Optional[str] = None
    bpf_filter: Optional[str] = None
    queue_size: int = 20000


@dataclass(frozen=True)
class Config:
    database_path: str = "lattice.db"
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    window: WindowConfig = field(default_factory=WindowConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["database"] = {"path": data.pop("database_path")}
        # JSON has no tuples; normalise so the dict round-trips through json.
        return json.loads(json.dumps(data))

    def processing_fingerprint(self) -> str:
        """Canonical string of settings that change PCAP results (window + detection)."""
        full = self.to_dict()
        payload = {"window": full["window"], "detection": full["detection"]}
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


_RANGE_RE = re.compile(r"^\s*(\d+)\s*-\s*(\d+)\s*$")


@dataclass(frozen=True)
class AllowList:
    """Protocol and port allowlists used to classify packets as expected/unexpected."""

    protocols: frozenset[str]
    port_ranges: tuple[tuple[int, int], ...]

    @classmethod
    def from_config(cls, cfg: UnexpectedTrafficConfig) -> "AllowList":
        return cls(
            protocols=frozenset(p.upper() for p in cfg.allowed_protocols),
            port_ranges=tuple(sorted(_parse_port_entry(e, "allowed_ports") for e in cfg.allowed_ports)),
        )

    def port_allowed(self, port: int) -> bool:
        return any(lo <= port <= hi for lo, hi in self.port_ranges)

    def violation(self, rec: PacketRecord) -> Optional[str]:
        """Return why ``rec`` is outside the allowlists, or ``None`` if it conforms.

        A TCP/UDP packet conforms if *either* endpoint port is allowed, because
        replies carry the service port as their source port.
        """
        if rec.protocol.upper() not in self.protocols:
            return f"protocol:{rec.protocol}"
        if rec.protocol in ("TCP", "UDP") and rec.dst_port is not None:
            ports = [p for p in (rec.dst_port, rec.src_port) if p is not None]
            if not any(self.port_allowed(p) for p in ports):
                return f"port:{rec.protocol}/{rec.dst_port}"
        return None


def _parse_port_entry(entry: Any, where: str) -> tuple[int, int]:
    if isinstance(entry, bool):
        raise ConfigError(f"{where}: invalid port entry {entry!r}")
    if isinstance(entry, int):
        lo = hi = entry
    elif isinstance(entry, str) and entry.strip().isdigit():
        lo = hi = int(entry)
    elif isinstance(entry, str) and _RANGE_RE.match(entry):
        m = _RANGE_RE.match(entry)
        assert m is not None
        lo, hi = int(m.group(1)), int(m.group(2))
    else:
        raise ConfigError(f"{where}: invalid port entry {entry!r} (use 443 or '8000-8100')")
    if not (0 <= lo <= hi <= 65535):
        raise ConfigError(f"{where}: port entry {entry!r} must satisfy 0 <= low <= high <= 65535")
    return lo, hi


class _Section:
    """Typed accessor over one JSON object that rejects unknown keys."""

    def __init__(self, data: Any, path: str) -> None:
        if not isinstance(data, Mapping):
            raise ConfigError(f"{path or 'config'}: expected a JSON object, got {type(data).__name__}")
        self._data = data
        self._path = path
        self._used: set[str] = set()

    def _full(self, key: str) -> str:
        return f"{self._path}.{key}" if self._path else key

    def raw(self, key: str, default: Any) -> Any:
        self._used.add(key)
        return self._data.get(key, default)

    def section(self, key: str) -> "_Section":
        self._used.add(key)
        return _Section(self._data.get(key, {}), self._full(key))

    def number(self, key: str, default: Optional[float], *, minimum: float = 0.0,
               integer: bool = False, nullable: bool = False, exclusive_min: bool = False) -> Any:
        value = self.raw(key, default)
        name = self._full(key)
        if value is None:
            if nullable:
                return None
            raise ConfigError(f"{name}: must not be null")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"{name}: expected a number, got {value!r}")
        if integer and (isinstance(value, float) and not value.is_integer()):
            raise ConfigError(f"{name}: expected a whole number, got {value!r}")
        too_small = value <= minimum if exclusive_min else value < minimum
        if too_small:
            cmp = ">" if exclusive_min else ">="
            raise ConfigError(f"{name}: must be {cmp} {minimum}, got {value!r}")
        return int(value) if integer else float(value)

    def boolean(self, key: str, default: bool) -> bool:
        value = self.raw(key, default)
        if not isinstance(value, bool):
            raise ConfigError(f"{self._full(key)}: expected true or false, got {value!r}")
        return value

    def optional_str(self, key: str, default: Optional[str]) -> Optional[str]:
        value = self.raw(key, default)
        if value is not None and not isinstance(value, str):
            raise ConfigError(f"{self._full(key)}: expected a string or null, got {value!r}")
        return value or None

    def str_list(self, key: str, default: tuple[str, ...]) -> tuple[str, ...]:
        value = self.raw(key, list(default))
        if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
            raise ConfigError(f"{self._full(key)}: expected a list of non-empty strings")
        return tuple(value)

    def finish(self) -> None:
        unknown = sorted(set(self._data) - self._used)
        if unknown:
            where = self._path or "top level"
            raise ConfigError(f"{where}: unknown key(s): {', '.join(unknown)}")


def parse_config(data: Mapping[str, Any]) -> Config:
    """Validate ``data`` (parsed JSON) and return a :class:`Config`."""
    d = Config()
    root = _Section(data, "")

    db = root.section("database")
    path = db.raw("path", d.database_path)
    if not isinstance(path, str) or not path.strip():
        raise ConfigError("database.path: expected a non-empty string")
    db.finish()

    cap = root.section("capture")
    capture = CaptureConfig(
        interface=cap.optional_str("interface", d.capture.interface),
        bpf_filter=cap.optional_str("bpf_filter", d.capture.bpf_filter),
        queue_size=cap.number("queue_size", d.capture.queue_size, minimum=1, integer=True),
    )
    cap.finish()

    win = root.section("window")
    wd = d.window
    window = WindowConfig(
        seconds=win.number("seconds", wd.seconds, minimum=0, exclusive_min=True),
        max_gap_windows=win.number("max_gap_windows", wd.max_gap_windows, minimum=0, integer=True),
        top_talkers=win.number("top_talkers", wd.top_talkers, minimum=1, integer=True),
        max_sources_per_window=win.number("max_sources_per_window", wd.max_sources_per_window,
                                          minimum=1, integer=True),
    )
    win.finish()

    det = root.section("detection")
    dd = d.detection
    cooldown = det.number("cooldown_seconds", dd.cooldown_seconds, minimum=0)

    sev = det.section("severity")
    severity = SeverityConfig(
        warning_ratio=sev.number("warning_ratio", dd.severity.warning_ratio, minimum=1, exclusive_min=True),
        high_ratio=sev.number("high_ratio", dd.severity.high_ratio, minimum=1, exclusive_min=True),
    )
    sev.finish()
    if severity.high_ratio <= severity.warning_ratio:
        raise ConfigError("detection.severity: high_ratio must be greater than warning_ratio")

    sp = det.section("traffic_spike")
    sd = dd.traffic_spike
    spike = TrafficSpikeConfig(
        enabled=sp.boolean("enabled", sd.enabled),
        pps_threshold=sp.number("pps_threshold", sd.pps_threshold, minimum=0, exclusive_min=True, nullable=True),
        bps_threshold=sp.number("bps_threshold", sd.bps_threshold, minimum=0, exclusive_min=True, nullable=True),
        moving_average_multiplier=sp.number("moving_average_multiplier", sd.moving_average_multiplier,
                                            minimum=1, exclusive_min=True, nullable=True),
        baseline_windows=sp.number("baseline_windows", sd.baseline_windows, minimum=1, integer=True),
        min_baseline_windows=sp.number("min_baseline_windows", sd.min_baseline_windows, minimum=1, integer=True),
        min_baseline_pps=sp.number("min_baseline_pps", sd.min_baseline_pps, minimum=0, exclusive_min=True),
        min_baseline_bps=sp.number("min_baseline_bps", sd.min_baseline_bps, minimum=0, exclusive_min=True),
    )
    sp.finish()
    if spike.min_baseline_windows > spike.baseline_windows:
        raise ConfigError("detection.traffic_spike: min_baseline_windows cannot exceed baseline_windows")
    if spike.enabled and spike.pps_threshold is None and spike.bps_threshold is None \
            and spike.moving_average_multiplier is None:
        raise ConfigError("detection.traffic_spike: enabled but every threshold is null; "
                          "set at least one or disable the rule")

    ca = det.section("connection_attempts")
    connection = ConnectionAttemptConfig(
        enabled=ca.boolean("enabled", dd.connection_attempts.enabled),
        max_syn_per_source=ca.number("max_syn_per_source", dd.connection_attempts.max_syn_per_source,
                                     minimum=1, integer=True),
    )
    ca.finish()

    ps = det.section("port_scan")
    port_scan = PortScanConfig(
        enabled=ps.boolean("enabled", dd.port_scan.enabled),
        max_distinct_ports=ps.number("max_distinct_ports", dd.port_scan.max_distinct_ports,
                                     minimum=1, integer=True),
        max_distinct_hosts=ps.number("max_distinct_hosts", dd.port_scan.max_distinct_hosts,
                                     minimum=1, integer=True, nullable=True),
    )
    ps.finish()

    ut = det.section("unexpected_traffic")
    ud = dd.unexpected_traffic
    ports = ut.raw("allowed_ports", list(ud.allowed_ports))
    if not isinstance(ports, list):
        raise ConfigError("detection.unexpected_traffic.allowed_ports: expected a list")
    for entry in ports:
        _parse_port_entry(entry, "detection.unexpected_traffic.allowed_ports")
    unexpected = UnexpectedTrafficConfig(
        enabled=ut.boolean("enabled", ud.enabled),
        max_packets=ut.number("max_packets", ud.max_packets, minimum=1, integer=True),
        allowed_protocols=ut.str_list("allowed_protocols", ud.allowed_protocols),
        allowed_ports=tuple(ports),
    )
    ut.finish()

    det.finish()
    root.finish()
    return Config(
        database_path=path,
        capture=capture,
        window=window,
        detection=DetectionConfig(
            cooldown_seconds=cooldown,
            severity=severity,
            traffic_spike=spike,
            connection_attempts=connection,
            port_scan=port_scan,
            unexpected_traffic=unexpected,
        ),
    )


def load_config(path: Optional[str | Path] = None) -> Config:
    """Load and validate a JSON config file.

    With no ``path`` the project's ``config.json`` is used if present, otherwise
    built-in defaults. An explicitly given path that does not exist is an error.
    """
    if path is None:
        if not DEFAULT_CONFIG_PATH.exists():
            return Config()
        path = DEFAULT_CONFIG_PATH
    file = Path(path)
    try:
        text = file.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {file}") from None
    except OSError as exc:
        raise ConfigError(f"cannot read config file {file}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{file}: invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    return parse_config(data)
