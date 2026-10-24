"""Rule-based anomaly detection over finalized windows.

Four rules, all driven by ``DetectionConfig``. Every rule fires when the
observed value is strictly greater than its threshold.

Severity
--------
Severity is derived from ``ratio = observed / threshold`` (always > 1 for a fired
rule) using ``severity.warning_ratio`` and ``severity.high_ratio``:

* INFO     ratio < warning_ratio: barely over the line; worth a glance.
* WARNING  warning_ratio <= ratio < high_ratio: clearly abnormal for the config.
* HIGH     ratio >= high_ratio: far beyond the threshold.

Cooldown
--------
Events are keyed by ``(rule, source, metric)``; the window-level unexpected
traffic rule has no source in its key. Once emitted, an identical key is
suppressed for ``cooldown_seconds`` of event time (window end), unless the new
event has a higher severity (escalation). Suppressed events are counted in
``Detector.suppressed``. Event time, not wall-clock time, is used so replays are
deterministic.

Alerts are indicators of potentially unusual behaviour, not proof of an attack.
"""
from __future__ import annotations

from collections import deque
from typing import Optional

from .config import DetectionConfig
from .models import Event, Severity, SourceStats, WindowStats

RULE_TRAFFIC_SPIKE = "traffic_spike"
RULE_CONNECTION_ATTEMPTS = "excessive_connection_attempts"
RULE_PORT_SCAN = "possible_port_scan"
RULE_UNEXPECTED = "unexpected_protocol_or_port"
ALL_RULES = (RULE_TRAFFIC_SPIKE, RULE_CONNECTION_ATTEMPTS, RULE_PORT_SCAN, RULE_UNEXPECTED)

_SAMPLE_LIMIT = 5


def _sample(values: list[str], total: int) -> str:
    shown = ", ".join(values[:_SAMPLE_LIMIT])
    return shown + (f" (+{total - _SAMPLE_LIMIT} more)" if total > _SAMPLE_LIMIT else "")


def _targets(stats: SourceStats) -> str:
    hosts = _sample(sorted(stats.dst_hosts), len(stats.dst_hosts))
    ports = _sample([str(p) for p in sorted(stats.dst_ports)], len(stats.dst_ports))
    return f"hosts: {hosts or '-'}; ports: {ports or '-'}"


class Detector:
    """Stateful evaluator: keeps a short rate history and the cooldown table."""

    def __init__(self, cfg: DetectionConfig) -> None:
        self._cfg = cfg
        self._history: deque[tuple[float, float]] = deque(maxlen=cfg.traffic_spike.baseline_windows)
        self._last: dict[tuple[str, Optional[str], str], tuple[float, int]] = {}
        self.suppressed = 0

    # -- public API ---------------------------------------------------------

    def evaluate(self, ws: WindowStats) -> list[Event]:
        """Return the events raised by ``ws``, in deterministic order."""
        if ws.after_gap:
            self._history.clear()  # a baseline from before a long gap is meaningless
        candidates: list[Event] = []
        if self._cfg.traffic_spike.enabled:
            candidates += self._traffic_spike(ws)
        if self._cfg.connection_attempts.enabled:
            candidates += self._connection_attempts(ws)
        if self._cfg.port_scan.enabled:
            candidates += self._port_scan(ws)
        if self._cfg.unexpected_traffic.enabled:
            candidates += self._unexpected(ws)
        self._history.append((ws.packets_per_second, ws.bytes_per_second))
        self._expire_cooldowns(ws.end)
        return [e for e in candidates if self._admit(e)]

    # -- helpers ------------------------------------------------------------

    def _severity(self, observed: float, threshold: float) -> Severity:
        ratio = observed / threshold
        sev = self._cfg.severity
        if ratio >= sev.high_ratio:
            return Severity.HIGH
        if ratio >= sev.warning_ratio:
            return Severity.WARNING
        return Severity.INFO

    def _event(self, ws: WindowStats, rule: str, metric: str, observed: float,
               threshold: float, explanation: str, src_ip: Optional[str] = None,
               dst_info: Optional[str] = None) -> Event:
        return Event(
            timestamp=ws.end, rule=rule, severity=self._severity(observed, threshold),
            observed=float(observed), threshold=float(threshold), explanation=explanation,
            window_start=ws.start, window_end=ws.end, metric=metric,
            src_ip=src_ip, dst_info=dst_info,
        )

    def _admit(self, event: Event) -> bool:
        cooldown = self._cfg.cooldown_seconds
        # The unexpected-traffic rule is a window-level condition; its src_ip is only
        # that window's largest contributor, so keying on it would re-report the same
        # ongoing condition every time the top contributor changes.
        source = None if event.rule == RULE_UNEXPECTED else event.src_ip
        key = (event.rule, source, event.metric)
        previous = self._last.get(key)
        if previous is not None and cooldown > 0:
            last_ts, last_rank = previous
            if event.timestamp - last_ts < cooldown and event.severity.rank <= last_rank:
                self.suppressed += 1
                return False
        self._last[key] = (event.timestamp, event.severity.rank)
        return True

    def _expire_cooldowns(self, now: float) -> None:
        cooldown = self._cfg.cooldown_seconds
        stale = [k for k, (ts, _) in self._last.items() if now - ts >= cooldown]
        for key in stale:
            del self._last[key]

    # -- Rule A: traffic spike ---------------------------------------------

    def _traffic_spike(self, ws: WindowStats) -> list[Event]:
        cfg = self._cfg.traffic_spike
        metrics = (
            ("packets_per_second", ws.packets_per_second, cfg.pps_threshold, 0, cfg.min_baseline_pps, "pkt/s"),
            ("bytes_per_second", ws.bytes_per_second, cfg.bps_threshold, 1, cfg.min_baseline_bps, "B/s"),
        )
        events: list[Event] = []
        history = list(self._history)
        for metric, value, absolute, col, min_baseline, unit in metrics:
            exceeded: list[tuple[float, str]] = []
            if absolute is not None and value > absolute:
                exceeded.append((absolute, f"the absolute limit of {absolute:g} {unit}"))
            if cfg.moving_average_multiplier is not None and len(history) >= cfg.min_baseline_windows:
                average = sum(h[col] for h in history) / len(history)
                # Skip near-zero baselines: any traffic would look like an infinite spike.
                if average >= min_baseline and value > cfg.moving_average_multiplier * average:
                    limit = cfg.moving_average_multiplier * average
                    exceeded.append((limit, f"{cfg.moving_average_multiplier:g}x the moving average "
                                            f"({average:.1f} {unit} over {len(history)} windows)"))
            if exceeded:
                threshold, why = min(exceeded)  # the limit that was crossed by the widest margin
                events.append(self._event(
                    ws, RULE_TRAFFIC_SPIKE, metric, value, threshold,
                    f"{metric.replace('_', ' ')} reached {value:.1f} {unit}, above {why}."))
        return events

    # -- Rule B: excessive connection attempts ------------------------------

    def _connection_attempts(self, ws: WindowStats) -> list[Event]:
        limit = self._cfg.connection_attempts.max_syn_per_source
        span = ws.end - ws.start
        events = []
        for ip in sorted(ws.sources):
            stats = ws.sources[ip]
            if stats.syn_attempts > limit:
                events.append(self._event(
                    ws, RULE_CONNECTION_ATTEMPTS, "syn_attempts", stats.syn_attempts, limit,
                    f"{ip} sent {stats.syn_attempts} TCP SYN (no ACK) connection attempts in a "
                    f"{span:g}s window, above the limit of {limit}. These are attempts, not "
                    f"established connections; retransmitted SYNs are counted.",
                    src_ip=ip, dst_info=_targets(stats)))
        return events

    # -- Rule C: possible port scan -----------------------------------------

    def _port_scan(self, ws: WindowStats) -> list[Event]:
        cfg = self._cfg.port_scan
        span = ws.end - ws.start
        events = []
        for ip in sorted(ws.sources):
            stats = ws.sources[ip]
            if stats.distinct_ports > cfg.max_distinct_ports:
                events.append(self._event(
                    ws, RULE_PORT_SCAN, "distinct_destination_ports", stats.distinct_ports,
                    cfg.max_distinct_ports,
                    f"{ip} sent SYN probes to {stats.distinct_ports} distinct destination ports in a "
                    f"{span:g}s window (limit {cfg.max_distinct_ports}). Possible port scan.",
                    src_ip=ip, dst_info=_targets(stats)))
            if cfg.max_distinct_hosts is not None and stats.distinct_hosts > cfg.max_distinct_hosts:
                events.append(self._event(
                    ws, RULE_PORT_SCAN, "distinct_destination_hosts", stats.distinct_hosts,
                    cfg.max_distinct_hosts,
                    f"{ip} sent SYN probes to {stats.distinct_hosts} distinct destination hosts in a "
                    f"{span:g}s window (limit {cfg.max_distinct_hosts}). Possible host sweep.",
                    src_ip=ip, dst_info=_targets(stats)))
        return events

    # -- Rule D: unexpected protocol or port --------------------------------

    def _unexpected(self, ws: WindowStats) -> list[Event]:
        limit = self._cfg.unexpected_traffic.max_packets
        if ws.unexpected_total <= limit:
            return []
        ranked = sorted(ws.unexpected_breakdown.items(), key=lambda kv: (-kv[1], kv[0]))
        detail = ", ".join(f"{key.split(':', 1)[-1]} x{n}" for key, n in ranked[:_SAMPLE_LIMIT])
        top_source: Optional[str] = None
        explanation = (f"{ws.unexpected_total} packets used a protocol or port outside the allowlists "
                       f"(limit {limit}): {detail}.")
        if ws.unexpected_sources:
            top_source, count = sorted(ws.unexpected_sources.items(), key=lambda kv: (-kv[1], kv[0]))[0]
            explanation += f" Largest contributor: {top_source} ({count} packets)."
        return [self._event(ws, RULE_UNEXPECTED, "unexpected_packets", ws.unexpected_total, limit,
                            explanation, src_ip=top_source, dst_info=detail)]
