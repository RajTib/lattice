"""Turn stored rows into display-ready tables for the dashboard.

Pure functions with no Streamlit dependency, so they are unit-tested directly.
"""
from __future__ import annotations

import datetime as dt
from typing import Any, Optional, Sequence

import pandas as pd

# A "running" live run whose database has not been written for this long is
# treated as interrupted rather than live (e.g. the capturing process died).
STALE_AFTER_SECONDS = 30.0


def human_bytes(n: float) -> str:
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(value) < 1024 or unit == "GiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GiB"


def human_duration(seconds: float) -> str:
    """Compact duration for traffic coverage, without implying wall-clock uptime."""
    value = max(0.0, float(seconds))
    if value < 60:
        return f"{value:g} s"
    minutes, remainder = divmod(int(value), 60)
    if minutes < 60:
        return f"{minutes}m {remainder:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


def measurement_text(metric: str, value: float) -> str:
    """Format a detector measurement with the unit users need to interpret it."""
    number = float(value)
    if metric == "packets_per_second":
        return f"{number:,.1f} packets/s"
    if metric == "bytes_per_second":
        return f"{human_bytes(number)}/s"
    unit = {
        "syn_attempts": "SYN packets",
        "distinct_destination_ports": "destination ports",
        "distinct_destination_hosts": "destination hosts",
        "unexpected_packets": "unexpected packets",
    }.get(metric, metric.replace("_", " "))
    return f"{number:,.0f} {unit}"


def measurement_value(metric: str, value: float) -> str:
    """Format a compact value for a metric card whose label supplies context."""
    number = float(value)
    if metric == "packets_per_second":
        return f"{number:,.1f} packets/s"
    if metric == "bytes_per_second":
        return f"{human_bytes(number)}/s"
    return f"{number:,.0f}"


def metric_label(metric: str) -> str:
    return {
        "packets_per_second": "Packet rate",
        "bytes_per_second": "Byte rate",
        "syn_attempts": "SYN packets",
        "distinct_destination_ports": "Destination ports",
        "distinct_destination_hosts": "Destination hosts",
        "unexpected_packets": "Unexpected packets",
    }.get(metric, metric.replace("_", " ").capitalize())


def rule_label(rule: str) -> str:
    return {
        "traffic_spike": "Traffic spike",
        "excessive_connection_attempts": "Excessive SYN activity",
        "possible_port_scan": "Port scan / host sweep",
        "unexpected_protocol_or_port": "Unexpected traffic",
    }.get(rule, rule.replace("_", " ").capitalize())


def to_datetime(ts: float) -> dt.datetime:
    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc)


def format_time(ts: float) -> str:
    return to_datetime(ts).strftime("%Y-%m-%d %H:%M:%S UTC")


def run_label(run: dict[str, Any]) -> str:
    source = str(run["source"]).replace("\\", "/").rsplit("/", 1)[-1]
    return f"#{run['id']} · {run['mode']} · {source} · {run['status']}"


def data_mode(run: Optional[dict[str, Any]], seconds_since_db_write: Optional[float]) -> tuple[str, str]:
    """Return the display state and an accurate status explanation for a run."""
    if run is None:
        return "none", "No run selected."
    if run["status"] == "failed":
        return "failed", ("Failed run: processing did not finish. Stored results may be incomplete; "
                          "review the run note and storage-error count below.")
    if run["status"] == "partial":
        return "partial", ("Partial run: some input or results could not be processed or stored. "
                           "Use the available data with caution and review the run note below.")
    if run["status"] == "running":
        if seconds_since_db_write is not None and seconds_since_db_write <= STALE_AFTER_SECONDS:
            if run["mode"] == "live":
                return "live", "Live: this run is still being written; the view refreshes automatically."
            return "active", "In progress: this PCAP run is still being written. Reload to see new results."
        return "interrupted", ("This run is marked 'running' but the database has not been updated recently; "
                               "the capturing process probably exited without closing it. Showing stored data.")
    if run["mode"] == "live":
        return "historical", "Historical: a finished live session. Data is read from the database."
    return "historical", "Historical: a PCAP replay. Data is read from the database, not from the file."


def windows_frame(rows: Sequence[dict[str, Any]]) -> pd.DataFrame:
    frame = pd.DataFrame(
        {"time": [to_datetime(r["window_start"]) for r in rows],
         "packets_per_second": [r["packets_per_second"] for r in rows],
         "bytes_per_second": [r["bytes_per_second"] for r in rows],
         "packets": [r["packets"] for r in rows],
         "bytes": [r["bytes"] for r in rows]},
        columns=["time", "packets_per_second", "bytes_per_second", "packets", "bytes"])
    return frame.set_index("time")


def events_frame(rows: Sequence[dict[str, Any]]) -> pd.DataFrame:
    columns = ["time", "severity", "rule", "source", "targets", "metric", "observed", "threshold",
               "ratio", "explanation"]
    return pd.DataFrame(
        [{"time": to_datetime(r["ts"]), "severity": r["severity"], "rule": r["rule"],
          "source": r["src_ip"] or "-", "targets": r["dst_info"] or "-", "metric": r["metric"],
          "observed": r["observed"], "threshold": r["threshold"],
          "ratio": r["observed"] / r["threshold"] if r["threshold"] else float("nan"),
          "explanation": r["explanation"]} for r in rows],
        columns=columns)


def event_markers(windows: Sequence[dict[str, Any]], events: Sequence[dict[str, Any]],
                  metric: str) -> pd.DataFrame:
    """Aggregate overlapping events onto their exact persisted traffic window.

    A single marker per window avoids hiding repeated rule matches at the same
    x/y coordinate while retaining their count, rules, and highest severity in
    the tooltip.
    """
    rates = {float(row["window_start"]): float(row[metric]) for row in windows}
    groups: dict[float, list[dict[str, Any]]] = {}
    for event in events:
        start = float(event["window_start"])
        if start in rates:
            groups.setdefault(start, []).append(event)
    severity_rank = {"INFO": 1, "WARNING": 2, "HIGH": 3}
    rows = []
    for start, matches in sorted(groups.items()):
        severity = max(matches, key=lambda item: severity_rank.get(item["severity"], 0))["severity"]
        rules = sorted({rule_label(str(item["rule"])) for item in matches})
        rows.append({
            "time": to_datetime(start),
            "utc": format_time(start),
            "value": rates[start],
            "severity": severity,
            "events": len(matches),
            "rules": ", ".join(rules),
        })
    return pd.DataFrame(rows, columns=["time", "utc", "value", "severity", "events", "rules"])


def protocol_frame(counts: dict[str, int]) -> pd.DataFrame:
    """Return sorted protocol totals and packet shares for display."""
    total = sum(max(0, int(value)) for value in counts.values())
    return pd.DataFrame([
        {"protocol": name, "packets": int(count), "share": int(count) / total if total else 0.0,
         "share_label": ("<0.1%" if total and 0 < int(count) / total < 0.001
                         else f"{int(count) / total:.1%}" if total else "0.0%")}
        for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ], columns=["protocol", "packets", "share", "share_label"])


def event_context_frame(rows: Sequence[dict[str, Any]], event_start: float) -> pd.DataFrame:
    """Compact before/event/after traffic rows for one selected detection event."""
    columns = ["window", "relation", "packets", "packets_per_second", "bytes",
               "bytes_per_second", "unexpected_packets", "protocols"]
    return pd.DataFrame(
        [{
            "window": to_datetime(r["window_start"]),
            "relation": "event" if r["window_start"] == event_start
            else ("before" if r["window_start"] < event_start else "after"),
            "packets": r["packets"],
            "packets_per_second": r["packets_per_second"],
            "bytes": r["bytes"],
            "bytes_per_second": r["bytes_per_second"],
            "unexpected_packets": r["unexpected_packets"],
            "protocols": ", ".join(f"{name} {count}" for name, count in r["protocol_counts"].items()) or "-",
        } for r in rows],
        columns=columns)


def sources_frame(rows: Sequence[dict[str, Any]]) -> pd.DataFrame:
    return pd.DataFrame(rows, columns=["src_ip", "packets", "bytes", "syn_attempts",
                                       "max_distinct_ports", "max_distinct_hosts"])


def protocol_series(counts: dict[str, int]) -> pd.Series:
    return pd.Series(counts, dtype="int64", name="packets")
