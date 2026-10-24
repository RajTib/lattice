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
    return pd.DataFrame(rows, columns=["src_ip", "packets", "bytes", "syn_attempts"])


def protocol_series(counts: dict[str, int]) -> pd.Series:
    return pd.Series(counts, dtype="int64", name="packets")
