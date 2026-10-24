"""Deterministic analytics and export helpers for the Streamlit dashboard.

The functions in this module deliberately have no Streamlit dependency.  They
turn persisted Lattice rows into concise findings, normalized run metrics, and
portable exports without making security claims beyond the stored evidence.
"""
from __future__ import annotations

import csv
import io
import json
import statistics
import tempfile
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from .config import Config
from .models import RunSummary
from .pipeline import process_pcap
from .storage import Storage

MAX_UPLOAD_BYTES = 100 * 1024 * 1024
SUPPORTED_CAPTURE_SUFFIXES = {".pcap", ".pcapng"}
_CAPTURE_MAGIC = {
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",  # PCAP, microsecond
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",  # PCAP, nanosecond
    b"\x0a\x0d\x0d\x0a",                          # PCAPNG
}


@dataclass(frozen=True)
class Finding:
    """One evidence-backed observation suitable for display or export."""

    category: str
    title: str
    summary: str
    significance: float
    severity: str = "INFO"
    event_id: int | None = None
    investigation: str = ""


_RULE_TITLES = {
    "traffic_spike": "Traffic rate exceeded its configured limit",
    "excessive_connection_attempts": "Elevated TCP SYN activity",
    "possible_port_scan": "High destination diversity in SYN probes",
    "unexpected_protocol_or_port": "Traffic fell outside the configured allowlists",
}

_NEXT_STEPS = {
    "traffic_spike": ("Correlate the window with the leading sources, protocols, and expected bulk "
                      "transfers before treating the increase as suspicious."),
    "excessive_connection_attempts": ("Inspect SYN retransmissions and corresponding SYN-ACK or RST "
                                      "traffic in the capture to distinguish failed connections from scans."),
    "possible_port_scan": ("Confirm whether the source and destinations belong to an approved scanner, "
                           "inventory process, or administrator before escalating."),
    "unexpected_protocol_or_port": ("Check the reported protocol or service port against the environment, "
                                    "then update the allowlist only if that traffic is expected."),
}


def _ratio(event: dict[str, Any]) -> float:
    threshold = float(event.get("threshold") or 0)
    return float(event.get("observed") or 0) / threshold if threshold > 0 else 0.0


def _metric_label(metric: str) -> str:
    return {
        "packets_per_second": "packet rate",
        "bytes_per_second": "byte rate",
        "syn_attempts": "SYN attempts",
        "distinct_destination_ports": "distinct destination ports",
        "distinct_destination_hosts": "distinct destination hosts",
        "unexpected_packets": "unexpected packets",
    }.get(metric, metric.replace("_", " "))


def _display_utc(ts: Any) -> str:
    value = _utc(ts)
    return value.replace("T", " ").replace("Z", " UTC") if value else "an unknown time"


def _display_measurement(metric: str, value: Any) -> str:
    number = float(value or 0)
    if metric == "packets_per_second":
        return f"{number:,.1f} packets/s"
    if metric == "bytes_per_second":
        scaled = number
        for unit in ("B/s", "KiB/s", "MiB/s", "GiB/s"):
            if abs(scaled) < 1024 or unit == "GiB/s":
                return f"{scaled:,.0f} {unit}" if unit == "B/s" else f"{scaled:,.1f} {unit}"
            scaled /= 1024
    unit = {
        "syn_attempts": "SYN packets",
        "distinct_destination_ports": "destination ports",
        "distinct_destination_hosts": "destination hosts",
        "unexpected_packets": "unexpected packets",
    }.get(metric, metric.replace("_", " "))
    return f"{number:,.0f} {unit}"


def investigation_guidance(event: dict[str, Any]) -> str:
    """Return a conservative next step for a stored detection event."""
    return _NEXT_STEPS.get(
        str(event.get("rule")),
        "Correlate this observation with the capture context and expected network activity.",
    )


def generate_findings(
    run: dict[str, Any],
    windows: Sequence[dict[str, Any]],
    events: Sequence[dict[str, Any]],
    sources: Sequence[dict[str, Any]],
    protocols: dict[str, int],
    *,
    limit: int = 6,
) -> list[Finding]:
    """Rank a small set of deterministic findings from persisted measurements.

    Detection findings are grouped by rule and metric so cooldown-separated
    repeats do not flood the overview.  Descriptive findings are labelled as
    observations and never imply malicious intent.
    """
    findings: list[Finding] = []
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for event in events:
        grouped.setdefault((event["rule"], event["metric"]), []).append(event)
    severity_rank = {"HIGH": 3, "WARNING": 2, "INFO": 1}
    for (rule, metric), group in grouped.items():
        peak = max(group, key=lambda row: (_ratio(row), float(row["observed"]), -int(row["id"])))
        source = f" from {peak['src_ip']}" if peak.get("src_ip") else ""
        repeat = f" across {len(group)} stored events" if len(group) > 1 else ""
        findings.append(Finding(
            category="detection",
            title=_RULE_TITLES.get(rule, rule.replace("_", " ").capitalize()),
            summary=(f"At {_display_utc(peak.get('ts'))}, the detector observed "
                     f"{_display_measurement(metric, peak['observed'])} against a threshold of "
                     f"{_display_measurement(metric, peak['threshold'])}{source}{repeat}."),
            significance=100 + severity_rank.get(peak["severity"], 0) * 10 + _ratio(peak),
            severity=peak["severity"],
            event_id=int(peak["id"]),
            investigation=investigation_guidance(peak),
        ))

    if run.get("status") in {"partial", "failed", "running"}:
        findings.append(Finding(
            category="data quality",
            title="Results may be incomplete",
            summary=(f"The run status is {run['status']}; missing windows or unfinished processing can "
                     "change totals and rates."),
            significance=95,
            severity="WARNING",
            investigation="Review the run note and skipped/storage-error counters before interpreting results.",
        ))

    positive_rates = [float(row["packets_per_second"]) for row in windows
                      if float(row["packets_per_second"]) > 0]
    if len(positive_rates) >= 3:
        baseline = statistics.median(positive_rates)
        peak_row = max(windows, key=lambda row: float(row["packets_per_second"]))
        peak_rate = float(peak_row["packets_per_second"])
        ratio = peak_rate / baseline if baseline else 0.0
        if ratio >= 2:
            findings.append(Finding(
                category="observation",
                title="A traffic window stands above the typical rate",
                summary=(f"At {_display_utc(peak_row.get('window_start'))}, the peak was "
                         f"{peak_rate:.1f} packets/s, {ratio:.1f}× the median non-empty "
                         f"window rate of {baseline:.1f} packets/s."),
                significance=ratio,
                investigation="Review the peak window alongside its protocols and leading sources.",
            ))

    protocol_packets = sum(protocols.values())
    if protocol_packets:
        protocol, count = max(protocols.items(), key=lambda item: (item[1], item[0]))
        share = count / protocol_packets
        if share >= 0.5:
            findings.append(Finding(
                category="observation",
                title=f"{protocol} dominated captured traffic",
                summary=f"{protocol} accounted for {share:.1%} of packets represented in stored windows.",
                significance=share * 5,
                investigation="Confirm that this protocol mix is expected for the captured network and time period.",
            ))

    if sources and int(run.get("packets") or 0) > 0:
        source = max(sources, key=lambda row: int(row["packets"]))
        share = int(source["packets"]) / int(run["packets"])
        if share >= 0.25:
            findings.append(Finding(
                category="observation",
                title="One tracked source contributed a large traffic share",
                summary=(f"{source['src_ip']} accounts for at least {share:.1%} of processed packets "
                         "in the retained source summaries."),
                significance=share * 5,
                investigation="Check whether the source role and transfer volume are expected; the share is a lower bound when source tracking is truncated.",
            ))

    return sorted(findings, key=lambda item: (-item.significance, item.title))[:max(0, limit)]


def normalized_metrics(run: dict[str, Any], windows: Sequence[dict[str, Any]],
                       events: Sequence[dict[str, Any]]) -> dict[str, float]:
    """Metrics suitable for comparing runs with different durations."""
    coverage = sum(max(0.0, float(row["window_end"]) - float(row["window_start"])) for row in windows)
    packets = sum(int(row["packets"]) for row in windows)
    bytes_count = sum(int(row["bytes"]) for row in windows)
    return {
        "coverage_seconds": coverage,
        "average_packets_per_second": packets / coverage if coverage else 0.0,
        "average_bytes_per_second": bytes_count / coverage if coverage else 0.0,
        "peak_packets_per_second": max((float(row["packets_per_second"]) for row in windows), default=0.0),
        "peak_bytes_per_second": max((float(row["bytes_per_second"]) for row in windows), default=0.0),
        "events_per_minute": len(events) * 60 / coverage if coverage else 0.0,
        "skipped_packet_share": (int(run.get("skipped_packets") or 0) /
                                 max(1, int(run.get("packets") or 0) + int(run.get("skipped_packets") or 0))),
    }


def validate_capture_upload(filename: str, content: bytes,
                            *, max_bytes: int = MAX_UPLOAD_BYTES) -> str:
    """Validate an uploaded capture and return a safe display filename."""
    safe_name = Path(str(filename).replace("\\", "/")).name
    suffix = Path(safe_name).suffix.lower()
    if not safe_name or suffix not in SUPPORTED_CAPTURE_SUFFIXES:
        raise ValueError("Choose a .pcap or .pcapng capture file.")
    if not content:
        raise ValueError("The uploaded capture is empty.")
    if len(content) > max_bytes:
        raise ValueError(f"The capture exceeds the {max_bytes // (1024 * 1024)} MiB dashboard limit.")
    if len(content) < 12 or content[:4] not in _CAPTURE_MAGIC:
        raise ValueError("The file does not contain a recognized PCAP or PCAPNG header.")
    return safe_name


def process_capture_upload(filename: str, content: bytes, config: Config, storage: Storage,
                           *, force: bool = False,
                           max_bytes: int = MAX_UPLOAD_BYTES) -> RunSummary:
    """Safely replay uploaded bytes through the existing PCAP pipeline."""
    safe_name = validate_capture_upload(filename, content, max_bytes=max_bytes)
    suffix = Path(safe_name).suffix.lower()
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="lattice-upload-", suffix=suffix, delete=False) as handle:
            handle.write(content)
            temp_path = Path(handle.name)
        return process_pcap(temp_path, config, storage, force=force, source_label=safe_name)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def _utc(ts: Any) -> str | None:
    if ts is None:
        return None
    import datetime as dt
    return dt.datetime.fromtimestamp(float(ts), tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")


def export_payload(run: dict[str, Any], windows: Sequence[dict[str, Any]],
                   events: Sequence[dict[str, Any]], sources: Sequence[dict[str, Any]],
                   findings: Sequence[Finding]) -> dict[str, Any]:
    """Create a path-safe, timestamp-explicit export payload."""
    metadata = {key: value for key, value in run.items()
                if key not in {"source", "fingerprint", "started_at", "finished_at"}}
    metadata["source_name"] = Path(str(run.get("source", "")).replace("\\", "/")).name
    metadata["started_at_utc"] = _utc(run.get("started_at"))
    metadata["finished_at_utc"] = _utc(run.get("finished_at"))
    window_rows = []
    for row in windows:
        item = {key: value for key, value in row.items()
                if key not in {"id", "window_start", "window_end"}}
        item["window_start_utc"] = _utc(row["window_start"])
        item["window_end_utc"] = _utc(row["window_end"])
        window_rows.append(item)
    event_rows = []
    for row in events:
        item = {key: value for key, value in row.items()
                if key not in {"window_id", "ts", "window_start", "window_end"}}
        item["timestamp_utc"] = _utc(row["ts"])
        item["window_start_utc"] = _utc(row["window_start"])
        item["window_end_utc"] = _utc(row["window_end"])
        event_rows.append(item)
    return {
        "schema": "lattice-dashboard-export-v1",
        "units": {"packet_rate": "packets/second", "byte_rate": "bytes/second", "timestamps": "UTC"},
        "run": metadata,
        "findings": [asdict(finding) for finding in findings],
        "traffic_windows": window_rows,
        "events": event_rows,
        "source_summaries": list(sources),
    }


def export_json_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _csv_text(rows: Iterable[dict[str, Any]]) -> str:
    rows = list(rows)
    if not rows:
        return ""
    flattened = []
    for row in rows:
        flattened.append({key: json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value
                          for key, value in row.items()})
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=list(flattened[0]))
    writer.writeheader()
    writer.writerows(flattened)
    return output.getvalue()


def export_csv_zip_bytes(payload: dict[str, Any]) -> bytes:
    """Bundle related CSV tables so their run context stays together."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, rows in (
            ("run.csv", [payload["run"]]),
            ("findings.csv", payload["findings"]),
            ("traffic_windows.csv", payload["traffic_windows"]),
            ("events.csv", payload["events"]),
            ("source_summaries.csv", payload["source_summaries"]),
        ):
            archive.writestr(name, _csv_text(rows))
        archive.writestr("README.txt", "Rates are per second. Timestamps are UTC. Empty CSV files mean no stored rows.\n")
    return output.getvalue()
