"""Lattice dashboard.  Run with:  streamlit run app.py

The dashboard only *reads* the SQLite database for display. PCAP processing and
live capture are started from the Controls tab and write to the same database.
Set LATTICE_CONFIG / LATTICE_DB to override the config file or database path.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Optional

import streamlit as st

from lattice import dashboard_data as dd
from lattice.capture import CaptureError, list_interfaces, live_capture_status
from lattice.config import Config, ConfigError, load_config
from lattice.detector import ALL_RULES
from lattice.live import LiveMonitor
from lattice.models import Severity
from lattice.pipeline import process_pcap
from lattice.storage import Storage, StorageError

REFRESH_SECONDS = 3
SAMPLES_DIR = Path(__file__).resolve().parent / "samples"

st.set_page_config(page_title="Lattice", page_icon="🕸️", layout="wide")


# ----------------------------------------------------------------- helpers ---

@st.cache_resource
def get_config(path: Optional[str]) -> Config:
    return load_config(path)


@st.cache_resource
def get_monitor(db_path: str, config_path: Optional[str]) -> LiveMonitor:
    """One live monitor per (database, config), shared across Streamlit reruns."""
    return LiveMonitor(get_config(config_path), db_path=db_path)


def seconds_since_write(db_path: str) -> Optional[float]:
    newest = None
    for suffix in ("", "-wal"):
        try:
            mtime = os.stat(db_path + suffix).st_mtime
        except OSError:
            continue
        newest = mtime if newest is None else max(newest, mtime)
    return None if newest is None else max(0.0, time.time() - newest)


def read_db(db_path: str, fn):
    """Run ``fn(storage)`` on a short-lived read-only connection; None if there is no database."""
    if not Path(db_path).is_file():
        return None
    try:
        with Storage(db_path, read_only=True) as storage:
            return fn(storage)
    except StorageError as exc:
        st.error(f"Database error: {exc}")
        return None


def load_run(db_path: str, run_id: int) -> Optional[dict[str, Any]]:
    return read_db(db_path, lambda s: s.get_run(run_id))


def fragment(live: bool):
    """Auto-refresh only while a run is live; historical views stay static."""
    return st.fragment(run_every=REFRESH_SECONDS if live else None)


# ------------------------------------------------------------------ tabs ---

def render_overview(db_path: str, run_id: int, live: bool) -> None:
    @fragment(live)
    def body() -> None:
        run = load_run(db_path, run_id)
        if run is None:
            st.info("The selected run no longer exists.")
            return
        windows = read_db(db_path, lambda s: s.query_windows(run_id)) or []
        cols = st.columns(4)
        cols[0].metric("Mode", run["mode"].upper())
        cols[1].metric("Status", run["status"])
        cols[2].metric("Packets processed", f"{run['packets']:,}")
        cols[3].metric("Bytes processed", dd.human_bytes(run["bytes"]))
        cols = st.columns(4)
        cols[0].metric("Windows", f"{run['windows']:,}")
        cols[1].metric("Detected events", f"{run['events']:,}")
        cols[2].metric("Skipped / unparseable packets", f"{run['skipped_packets']:,}",
                       help="Malformed packets that could not be parsed, plus packets dropped "
                            "because the live-capture queue was full.")
        cols[3].metric("Suppressed by cooldown", f"{run['suppressed_events']:,}",
                       help="Repeat alerts hidden by the cooldown policy (detection.cooldown_seconds).")
        if run["storage_errors"]:
            st.warning(f"{run['storage_errors']} window(s) could not be written to the database. "
                       "Statistics for those windows are missing.")
        if run["note"]:
            st.caption(f"Note: {run['note']}")

        st.subheader("Most recent window")
        if not windows:
            st.info("No windows have been stored for this run yet.")
            return
        last = windows[-1]
        left, mid, right = st.columns(3)
        left.metric("Window", f"{dd.format_time(last['window_start'])[11:]} → "
                              f"{dd.format_time(last['window_end'])[11:]}")
        mid.metric("Packets / s", f"{last['packets_per_second']:.1f}")
        right.metric("Bytes / s", dd.human_bytes(last["bytes_per_second"]) + "/s")
        top = sorted(last["protocol_counts"].items(), key=lambda kv: -kv[1])[:5]
        st.caption("Protocols in this window: " + (", ".join(f"{p} ×{n}" for p, n in top) or "none"))
        started = dd.format_time(run["started_at"])
        st.caption(f"Run started {started} (processing time) · source: {run['source']}")

    body()


def render_traffic(db_path: str, run_id: int, live: bool) -> None:
    @fragment(live)
    def body() -> None:
        windows = read_db(db_path, lambda s: s.query_windows(run_id)) or []
        if not windows:
            st.info("No traffic statistics stored for this run yet.")
            return
        frame = dd.windows_frame(windows)
        st.caption("Rates are per fixed time window. Windows with no packets appear as zero. "
                   "The final window of a capture may be only partly filled, so its rate reads low.")
        a, b = st.columns(2)
        with a:
            st.subheader("Packets per second")
            st.line_chart(frame[["packets_per_second"]], height=260)
        with b:
            st.subheader("Bytes per second")
            st.line_chart(frame[["bytes_per_second"]], height=260)

        c, d = st.columns(2)
        with c:
            st.subheader("Protocol distribution")
            protocols = read_db(db_path, lambda s: s.protocol_totals(run_id)) or {}
            st.bar_chart(dd.protocol_series(protocols), height=280)
        with d:
            st.subheader("Top source IPs")
            by = st.radio("Rank by", ["packets", "bytes"], horizontal=True, key=f"rank_{run_id}")
            sources = read_db(db_path, lambda s: s.top_sources(run_id, by=by, limit=10)) or []
            if sources:
                table = dd.sources_frame(sources)
                st.bar_chart(table.set_index("src_ip")[[by]], height=240)
                st.caption("Sums the per-window top talkers stored for this run.")
            else:
                st.info("No per-source data (traffic without IP headers).")

    body()


def render_events(db_path: str, run_id: int, live: bool) -> None:
    @fragment(live)
    def body() -> None:
        bounds = read_db(db_path, lambda s: s.time_bounds(run_id))
        st.caption("Events are indicators of potentially unusual behaviour, not proof of an attack. "
                   "Thresholds come from config.json.")
        f1, f2 = st.columns(2)
        rules = f1.multiselect("Rule", list(ALL_RULES), default=list(ALL_RULES), key=f"rules_{run_id}")
        severities = f2.multiselect("Severity", [s.value for s in Severity],
                                    default=[s.value for s in Severity], key=f"sev_{run_id}")
        start = end = None
        if bounds is not None and bounds[1] > bounds[0]:
            lo, hi = dd.to_datetime(bounds[0]), dd.to_datetime(bounds[1])
            chosen = st.slider("Time range (UTC)", min_value=lo, max_value=hi, value=(lo, hi),
                               key=f"range_{run_id}_{bounds[0]}_{int(bounds[1] // 60)}",
                               format="HH:mm:ss")
            start, end = chosen[0].timestamp(), chosen[1].timestamp()

        events = read_db(db_path, lambda s: s.query_events(run_id, start, end, rules, severities, limit=2000))
        if not events:
            st.info("No events match the current filters." if bounds is not None
                    else "No events: nothing has been stored for this run yet.")
            return
        frame = dd.events_frame(events)
        st.write(f"**{len(frame)}** event(s)")
        st.dataframe(
            frame, hide_index=True, use_container_width=True,
            column_config={
                "time": st.column_config.DatetimeColumn("Window end (UTC)", format="HH:mm:ss"),
                "observed": st.column_config.NumberColumn("Observed", format="%.1f"),
                "threshold": st.column_config.NumberColumn("Threshold", format="%.1f"),
                "ratio": st.column_config.NumberColumn("Observed ÷ threshold", format="%.1f×"),
                "targets": "Destinations (sample)",
                "explanation": st.column_config.TextColumn("Explanation", width="large"),
            })
        if len(frame) >= 2:
            st.subheader("Observed vs configured threshold")
            chart = frame.head(40).reset_index(drop=True)
            chart.index = [f"{n + 1}. {r.rule.split('_')[0]} {r.source}" for n, r in enumerate(chart.itertuples())]
            st.bar_chart(chart[["observed", "threshold"]], height=260)
            st.caption("Showing the first 40 matching events; the table above lists them all.")

    body()


def render_controls(db_path: str, config: Config, config_path: Optional[str]) -> None:
    st.subheader("Replay a PCAP file")
    st.caption("Offline analysis is deterministic: windows come from packet timestamps, and a file already "
               "processed with the same settings is not processed again.")
    samples = sorted(p.name for p in SAMPLES_DIR.glob("*.pcap*")) if SAMPLES_DIR.is_dir() else []
    pick = st.selectbox("Sample files (samples/)", ["(none)"] + samples)
    typed = st.text_input("…or a path to a .pcap / .pcapng file", placeholder=r"C:\captures\example.pcap")
    force = st.checkbox("Reprocess even if already processed (replaces the earlier run)")
    path = typed.strip() or (str(SAMPLES_DIR / pick) if pick != "(none)" else "")
    if st.button("Process PCAP", type="primary", disabled=not path):
        with st.spinner(f"Processing {Path(path).name}…"):
            try:
                with Storage(db_path) as storage:
                    summary = process_pcap(path, config, storage, force=force)
            except (CaptureError, StorageError) as exc:
                st.error(str(exc))
            else:
                st.session_state["selected_run"] = summary.run_id
                if summary.duplicate:
                    st.info(f"Already processed as run #{summary.run_id}; showing the stored results.")
                else:
                    st.success(f"Run #{summary.run_id}: {summary.packets:,} packets, {summary.windows} windows, "
                               f"{summary.events} events, {summary.skipped_packets} skipped, in "
                               f"{summary.elapsed_seconds:.2f}s.")
                if summary.note:
                    st.warning(summary.note)

    st.divider()
    st.subheader("Live capture")
    status = live_capture_status()
    (st.info if status.available else st.warning)(status.message)
    monitor = get_monitor(db_path, config_path)
    state = monitor.state()
    if state.running:
        st.success(f"Capturing on {state.interface or 'default interface'} (run #{state.run_id}).")
        if st.button("Stop monitoring"):
            with st.spinner("Stopping capture and flushing the last window…"):
                monitor.stop()
            st.rerun()
    else:
        if state.error:
            st.error(f"Last session failed: {state.error}")
        interfaces = list_interfaces()
        labels = {f"{i.name}  {('— ' + i.description) if i.description else ''}".strip(): i.name
                  for i in interfaces}
        choice = st.selectbox("Interface", list(labels) or ["(none detected)"])
        bpf = st.text_input("Capture filter (BPF, optional)", value=config.capture.bpf_filter or "",
                            placeholder="tcp or udp or icmp")
        authorized = st.checkbox("I am authorized to monitor traffic on this interface and network.")
        can_start = authorized and bool(labels) and status.available
        if st.button("Start monitoring", disabled=not can_start, type="primary"):
            try:
                with st.spinner("Starting capture…"):
                    run_id = monitor.start(labels[choice], bpf or None)
                st.session_state["selected_run"] = run_id
                st.rerun()
            except (CaptureError, StorageError) as exc:
                st.error(str(exc))
        st.caption("Lattice only observes traffic; it never blocks or modifies it.")

    st.divider()
    with st.expander("Configuration (read-only; edit config.json and reload)"):
        st.caption(f"Database: `{db_path}`  ·  Config: `{config_path or 'config.json'}`")
        st.json(config.to_dict())


# ------------------------------------------------------------------ main ---

def main() -> None:
    config_path = os.environ.get("LATTICE_CONFIG") or None
    try:
        config = get_config(config_path)
    except ConfigError as exc:
        st.error(f"Configuration error: {exc}")
        st.stop()
        return

    st.title("Lattice")
    st.caption("Passive network traffic analysis and anomaly detection · educational prototype")

    with st.sidebar:
        st.header("Data")
        db_path = st.text_input("SQLite database", value=os.environ.get("LATTICE_DB") or config.database_path)
        runs = read_db(db_path, lambda s: s.list_runs()) or []
        run_id: Optional[int] = None
        if runs:
            ids = [r["id"] for r in runs]
            preferred = st.session_state.get("selected_run")
            index = ids.index(preferred) if preferred in ids else 0
            by_id = {r["id"]: r for r in runs}
            run_id = st.selectbox("Run", ids, index=index, format_func=lambda i: dd.run_label(by_id[i]),
                                  key="run_picker")
            st.session_state["selected_run"] = run_id
        else:
            st.caption("No runs yet.")
        if st.button("Reload data"):
            st.rerun()

    run = next((r for r in runs if r["id"] == run_id), None)
    kind, message = dd.data_mode(run, seconds_since_write(db_path))
    live = kind == "live"
    {"live": st.success, "historical": st.info, "interrupted": st.warning, "none": st.info}[kind](message)

    overview, traffic, events, controls = st.tabs(["Overview", "Traffic analytics", "Anomaly events",
                                                   "Input & controls"])
    with overview:
        if run_id is None:
            st.info("Nothing to show yet. Open **Input & controls** to replay a PCAP file "
                    "(try the files in `samples/`, created by `python -m scripts.traffic_gen`).")
        else:
            render_overview(db_path, run_id, live)
    with traffic:
        if run_id is None:
            st.info("No data yet.")
        else:
            render_traffic(db_path, run_id, live)
    with events:
        if run_id is None:
            st.info("No data yet.")
        else:
            render_events(db_path, run_id, live)
    with controls:
        render_controls(db_path, config, config_path)


main()
