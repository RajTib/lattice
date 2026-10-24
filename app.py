"""Lattice dashboard. Run with ``streamlit run app.py``."""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Optional

import altair as alt
import pandas as pd
import streamlit as st

from lattice import dashboard_analysis as analysis
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

st.set_page_config(page_title="Lattice", page_icon=":material/hub:", layout="wide",
                   initial_sidebar_state="expanded")


@st.cache_resource
def get_config(path: Optional[str]) -> Config:
    return load_config(path)


@st.cache_resource
def get_monitor(db_path: str, config_path: Optional[str]) -> LiveMonitor:
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
    """Use a short-lived read-only connection and surface safe errors."""
    if not Path(db_path).is_file():
        return None
    try:
        with Storage(db_path, read_only=True) as storage:
            return fn(storage)
    except StorageError as exc:
        st.error(f"Database error: {exc}", title="Results could not be read")
        return None


def fragment(live: bool):
    return st.fragment(run_every=REFRESH_SECONDS if live else None)


def source_name(source: str) -> str:
    return Path(str(source).replace("\\", "/")).name or "unknown source"


def load_run_data(db_path: str, run_id: int):
    def query(storage: Storage):
        return (storage.get_run(run_id), storage.query_windows(run_id),
                storage.query_events(run_id, limit=10000),
                storage.top_sources(run_id, by="packets", limit=1000),
                storage.protocol_totals(run_id))
    return read_db(db_path, query) or (None, [], [], [], {})


def traffic_chart(windows: list[dict[str, Any]], events: list[dict[str, Any]],
                  metric: str = "packets_per_second") -> alt.LayerChart:
    """Layer detection markers on the exact windows that produced them."""
    unit = "Packets / s" if metric == "packets_per_second" else "Bytes / s"
    rows = [{"time": dd.to_datetime(row["window_start"]), "value": row[metric]}
            for row in windows]
    rates = {row["window_start"]: row[metric] for row in windows}
    markers = [{"time": dd.to_datetime(event["window_start"]),
                "value": rates.get(event["window_start"], 0), "severity": event["severity"],
                "rule": event["rule"], "observed": event["observed"],
                "threshold": event["threshold"]} for event in events]
    line = alt.Chart(pd.DataFrame(rows)).mark_line(color="#f5f5f5", strokeWidth=2).encode(
        x=alt.X("time:T", title="Window start (UTC)"),
        y=alt.Y("value:Q", title=unit, scale=alt.Scale(zero=True)),
        tooltip=[alt.Tooltip("time:T", title="Window", format="%Y-%m-%d %H:%M:%S UTC"),
                 alt.Tooltip("value:Q", title=unit, format=",.1f")])
    if not markers:
        return line.interactive()
    points = alt.Chart(pd.DataFrame(markers)).mark_point(filled=True, size=90, stroke="#0a0a0a").encode(
        x="time:T", y="value:Q",
        color=alt.Color("severity:N", scale=alt.Scale(
            domain=["INFO", "WARNING", "HIGH"], range=["#a3a3a3", "#f59e0b", "#ef4444"]),
            legend=alt.Legend(title="Detected event")),
        tooltip=[alt.Tooltip("time:T", title="Event window", format="%Y-%m-%d %H:%M:%S UTC"),
                 alt.Tooltip("rule:N", title="Rule"), alt.Tooltip("severity:N", title="Severity"),
                 alt.Tooltip("observed:Q", title="Observed", format=",.1f"),
                 alt.Tooltip("threshold:Q", title="Threshold", format=",.1f")])
    return (line + points).interactive()


def select_finding_event(run_id: int, event_id: int) -> None:
    """Navigate from an overview finding to its representative stored event."""
    st.session_state["view"] = "Anomaly events"
    st.session_state[f"selected_event_{run_id}"] = event_id
    st.session_state[f"event_picker_{run_id}"] = event_id


def render_findings(findings: list[analysis.Finding], run_id: int) -> None:
    st.subheader("Key findings")
    st.caption("Ranked observations from stored measurements. Detection findings are rule matches, not proof of an attack.")
    if not findings:
        st.info("No material findings were identified from the stored measurements.")
        return
    for finding in findings:
        with st.container(border=True):
            label = "Detection" if finding.category == "detection" else finding.category.capitalize()
            st.markdown(f"**{finding.title}**  ·  `{label}`  ·  `{finding.severity}`")
            st.markdown(finding.summary)
            if finding.investigation:
                st.caption("Next check: " + finding.investigation)
            if finding.event_id is not None:
                st.button("Investigate event", key=f"finding_{run_id}_{finding.event_id}",
                          icon=":material/arrow_forward:", type="tertiary",
                          on_click=select_finding_event, args=(run_id, finding.event_id))


def render_overview(db_path: str, run_id: int, live: bool) -> None:
    @fragment(live)
    def body() -> None:
        run, windows, events, sources, protocols = load_run_data(db_path, run_id)
        if run is None:
            st.info("The selected run no longer exists.")
            return
        coverage = sum(max(0.0, row["window_end"] - row["window_start"]) for row in windows)
        average_pps = sum(row["packets"] for row in windows) / coverage if coverage else 0.0
        peak_pps = max((row["packets_per_second"] for row in windows), default=0.0)
        st.subheader(f"Run #{run_id}")
        st.caption(f"{source_name(run['source'])} · {run['mode'].upper()} · {run['status']} · "
                   f"processing started {dd.format_time(run['started_at'])}")
        metrics = st.columns(4)
        metrics[0].metric("Packets processed", f"{run['packets']:,}", border=True,
                          help="Packets successfully normalized and aggregated. Skipped packets are separate.")
        metrics[1].metric("Bytes processed", dd.human_bytes(run["bytes"]), border=True)
        metrics[2].metric("Stored-window coverage", dd.human_duration(coverage), border=True,
                          help="Sum of persisted fixed windows, not processing wall-clock time.")
        metrics[3].metric("Detected events", f"{run['events']:,}", border=True,
                          help="Stored rule matches after cooldown suppression; not confirmed attacks.")
        metrics = st.columns(4)
        metrics[0].metric("Average packet rate", f"{average_pps:,.1f} /s", border=True)
        metrics[1].metric("Peak packet rate", f"{peak_pps:,.1f} /s", border=True)
        metrics[2].metric("Skipped packets", f"{run['skipped_packets']:,}", border=True,
                          help="Malformed packets plus live packets dropped when the queue was full.")
        metrics[3].metric("Cooldown suppressions", f"{run['suppressed_events']:,}", border=True,
                          help="Repeated rule matches hidden during the configured cooldown.")
        if run["storage_errors"]:
            st.warning(f"{run['storage_errors']} traffic window(s) could not be stored.",
                       title="Stored results are incomplete")
        if run["note"]:
            st.caption("Run note: " + run["note"])
        if not windows:
            st.info("No traffic windows have been stored for this run.")
            return

        findings = analysis.generate_findings(run, windows, events, sources, protocols)
        chart_col, protocol_col = st.columns([3, 1])
        with chart_col.container(border=True):
            st.subheader("Traffic over time")
            st.caption("Packet rate per stored window; markers show windows that produced detection events.")
            st.altair_chart(traffic_chart(windows, events), height=330,
                            alt="Packet-rate timeline with markers at detected-event windows")
        with protocol_col.container(border=True):
            st.subheader("Protocol distribution")
            total = max(1, sum(protocols.values()))
            frame = pd.DataFrame([{"Protocol": name, "Packets": count, "Share": count / total}
                                  for name, count in protocols.items()])
            if frame.empty:
                st.info("No protocol counts are available.")
            else:
                st.dataframe(frame, hide_index=True, height=330, alt="Packet totals and shares by protocol",
                             column_config={"Packets": st.column_config.NumberColumn(format=",%d"),
                                            "Share": st.column_config.NumberColumn(format="percent")})

        findings_col, events_col = st.columns(2)
        with findings_col:
            render_findings(findings, run_id)
        with events_col:
            st.subheader("Significant events")
            if events:
                rank = {"HIGH": 3, "WARNING": 2, "INFO": 1}
                ranked = sorted(events, key=lambda event: (-rank.get(event["severity"], 0),
                    -(event["observed"] / event["threshold"] if event["threshold"] else 0), event["ts"]))[:8]
                st.dataframe(dd.events_frame(ranked)[["time", "severity", "rule", "source", "ratio"]],
                             hide_index=True, alt="Highest-severity detected events",
                             column_config={"time": st.column_config.DatetimeColumn("Time (UTC)", format="HH:mm:ss"),
                                            "ratio": st.column_config.NumberColumn("Observed / threshold", format="%.2f×")})
            else:
                st.info("No detection events were stored for this run.")
            if sources:
                st.markdown("**Leading tracked sources**")
                st.dataframe(dd.sources_frame(sources[:5]), hide_index=True,
                             alt="Leading retained sources by packet count", column_config={
                                 "src_ip": "Source", "packets": st.column_config.NumberColumn(format=",%d"),
                                 "bytes": st.column_config.NumberColumn(format=",%d"),
                                 "syn_attempts": "SYN attempts", "max_distinct_ports": "Max ports / window",
                                 "max_distinct_hosts": "Max hosts / window"})
    body()


def render_traffic(db_path: str, run_id: int, live: bool) -> None:
    @fragment(live)
    def body() -> None:
        _, windows, events, _, protocols = load_run_data(db_path, run_id)
        if not windows:
            st.info("No traffic statistics are stored for this run.")
            return
        st.subheader("Traffic analytics")
        st.caption("Rates use fixed windows. Empty windows are zero; a partially filled final window can read low.")
        rate_view = st.segmented_control("Rate", ["Packets / s", "Bytes / s"], default="Packets / s",
                                         required=True, key=f"rate_view_{run_id}")
        metric = "packets_per_second" if rate_view == "Packets / s" else "bytes_per_second"
        with st.container(border=True):
            st.altair_chart(traffic_chart(windows, events, metric), height=380,
                            alt=f"{rate_view} over time with event markers")
        left, right = st.columns(2)
        with left.container(border=True):
            st.subheader("Protocols")
            frame = pd.DataFrame([{"Protocol": name, "Packets": count} for name, count in protocols.items()])
            if frame.empty:
                st.info("No protocol counts are available.")
            else:
                st.bar_chart(frame, x="Protocol", y="Packets", alt="Packets by protocol")
        with right.container(border=True):
            st.subheader("Tracked sources")
            rank_by = st.segmented_control("Rank by", ["packets", "bytes", "syn_attempts"],
                                           default="packets", required=True, key=f"rank_{run_id}")
            sources = read_db(db_path, lambda storage: storage.top_sources(run_id, by=rank_by, limit=50)) or []
            if sources:
                st.dataframe(dd.sources_frame(sources), hide_index=True,
                             alt="Retained source summaries ranked by the selected measurement",
                             column_config={"src_ip": "Source IP",
                                            "packets": st.column_config.NumberColumn(format=",%d"),
                                            "bytes": st.column_config.NumberColumn(format=",%d"),
                                            "syn_attempts": "SYN attempts",
                                            "max_distinct_ports": "Max ports / window",
                                            "max_distinct_hosts": "Max hosts / window"})
                st.caption("Source rows are retained top-talkers, not a complete flow table. Destination "
                           "diversity is the maximum observed in any stored window.")
            else:
                st.info("No source-level rows are available, such as for traffic without IP headers.")
        with st.expander("Window-level measurements"):
            st.dataframe(dd.windows_frame(windows).reset_index(), hide_index=True,
                         alt="All stored traffic-window measurements",
                         column_config={"time": st.column_config.DatetimeColumn("Start (UTC)"),
                                        "packets_per_second": st.column_config.NumberColumn("Packets / s", format=",.1f"),
                                        "bytes_per_second": st.column_config.NumberColumn("Bytes / s", format=",.1f")})
    body()


def render_event_detail(db_path: str, run_id: int, event: dict[str, Any]) -> None:
    left, middle, right = st.columns(3)
    left.metric("Observed", f"{event['observed']:g}", help=event["metric"], border=True)
    middle.metric("Configured threshold", f"{event['threshold']:g}", border=True)
    ratio = event["observed"] / event["threshold"] if event["threshold"] else float("nan")
    right.metric("Observed / threshold", f"{ratio:.2f}×", border=True)
    st.markdown(event["explanation"])
    details = [f"Severity **{event['severity']}**", f"Rule `{event['rule']}`",
               f"Window {dd.format_time(event['window_start'])} to {dd.format_time(event['window_end'])}"]
    if event["src_ip"]:
        details.insert(2, f"Source `{event['src_ip']}`")
    st.caption(" · ".join(details))
    if event["dst_info"]:
        st.caption("Destination evidence: " + event["dst_info"])
    st.info(analysis.investigation_guidance(event), title="Suggested investigation")
    span = event["window_end"] - event["window_start"]
    rows = read_db(db_path, lambda storage: storage.query_windows(
        run_id, event["window_start"] - span, event["window_end"] + span)) or []
    if rows:
        st.markdown("**Traffic around this event**")
        st.caption("The triggering window and immediately adjacent stored windows, when available.")
        st.dataframe(dd.event_context_frame(rows, event["window_start"]), hide_index=True,
                     alt="Traffic measurements before, during, and after the selected event",
                     column_config={"window": st.column_config.DatetimeColumn("Window start (UTC)", format="HH:mm:ss"),
                                    "relation": "Position",
                                    "packets_per_second": st.column_config.NumberColumn("Packets / s", format=",.1f"),
                                    "bytes_per_second": st.column_config.NumberColumn("Bytes / s", format=",.1f"),
                                    "unexpected_packets": "Unexpected packets"})


def render_events(db_path: str, run_id: int, live: bool) -> None:
    @fragment(live)
    def body() -> None:
        st.subheader("Anomaly events")
        st.caption("Events are explainable rule matches, not confirmation that an attack occurred.")
        bounds = read_db(db_path, lambda storage: storage.time_bounds(run_id))
        search = st.text_input("Search events", type="search", placeholder="Rule, source, metric, or evidence",
                               key=f"event_search_{run_id}")
        f1, f2 = st.columns(2)
        rules = f1.multiselect("Detection rule", list(ALL_RULES), default=list(ALL_RULES), key=f"rules_{run_id}")
        severities = f2.multiselect("Severity", [severity.value for severity in Severity],
                                    default=[severity.value for severity in Severity], key=f"sev_{run_id}")
        start = end = None
        if bounds is not None and bounds[1] > bounds[0]:
            lo, hi = dd.to_datetime(bounds[0]), dd.to_datetime(bounds[1])
            chosen = st.slider("Event time range (UTC)", min_value=lo, max_value=hi, value=(lo, hi),
                               key=f"range_{run_id}_{bounds[0]}_{int(bounds[1] // 60)}", format="HH:mm:ss")
            start, end = chosen[0].timestamp(), chosen[1].timestamp()
        events = read_db(db_path, lambda storage: storage.query_events(
            run_id, start, end, rules, severities, limit=2000)) or []
        if search.strip():
            needle = search.casefold().strip()
            fields = ("rule", "severity", "metric", "src_ip", "dst_info", "explanation")
            events = [event for event in events if needle in " ".join(
                str(event.get(field) or "") for field in fields).casefold()]
        if not events:
            st.info("No events match the current filters." if bounds else "No events have been stored for this run.")
            return
        frame = dd.events_frame(events)
        st.caption(f"{len(events):,} matching stored event(s); queries are limited to 2,000 rows.")
        st.dataframe(frame[["time", "severity", "rule", "source", "metric", "observed", "threshold", "ratio"]],
                     hide_index=True, alt="Detected events matching the current filters",
                     column_config={"time": st.column_config.DatetimeColumn("Window end (UTC)", format="HH:mm:ss"),
                                    "observed": st.column_config.NumberColumn(format=",.1f"),
                                    "threshold": st.column_config.NumberColumn(format=",.1f"),
                                    "ratio": st.column_config.NumberColumn("Observed / threshold", format="%.2f×")})
        st.subheader("Event investigation")
        by_id = {event["id"]: event for event in events}
        ids = list(by_id)
        preferred = st.session_state.get(f"selected_event_{run_id}")
        selected_id = st.selectbox("Selected event", ids, index=ids.index(preferred) if preferred in ids else 0,
            key=f"event_picker_{run_id}", format_func=lambda event_id: (
                f"{dd.format_time(by_id[event_id]['ts'])} · {by_id[event_id]['severity']} · "
                f"{by_id[event_id]['rule']} · {by_id[event_id]['src_ip'] or 'all sources'}"))
        st.session_state[f"selected_event_{run_id}"] = selected_id
        render_event_detail(db_path, run_id, by_id[selected_id])
    body()


def replay_notice(summary) -> None:
    st.session_state["selected_run"] = summary.run_id
    st.session_state["next_view"] = "Overview"
    if summary.duplicate:
        st.session_state["replay_notice"] = (
            "info", f"This capture already exists as run #{summary.run_id}; showing its stored results.")
    else:
        st.session_state["replay_notice"] = (
            "success", f"Run #{summary.run_id} completed: {summary.packets:,} packets, "
            f"{summary.windows} windows, {summary.events} events, {summary.skipped_packets} skipped "
            f"in {summary.elapsed_seconds:.2f}s.")
    if summary.note:
        st.session_state["replay_warning"] = summary.note


def render_capture_input(db_path: str, config: Config) -> None:
    st.subheader("Analyze a capture")
    st.caption("Upload a PCAP or PCAPNG file. Lattice reads packet headers and does not retain payload bytes.")
    uploaded = st.file_uploader("Capture file", type=["pcap", "pcapng"], max_upload_size=100,
                                help="Maximum 100 MiB. The file header is validated before processing.")
    force_upload = st.checkbox("Reprocess an identical capture", key="force_upload")
    if st.button("Analyze uploaded capture", type="primary", disabled=uploaded is None,
                 icon=":material/upload_file:", width="stretch"):
        try:
            with st.spinner("Validating and analyzing the uploaded capture…"):
                with Storage(db_path) as storage:
                    summary = analysis.process_capture_upload(
                        uploaded.name, uploaded.getvalue(), config, storage, force=force_upload)
        except (ValueError, CaptureError, StorageError, OSError) as exc:
            st.error(str(exc), title="Capture could not be analyzed")
        else:
            replay_notice(summary)
            st.rerun()
    with st.expander("Repository samples and local paths"):
        st.caption("Samples are repeatable demonstrations. Local paths are available only to the Streamlit host.")
        samples = sorted(path.name for path in SAMPLES_DIR.glob("*.pcap*")) if SAMPLES_DIR.is_dir() else []
        sample = st.selectbox("Repository sample", ["(none)"] + samples)
        typed = st.text_input("Local capture path", placeholder=r"C:\captures\example.pcap")
        force = st.checkbox("Reprocess even if already analyzed", key="force_path")
        path = typed.strip() or (str(SAMPLES_DIR / sample) if sample != "(none)" else "")
        if st.button("Process PCAP", disabled=not path, icon=":material/play_arrow:"):
            try:
                with st.spinner(f"Analyzing {source_name(path)}…"):
                    with Storage(db_path) as storage:
                        summary = process_pcap(path, config, storage, force=force)
            except (CaptureError, StorageError) as exc:
                st.error(str(exc), title="Capture could not be analyzed")
            else:
                replay_notice(summary)
                st.rerun()


def render_live_controls(db_path: str, config: Config, config_path: Optional[str]) -> None:
    st.subheader("Live capture")
    status = live_capture_status()
    (st.info if status.available else st.warning)(status.message)
    monitor = get_monitor(db_path, config_path)
    state = monitor.state()
    if state.running:
        st.success(f"Capturing on {state.interface or 'the default interface'} as run #{state.run_id}.")
        if st.button("Stop live capture", icon=":material/stop:"):
            with st.spinner("Stopping capture and storing the final window…"):
                monitor.stop()
            st.rerun()
        return
    if state.error:
        st.error(state.error, title="Previous live session failed")
    interfaces = list_interfaces()
    labels = {f"{item.name}{' — ' + item.description if item.description else ''}": item.name
              for item in interfaces}
    choice = st.selectbox("Network interface", list(labels) or ["No interfaces detected"])
    bpf = st.text_input("Capture filter (optional)", value=config.capture.bpf_filter or "",
                        placeholder="tcp or udp or icmp", help="Berkeley Packet Filter syntax.")
    authorized = st.checkbox("I am authorized to monitor this interface and network.")
    if st.button("Start live capture", disabled=not (authorized and labels and status.available),
                 type="primary", icon=":material/fiber_manual_record:"):
        try:
            with st.spinner("Starting live capture…"):
                run_id = monitor.start(labels[choice], bpf or None)
            st.session_state["selected_run"] = run_id
            st.rerun()
        except (CaptureError, StorageError) as exc:
            st.error(str(exc), title="Live capture could not start")
    st.caption("Live capture may require Npcap and elevated permissions on Windows. Lattice observes traffic; "
               "it does not block or modify packets.")


def render_exports(db_path: str, run_id: int) -> None:
    run, windows, events, sources, protocols = load_run_data(db_path, run_id)
    if run is None:
        return
    findings = analysis.generate_findings(run, windows, events, sources, protocols)
    payload = analysis.export_payload(run, windows, events, sources, findings)
    st.subheader("Export results")
    st.caption("Exports use UTC timestamps, per-second rates, and source filenames without local directory paths.")
    left, right = st.columns(2)
    left.download_button("Download JSON", analysis.export_json_bytes(payload),
                         file_name=f"lattice-run-{run_id}.json", mime="application/json",
                         icon=":material/data_object:", width="stretch")
    right.download_button("Download CSV bundle", analysis.export_csv_zip_bytes(payload),
                          file_name=f"lattice-run-{run_id}-csv.zip", mime="application/zip",
                          icon=":material/archive:", width="stretch")


def render_comparison(db_path: str, run_id: int, runs: list[dict[str, Any]]) -> None:
    candidates = [run for run in runs if run["id"] != run_id]
    st.subheader("Compare runs")
    st.caption("Rates and event frequency are normalized by stored-window coverage; raw totals are not treated "
               "as directly comparable when capture durations differ.")
    if not candidates:
        st.info("Analyze another capture to compare normalized traffic and event measurements.")
        return
    by_id = {run["id"]: run for run in candidates}
    other_id = st.selectbox("Comparison run", list(by_id), format_func=lambda value: dd.run_label(by_id[value]),
                            key=f"compare_{run_id}")
    current_run, current_windows, current_events, _, current_protocols = load_run_data(db_path, run_id)
    other_run, other_windows, other_events, _, other_protocols = load_run_data(db_path, other_id)
    if current_run is None or other_run is None:
        st.warning("One of the selected runs is no longer available.")
        return
    current = analysis.normalized_metrics(current_run, current_windows, current_events)
    other = analysis.normalized_metrics(other_run, other_windows, other_events)
    labels = {"coverage_seconds": "Stored-window coverage (s)",
              "average_packets_per_second": "Average packets / s",
              "average_bytes_per_second": "Average bytes / s",
              "peak_packets_per_second": "Peak packets / s", "peak_bytes_per_second": "Peak bytes / s",
              "events_per_minute": "Stored events / minute", "skipped_packet_share": "Skipped share"}
    frame = pd.DataFrame([{"Measurement": label, f"Run #{run_id}": current[key],
                           f"Run #{other_id}": other[key]} for key, label in labels.items()])
    st.dataframe(frame, hide_index=True, alt="Normalized measurements for the two selected runs",
                 column_config={f"Run #{run_id}": st.column_config.NumberColumn(format=",.2f"),
                                f"Run #{other_id}": st.column_config.NumberColumn(format=",.2f")})
    names = sorted(set(current_protocols) | set(other_protocols))
    current_total, other_total = sum(current_protocols.values()), sum(other_protocols.values())
    protocols = pd.DataFrame([{"Protocol": name,
        f"Run #{run_id}": current_protocols.get(name, 0) / max(1, current_total),
        f"Run #{other_id}": other_protocols.get(name, 0) / max(1, other_total)} for name in names])
    if not protocols.empty:
        st.markdown("**Protocol share**")
        st.dataframe(protocols, hide_index=True, alt="Protocol packet shares for the selected runs",
                     column_config={f"Run #{run_id}": st.column_config.NumberColumn(format="percent"),
                                    f"Run #{other_id}": st.column_config.NumberColumn(format="percent")})
    if current_run["status"] not in {"completed", "stopped"} or other_run["status"] not in {"completed", "stopped"}:
        st.warning("At least one run is incomplete. Treat differences as provisional.")


def render_history(db_path: str, run_id: Optional[int], runs: list[dict[str, Any]],
                   config: Config, config_path: Optional[str]) -> None:
    st.subheader("Captures and history")
    st.caption("Analyze files, compare persisted runs, export evidence, or start an authorized live session.")
    section = st.segmented_control(
        "Capture tools", ["Analyze capture", "Compare and export", "Live capture", "Configuration"],
        default="Analyze capture", required=True, key="history_section", width="stretch")
    if section == "Analyze capture":
        render_capture_input(db_path, config)
    elif section == "Compare and export":
        if run_id is None:
            st.info("Select or create a run before comparing or exporting results.")
        else:
            render_comparison(db_path, run_id, runs)
            st.divider()
            render_exports(db_path, run_id)
    elif section == "Live capture":
        render_live_controls(db_path, config, config_path)
    else:
        st.subheader("Active configuration")
        st.caption("Rules fire only when a measurement is strictly above its threshold. Defaults are examples, "
                   "not a universal security policy. Review event evidence before tuning config.json, then restart Streamlit.")
        st.json(config.to_dict())


def render_status(run: dict[str, Any] | None, db_path: str) -> bool:
    kind, message = dd.data_mode(run, seconds_since_write(db_path))
    renderer = {"live": st.success, "active": st.info, "historical": st.info,
                "interrupted": st.warning, "partial": st.warning, "failed": st.error, "none": st.info}[kind]
    renderer(message)
    notice = st.session_state.pop("replay_notice", None)
    if notice:
        getattr(st, notice[0])(notice[1])
    warning = st.session_state.pop("replay_warning", None)
    if warning:
        st.warning(warning)
    return kind == "live"


def main() -> None:
    st.session_state.setdefault("selected_run", None)
    next_view = st.session_state.pop("next_view", None)
    if next_view is not None:
        st.session_state["view"] = next_view
    config_path = os.environ.get("LATTICE_CONFIG") or None
    try:
        config = get_config(config_path)
    except ConfigError as exc:
        st.error(f"Configuration error: {exc}", title="Configuration could not be loaded")
        st.stop()
        return
    st.title("Lattice")
    st.caption("Evidence-based network traffic analysis from packet headers and configurable detection rules")
    with st.sidebar:
        st.markdown("### :material/hub: Lattice")
        st.caption("Network traffic analysis")
        db_path = st.text_input("Results database", value=os.environ.get("LATTICE_DB") or config.database_path,
                                help="SQLite database used for processing results.")
        runs = read_db(db_path, lambda storage: storage.list_runs()) or []
        run_id: Optional[int] = None
        if runs:
            ids = [run["id"] for run in runs]
            preferred = st.session_state.get("selected_run")
            index = ids.index(preferred) if preferred in ids else 0
            by_id = {run["id"]: run for run in runs}
            run_id = st.selectbox("Current run", ids, index=index,
                                  format_func=lambda value: dd.run_label(by_id[value]), key="run_picker")
            st.session_state["selected_run"] = run_id
            selected = by_id[run_id]
            st.caption(f"{selected['packets']:,} processed packets · {selected['events']:,} stored events")
        else:
            st.caption("No stored runs yet.")
        if st.button("Reload results", icon=":material/refresh:", width="stretch"):
            st.rerun()
        st.divider()
        view = st.radio("Navigation", ["Overview", "Traffic analytics", "Anomaly events", "Captures and history"],
                        key="view", label_visibility="collapsed")
    run = next((candidate for candidate in runs if candidate["id"] == run_id), None)
    live = render_status(run, db_path)
    if view == "Overview":
        if run_id is None:
            st.info("Nothing to show yet. Open Captures and history to upload a PCAP or use a repository sample.")
        else:
            render_overview(db_path, run_id, live)
    elif view == "Traffic analytics":
        if run_id is None:
            st.info("Traffic analytics will appear after a capture has been processed.")
        else:
            render_traffic(db_path, run_id, live)
    elif view == "Anomaly events":
        if run_id is None:
            st.info("Detection events will appear after a capture has been processed.")
        else:
            render_events(db_path, run_id, live)
    else:
        render_history(db_path, run_id, runs, config, config_path)


main()
