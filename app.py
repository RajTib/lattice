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
EVENT_UI_LIMIT = 2000
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


def load_export_data(db_path: str, run_id: int):
    """Load complete persisted results for an explicit user export."""
    def query(storage: Storage):
        return (storage.get_run(run_id), storage.query_windows(run_id),
                storage.query_events(run_id, limit=None),
                storage.top_sources(run_id, by="packets", limit=1000),
                storage.protocol_totals(run_id))
    return read_db(db_path, query) or (None, [], [], [], {})


def traffic_chart(windows: list[dict[str, Any]], events: list[dict[str, Any]],
                  metric: str = "packets_per_second") -> alt.LayerChart:
    """Layer detection markers on the exact windows that produced them."""
    unit = "Packets / s" if metric == "packets_per_second" else "Bytes / s"
    rows = [{"time": dd.to_datetime(row["window_start"]), "utc": dd.format_time(row["window_start"]),
             "value": row[metric]}
            for row in windows]
    markers = dd.event_markers(windows, events, metric)
    source = alt.Chart(pd.DataFrame(rows))
    x_axis = alt.X("time:T", title="Window start (UTC)",
                   scale=alt.Scale(type="utc"), axis=alt.Axis(format="%H:%M:%S", labelAngle=0))
    y_axis = alt.Y("value:Q", title=unit, scale=alt.Scale(zero=True), axis=alt.Axis(format="~s"))
    area = source.mark_area(color="#d4d4d4", opacity=0.09).encode(x=x_axis, y=y_axis)
    line = source.mark_line(color="#f5f5f5", strokeWidth=2).encode(
        x=x_axis, y=y_axis,
        tooltip=[alt.Tooltip("utc:N", title="Window"),
                 alt.Tooltip("value:Q", title=unit, format=",.1f")])
    base = area + line
    if markers.empty:
        return base.interactive(bind_y=False)
    marker_source = alt.Chart(markers)
    severity_color = alt.Color("severity:N", scale=alt.Scale(
        domain=["INFO", "WARNING", "HIGH"], range=["#a3a3a3", "#f59e0b", "#ef4444"]),
        legend=alt.Legend(title=None, orient="top", direction="horizontal"))
    event_rules = marker_source.mark_rule(strokeDash=[4, 4], opacity=0.7).encode(
        x="time:T", y=alt.Y("value:Q"), y2=alt.Y2(datum=0),
        color=severity_color)
    points = marker_source.mark_point(filled=True, size=95, stroke="#090909", strokeWidth=1.5).encode(
        x="time:T", y="value:Q",
        color=severity_color,
        size=alt.Size("events:Q", scale=alt.Scale(range=[80, 180]), legend=None),
        tooltip=[alt.Tooltip("utc:N", title="Event window"),
                 alt.Tooltip("severity:N", title="Highest severity"),
                 alt.Tooltip("events:Q", title="Events", format=",d"),
                 alt.Tooltip("rules:N", title="Rules"),
                 alt.Tooltip("value:Q", title=unit, format=",.1f")])
    return (base + event_rules + points).interactive(bind_y=False)


def protocol_chart(protocols: dict[str, int]) -> alt.LayerChart:
    """Compact monochrome packet-share chart with precise tooltips."""
    frame = dd.protocol_frame(protocols)
    protocol_sort = alt.SortField(field="share", order="descending")
    base = alt.Chart(frame).encode(
        y=alt.Y("protocol:N", title=None, sort=protocol_sort, axis=alt.Axis(labelLimit=110)))
    bars = base.mark_bar(color="#d4d4d4", cornerRadiusEnd=3).encode(
        x=alt.X("share:Q", title="Share of stored packets", axis=alt.Axis(format="%"),
                scale=alt.Scale(domain=[0, 1])),
        tooltip=[alt.Tooltip("protocol:N", title="Protocol"),
                 alt.Tooltip("packets:Q", title="Packets", format=",d"),
                 alt.Tooltip("share:Q", title="Share", format=".1%")])
    labels = base.mark_text(align="left", baseline="middle", dx=5, color="#f5f5f5").encode(
        x="share:Q", text="share_label:N")
    return bars + labels


def select_finding_event(run_id: int, event_id: int) -> None:
    """Navigate from an overview finding to its representative stored event."""
    st.session_state["view"] = "Anomaly events"
    st.session_state[f"selected_event_{run_id}"] = event_id
    st.session_state[f"event_picker_{run_id}"] = event_id


def render_finding_card(finding: analysis.Finding, run_id: int, index: int) -> None:
    label = "Detection" if finding.category == "detection" else "Observation"
    badge_color = {"HIGH": "red", "WARNING": "orange"}.get(finding.severity, "gray")
    with st.container(border=True, height="stretch", gap="small"):
        with st.container(horizontal=True, vertical_alignment="center"):
            st.badge(label, color=badge_color)
            if finding.category == "detection":
                st.badge(finding.severity.title(), color=badge_color)
        st.markdown(f"**{finding.title}**")
        st.caption(finding.summary)
        if finding.event_id is not None:
            if st.button("Review evidence", key=f"finding_{run_id}_{finding.event_id}_{index}",
                         icon=":material/arrow_forward:", type="tertiary"):
                select_finding_event(run_id, finding.event_id)
                st.rerun(scope="app")


def render_findings(findings: list[analysis.Finding], run_id: int) -> None:
    st.subheader("Key findings")
    st.caption("Highest-priority measured observations. Detection findings are rule matches, not confirmed attacks.")
    if not findings:
        st.info("No material findings were identified from the stored measurements.")
        return
    primary = findings[:3]
    for index, (column, finding) in enumerate(zip(st.columns(len(primary)), primary)):
        with column:
            render_finding_card(finding, run_id, index)
    if len(findings) > len(primary):
        with st.expander(f"{len(findings) - len(primary)} more measured observations"):
            for index, finding in enumerate(findings[len(primary):], start=len(primary)):
                render_finding_card(finding, run_id, index)


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
        with st.container(horizontal=True, vertical_alignment="center"):
            st.subheader(f"Run #{run_id}")
            status_color = "green" if run["status"] in {"completed", "stopped"} else (
                "red" if run["status"] == "failed" else "orange")
            st.badge(run["status"].title(), color=status_color)
        mode_label = "Live capture" if run["mode"] == "live" else "PCAP replay"
        st.caption(f"{source_name(run['source'])} · {mode_label} · "
                   f"processing started {dd.format_time(run['started_at'])}")
        metrics = st.columns(4)
        metrics[0].metric("Packets processed", f"{run['packets']:,}", border=True,
                          help="Packets successfully normalized and aggregated. Skipped packets are separate.")
        metrics[1].metric("Bytes processed", dd.human_bytes(run["bytes"]), border=True)
        metrics[2].metric("Stored-window coverage", dd.human_duration(coverage), border=True,
                          help="Sum of persisted fixed windows, not processing wall-clock time.")
        metrics[3].metric("Detected events", f"{run['events']:,}", border=True,
                          help="Rule matches emitted after cooldown handling; not confirmed attacks.")
        st.caption(f"Average **{average_pps:,.1f} packets/s** · Peak **{peak_pps:,.1f} packets/s** · "
                   f"Skipped **{run['skipped_packets']:,}** · Cooldown suppressions "
                   f"**{run['suppressed_events']:,}**")
        if run["storage_errors"]:
            st.warning(f"{run['storage_errors']} traffic window(s) could not be stored.",
                       title="Stored results are incomplete")
        if run["note"]:
            st.caption("Run note: " + run["note"])
        if not windows:
            st.info("No traffic windows have been stored for this run.")
            return

        findings = analysis.generate_findings(run, windows, events, sources, protocols)
        if run["events"] > len(events):
            st.warning(f"The overview uses the first {len(events):,} of {run['events']:,} detected events. "
                       "Exports still include every persisted event.", title="Overview event limit reached")
        render_findings(findings, run_id)
        chart_col, protocol_col = st.columns([2.7, 1.3])
        with chart_col.container(border=True):
            st.subheader("Traffic over time")
            st.caption("Packet rate per stored window. Markers identify windows with one or more rule matches.")
            st.altair_chart(traffic_chart(windows, events), height=300,
                            alt="Packet-rate timeline with markers at detected-event windows")
        with protocol_col.container(border=True):
            st.subheader("Protocol distribution")
            frame = dd.protocol_frame(protocols)
            if frame.empty:
                st.info("No protocol counts are available.")
            else:
                st.altair_chart(protocol_chart(protocols), height=max(190, min(300, len(frame) * 42)),
                                alt="Protocol packet shares for stored traffic windows")
                st.caption(f"{int(frame['packets'].sum()):,} packets represented in stored windows")

        events_col, sources_col = st.columns([1.15, 0.85])
        with events_col.container(border=True):
            st.subheader("Significant events")
            if events:
                rank = {"HIGH": 3, "WARNING": 2, "INFO": 1}
                ranked = sorted(events, key=lambda event: (-rank.get(event["severity"], 0),
                    -(event["observed"] / event["threshold"] if event["threshold"] else 0), event["ts"]))[:8]
                event_frame = dd.events_frame(ranked)
                event_frame["rule"] = event_frame["rule"].map(dd.rule_label)
                st.dataframe(event_frame[["time", "severity", "rule", "source", "ratio"]],
                             hide_index=True, alt="Highest-severity detected events",
                             column_config={"time": st.column_config.DatetimeColumn("Time (UTC)", format="HH:mm:ss"),
                                            "ratio": st.column_config.NumberColumn("Observed / threshold", format="%.2f×")})
            else:
                st.info("No detection events were stored for this run.")
        with sources_col.container(border=True):
            st.subheader("Leading tracked sources")
            if sources:
                st.dataframe(dd.sources_frame(sources[:5]), hide_index=True,
                             alt="Leading retained sources by packet count", column_config={
                                 "src_ip": "Source", "packets": st.column_config.NumberColumn(format="%,d"),
                                 "bytes": st.column_config.NumberColumn(format="bytes"),
                                 "syn_attempts": "SYN attempts", "max_distinct_ports": "Max ports / window",
                                 "max_distinct_hosts": "Max hosts / window"})
                st.caption("Retained source summaries; destination diversity is a per-window maximum.")
            else:
                st.info("No IP source summaries are stored for this run.")
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
            st.subheader("Protocol distribution")
            frame = dd.protocol_frame(protocols)
            if frame.empty:
                st.info("No protocol counts are available.")
            else:
                st.altair_chart(protocol_chart(protocols), height=max(240, min(380, len(frame) * 45)),
                                alt="Protocol shares across stored traffic windows")
        with right.container(border=True):
            st.subheader("Tracked sources")
            rank_by = st.segmented_control("Rank by", ["packets", "bytes", "syn_attempts"],
                                           default="packets", required=True, key=f"rank_{run_id}")
            sources = read_db(db_path, lambda storage: storage.top_sources(run_id, by=rank_by, limit=50)) or []
            if sources:
                st.dataframe(dd.sources_frame(sources), hide_index=True,
                             alt="Retained source summaries ranked by the selected measurement",
                             column_config={"src_ip": "Source IP",
                                            "packets": st.column_config.NumberColumn(format="%,d"),
                                            "bytes": st.column_config.NumberColumn(format="bytes"),
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
                                        "packets": st.column_config.NumberColumn("Packets", format="%,d"),
                                        "bytes": st.column_config.NumberColumn("Bytes", format="bytes"),
                                        "packets_per_second": st.column_config.NumberColumn("Packets / s", format="%,.1f"),
                                        "bytes_per_second": st.column_config.NumberColumn("Bytes / s", format="%,.1f")})
    body()


def render_event_detail(db_path: str, run_id: int, event: dict[str, Any]) -> None:
    with st.container(horizontal=True, vertical_alignment="center"):
        st.subheader("Event evidence")
        st.badge(event["severity"].title(), color={"HIGH": "red", "WARNING": "orange"}.get(
            event["severity"], "gray"))
    left, middle = st.columns(2)
    left.metric("Observed", dd.measurement_value(event["metric"], event["observed"]), border=True)
    middle.metric("Threshold", dd.measurement_value(event["metric"], event["threshold"]), border=True)
    ratio = event["observed"] / event["threshold"] if event["threshold"] else float("nan")
    st.caption(f"Measurement: {dd.metric_label(event['metric'])} · Observed value is {ratio:.2f}× the threshold")
    st.markdown(event["explanation"])
    details = [f"Rule: **{dd.rule_label(event['rule'])}**",
               f"Window {dd.format_time(event['window_start'])} to {dd.format_time(event['window_end'])}"]
    if event["src_ip"]:
        # The unexpected-traffic rule counts the whole window; its source is only the
        # largest contributor, not the origin of every counted packet.
        label = "Largest contributor" if event["rule"] == "unexpected_protocol_or_port" else "Source"
        details.insert(2, f"{label} `{event['src_ip']}`")
    st.caption(" · ".join(details))
    if event["dst_info"]:
        st.caption("Destination evidence: " + event["dst_info"])
    st.markdown("**Suggested next check**")
    st.caption(analysis.investigation_guidance(event))
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
                                    "packets": st.column_config.NumberColumn("Packets", format="%,d"),
                                    "bytes": st.column_config.NumberColumn("Bytes", format="bytes"),
                                    "packets_per_second": st.column_config.NumberColumn("Packets / s", format="%,.1f"),
                                    "bytes_per_second": st.column_config.NumberColumn("Bytes / s", format="%,.1f"),
                                    "unexpected_packets": "Unexpected packets"})


def render_events(db_path: str, run_id: int, live: bool) -> None:
    @fragment(live)
    def body() -> None:
        st.subheader("Anomaly events")
        st.caption("Events are explainable rule matches, not confirmation that an attack occurred.")
        bounds = read_db(db_path, lambda storage: storage.time_bounds(run_id))
        f1, f2, f3 = st.columns([1.35, 1, 0.8])
        search = f1.text_input("Search", type="search", placeholder="Rule, source, metric, or evidence",
                               key=f"event_search_{run_id}")
        rules = f2.multiselect("Rule", list(ALL_RULES), default=list(ALL_RULES),
                               format_func=dd.rule_label, key=f"rules_{run_id}")
        severities = f3.multiselect("Severity", [severity.value for severity in Severity],
                                    default=[severity.value for severity in Severity], key=f"sev_{run_id}")
        start = end = None
        if bounds is not None and bounds[1] > bounds[0]:
            lo, hi = dd.to_datetime(bounds[0]), dd.to_datetime(bounds[1])
            chosen = st.slider("Event time range (UTC)", min_value=lo, max_value=hi, value=(lo, hi),
                               key=f"range_{run_id}_{bounds[0]}_{int(bounds[1] // 60)}", format="HH:mm:ss")
            # An untouched end of the slider means "no limit": round-tripping the bound
            # through a microsecond datetime could otherwise exclude an event that sits
            # exactly on it.
            start = None if chosen[0] == lo else chosen[0].timestamp()
            end = None if chosen[1] == hi else chosen[1].timestamp()
        result = read_db(db_path, lambda storage: (
            storage.query_events(run_id, start, end, rules, severities,
                                 limit=EVENT_UI_LIMIT, search=search),
            storage.count_events(run_id, start, end, rules, severities, search=search)))
        events, total = result or ([], 0)
        if not events:
            st.info("No events match the current filters." if bounds else "No events have been stored for this run.")
            return
        frame = dd.events_frame(events)
        frame["rule"] = frame["rule"].map(dd.rule_label)
        by_id = {event["id"]: event for event in events}
        ids = list(by_id)
        preferred = st.session_state.get(f"selected_event_{run_id}")
        selected_id = st.selectbox("Selected event", ids, index=ids.index(preferred) if preferred in ids else 0,
            key=f"event_picker_{run_id}", format_func=lambda event_id: (
                f"{dd.format_time(by_id[event_id]['ts'])} · {by_id[event_id]['severity']} · "
                f"{dd.rule_label(by_id[event_id]['rule'])} · {by_id[event_id]['src_ip'] or 'all sources'}"))
        st.session_state[f"selected_event_{run_id}"] = selected_id
        list_col, detail_col = st.columns([1.05, 0.95])
        with list_col.container(border=True):
            shown = f"Showing {len(events):,} of {total:,} matching events" if total > len(events) else (
                f"{total:,} matching event{'s' if total != 1 else ''}")
            st.caption(shown)
            st.dataframe(frame[["time", "severity", "rule", "source", "ratio"]],
                         hide_index=True, height=470, alt="Detected events matching the current filters",
                         column_config={"time": st.column_config.DatetimeColumn("Time (UTC)", format="HH:mm:ss"),
                                        "ratio": st.column_config.NumberColumn("Observed / threshold", format="%.2f×")})
            if total > len(events):
                st.caption(f"The interactive list is limited to {EVENT_UI_LIMIT:,} rows. Exports include all events.")
        with detail_col.container(border=True):
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
        except Exception as exc:  # the run is already recorded as failed; show why instead of a traceback
            st.error(f"{type(exc).__name__}: {exc}", title="Capture analysis failed")
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
            except Exception as exc:  # the run is already recorded as failed; show why instead of a traceback
                st.error(f"{type(exc).__name__}: {exc}", title="Capture analysis failed")
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
    run, windows, events, sources, protocols = load_export_data(db_path, run_id)
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
                 column_config={f"Run #{run_id}": st.column_config.NumberColumn(format="%,.2f"),
                                f"Run #{other_id}": st.column_config.NumberColumn(format="%,.2f")})
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
    if kind == "historical":
        st.caption(":material/database: " + message)
    elif kind != "none":
        renderer = {"live": st.success, "active": st.info, "interrupted": st.warning,
                    "partial": st.warning, "failed": st.error}[kind]
        renderer(message)
    notice = st.session_state.pop("replay_notice", None)
    if notice:
        getattr(st, notice[0])(notice[1])
    warning = st.session_state.pop("replay_warning", None)
    if warning:
        st.warning(warning)
    return kind == "live"


def render_navigation() -> str:
    """Render compact native navigation without radio-button affordances."""
    items = (
        ("Overview", ":material/dashboard:"),
        ("Traffic analytics", ":material/query_stats:"),
        ("Anomaly events", ":material/notification_important:"),
        ("Captures and history", ":material/history:"),
    )
    current = st.session_state.setdefault("view", "Overview")
    st.caption("Explore")
    for label, icon in items:
        if st.button(label, icon=icon, key=f"nav_{label}", width="stretch",
                     type="primary" if current == label else "tertiary"):
            st.session_state["view"] = label
            st.rerun()
    return current


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
    st.caption("Explainable traffic analysis from packet headers and configurable rules")
    with st.sidebar:
        st.markdown("### :material/hub: Lattice")
        st.caption("Network traffic analysis")
        view = render_navigation()
        with st.expander("Data source", icon=":material/database:"):
            db_path = st.text_input("Results database", value=os.environ.get("LATTICE_DB") or config.database_path,
                                    help="SQLite database used for processing results.")
            if st.button("Reload results", icon=":material/refresh:", width="stretch"):
                st.rerun()
        runs = read_db(db_path, lambda storage: storage.list_runs()) or []
        run_id: Optional[int] = None
        st.caption("Current run")
        if runs:
            ids = [run["id"] for run in runs]
            preferred = st.session_state.get("selected_run")
            index = ids.index(preferred) if preferred in ids else 0
            by_id = {run["id"]: run for run in runs}
            run_id = st.selectbox("Current run", ids, index=index, label_visibility="collapsed",
                                  format_func=lambda value: dd.run_label(by_id[value]), key="run_picker")
            st.session_state["selected_run"] = run_id
            selected = by_id[run_id]
            st.caption(f"{selected['packets']:,} processed packets · {selected['events']:,} stored events")
        else:
            st.caption("No stored runs yet.")
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
