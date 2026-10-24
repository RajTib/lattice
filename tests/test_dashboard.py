"""Dashboard data layer and a headless smoke test of the Streamlit app."""
import json
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from lattice import dashboard_data as dd
from lattice import dashboard_analysis as analysis
from lattice.pipeline import process_pcap
from lattice.storage import Storage

from factories import make_config, udp_packet, write_pcap
from test_pipeline import CONFIG, attack_pcap

APP = str(Path(__file__).resolve().parent.parent / "app.py")


@pytest.fixture
def populated(tmp_path):
    db = tmp_path / "dash.db"
    with Storage(db) as storage:
        summary = process_pcap(attack_pcap(tmp_path), CONFIG, storage)
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps(CONFIG.to_dict()), encoding="utf-8")
    return db, cfg, summary


# -- data layer: the queries the dashboard issues return the expected records -----------

def test_dashboard_queries_return_expected_records(populated):
    db, _, summary = populated
    with Storage(db, read_only=True) as s:
        run = s.get_run(summary.run_id)
        windows = s.query_windows(summary.run_id)
        events = s.query_events(summary.run_id, rules=["possible_port_scan"], severities=["WARNING"])
        sources = s.top_sources(summary.run_id, by="bytes", limit=3)
        protocols = s.protocol_totals(summary.run_id)

    assert (run["packets"], run["windows"], run["events"]) == (350, 8, 4)
    frame = dd.windows_frame(windows)
    assert len(frame) == 8 and frame["packets"].sum() == 350
    assert frame.index[0].isoformat() == "1970-01-01T00:00:00+00:00"   # fixture timestamps start at 0
    ev = dd.events_frame(events)
    assert list(ev["rule"]) == ["possible_port_scan"] and list(ev["source"]) == ["203.0.113.9"]
    assert ev["ratio"].iloc[0] == pytest.approx(40 / 15)
    assert dd.sources_frame(sources).shape == (3, 6)
    assert dd.protocol_series(protocols).sum() == 350


def test_empty_inputs_produce_empty_frames():
    assert dd.windows_frame([]).empty and dd.events_frame([]).empty and dd.sources_frame([]).empty
    assert list(dd.events_frame([]).columns)[:3] == ["time", "severity", "rule"]


def test_human_bytes():
    assert dd.human_bytes(0) == "0 B" and dd.human_bytes(1023) == "1023 B"
    assert dd.human_bytes(1536) == "1.5 KiB" and dd.human_bytes(5 * 1024 ** 3) == "5.0 GiB"


def test_human_duration_and_event_context():
    assert dd.human_duration(5) == "5 s"
    assert dd.human_duration(65) == "1m 05s"
    assert dd.human_duration(7265) == "2h 01m"
    rows = [
        {"window_start": start, "packets": 10, "packets_per_second": 2.0, "bytes": 100,
         "bytes_per_second": 20.0, "unexpected_packets": 0, "protocol_counts": {"TCP": 10}}
        for start in (0.0, 5.0, 10.0)
    ]
    context = dd.event_context_frame(rows, 5.0)
    assert list(context["relation"]) == ["before", "event", "after"]
    assert list(context["protocols"]) == ["TCP 10"] * 3


def test_display_frames_keep_units_and_merge_overlapping_event_markers():
    assert dd.measurement_text("packets_per_second", 1234.5) == "1,234.5 packets/s"
    assert dd.measurement_text("bytes_per_second", 1536) == "1.5 KiB/s"
    assert dd.measurement_value("unexpected_packets", 174) == "174"
    assert dd.metric_label("unexpected_packets") == "Unexpected packets"
    assert dd.rule_label("possible_port_scan") == "Port scan / host sweep"
    protocols = dd.protocol_frame({"UDP": 3, "TCP": 1})
    assert list(protocols["protocol"]) == ["UDP", "TCP"]
    assert list(protocols["share"]) == [pytest.approx(0.75), pytest.approx(0.25)]
    assert list(protocols["share_label"]) == ["75.0%", "25.0%"]
    windows = [{"window_start": 5.0, "packets_per_second": 20.0}]
    events = [
        {"window_start": 5.0, "severity": "INFO", "rule": "traffic_spike"},
        {"window_start": 5.0, "severity": "HIGH", "rule": "possible_port_scan"},
        {"window_start": 10.0, "severity": "WARNING", "rule": "traffic_spike"},
    ]
    markers = dd.event_markers(windows, events, "packets_per_second")
    assert len(markers) == 1
    assert markers.iloc[0]["events"] == 2 and markers.iloc[0]["severity"] == "HIGH"
    assert "Port scan / host sweep" in markers.iloc[0]["rules"]
    assert markers.iloc[0]["utc"] == "1970-01-01 00:00:05 UTC"


@pytest.mark.parametrize("run,age,kind", [
    (None, None, "none"),
    ({"status": "running", "mode": "live"}, 2.0, "live"),
    ({"status": "running", "mode": "pcap"}, 2.0, "active"),
    ({"status": "running", "mode": "live"}, 600.0, "interrupted"),
    ({"status": "running", "mode": "live"}, None, "interrupted"),
    ({"status": "completed", "mode": "pcap"}, 0.0, "historical"),
    ({"status": "stopped", "mode": "live"}, 0.0, "historical"),
    ({"status": "partial", "mode": "pcap"}, 0.0, "partial"),
    ({"status": "failed", "mode": "pcap"}, 0.0, "failed"),
])
def test_data_mode_distinguishes_live_from_historical(run, age, kind):
    assert dd.data_mode(run, age)[0] == kind


# -- headless app ------------------------------------------------------------------------

def run_app(db, cfg, tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    monkeypatch.setenv("LATTICE_DB", str(db))
    monkeypatch.setenv("LATTICE_CONFIG", str(cfg))
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    return at


def open_view(at, name):
    navigation = next(button for button in at.button if button.label == name)
    navigation.click().run()
    return at


def test_app_shows_persisted_statistics_and_events(populated, tmp_path, monkeypatch):
    db, cfg, summary = populated
    at = run_app(db, cfg, tmp_path, monkeypatch)
    assert not at.exception, [e.value for e in at.exception]
    assert not at.error
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Packets processed"] == "350"
    assert metrics["Detected events"] == "4" and metrics["Stored-window coverage"] == "40 s"
    assert any("PCAP replay" in caption.value for caption in at.caption)
    assert any("Average **" in caption.value and "Peak **" in caption.value for caption in at.caption)
    assert any("Historical" in caption.value for caption in at.caption)
    event_tables = [table.value for table in at.dataframe if "rule" in table.value.columns]
    assert event_tables and any(len(table) == 4 for table in event_tables)
    investigate = next(button for button in at.button if button.label == "Review evidence")
    investigate.click().run()
    assert at.session_state["view"] == "Anomaly events"
    context_tables = [table.value for table in at.dataframe if "relation" in table.value.columns]
    assert context_tables and "event" in set(context_tables[0]["relation"])
    assert any(box.label == "Selected event" for box in at.selectbox)


def test_event_filters_update_summary_and_inspector(populated, tmp_path, monkeypatch):
    db, cfg, _ = populated
    at = run_app(db, cfg, tmp_path, monkeypatch)
    open_view(at, "Anomaly events")
    at.multiselect[0].set_value(["possible_port_scan"]).run()
    assert not at.exception, [e.value for e in at.exception]
    event_tables = [table.value for table in at.dataframe if "rule" in table.value.columns]
    assert any(set(table["rule"]) == {"Port scan / host sweep"} for table in event_tables)
    event_pickers = [box for box in at.selectbox if box.label == "Selected event"]
    assert len(event_pickers) == 1


def test_app_normal_run_has_clear_no_event_state(tmp_path, monkeypatch):
    db = tmp_path / "normal.db"
    cfg_obj = make_config()
    capture = write_pcap(tmp_path / "normal.pcap", [udp_packet(i / 2, dport=53) for i in range(10)])
    with Storage(db) as storage:
        process_pcap(capture, cfg_obj, storage)
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps(cfg_obj.to_dict()), encoding="utf-8")

    at = run_app(db, cfg, tmp_path, monkeypatch)
    open_view(at, "Anomaly events")
    assert not at.exception, [e.value for e in at.exception]
    assert any("No events match" in info.value for info in at.info)


def test_dashboard_processes_sample_and_selects_new_run(tmp_path, monkeypatch):
    db = tmp_path / "dashboard-replay.db"
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps(make_config().to_dict()), encoding="utf-8")
    at = run_app(db, cfg, tmp_path, monkeypatch)

    open_view(at, "Captures and history")
    sample = next(box for box in at.selectbox if box.label == "Repository sample")
    sample.set_value("normal.pcap").run()
    process = next(button for button in at.button if button.label == "Process PCAP")
    process.click().run(timeout=60)

    assert not at.exception, [e.value for e in at.exception]
    assert any("2,395 packets" in message.value for message in at.success)
    metrics = {metric.label: metric.value for metric in at.metric}
    assert metrics["Packets processed"] == "2,395"
    assert any("PCAP replay" in caption.value for caption in at.caption)
    with Storage(db, read_only=True) as storage:
        (run,) = storage.list_runs()
    assert run["packets"] == 2395 and run["events"] == 0


def test_findings_are_evidence_based_and_rank_detections_first(populated):
    db, _, summary = populated
    with Storage(db, read_only=True) as storage:
        run = storage.get_run(summary.run_id)
        windows = storage.query_windows(summary.run_id)
        events = storage.query_events(summary.run_id)
        sources = storage.top_sources(summary.run_id, limit=50)
        protocols = storage.protocol_totals(summary.run_id)
    findings = analysis.generate_findings(run, windows, events, sources, protocols)
    assert findings and findings[0].category == "detection"
    assert any(item.event_id in {event["id"] for event in events} for item in findings if item.event_id)
    assert all("attack occurred" not in item.summary.lower() for item in findings)
    assert all("UTC" in item.summary for item in findings if item.category == "detection")
    assert any("packets/s" in item.summary or "destination ports" in item.summary
               for item in findings if item.category == "detection")


def test_normalized_metrics_use_window_coverage():
    run = {"skipped_packets": 1, "packets": 19}
    windows = [
        {"window_start": 0.0, "window_end": 5.0, "packets": 10, "bytes": 100,
         "packets_per_second": 2.0, "bytes_per_second": 20.0},
        {"window_start": 5.0, "window_end": 10.0, "packets": 10, "bytes": 200,
         "packets_per_second": 2.0, "bytes_per_second": 40.0},
    ]
    metrics = analysis.normalized_metrics(run, windows, [{}, {}])
    assert metrics["coverage_seconds"] == 10
    assert metrics["average_packets_per_second"] == 2
    assert metrics["events_per_minute"] == 12
    assert metrics["skipped_packet_share"] == pytest.approx(0.05)


def test_upload_validation_processing_and_path_safe_exports(tmp_path):
    capture = write_pcap(tmp_path / "source.pcap", [udp_packet(i / 2, dport=53) for i in range(10)])
    content = capture.read_bytes()
    assert analysis.validate_capture_upload(r"C:\private\capture.pcap", content) == "capture.pcap"
    with pytest.raises(ValueError, match="recognized"):
        analysis.validate_capture_upload("bad.pcap", b"not a capture")
    with pytest.raises(ValueError, match="limit"):
        analysis.validate_capture_upload("large.pcap", content, max_bytes=4)

    db = tmp_path / "upload.db"
    with Storage(db) as storage:
        summary = analysis.process_capture_upload(r"C:\private\capture.pcap", content,
                                                   make_config(), storage)
    with Storage(db, read_only=True) as storage:
        run = storage.get_run(summary.run_id)
        windows = storage.query_windows(summary.run_id)
        sources = storage.top_sources(summary.run_id)
    assert run["source"] == "capture.pcap" and summary.packets == 10
    payload = analysis.export_payload(run, windows, [], sources, [])
    encoded = analysis.export_json_bytes(payload).decode("utf-8")
    assert "capture.pcap" in encoded and "private" not in encoded
    with zipfile.ZipFile(BytesIO(analysis.export_csv_zip_bytes(payload))) as archive:
        assert {"run.csv", "findings.csv", "traffic_windows.csv", "events.csv",
                "source_summaries.csv", "README.txt"} == set(archive.namelist())


def test_dashboard_compares_and_exports_two_runs(populated, tmp_path, monkeypatch):
    db, cfg, first = populated
    capture = write_pcap(tmp_path / "comparison.pcap", [udp_packet(i / 2, dport=53) for i in range(20)])
    with Storage(db) as storage:
        second = process_pcap(capture, CONFIG, storage)
    at = run_app(db, cfg, tmp_path, monkeypatch)
    open_view(at, "Captures and history")
    tools = next(control for control in at.segmented_control if control.label == "Capture tools")
    tools.set_value("Compare and export").run()

    assert not at.exception, [exception.value for exception in at.exception]
    comparisons = [table.value for table in at.dataframe if "Measurement" in table.value.columns]
    assert comparisons and "Average packets / s" in set(comparisons[0]["Measurement"])
    assert {button.label for button in at.download_button} >= {"Download JSON", "Download CSV bundle"}
    with Storage(db, read_only=True) as storage:
        assert {first.run_id, second.run_id} == {run["id"] for run in storage.list_runs()}


@pytest.mark.parametrize("status,expected", [
    ("partial", "Partial run"),
    ("failed", "Failed run"),
])
def test_app_highlights_incomplete_runs(tmp_path, monkeypatch, status, expected):
    db = tmp_path / f"{status}.db"
    with Storage(db) as storage:
        run_id = storage.start_run("pcap", "input.pcap")
        storage.finish_run(run_id, status, {
            "packets": 0, "bytes": 0, "windows": 0, "events": 0,
            "suppressed_events": 0, "skipped_packets": 1, "storage_errors": 0,
        }, "input could not be read completely")
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps(make_config().to_dict()), encoding="utf-8")

    at = run_app(db, cfg, tmp_path, monkeypatch)
    messages = [item.value for item in (*at.warning, *at.error)]
    assert any(expected in message for message in messages)


def test_app_empty_state_without_a_database(tmp_path, monkeypatch):
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps(make_config().to_dict()), encoding="utf-8")
    at = run_app(tmp_path / "none.db", cfg, tmp_path, monkeypatch)
    assert not at.exception, [e.value for e in at.exception]
    assert any("Nothing to show yet" in i.value for i in at.info)


def test_app_reports_invalid_configuration(tmp_path, monkeypatch):
    cfg = tmp_path / "bad.json"
    cfg.write_text('{"window": {"seconds": -1}}', encoding="utf-8")
    at = run_app(tmp_path / "x.db", cfg, tmp_path, monkeypatch)
    assert any("Configuration error" in e.value and "window.seconds" in e.value for e in at.error)


def test_app_reports_corrupt_stored_window(tmp_path, monkeypatch):
    db = tmp_path / "corrupt.db"
    with Storage(db) as storage:
        run = storage.start_run("pcap", "capture.pcap")
        from lattice.models import WindowStats
        window_id = storage.save_window(
            run, WindowStats(0, 5, packets=1, bytes=60, packets_per_second=0.2,
                             bytes_per_second=12, protocol_counts={"TCP": 1}),
            [], 10, {"packets": 1, "bytes": 60, "windows": 1, "events": 0,
                     "suppressed_events": 0, "skipped_packets": 0, "storage_errors": 0})
        storage._conn.execute("UPDATE traffic_stats SET protocol_counts = ? WHERE id = ?",
                              ("broken", window_id))
        storage._conn.commit()
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps(make_config().to_dict()), encoding="utf-8")

    at = run_app(db, cfg, tmp_path, monkeypatch)
    assert not at.exception, [e.value for e in at.exception]
    assert any("Database error" in e.value and "invalid protocol counts" in e.value for e in at.error)
