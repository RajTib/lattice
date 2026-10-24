"""Dashboard data layer and a headless smoke test of the Streamlit app."""
import json
from pathlib import Path

import pytest

from lattice import dashboard_data as dd
from lattice.pipeline import process_pcap
from lattice.storage import Storage

from factories import make_config
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
    assert dd.sources_frame(sources).shape == (3, 4)
    assert dd.protocol_series(protocols).sum() == 350


def test_empty_inputs_produce_empty_frames():
    assert dd.windows_frame([]).empty and dd.events_frame([]).empty and dd.sources_frame([]).empty
    assert list(dd.events_frame([]).columns)[:3] == ["time", "severity", "rule"]


def test_human_bytes():
    assert dd.human_bytes(0) == "0 B" and dd.human_bytes(1023) == "1023 B"
    assert dd.human_bytes(1536) == "1.5 KiB" and dd.human_bytes(5 * 1024 ** 3) == "5.0 GiB"


@pytest.mark.parametrize("run,age,kind", [
    (None, None, "none"),
    ({"status": "running", "mode": "live"}, 2.0, "live"),
    ({"status": "running", "mode": "live"}, 600.0, "interrupted"),
    ({"status": "running", "mode": "live"}, None, "interrupted"),
    ({"status": "completed", "mode": "pcap"}, 0.0, "historical"),
    ({"status": "stopped", "mode": "live"}, 0.0, "historical"),
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


def test_app_shows_persisted_statistics_and_events(populated, tmp_path, monkeypatch):
    db, cfg, summary = populated
    at = run_app(db, cfg, tmp_path, monkeypatch)
    assert not at.exception, [e.value for e in at.exception]
    assert not at.error
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Packets processed"] == "350"
    assert metrics["Detected events"] == "4" and metrics["Windows"] == "8"
    assert metrics["Mode"] == "PCAP" and metrics["Status"] == "completed"
    assert any("Historical" in i.value for i in at.info)       # clearly labelled as stored data
    assert at.dataframe, "events table was not rendered"
    assert len(at.dataframe[-1].value) == 4


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
