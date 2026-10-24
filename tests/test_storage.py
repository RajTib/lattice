"""SQLite persistence."""
import sqlite3

import pytest

from lattice.models import Event, Severity, WindowStats
from lattice.storage import APPLICATION_ID, Storage, StorageError, reset_database

from factories import source, window

TOTALS = {"packets": 0, "bytes": 0, "windows": 0, "events": 0, "suppressed_events": 0,
          "skipped_packets": 0, "storage_errors": 0}


def event(ts=10.0, rule="traffic_spike", severity=Severity.WARNING, src="1.1.1.1", **kw):
    fields = dict(timestamp=ts, rule=rule, severity=severity, observed=150.0, threshold=100.0,
                  explanation="because", window_start=ts - 5, window_end=ts, metric="m",
                  src_ip=src, dst_info="hosts: 9.9.9.9")
    fields.update(kw)
    return Event(**fields)


def stats_window(start=0.0):
    return WindowStats(start=start, end=start + 5, packets=10, bytes=1000, packets_per_second=2.0,
                       bytes_per_second=200.0, protocol_counts={"TCP": 7, "UDP": 3},
                       sources={"1.1.1.1": source(syn=4, ports=[80, 81], hosts=["9.9.9.9"], packets=6),
                                "2.2.2.2": source(packets=4)})


def test_schema_is_created_and_marked(storage):
    names = {r[0] for r in storage._conn.execute("SELECT name FROM sqlite_master")}
    assert {"runs", "traffic_stats", "source_stats", "events", "idx_events_run_ts",
            "idx_traffic_run_time"} <= names
    assert storage._conn.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
    assert storage._conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_reopening_existing_database_is_safe(tmp_path):
    path = tmp_path / "x.db"
    with Storage(path) as db:
        run = db.start_run("pcap", "a.pcap")
        db.save_window(run, stats_window(), [event()], 10, TOTALS)
    with Storage(path) as db:  # init_schema again: CREATE IF NOT EXISTS keeps the data
        assert len(db.list_runs()) == 1 and db.count_events(run) == 1


def test_window_roundtrip_with_top_talkers(storage):
    run = storage.start_run("pcap", "a.pcap")
    storage.save_window(run, stats_window(0.0), [], top_n=1, totals=TOTALS)
    (row,) = storage.query_windows(run)
    assert (row["window_start"], row["window_end"], row["packets"], row["bytes"]) == (0.0, 5.0, 10, 1000)
    assert row["packets_per_second"] == 2.0 and row["protocol_counts"] == {"TCP": 7, "UDP": 3}
    top = storage.top_sources(run)
    assert [(r["src_ip"], r["packets"], r["syn_attempts"]) for r in top] == [("1.1.1.1", 6, 4)]  # top_n=1


def test_query_windows_time_range(storage):
    run = storage.start_run("pcap", "a")
    for start in (0.0, 5.0, 10.0, 15.0):
        storage.save_window(run, stats_window(start), [], 10, TOTALS)
    assert [w["window_start"] for w in storage.query_windows(run, start=5.0, end=15.0)] == [5.0, 10.0]
    assert len(storage.query_windows(run)) == 4


def test_event_roundtrip_and_filters(storage):
    run = storage.start_run("pcap", "a")
    storage.save_window(run, stats_window(0), [
        event(10, "traffic_spike", Severity.INFO), event(20, "possible_port_scan", Severity.HIGH, "2.2.2.2"),
        event(30, "possible_port_scan", Severity.WARNING, "3.3.3.3")], 10, TOTALS)
    everything = storage.query_events(run)
    assert [e["ts"] for e in everything] == [10, 20, 30]
    first = everything[0]
    assert (first["rule"], first["severity"], first["observed"], first["threshold"]) == \
        ("traffic_spike", "INFO", 150.0, 100.0)
    assert first["explanation"] == "because" and first["dst_info"] == "hosts: 9.9.9.9"
    assert [e["ts"] for e in storage.query_events(run, start=15, end=30)] == [20, 30]
    assert [e["ts"] for e in storage.query_events(run, rules=["possible_port_scan"])] == [20, 30]
    assert [e["ts"] for e in storage.query_events(run, severities=["HIGH", "INFO"])] == [10, 20]
    assert [e["ts"] for e in storage.query_events(run, rules=["possible_port_scan"],
                                                  severities=["WARNING"])] == [30]
    assert storage.query_events(run, rules=[]) == []
    assert len(storage.query_events(run, limit=2)) == 2


def test_event_filters_are_parameterized(storage):
    run = storage.start_run("pcap", "a")
    storage.save_window(run, stats_window(0), [event()], 10, TOTALS)
    hostile = "x'); DROP TABLE events; --"
    assert storage.query_events(run, rules=[hostile]) == []
    assert storage.query_events(run, severities=["' OR '1'='1"]) == []
    assert storage.count_events(run) == 1  # table survived


def test_hostile_values_are_stored_verbatim(storage):
    run = storage.start_run("pcap", "a'; DROP TABLE runs; --")
    storage.save_window(run, stats_window(0), [event(src="1.1.1.1'; --", explanation="it's \"quoted\"")], 10,
                        TOTALS)
    (e,) = storage.query_events(run)
    assert e["src_ip"] == "1.1.1.1'; --" and e["explanation"] == "it's \"quoted\""
    assert storage.get_run(run)["source"] == "a'; DROP TABLE runs; --"


def test_top_sources_sum_over_windows_and_validate_sort_key(storage):
    run = storage.start_run("pcap", "a")
    for start in (0.0, 5.0):
        storage.save_window(run, stats_window(start), [], 10, TOTALS)
    top = storage.top_sources(run, by="packets")
    assert top[0]["src_ip"] == "1.1.1.1" and top[0]["packets"] == 12
    assert storage.top_sources(run, start=5.0)[0]["packets"] == 6
    with pytest.raises(ValueError):
        storage.top_sources(run, by="packets; DROP TABLE runs")


def test_protocol_totals_and_bounds(storage):
    run = storage.start_run("pcap", "a")
    assert storage.time_bounds(run) is None
    for start in (0.0, 5.0):
        storage.save_window(run, stats_window(start), [], 10, TOTALS)
    assert storage.protocol_totals(run) == {"TCP": 14, "UDP": 6}
    assert storage.time_bounds(run) == (0.0, 10.0)


def test_save_window_updates_run_progress(storage):
    run = storage.start_run("pcap", "a")
    storage.save_window(run, stats_window(), [event()], 10, {**TOTALS, "packets": 10, "windows": 1, "events": 1})
    row = storage.get_run(run)
    assert (row["status"], row["packets"], row["windows"], row["events"]) == ("running", 10, 1, 1)
    storage.finish_run(run, "completed", {**TOTALS, "packets": 10}, "done")
    row = storage.get_run(run)
    assert row["status"] == "completed" and row["finished_at"] is not None and row["note"] == "done"


def test_duplicate_window_is_rejected_atomically(storage):
    run = storage.start_run("pcap", "a")
    storage.save_window(run, stats_window(0), [event()], 10, TOTALS)
    with pytest.raises(StorageError):
        storage.save_window(run, stats_window(0), [event(ts=99), event(ts=98)], 10, TOTALS)
    assert len(storage.query_windows(run)) == 1
    assert [e["ts"] for e in storage.query_events(run)] == [10.0]  # nothing from the failed write


def test_failure_midway_rolls_back_whole_window(storage):
    run = storage.start_run("pcap", "a")
    bad = event(explanation=None)  # NOT NULL violation after the stats rows were already inserted
    with pytest.raises(StorageError):
        storage.save_window(run, stats_window(0), [event(), bad], 10, {**TOTALS, "packets": 10})
    assert storage.query_windows(run) == [] and storage.query_events(run) == []
    assert storage._conn.execute("SELECT COUNT(*) FROM source_stats").fetchone()[0] == 0
    assert storage.get_run(run)["packets"] == 0
    storage.save_window(run, stats_window(0), [event()], 10, TOTALS)  # connection still usable
    assert len(storage.query_windows(run)) == 1


def test_repeated_writes_do_not_duplicate_rows(storage):
    run = storage.start_run("pcap", "a")
    for start in (0.0, 5.0, 10.0):
        storage.save_window(run, stats_window(start), [event(ts=start + 5)], 10, TOTALS)
    for _ in range(3):  # reads (dashboard refreshes) never add rows
        storage.query_windows(run), storage.query_events(run), storage.top_sources(run)
    assert len(storage.query_windows(run)) == 3 and storage.count_events(run) == 3


def test_delete_run_cascades(storage):
    run = storage.start_run("pcap", "a")
    other = storage.start_run("pcap", "b")
    storage.save_window(run, stats_window(0), [event()], 10, TOTALS)
    storage.save_window(other, stats_window(0), [event()], 10, TOTALS)
    storage.delete_run(run)
    assert storage.get_run(run) is None and storage.query_windows(run) == []
    assert storage.query_events(run) == []
    assert len(storage.query_events(other)) == 1 and storage.top_sources(other)


def test_find_completed_run_ignores_unfinished(storage):
    run = storage.start_run("pcap", "a", "fp1")
    assert storage.find_completed_run("fp1") is None
    storage.finish_run(run, "completed", TOTALS)
    assert storage.find_completed_run("fp1")["id"] == run
    assert storage.find_completed_run("other") is None


# -- ownership, read-only access and reset --------------------------------------

def test_foreign_sqlite_database_is_refused(tmp_path):
    path = tmp_path / "foreign.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE notes (id INTEGER)")
    conn.commit()
    conn.close()
    with pytest.raises(StorageError, match="not a Lattice database"):
        Storage(path)
    with pytest.raises(StorageError, match="not a Lattice database"):
        reset_database(path, confirm=True)
    conn = sqlite3.connect(path)  # untouched
    assert conn.execute("SELECT name FROM sqlite_master").fetchall() == [("notes",)]
    conn.close()


def test_reset_requires_confirmation_and_clears_lattice_data(tmp_path):
    path = tmp_path / "x.db"
    with Storage(path) as db:
        run = db.start_run("pcap", "a")
        db.save_window(run, stats_window(0), [event()], 10, TOTALS)
    with pytest.raises(StorageError, match="confirm"):
        reset_database(path)
    with Storage(path) as db:
        assert len(db.list_runs()) == 1  # still there after the refusal
    reset_database(path, confirm=True)
    with Storage(path) as db:
        assert db.list_runs() == [] and db.query_events() == []


def test_reset_creates_a_missing_database(tmp_path):
    path = tmp_path / "sub" / "new.db"
    reset_database(path, confirm=True)
    assert path.exists()


def test_read_only_connection(tmp_path):
    path = tmp_path / "x.db"
    with Storage(path) as db:
        run = db.start_run("pcap", "a")
        db.save_window(run, stats_window(0), [event()], 10, TOTALS)
    with Storage(path, read_only=True) as ro:
        assert len(ro.query_events(run)) == 1
        with pytest.raises(StorageError):
            ro.start_run("pcap", "b")
    with pytest.raises(StorageError, match="not found"):
        Storage(tmp_path / "missing.db", read_only=True)


def test_in_memory_database_works():
    with Storage(":memory:") as db:
        run = db.start_run("pcap", "a")
        assert db.get_run(run)["status"] == "running"
