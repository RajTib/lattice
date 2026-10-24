"""End-to-end offline pipeline: PCAP -> windows -> events -> SQLite -> dashboard queries."""
import pytest

from lattice.capture import CaptureError
from lattice.cli import main
from lattice.pipeline import process_pcap
from lattice.storage import Storage, StorageError

from factories import make_config, stamp, tcp_packet, udp_packet, write_pcap, eth

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

CONFIG = make_config({"window": {"seconds": 5}, "detection": {
    "cooldown_seconds": 0,
    # Absolute limits only: the attack scenarios must be attributable to exactly one rule each.
    "traffic_spike": {"pps_threshold": 1000, "bps_threshold": None, "moving_average_multiplier": None},
    "connection_attempts": {"max_syn_per_source": 50},
    "port_scan": {"max_distinct_ports": 15, "max_distinct_hosts": None},
    "unexpected_traffic": {"max_packets": 5}}})


def background(start, seconds, per_second=4):
    """Steady, conforming traffic: HTTPS data and DNS from a few clients."""
    packets = []
    for s in range(seconds):
        for k in range(per_second):
            ts = start + s + k / per_second
            client = f"192.168.1.{10 + k % 3}"
            if k % 2:
                packets.append(tcp_packet(ts, client, "10.0.0.2", 50000 + k, 443, "A", payload=200))
            else:
                packets.append(udp_packet(ts, client, "10.0.0.53", 40000 + k, 53, payload=30))
    return packets


def attack_pcap(tmp_path):
    packets = background(0, 40)
    # t=10..14: one source opens 120 connections to a single port
    packets += [tcp_packet(10 + i / 40, "203.0.113.5", "10.0.0.2", 30000 + i, 80, "S") for i in range(120)]
    # t=20..24: another source probes 40 distinct ports
    packets += [tcp_packet(20 + i / 20, "203.0.113.9", "10.0.0.2", 31000, 1000 + i, "S") for i in range(40)]
    # t=30..34: traffic on an unexpected port and an unexpected IP protocol
    packets += [tcp_packet(30 + i / 10, "192.168.1.10", "10.0.0.2", 50100, 31337, "A") for i in range(20)]
    packets += [stamp(eth() / IP(src="192.168.1.11", dst="10.0.0.2", proto=47) / Raw(b"g"), 31 + i / 10)
                for i in range(10)]
    return write_pcap(tmp_path / "attack.pcap", packets)


def event_keys(storage, run):
    return [(e["rule"], e["src_ip"], e["window_start"]) for e in storage.query_events(run)]


def test_full_pipeline_statistics_and_events(tmp_path, storage):
    summary = process_pcap(attack_pcap(tmp_path), CONFIG, storage)
    expected_packets = 40 * 4 + 120 + 40 + 20 + 10
    assert summary.status == "completed" and not summary.duplicate
    assert summary.packets == expected_packets and summary.skipped_packets == 0
    assert summary.windows == 8 and summary.storage_errors == 0

    run = summary.run_id
    windows = storage.query_windows(run)
    assert [w["window_start"] for w in windows] == [i * 5.0 for i in range(8)]
    assert sum(w["packets"] for w in windows) == expected_packets
    assert storage.protocol_totals(run)["UDP"] == 80

    events = storage.query_events(run)
    # The scan probes ports outside the allowlist, so it legitimately raises Rule D as well.
    assert event_keys(storage, run) == [
        ("excessive_connection_attempts", "203.0.113.5", 10.0),
        ("possible_port_scan", "203.0.113.9", 20.0),
        ("unexpected_protocol_or_port", "203.0.113.9", 20.0),
        ("unexpected_protocol_or_port", "192.168.1.10", 30.0),
    ]
    syn, scan, _, odd = events
    assert (syn["observed"], syn["threshold"], syn["severity"]) == (120.0, 50.0, "WARNING")
    assert (scan["observed"], scan["threshold"], scan["metric"]) == (40.0, 15.0, "distinct_destination_ports")
    assert odd["observed"] == 30.0 and "31337" in odd["explanation"] and "47" in odd["dst_info"]
    assert summary.events == 4 and storage.get_run(run)["events"] == 4

    top = storage.top_sources(run, by="syn_attempts", limit=2)
    assert [(r["src_ip"], r["syn_attempts"]) for r in top] == [("203.0.113.5", 120), ("203.0.113.9", 40)]
    assert storage.time_bounds(run) == (0.0, 40.0)


def test_clean_traffic_produces_no_events(tmp_path, storage):
    path = write_pcap(tmp_path / "clean.pcap", background(0, 60))
    summary = process_pcap(path, CONFIG, storage)
    assert summary.events == 0 and summary.packets == 240 and storage.query_events(summary.run_id) == []


def test_traffic_spike_through_the_pipeline(tmp_path, storage):
    packets = background(0, 40) + [tcp_packet(40 + i / 100, "192.168.1.10", "10.0.0.2", 50000, 443, "A",
                                              payload=500) for i in range(500)]
    relative = make_config({"window": {"seconds": 5}, "detection": {
        "traffic_spike": {"pps_threshold": None, "bps_threshold": None, "moving_average_multiplier": 4.0}}})
    summary = process_pcap(write_pcap(tmp_path / "spike.pcap", packets), relative, storage)
    spikes = [e for e in storage.query_events(summary.run_id) if e["rule"] == "traffic_spike"]
    assert {(e["window_start"], e["metric"]) for e in spikes} == {
        (40.0, "packets_per_second"), (40.0, "bytes_per_second")}
    pps = next(e for e in spikes if e["metric"] == "packets_per_second")
    assert pps["observed"] == pytest.approx(100.0)
    assert pps["threshold"] == pytest.approx(16.0)   # 4 x the 4 pkt/s moving average


def test_rerunning_the_same_pcap_does_not_duplicate_records(tmp_path, storage):
    path = attack_pcap(tmp_path)
    first = process_pcap(path, CONFIG, storage)
    counts = (len(storage.query_windows(first.run_id)), storage.count_events(first.run_id))
    again = process_pcap(path, CONFIG, storage)
    assert again.duplicate and again.run_id == first.run_id and again.events == first.events
    assert len(storage.list_runs()) == 1
    assert (len(storage.query_windows(first.run_id)), storage.count_events(first.run_id)) == counts


def test_force_replaces_the_previous_run(tmp_path, storage):
    path = attack_pcap(tmp_path)
    first = process_pcap(path, CONFIG, storage)
    forced = process_pcap(path, CONFIG, storage, force=True)
    assert not forced.duplicate and forced.run_id != first.run_id
    assert [r["id"] for r in storage.list_runs()] == [forced.run_id]
    assert storage.get_run(first.run_id) is None and storage.query_events(first.run_id) == []


def test_changed_settings_reprocess_the_same_file(tmp_path, storage):
    path = attack_pcap(tmp_path)
    process_pcap(path, CONFIG, storage)
    stricter = make_config({"window": {"seconds": 5}, "detection": {
        **CONFIG.to_dict()["detection"], "connection_attempts": {"max_syn_per_source": 10}}})
    second = process_pcap(path, stricter, storage)
    assert not second.duplicate and len(storage.list_runs()) == 2


def test_multiple_files_are_kept_as_separate_runs(tmp_path, storage):
    a = process_pcap(attack_pcap(tmp_path), CONFIG, storage)
    b = process_pcap(write_pcap(tmp_path / "clean.pcap", background(0, 20)), CONFIG, storage)
    assert a.run_id != b.run_id and (a.events, b.events) == (4, 0)
    assert storage.query_events(b.run_id) == []
    assert len(storage.query_events()) == 4                      # across all runs
    assert len(storage.query_windows(b.run_id)) == 4 and len(storage.query_windows(a.run_id)) == 8


def test_out_of_order_capture_is_replayed_in_timestamp_order(tmp_path, storage):
    packets = background(0, 20)
    shuffled = packets[::-1]  # file order is reverse of time order
    forward = process_pcap(write_pcap(tmp_path / "f.pcap", packets), CONFIG, storage)
    with Storage(tmp_path / "other.db") as other:
        backward = process_pcap(write_pcap(tmp_path / "b.pcap", shuffled), CONFIG, other)
        assert other.query_windows(backward.run_id) == [
            {**w, "id": o["id"], "run_id": backward.run_id}
            for w, o in zip(storage.query_windows(forward.run_id), other.query_windows(backward.run_id))]


def test_malformed_packets_are_reported_in_the_summary(tmp_path, storage):
    bad = stamp(eth() / IP(ihl=2) / TCP(), 1.5)
    path = write_pcap(tmp_path / "m.pcap", background(0, 5) + [bad, bad])
    summary = process_pcap(path, CONFIG, storage)
    assert summary.skipped_packets == 2 and summary.packets == 20
    assert storage.get_run(summary.run_id)["skipped_packets"] == 2


def test_missing_pcap_fails_cleanly_without_creating_a_run(tmp_path, storage):
    with pytest.raises(CaptureError):
        process_pcap(tmp_path / "nope.pcap", CONFIG, storage)
    assert storage.list_runs() == []


def test_storage_failure_does_not_stop_processing(tmp_path, storage, monkeypatch):
    path = write_pcap(tmp_path / "c.pcap", background(0, 30))
    original = storage.save_window
    calls = []

    def flaky(run_id, ws, events, top_n, totals):
        calls.append(ws.start)
        if len(calls) == 2:
            raise StorageError("disk full")
        return original(run_id, ws, events, top_n, totals)

    monkeypatch.setattr(storage, "save_window", flaky)
    summary = process_pcap(path, CONFIG, storage)
    assert summary.status == "completed" and summary.storage_errors == 1
    assert summary.windows == 6 and summary.packets == 120   # processing saw every window
    assert len(storage.query_windows(summary.run_id)) == 5   # only the failed one is missing
    assert "could not be stored" in summary.note


def test_identical_input_gives_identical_results(tmp_path):
    path = attack_pcap(tmp_path)
    results = []
    for name in ("one.db", "two.db"):
        with Storage(tmp_path / name) as db:
            run = process_pcap(path, CONFIG, db).run_id
            strip = lambda rows: [{k: v for k, v in r.items() if k not in ("id", "run_id", "window_id")}
                                  for r in rows]
            results.append((strip(db.query_windows(run)), strip(db.query_events(run))))
    assert results[0] == results[1]


# -- CLI -------------------------------------------------------------------------

def test_cli_replay_and_reset(tmp_path, capsys):
    import json
    pcap = attack_pcap(tmp_path)
    db = str(tmp_path / "cli.db")
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps(CONFIG.to_dict()), encoding="utf-8")
    base = ["--config", str(cfg), "--db", db]
    assert main([*base, "replay", str(pcap)]) == 0
    out = capsys.readouterr().out
    assert "4 events" in out and "run 1" in out
    assert main([*base, "replay", str(pcap)]) == 0
    assert "already processed" in capsys.readouterr().out

    assert main([*base, "reset-db"]) == 1                            # no --yes: refused
    assert "confirm" in capsys.readouterr().err
    with Storage(db) as s:
        assert len(s.list_runs()) == 1
    assert main([*base, "reset-db", "--yes"]) == 0
    with Storage(db) as s:
        assert s.list_runs() == []


def test_cli_reports_errors(tmp_path, capsys):
    assert main(["--db", str(tmp_path / "x.db"), "replay", str(tmp_path / "missing.pcap")]) == 1
    assert "not found" in capsys.readouterr().err
    assert main(["--config", str(tmp_path / "nope.json"), "init-db"]) == 1
    assert "config file not found" in capsys.readouterr().err
    assert main(["--db", str(tmp_path / "ok.db"), "init-db"]) == 0
