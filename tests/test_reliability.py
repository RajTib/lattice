"""Regression tests for the defects found in the end-to-end functional audit.

Each test here failed against the code as audited (``e158edc``); the docstrings
say what the original behaviour was.
"""
import collections
import csv
import datetime as dt
import io
import json
import math
import random
import sqlite3
import struct
import tempfile
import zipfile
from pathlib import Path

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.packet import Raw

import lattice.pipeline as pipeline_module
from lattice import dashboard_analysis as analysis
from lattice.capture import CaptureError, iter_pcap_records
from lattice.config import parse_config
from lattice.models import IngestStats
from lattice.pipeline import process_pcap, process_records
from lattice.storage import Storage

from factories import (eth, make_config, record, stamp, tcp_packet, udp_packet, write_pcap,
                       write_pcapng)
from test_pipeline import CONFIG, attack_pcap
from test_dashboard import open_view, run_app


def three_packets():
    return [tcp_packet(100.0 + i, sport=1000 + i, flags="A") for i in range(3)]


# -- truncated captures must not look like successful runs --------------------------------

@pytest.mark.parametrize("writer", [write_pcap, write_pcapng], ids=["pcap", "pcapng"])
@pytest.mark.parametrize("cut", [1, 40, 100])
def test_truncated_capture_is_partial_not_completed(tmp_path, writer, cut):
    """A file cut off mid-record used to be reported as a clean ``completed`` run."""
    path = writer(tmp_path / "t.cap", three_packets())
    path.write_bytes(path.read_bytes()[:-cut])
    with Storage(tmp_path / "t.db") as storage:
        summary = process_pcap(path, CONFIG, storage)
        assert summary.status == "partial"
        assert "incomplete" in summary.note
        assert storage.find_completed_run(storage.get_run(summary.run_id)["fingerprint"]) is None


@pytest.mark.parametrize("writer", [write_pcap, write_pcapng], ids=["pcap", "pcapng"])
def test_intact_capture_has_no_framing_error(tmp_path, writer):
    stats = IngestStats()
    records = list(iter_pcap_records(writer(tmp_path / "ok.cap", three_packets()), stats))
    assert len(records) == 3 and stats.read_error is None


@pytest.mark.parametrize("endian,magic,frac", [("<", 0xA1B2C3D4, 1e6), (">", 0xA1B2C3D4, 1e6),
                                               ("<", 0xA1B23C4D, 1e9), (">", 0xA1B23C4D, 1e9)])
def test_other_pcap_flavours_are_not_flagged(tmp_path, endian, magic, frac):
    """Big-endian and nanosecond files are valid and must not trip the framing check."""
    frame = bytes(eth() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5, dport=53))
    path = tmp_path / "flavour.pcap"
    with open(path, "wb") as fh:
        fh.write(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1))
        for i in range(3):
            fh.write(struct.pack(endian + "IIII", 1_700_000_000 + i, int(0.25 * frac), len(frame), len(frame)))
            fh.write(frame)
    stats = IngestStats()
    records = list(iter_pcap_records(path, stats))
    assert [r.timestamp for r in records] == [1_700_000_000.25, 1_700_000_001.25, 1_700_000_002.25]
    assert stats.read_error is None


@pytest.mark.parametrize("payload", [
    b"\xd4\xc3\xb2\xa1" + b"\x00" * 30,                        # PCAP magic, zeroed header (version 0.0)
    b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 28) + b"\xff" * 20,  # PCAPNG block with a bad byte-order magic
], ids=["pcap-bad-version", "pcapng-bad-byte-order"])
def test_invalid_capture_header_fails_without_creating_a_run(tmp_path, payload):
    """These used to be accepted as empty captures and stored as successful zero-packet runs."""
    path = tmp_path / "bad.pcap"
    path.write_bytes(payload)
    with Storage(tmp_path / "bad.db") as storage:
        with pytest.raises(CaptureError):
            process_pcap(path, CONFIG, storage)
        assert storage.list_runs() == []


def test_zero_length_record_is_malformed_not_a_14_byte_packet(tmp_path):
    """An empty record used to dissect as a default Ether frame and be counted with length 14."""
    frame = bytes(eth() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5, dport=53))
    path = tmp_path / "zero.pcap"
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        fh.write(struct.pack("<IIII", 1, 0, 0, 0))                               # caplen 0, wirelen 0
        fh.write(struct.pack("<IIII", 2, 0, len(frame), len(frame)) + frame)
    stats = IngestStats()
    records = list(iter_pcap_records(path, stats))
    assert (stats.seen, stats.parsed, stats.malformed) == (2, 1, 1)
    assert [r.length for r in records] == [len(frame)]


# -- run lifecycle ---------------------------------------------------------------------

def test_interrupted_replay_closes_the_run_as_failed(tmp_path, monkeypatch):
    """Ctrl+C mid-replay used to leave the run 'running' with no finish time, forever."""
    path = write_pcap(tmp_path / "a.pcap", [tcp_packet(float(i), sport=1000 + i) for i in range(50)])
    original = pipeline_module.Pipeline.feed
    calls = {"n": 0}

    def interrupt(self, rec):
        calls["n"] += 1
        if calls["n"] == 30:
            raise KeyboardInterrupt
        return original(self, rec)

    monkeypatch.setattr(pipeline_module.Pipeline, "feed", interrupt)
    with Storage(tmp_path / "i.db") as storage:
        with pytest.raises(KeyboardInterrupt):
            process_pcap(path, CONFIG, storage)
        run = storage.list_runs()[0]
        assert run["status"] == "failed" and run["finished_at"] is not None
        assert "interrupted" in run["note"]
        assert run["windows"] == len(storage.query_windows(run["id"])) > 0


# -- detection -------------------------------------------------------------------------

def test_unexpected_traffic_is_reported_once_per_cooldown_when_top_contributor_changes():
    """The rule counts the whole window, but its cooldown was keyed on the window's top
    contributor, so each distinct contributor re-reported the same ongoing condition."""
    cfg = make_config({"detection": {"cooldown_seconds": 30}})
    storage = Storage(":memory:")
    run_id = storage.start_run("pcap", "alt")
    records = []
    for window in range(6):
        top, other = ("10.0.0.1", "10.0.0.9") if window % 2 == 0 else ("10.0.0.9", "10.0.0.1")
        records += [record(window * 5 + 0.01 * i, src=top, dport=31337, flags=0x10) for i in range(30)]
        records += [record(window * 5 + 3 + 0.01 * i, src=other, dport=31337, flags=0x10) for i in range(20)]
    pipeline = process_records(records, cfg, storage, run_id, IngestStats())
    events = storage.query_events(run_id)
    assert [e["window_start"] for e in events] == [0.0]
    assert pipeline.detector.suppressed == 5


@pytest.mark.parametrize("kind,count,expected", [
    ("syn", 100, set()), ("syn", 101, {"excessive_connection_attempts"}),
    ("ports", 20, {"unexpected_protocol_or_port"}),  # 20 ports is at the limit; ports 1000+ are off-allowlist
    ("ports", 21, {"possible_port_scan", "unexpected_protocol_or_port"}),
    ("hosts", 20, set()), ("hosts", 21, {"possible_port_scan"}),
    ("synack", 500, set()), ("established", 500, set()),
])
def test_threshold_boundaries_through_a_real_pcap(tmp_path, kind, count, expected):
    """Strictly-greater-than semantics, measured on SYN-without-ACK only."""
    packets = []
    for i in range(count):
        ts = i * 4.9 / count
        if kind == "syn":
            packets.append(tcp_packet(ts, dport=443, sport=40000))
        elif kind == "ports":
            packets.append(tcp_packet(ts, dport=1000 + i))
        elif kind == "hosts":
            packets.append(tcp_packet(ts, dst=f"10.1.0.{i + 1}", dport=443))
        elif kind == "synack":
            packets.append(tcp_packet(ts, flags="SA"))
        else:
            packets.append(tcp_packet(ts, flags="PA"))
    path = write_pcap(tmp_path / "b.pcap", packets)
    with Storage(tmp_path / "b.db") as storage:
        summary = process_pcap(path, make_config(), storage)
        assert {e["rule"] for e in storage.query_events(summary.run_id)} == expected


def test_spoofed_sources_beyond_the_tracking_limit_are_surfaced_not_silent():
    """Sources past ``max_sources_per_window`` are counted in totals only; the stored window
    carries the count and the dashboard must report it."""
    cfg = make_config({"window": {"max_sources_per_window": 3}})
    storage = Storage(":memory:")
    run_id = storage.start_run("pcap", "cap")
    records = [record(0.01 * i, src=f"172.16.0.{i + 1}", dport=443, flags=0x02) for i in range(10)]
    process_records(records, cfg, storage, run_id, IngestStats())
    windows = storage.query_windows(run_id)
    assert sum(w["untracked_packets"] for w in windows) == 7
    findings = analysis.generate_findings(storage.get_run(run_id), windows, [], [], {})
    quality = [f for f in findings if f.title == "Per-source tracking was truncated"]
    assert len(quality) == 1 and "7 packets" in quality[0].summary and quality[0].category == "data quality"


def test_no_data_quality_finding_for_clean_runs():
    storage = Storage(":memory:")
    run_id = storage.start_run("pcap", "x")
    pipeline = process_records([record(i, flags=0x10) for i in range(10)], make_config(), storage, run_id,
                               IngestStats())
    storage.finish_run(run_id, "completed", pipeline.totals())
    findings = analysis.generate_findings(storage.get_run(run_id), storage.query_windows(run_id), [], [], {})
    assert not [f for f in findings if f.category == "data quality"]


# -- independent reference model ------------------------------------------------------------

def test_stored_windows_match_an_independent_recomputation(tmp_path):
    """Random mixed traffic written in shuffled order; per-window totals, protocol counts and
    per-source SYN/port/host counts are recomputed here from the raw Scapy packets."""
    rng = random.Random(99)
    window = 5.0
    packets = []
    for _ in range(900):
        ts = 1_700_000_001.37 + rng.random() * 90
        src, dst = f"10.0.{rng.randrange(3)}.{rng.randrange(1, 12)}", f"192.168.1.{rng.randrange(1, 30)}"
        kind = rng.choice(["tcp", "tcp", "udp", "icmp", "arp", "v6", "lldp"])
        body = Raw(b"x" * rng.randrange(0, 150))
        if kind == "tcp":
            pkt = eth() / IP(src=src, dst=dst) / TCP(sport=rng.randrange(1024, 65535),
                                                      dport=rng.choice([22, 80, 8080] + list(range(1000, 1030))),
                                                      flags=rng.choice(["S", "S", "SA", "A", "PA", "F", ""])) / body
        elif kind == "udp":
            pkt = eth() / IP(src=src, dst=dst) / UDP(sport=rng.randrange(1024, 65535), dport=53) / body
        elif kind == "icmp":
            pkt = eth() / IP(src=src, dst=dst) / ICMP() / body
        elif kind == "arp":
            pkt = eth() / ARP(psrc=src, pdst=dst)
        elif kind == "v6":
            pkt = eth() / IPv6(src=f"2001:db8::{rng.randrange(1, 5):x}", dst="2001:db8::ff") / \
                TCP(sport=4000, dport=443, flags=rng.choice(["S", "A"])) / body
        else:
            pkt = eth(type=0x88CC) / Raw(b"lldp" * 8)
        packets.append(stamp(pkt, ts))
    rng.shuffle(packets)
    path = write_pcap(tmp_path / "ref.pcap", packets)
    config = parse_config({"window": {"seconds": window, "top_talkers": 100000},
                           "detection": {"traffic_spike": {"enabled": False}}})

    expected = collections.defaultdict(lambda: {"p": 0, "b": 0, "proto": collections.Counter(),
                                                "src": collections.defaultdict(
                                                    lambda: [0, 0, 0, set(), set()])})
    for pkt in packets:
        win = expected[math.floor(float(pkt.time) / window)]
        length = len(bytes(pkt))
        win["p"] += 1
        win["b"] += length
        if pkt.haslayer(IP):
            ip = pkt[IP]
            proto = {1: "ICMP", 6: "TCP", 17: "UDP"}[ip.proto]
            src, dst = ip.src, ip.dst
        elif pkt.haslayer(IPv6):
            proto, src, dst = "TCP", pkt[IPv6].src, pkt[IPv6].dst
        elif pkt.haslayer(ARP):
            proto, src, dst = "ARP", None, None
        else:
            proto, src, dst = "ETHERTYPE_0x88cc", None, None
        win["proto"][proto] += 1
        if src:
            row = win["src"][src]
            row[0] += 1
            row[1] += length
            if pkt.haslayer(TCP) and int(pkt[TCP].flags) & 0x02 and not int(pkt[TCP].flags) & 0x10:
                row[2] += 1
                row[3].add(pkt[TCP].dport)
                row[4].add(dst)

    db = tmp_path / "ref.db"
    with Storage(db) as storage:
        summary = process_pcap(path, config, storage)
    assert summary.status == "completed" and summary.packets == len(packets)
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    stored = {round(r["window_start"] / window): r for r in conn.execute("SELECT * FROM traffic_stats")}
    assert {i for i, w in expected.items() if w["p"]} == {i for i, r in stored.items() if r["packets"]}
    for index, want in expected.items():
        row = stored[index]
        assert (row["packets"], row["bytes"]) == (want["p"], want["b"])
        assert json.loads(row["protocol_counts"]) == dict(sorted(want["proto"].items()))
        assert row["packets_per_second"] == pytest.approx(want["p"] / window)
        sources = {s["src_ip"]: (s["packets"], s["bytes"], s["syn_attempts"], s["distinct_ports"], s["distinct_hosts"])
                   for s in conn.execute("SELECT * FROM source_stats WHERE window_id = ?", (row["id"],))}
        assert sources == {ip: (v[0], v[1], v[2], len(v[3]), len(v[4])) for ip, v in want["src"].items()}
    totals = conn.execute("SELECT SUM(packets), SUM(bytes) FROM traffic_stats").fetchone()
    assert tuple(totals) == (summary.packets, summary.bytes)


# -- exports are complete and consistent with SQLite ----------------------------------------

def test_exports_match_the_database_independently(tmp_path):
    db = tmp_path / "exp.db"
    with Storage(db) as storage:
        summary = process_pcap(attack_pcap(tmp_path), CONFIG, storage)
        run = storage.get_run(summary.run_id)
        windows = storage.query_windows(summary.run_id)
        events = storage.query_events(summary.run_id, limit=None)
        sources = storage.top_sources(summary.run_id, limit=1000)
        protocols = storage.protocol_totals(summary.run_id)
    payload = analysis.export_payload(run, windows, events, sources,
                                      analysis.generate_findings(run, windows, events, sources, protocols))
    exported = json.loads(analysis.export_json_bytes(payload))
    archive = zipfile.ZipFile(io.BytesIO(analysis.export_csv_zip_bytes(payload)))

    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    raw_windows = list(conn.execute("SELECT * FROM traffic_stats ORDER BY window_start"))
    raw_events = list(conn.execute("SELECT * FROM events ORDER BY ts, id"))

    def utc(ts):
        return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")

    assert [w["window_start_utc"] for w in exported["traffic_windows"]] == [utc(r["window_start"]) for r in raw_windows]
    assert sum(w["packets"] for w in exported["traffic_windows"]) == exported["run"]["packets"] == sum(r["packets"] for r in raw_windows)
    assert sum(w["bytes"] for w in exported["traffic_windows"]) == exported["run"]["bytes"]
    assert [e["id"] for e in exported["events"]] == [r["id"] for r in raw_events]
    assert len(exported["events"]) == exported["run"]["events"] == summary.events
    for want, got in zip(raw_events, exported["events"]):
        assert (got["rule"], got["severity"], got["src_ip"], got["observed"], got["threshold"]) == \
            (want["rule"], want["severity"], want["src_ip"], want["observed"], want["threshold"])
        assert got["timestamp_utc"] == utc(want["ts"])
    rows = list(csv.DictReader(io.StringIO(archive.read("events.csv").decode())))
    assert [int(r["id"]) for r in rows] == [r["id"] for r in raw_events]
    win_rows = list(csv.DictReader(io.StringIO(archive.read("traffic_windows.csv").decode())))
    assert sum(int(r["packets"]) for r in win_rows) == summary.packets
    assert [json.loads(r["protocol_counts"]) for r in win_rows] == [json.loads(r["protocol_counts"]) for r in raw_windows]
    assert str(tmp_path) not in json.dumps(exported)  # no local directory leaks


def test_truncated_upload_is_partial_and_leaves_no_temp_file(tmp_path):
    path = write_pcap(tmp_path / "u.pcap", three_packets())
    content = path.read_bytes()[:-30]
    before = set(Path(tempfile.gettempdir()).glob("lattice-upload-*"))
    with Storage(tmp_path / "u.db") as storage:
        summary = analysis.process_capture_upload("u.pcap", content, CONFIG, storage)
    assert summary.status == "partial" and "incomplete" in summary.note
    assert set(Path(tempfile.gettempdir()).glob("lattice-upload-*")) == before


# -- dashboard -----------------------------------------------------------------------------

def test_unexpected_event_labels_its_source_as_largest_contributor(tmp_path, monkeypatch):
    db = tmp_path / "d.db"
    with Storage(db) as storage:
        process_pcap(attack_pcap(tmp_path), CONFIG, storage)
        unexpected = next(e for e in storage.query_events(1) if e["rule"] == "unexpected_protocol_or_port")
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps(CONFIG.to_dict()), encoding="utf-8")
    at = run_app(db, cfg, tmp_path, monkeypatch)
    open_view(at, "Anomaly events")
    picker = next(box for box in at.selectbox if box.label == "Selected event")
    picker.set_value(unexpected["id"]).run()
    assert not at.exception, [e.value for e in at.exception]
    text = " ".join(c.value for c in at.caption)
    assert "Largest contributor" in text


def _window_whose_end_does_not_survive_a_datetime_round_trip(length):
    """Find a window start whose end ``e`` has ``datetime(e).timestamp() < e`` (about 1 in 5)."""
    first = int(1_700_000_000 / length)
    for index in range(first, first + 10_000):
        end = (index + 1) * length
        if dt.datetime.fromtimestamp(end, tz=dt.timezone.utc).timestamp() < end:
            return index * length
    raise AssertionError(f"no affected window found for length {length}")


def test_events_in_the_last_window_survive_the_default_time_range(tmp_path, monkeypatch):
    """With fractional windows the slider's upper bound, round-tripped through a datetime,
    fell below the final event's timestamp and silently excluded it from the list."""
    length = 0.1
    config = make_config({"window": {"seconds": length}, "detection": {
        "cooldown_seconds": 0, "traffic_spike": {"enabled": False},
        "connection_attempts": {"enabled": False}, "unexpected_traffic": {"enabled": False},
        "port_scan": {"max_distinct_ports": 5, "max_distinct_hosts": None}}})
    start = _window_whose_end_does_not_survive_a_datetime_round_trip(length)
    packets = [udp_packet(start - length + 0.05)]                                          # earlier window
    packets += [tcp_packet(start + 0.01 + i * 0.001, dport=2000 + i) for i in range(12)]  # scan in the last
    db = tmp_path / "frac.db"
    with Storage(db) as storage:
        summary = process_pcap(write_pcap(tmp_path / "frac.pcap", packets), config, storage)
    assert summary.events == 1
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps(config.to_dict()), encoding="utf-8")
    at = run_app(db, cfg, tmp_path, monkeypatch)
    open_view(at, "Anomaly events")
    assert not at.exception, [e.value for e in at.exception]
    assert any("1 matching event" in c.value for c in at.caption)
    assert not any("No events match" in i.value for i in at.info)
