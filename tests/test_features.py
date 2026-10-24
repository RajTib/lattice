"""Window aggregation."""
import pytest

from lattice.config import AllowList, WindowConfig
from lattice.features import Aggregator

from factories import make_config, record


def run(records, window=None, allow=None):
    agg = Aggregator(window or WindowConfig(seconds=5), allow)
    out = []
    for rec in records:
        out += agg.add(rec)
    out += agg.flush()
    return out, agg


def test_counts_bytes_and_rates():
    recs = [record(t, length=100) for t in (0.0, 1.0, 2.0, 3.0, 4.0)] + [record(4.5, length=250)]
    (win,), _ = run(recs)
    assert (win.start, win.end) == (0.0, 5.0)
    assert win.packets == 6 and win.bytes == 750
    assert win.packets_per_second == pytest.approx(6 / 5)
    assert win.bytes_per_second == pytest.approx(750 / 5)


def test_protocol_distribution():
    recs = [record(0, protocol="TCP"), record(1, protocol="TCP"), record(2, protocol="UDP", flags=None),
            record(3, protocol="ICMP", sport=None, dport=None, flags=None)]
    (win,), _ = run(recs)
    assert win.protocol_counts == {"ICMP": 1, "TCP": 2, "UDP": 1}


def test_window_boundaries_are_half_open():
    recs = [record(0.0), record(4.999), record(5.0), record(9.999)]
    wins, _ = run(recs)
    assert [(w.start, w.end, w.packets) for w in wins] == [(0.0, 5.0, 2), (5.0, 10.0, 2)]


def test_windows_are_aligned_to_multiples_of_the_length():
    (win,), _ = run([record(1_700_000_003.2)])
    assert win.start == 1_700_000_000.0 and win.end == 1_700_000_005.0


def test_window_placement_ignores_the_wall_clock(monkeypatch):
    import time
    monkeypatch.setattr(time, "time", lambda: 42.0)
    (win,), _ = run([record(1000.0)])
    assert win.start == 1000.0


def test_gap_produces_empty_windows_with_zero_rates():
    wins, _ = run([record(0.0), record(20.0)])
    assert [w.start for w in wins] == [0.0, 5.0, 10.0, 15.0, 20.0]
    empty = wins[1:4]
    assert all(w.packets == 0 and w.bytes == 0 and w.packets_per_second == 0 for w in empty)
    assert all(w.protocol_counts == {} and w.sources == {} for w in empty)


def test_very_large_gap_is_skipped_and_flagged():
    wins, _ = run([record(0.0), record(10_000.0)], WindowConfig(seconds=5, max_gap_windows=3))
    assert [w.start for w in wins] == [0.0, 10_000.0]
    assert wins[1].after_gap and not wins[0].after_gap


def test_gap_exactly_at_limit_is_filled():
    wins, _ = run([record(0.0), record(20.0)], WindowConfig(seconds=5, max_gap_windows=3))
    assert len(wins) == 5 and not any(w.after_gap for w in wins)


def test_no_packets_means_no_windows():
    wins, _ = run([])
    assert wins == []


def test_late_packet_is_folded_into_open_window_and_counted():
    wins, agg = run([record(10.0), record(2.0)])
    assert len(wins) == 1
    assert wins[0].packets == 2 and wins[0].late_packets == 1
    assert agg.late_packets_total == 1


def test_syn_attempts_ports_and_hosts_per_source():
    recs = [record(0, src="1.1.1.1", dst="9.9.9.1", dport=80),
            record(1, src="1.1.1.1", dst="9.9.9.1", dport=81),
            record(2, src="1.1.1.1", dst="9.9.9.2", dport=80),
            record(3, src="2.2.2.2", dst="9.9.9.1", dport=443)]
    (win,), _ = run(recs)
    a, b = win.sources["1.1.1.1"], win.sources["2.2.2.2"]
    assert (a.packets, a.syn_attempts, a.distinct_ports, a.distinct_hosts) == (3, 3, 2, 2)
    assert (b.packets, b.syn_attempts, b.distinct_ports, b.distinct_hosts) == (1, 1, 1, 1)


def test_only_syn_without_ack_counts_as_connection_attempt():
    recs = [record(0, flags=0x02),            # SYN: counts
            record(1, flags=0x12, dport=81),  # SYN+ACK (a reply): not an attempt
            record(2, flags=0x10, dport=82),  # ACK
            record(3, flags=0x04, dport=83),  # RST
            record(4, protocol="UDP", flags=None, dport=84)]
    (win,), _ = run(recs)
    s = win.sources["10.0.0.1"]
    assert s.packets == 5 and s.syn_attempts == 1
    assert s.dst_ports == {443}  # replies and UDP never inflate scan counters


def test_retransmitted_syns_count_as_attempts_but_not_as_new_ports():
    recs = [record(t, dport=80) for t in (0.0, 1.0, 3.0)]
    (win,), _ = run(recs)
    s = win.sources["10.0.0.1"]
    assert s.syn_attempts == 3 and s.distinct_ports == 1 and s.distinct_hosts == 1


def test_packets_without_ip_are_counted_but_not_attributed():
    arp = record(0, src=None, dst=None, protocol="ARP", sport=None, dport=None, flags=None)
    (win,), _ = run([arp])
    assert win.packets == 1 and win.sources == {} and win.protocol_counts == {"ARP": 1}


def test_source_table_is_capped_and_overflow_is_reported():
    recs = [record(0, src=f"10.0.0.{i}") for i in range(1, 6)]
    (win,), _ = run(recs, WindowConfig(seconds=5, max_sources_per_window=3))
    assert len(win.sources) == 3 and win.untracked_packets == 2 and win.packets == 5


def test_state_does_not_leak_between_windows():
    wins, agg = run([record(0, src="1.1.1.1"), record(6, src="2.2.2.2")])
    assert set(wins[0].sources) == {"1.1.1.1"} and set(wins[1].sources) == {"2.2.2.2"}
    assert agg._open is None and agg._idx is None  # flush released everything


def test_top_sources_ranking_is_deterministic():
    recs = [record(0, src="9.9.9.9")] * 2 + [record(0, src="1.1.1.1")] * 2 + [record(0, src="5.5.5.5")]
    (win,), _ = run(recs)
    assert [ip for ip, _ in win.top_sources(2)] == ["1.1.1.1", "9.9.9.9"]


def test_advance_closes_windows_from_the_clock():
    agg = Aggregator(WindowConfig(seconds=5))
    assert agg.advance(100.0) == []           # anchors, nothing to emit
    agg.add(record(101.0))
    closed = agg.advance(112.0)
    assert [(w.start, w.packets) for w in closed] == [(100.0, 1), (105.0, 0)]
    assert agg.advance(113.0) == []           # same open window


def test_flush_skips_an_empty_open_window():
    agg = Aggregator(WindowConfig(seconds=5))
    agg.advance(100.0)
    assert agg.flush() == []


def test_unexpected_traffic_is_classified_during_aggregation():
    allow = AllowList.from_config(make_config().detection.unexpected_traffic)
    recs = [record(0, sport=50000, dport=31337)] * 3 + [record(1, protocol="IP_PROTO_47", sport=None,
                                                               dport=None, flags=None)] \
        + [record(2, sport=50000, dport=443)]
    (win,), _ = run(recs, allow=allow)
    assert win.unexpected_total == 4
    assert win.unexpected_breakdown == {"port:TCP/31337": 3, "protocol:IP_PROTO_47": 1}
    assert win.unexpected_sources == {"10.0.0.1": 4}


def test_unexpected_breakdown_is_bounded():
    allow = AllowList.from_config(make_config().detection.unexpected_traffic)
    recs = [record(0, sport=50000, dport=10_000 + i) for i in range(200)]
    (win,), _ = run(recs, allow=allow)
    assert win.unexpected_total == 200 and len(win.unexpected_breakdown) <= 65
    assert win.unexpected_breakdown["other"] == 200 - 64


def test_aggregation_is_deterministic():
    recs = [record(i * 0.7, src=f"10.0.0.{i % 4}", dport=80 + i % 9) for i in range(60)]
    first, _ = run(list(recs))
    second, _ = run(list(recs))
    assert first == second
