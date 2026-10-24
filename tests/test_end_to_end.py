"""Deterministic end-to-end scenarios: packets -> SQLite -> dashboard data."""
from __future__ import annotations

import pytest
from scapy.layers.inet import IP
from scapy.packet import Raw

from lattice import dashboard_data as dd
from lattice.pipeline import process_pcap
from lattice.storage import Storage

from factories import eth, make_config, stamp, tcp_packet, udp_packet, write_pcap


DISABLED_RULES = {
    "traffic_spike": {"enabled": False},
    "connection_attempts": {"enabled": False},
    "port_scan": {"enabled": False},
    "unexpected_traffic": {"enabled": False},
}


def config_for(rule: str, settings: dict, *, cooldown: float = 0):
    detection = {name: dict(values) for name, values in DISABLED_RULES.items()}
    detection[rule] = {"enabled": True, **settings}
    detection["cooldown_seconds"] = cooldown
    return make_config({"window": {"seconds": 5}, "detection": detection})


def play(tmp_path, packets, config):
    path = write_pcap(tmp_path / "scenario.pcap", packets)
    with Storage(tmp_path / "scenario.db") as storage:
        summary = process_pcap(path, config, storage)
        windows = storage.query_windows(summary.run_id)
        events = storage.query_events(summary.run_id)
        protocols = storage.protocol_totals(summary.run_id)
        # Exercise the same transformations used by the dashboard.
        window_frame = dd.windows_frame(windows)
        event_frame = dd.events_frame(events)
    return summary, windows, events, protocols, window_frame, event_frame


@pytest.mark.parametrize("name,packets,config,expected", [
    (
        "normal",
        [udp_packet(i / 2, dport=53) for i in range(20)],
        make_config({"window": {"seconds": 5}, "detection": DISABLED_RULES}),
        None,
    ),
    (
        "traffic_spike",
        [tcp_packet(i / 12, flags="A") for i in range(60)],
        config_for("traffic_spike", {
            "pps_threshold": 10, "bps_threshold": None, "moving_average_multiplier": None}),
        ("traffic_spike", "packets_per_second", None, 12.0, 10.0),
    ),
    (
        "syn_activity",
        [tcp_packet(i / 2, src="203.0.113.10", dport=443, flags="S") for i in range(6)],
        config_for("connection_attempts", {"max_syn_per_source": 5}),
        ("excessive_connection_attempts", "syn_attempts", "203.0.113.10", 6.0, 5.0),
    ),
    (
        "port_scan",
        [tcp_packet(i / 2, src="203.0.113.20", dport=1000 + i, flags="S") for i in range(6)],
        config_for("port_scan", {"max_distinct_ports": 5, "max_distinct_hosts": None}),
        ("possible_port_scan", "distinct_destination_ports", "203.0.113.20", 6.0, 5.0),
    ),
    (
        "host_sweep",
        [tcp_packet(i / 2, src="203.0.113.30", dst=f"198.51.100.{i + 1}", dport=443, flags="S")
         for i in range(6)],
        config_for("port_scan", {"max_distinct_ports": 100, "max_distinct_hosts": 5}),
        ("possible_port_scan", "distinct_destination_hosts", "203.0.113.30", 6.0, 5.0),
    ),
    (
        "unexpected_protocol",
        [stamp(eth() / IP(src="192.0.2.10", dst="198.51.100.10", proto=47) / Raw(b"x"), i / 2)
         for i in range(6)],
        config_for("unexpected_traffic", {"max_packets": 5}),
        ("unexpected_protocol_or_port", "unexpected_packets", "192.0.2.10", 6.0, 5.0),
    ),
    (
        "unexpected_port",
        [tcp_packet(i / 2, src="192.0.2.20", dport=31337, flags="A") for i in range(6)],
        config_for("unexpected_traffic", {"max_packets": 5}),
        ("unexpected_protocol_or_port", "unexpected_packets", "192.0.2.20", 6.0, 5.0),
    ),
])
def test_scenario_end_to_end(tmp_path, name, packets, config, expected):
    summary, windows, events, protocols, window_frame, event_frame = play(tmp_path, packets, config)

    assert summary.status == "completed" and summary.packets == len(packets), name
    assert sum(w["packets"] for w in windows) == len(packets)
    assert sum(protocols.values()) == len(packets)
    assert int(window_frame["packets"].sum()) == len(packets)

    if expected is None:
        assert events == [] and event_frame.empty
        return

    assert len(events) == 1
    event = events[0]
    assert (event["rule"], event["metric"], event["src_ip"], event["observed"], event["threshold"]) == expected
    assert len(event_frame) == 1 and event_frame.iloc[0]["rule"] == expected[0]


def test_repeated_anomaly_cooldown_is_persisted(tmp_path):
    packets = [
        tcp_packet(window + i / 2, src="203.0.113.40", dport=443, flags="S")
        for window in (0, 5, 10)
        for i in range(6)
    ]
    config = config_for("connection_attempts", {"max_syn_per_source": 5}, cooldown=10)
    summary, windows, events, _, _, _ = play(tmp_path, packets, config)

    assert len(windows) == 3 and [e["window_start"] for e in events] == [0.0, 10.0]
    assert summary.events == 2 and summary.suppressed_events == 1
