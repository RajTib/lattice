"""Configuration validation and allowlists."""
import json

import pytest

from lattice.config import AllowList, Config, ConfigError, load_config, parse_config

from factories import make_config, record


def test_shipped_config_is_valid():
    cfg = load_config()
    assert cfg.window.seconds > 0
    assert cfg.detection.unexpected_traffic.allowed_ports


def test_empty_config_uses_defaults():
    assert parse_config({}) == Config()


def test_partial_section_keeps_other_defaults():
    cfg = parse_config({"detection": {"connection_attempts": {"max_syn_per_source": 7}}})
    assert cfg.detection.connection_attempts.max_syn_per_source == 7
    assert cfg.detection.port_scan == Config().detection.port_scan


def test_missing_file_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.json")


def test_invalid_json_reports_location(tmp_path):
    path = tmp_path / "c.json"
    path.write_text('{"window": {"seconds": }', encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid JSON at line 1"):
        load_config(path)


def test_load_from_file(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"window": {"seconds": 2.5}, "database": {"path": "x.db"}}), encoding="utf-8")
    cfg = load_config(path)
    assert cfg.window.seconds == 2.5 and cfg.database_path == "x.db"


@pytest.mark.parametrize("data,message", [
    ({"windows": {}}, "unknown key"),
    ({"window": {"secs": 5}}, "window: unknown key"),
    ({"window": {"seconds": "5"}}, "window.seconds: expected a number"),
    ({"window": {"seconds": 0}}, "window.seconds: must be >"),
    ({"window": {"seconds": True}}, "expected a number"),
    ({"window": {"top_talkers": 2.5}}, "whole number"),
    ({"window": []}, "expected a JSON object"),
    ({"detection": {"cooldown_seconds": -1}}, "cooldown_seconds"),
    ({"detection": {"connection_attempts": {"max_syn_per_source": 0}}}, "max_syn_per_source"),
    ({"detection": {"connection_attempts": {"enabled": "yes"}}}, "true or false"),
    ({"detection": {"severity": {"warning_ratio": 5, "high_ratio": 3}}}, "high_ratio must be greater"),
    ({"detection": {"traffic_spike": {"baseline_windows": 2, "min_baseline_windows": 5}}}, "cannot exceed"),
    ({"detection": {"traffic_spike": {"pps_threshold": None, "bps_threshold": None,
                                      "moving_average_multiplier": None}}}, "every threshold is null"),
    ({"detection": {"traffic_spike": {"moving_average_multiplier": 1.0}}}, "moving_average_multiplier"),
    ({"detection": {"unexpected_traffic": {"allowed_ports": [70000]}}}, "port entry"),
    ({"detection": {"unexpected_traffic": {"allowed_ports": ["abc"]}}}, "invalid port entry"),
    ({"detection": {"unexpected_traffic": {"allowed_ports": "80"}}}, "expected a list"),
    ({"detection": {"unexpected_traffic": {"allowed_protocols": [1]}}}, "list of non-empty strings"),
    ({"database": {"path": ""}}, "database.path"),
    ({"capture": {"interface": 5}}, "capture.interface"),
])
def test_invalid_config_names_the_problem(data, message):
    with pytest.raises(ConfigError, match=message):
        parse_config(data)


def test_null_thresholds_are_allowed_when_another_remains():
    cfg = parse_config({"detection": {"traffic_spike": {"pps_threshold": None, "bps_threshold": None}},
                        "capture": {"interface": ""}})
    assert cfg.detection.traffic_spike.pps_threshold is None
    assert cfg.capture.interface is None


def test_processing_fingerprint_tracks_detection_settings_only():
    base = make_config()
    changed = make_config({"detection": {"port_scan": {"max_distinct_ports": 5}}})
    other_db = make_config({"database": {"path": "other.db"}})
    assert base.processing_fingerprint() != changed.processing_fingerprint()
    assert base.processing_fingerprint() == other_db.processing_fingerprint()


# -- allowlist -----------------------------------------------------------------

def _allow(**kw):
    return AllowList.from_config(make_config({"detection": {"unexpected_traffic": kw}})
                                 .detection.unexpected_traffic)


def test_allowlist_accepts_allowed_protocol_and_port():
    assert _allow().violation(record(0, dport=443, sport=50000)) is None


def test_reply_traffic_conforms_via_source_port():
    reply = record(0, src="10.0.0.2", dst="10.0.0.1", sport=443, dport=51234)
    assert _allow().violation(reply) is None


def test_unallowed_port_is_a_violation():
    assert _allow().violation(record(0, sport=50000, dport=31337)) == "port:TCP/31337"


def test_unallowed_protocol_is_a_violation_even_without_ports():
    rec = record(0, protocol="IP_PROTO_47", sport=None, dport=None, flags=None)
    assert _allow().violation(rec) == "protocol:IP_PROTO_47"


def test_icmp_without_ports_conforms():
    assert _allow().violation(record(0, protocol="ICMP", sport=None, dport=None, flags=None)) is None


def test_port_ranges_and_protocol_case():
    allow = _allow(allowed_ports=["8000-8100", "22"], allowed_protocols=["tcp"])
    assert allow.violation(record(0, sport=50000, dport=8050)) is None
    assert allow.violation(record(0, sport=50000, dport=22)) is None
    assert allow.violation(record(0, sport=50000, dport=8101)) is not None
    assert allow.violation(record(0, protocol="UDP", sport=1, dport=22)) == "protocol:UDP"
