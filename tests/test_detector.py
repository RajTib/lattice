"""Rule evaluation, severity and cooldown."""
import pytest

from lattice.detector import (RULE_CONNECTION_ATTEMPTS, RULE_PORT_SCAN, RULE_TRAFFIC_SPIKE,
                              RULE_UNEXPECTED, Detector)
from lattice.models import Severity

from factories import make_config, source, window


def detector(**sections):
    return Detector(make_config({"detection": sections}).detection)


def spike_cfg(**kw):
    base = {"pps_threshold": None, "bps_threshold": None, "moving_average_multiplier": None}
    base.update(kw)
    return {"traffic_spike": base, "cooldown_seconds": 0}


def rules(events):
    return [(e.rule, e.metric) for e in events]


# -- Rule A: traffic spike -----------------------------------------------------

def test_absolute_pps_threshold_triggers_only_above():
    det = detector(**spike_cfg(pps_threshold=100))
    assert det.evaluate(window(0, pps=100)) == []        # equal is not "exceeds"
    assert det.evaluate(window(5, pps=99)) == []
    (event,) = det.evaluate(window(10, pps=101))
    assert event.rule == RULE_TRAFFIC_SPIKE and event.metric == "packets_per_second"
    assert (event.observed, event.threshold) == (101.0, 100.0)


def test_absolute_bps_threshold_is_independent_of_pps():
    det = detector(**spike_cfg(bps_threshold=1000))
    (event,) = det.evaluate(window(0, pps=1, bps=5000))
    assert event.metric == "bytes_per_second" and event.observed == 5000


def test_both_metrics_can_fire_in_one_window():
    det = detector(**spike_cfg(pps_threshold=10, bps_threshold=100))
    assert rules(det.evaluate(window(0, pps=50, bps=500))) == [
        (RULE_TRAFFIC_SPIKE, "packets_per_second"), (RULE_TRAFFIC_SPIKE, "bytes_per_second")]


def _warmed(multiplier=3.0, windows=4, pps=10.0, **kw):
    det = detector(**spike_cfg(moving_average_multiplier=multiplier, baseline_windows=6,
                               min_baseline_windows=3, **kw))
    for i in range(windows):
        assert det.evaluate(window(i * 5, pps=pps)) == []
    return det


def test_moving_average_spike_triggers_above_multiple():
    det = _warmed()
    (event,) = det.evaluate(window(20, pps=31))
    assert event.threshold == pytest.approx(30.0) and "moving average" in event.explanation


def test_moving_average_does_not_trigger_at_or_below_multiple():
    det = _warmed()
    assert det.evaluate(window(20, pps=30)) == []
    assert det.evaluate(window(25, pps=12)) == []


def test_no_baseline_means_no_relative_comparison():
    det = detector(**spike_cfg(moving_average_multiplier=2.0, min_baseline_windows=3))
    # Enormous values, but fewer than min_baseline_windows of history.
    assert det.evaluate(window(0, pps=10_000)) == []
    assert det.evaluate(window(5, pps=10_000)) == []


def test_zero_baseline_is_not_compared_against():
    det = _warmed(pps=0.0)
    assert det.evaluate(window(20, pps=500)) == []  # avg 0: never "infinitely larger"


def test_tiny_baseline_below_floor_is_not_compared_against():
    det = _warmed(pps=0.2, min_baseline_pps=1.0)
    assert det.evaluate(window(20, pps=50)) == []


def test_baseline_only_uses_recent_windows():
    det = detector(**spike_cfg(moving_average_multiplier=2.0, baseline_windows=3, min_baseline_windows=3))
    for i, pps in enumerate([1000, 1000, 1000, 10, 10, 10]):   # old high traffic ages out
        det.evaluate(window(i * 5, pps=pps))
    assert det.evaluate(window(30, pps=15)) == []
    assert len(det.evaluate(window(35, pps=25))) == 1


def test_gap_resets_the_baseline():
    det = _warmed()
    assert det.evaluate(window(1000, pps=500, after_gap=True)) == []


def test_absolute_limit_reported_when_it_is_the_widest_margin():
    det = detector(**spike_cfg(pps_threshold=20, moving_average_multiplier=2.0, min_baseline_windows=3))
    for i in range(3):
        det.evaluate(window(i * 5, pps=15))
    (event,) = det.evaluate(window(15, pps=40))   # absolute 20 < relative 30
    assert event.threshold == 20.0


# -- Rule B: connection attempts -------------------------------------------------

def test_connection_attempts_threshold():
    det = detector(connection_attempts={"max_syn_per_source": 50}, cooldown_seconds=0)
    ws = window(0, sources={"1.1.1.1": source(syn=50), "2.2.2.2": source(syn=51, hosts=["9.9.9.9"],
                                                                         ports=[80]),
                            "3.3.3.3": source(syn=10)})
    (event,) = det.evaluate(ws)
    assert event.rule == RULE_CONNECTION_ATTEMPTS and event.src_ip == "2.2.2.2"
    assert (event.observed, event.threshold) == (51.0, 50.0)
    assert "9.9.9.9" in event.dst_info and "80" in event.dst_info
    assert "not established" in event.explanation


def test_each_offending_source_gets_its_own_event():
    det = detector(connection_attempts={"max_syn_per_source": 5}, cooldown_seconds=0)
    ws = window(0, sources={"2.2.2.2": source(syn=9), "1.1.1.1": source(syn=9)})
    assert [e.src_ip for e in det.evaluate(ws)] == ["1.1.1.1", "2.2.2.2"]  # sorted, deterministic


# -- Rule C: port scan ---------------------------------------------------------

def test_port_scan_by_distinct_ports():
    det = detector(port_scan={"max_distinct_ports": 10, "max_distinct_hosts": None}, cooldown_seconds=0)
    ws = window(0, sources={"1.1.1.1": source(ports=range(10)), "2.2.2.2": source(ports=range(11),
                                                                                   hosts=["9.9.9.9"])})
    (event,) = det.evaluate(ws)
    assert event.rule == RULE_PORT_SCAN and event.src_ip == "2.2.2.2"
    assert event.metric == "distinct_destination_ports" and event.observed == 11.0
    assert "(+6 more)" in event.dst_info  # only a sample of ports is stored


def test_port_scan_by_distinct_hosts():
    det = detector(port_scan={"max_distinct_ports": 1000, "max_distinct_hosts": 5}, cooldown_seconds=0)
    hosts = [f"10.1.0.{i}" for i in range(6)]
    (event,) = det.evaluate(window(0, sources={"1.1.1.1": source(ports=[22], hosts=hosts)}))
    assert event.metric == "distinct_destination_hosts" and event.observed == 6.0


def test_host_check_can_be_disabled():
    det = detector(port_scan={"max_distinct_ports": 1000, "max_distinct_hosts": None}, cooldown_seconds=0)
    assert det.evaluate(window(0, sources={"1.1.1.1": source(hosts=[f"h{i}" for i in range(500)])})) == []


# -- Rule D: unexpected protocol/port --------------------------------------------

def test_unexpected_traffic_threshold_and_details():
    det = detector(unexpected_traffic={"max_packets": 5}, cooldown_seconds=0)
    below = window(0, unexpected_total=5, unexpected_breakdown={"port:TCP/31337": 5},
                   unexpected_sources={"1.1.1.1": 5})
    assert det.evaluate(below) == []
    above = window(5, unexpected_total=8, unexpected_breakdown={"port:TCP/31337": 6, "protocol:GRE": 2},
                   unexpected_sources={"1.1.1.1": 6, "2.2.2.2": 2})
    (event,) = det.evaluate(above)
    assert event.rule == RULE_UNEXPECTED and (event.observed, event.threshold) == (8.0, 5.0)
    assert event.src_ip == "1.1.1.1"
    assert "TCP/31337 x6" in event.explanation and "GRE x2" in event.dst_info


# -- configuration switches ---------------------------------------------------------

def test_disabled_rules_stay_silent():
    det = detector(connection_attempts={"enabled": False, "max_syn_per_source": 1},
                   port_scan={"enabled": False, "max_distinct_ports": 1},
                   unexpected_traffic={"enabled": False, "max_packets": 1},
                   traffic_spike={"enabled": False, "pps_threshold": 1})
    ws = window(0, pps=999, sources={"1.1.1.1": source(syn=999, ports=range(99), hosts=["a", "b"])},
                unexpected_total=99, unexpected_breakdown={"x:y": 99})
    assert det.evaluate(ws) == []


# -- severity ---------------------------------------------------------------------

@pytest.mark.parametrize("observed,expected", [
    (101, Severity.INFO), (199, Severity.INFO),
    (200, Severity.WARNING), (499, Severity.WARNING),
    (500, Severity.HIGH), (5000, Severity.HIGH),
])
def test_severity_follows_observed_to_threshold_ratio(observed, expected):
    det = detector(connection_attempts={"max_syn_per_source": 100},
                   severity={"warning_ratio": 2.0, "high_ratio": 5.0}, cooldown_seconds=0)
    (event,) = det.evaluate(window(0, sources={"1.1.1.1": source(syn=observed)}))
    assert event.severity is expected


# -- cooldown / deduplication --------------------------------------------------------

def _scan_window(start, syn=150, ip="1.1.1.1"):
    return window(start, sources={ip: source(syn=syn)})


def test_continuous_condition_is_reported_once_per_cooldown():
    det = detector(connection_attempts={"max_syn_per_source": 100}, cooldown_seconds=30)
    emitted = [len(det.evaluate(_scan_window(i * 5))) for i in range(8)]  # event times 5..40
    assert emitted == [1, 0, 0, 0, 0, 0, 1, 0]
    assert det.suppressed == 6


def test_cooldown_is_per_source_and_per_rule():
    det = detector(connection_attempts={"max_syn_per_source": 100}, cooldown_seconds=30)
    assert len(det.evaluate(_scan_window(0, ip="1.1.1.1"))) == 1
    assert len(det.evaluate(_scan_window(5, ip="2.2.2.2"))) == 1     # different source
    assert len(det.evaluate(_scan_window(10, ip="1.1.1.1"))) == 0    # same key


def test_escalation_bypasses_cooldown():
    det = detector(connection_attempts={"max_syn_per_source": 100}, cooldown_seconds=60)
    assert det.evaluate(_scan_window(0, syn=120))[0].severity is Severity.INFO
    assert det.evaluate(_scan_window(5, syn=120)) == []
    (event,) = det.evaluate(_scan_window(10, syn=900))
    assert event.severity is Severity.HIGH


def test_zero_cooldown_reports_every_window():
    det = detector(connection_attempts={"max_syn_per_source": 100}, cooldown_seconds=0)
    assert [len(det.evaluate(_scan_window(i * 5))) for i in range(4)] == [1, 1, 1, 1]
    assert det.suppressed == 0


def test_cooldown_table_does_not_grow_without_bound():
    det = detector(connection_attempts={"max_syn_per_source": 1}, cooldown_seconds=10)
    for i in range(200):
        det.evaluate(window(i * 5, sources={f"10.0.{i // 250}.{i % 250}": source(syn=5)}))
    assert len(det._last) <= 3


# -- determinism ---------------------------------------------------------------------

def test_identical_input_gives_identical_events():
    def play():
        det = detector(cooldown_seconds=15)
        out = []
        for i in range(20):
            sources = {f"10.0.0.{j}": source(syn=60 * j, ports=range(5 * j), hosts=[f"h{k}" for k in range(j)])
                       for j in range(1, 5)}
            out += det.evaluate(window(i * 5, pps=10 + (i % 7) * 40, bps=1000 * (i % 5), sources=sources))
        return out, det.suppressed

    assert play() == play()
