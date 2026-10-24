"""The evaluation scenarios must be reproducible and detect exactly what they inject."""
import pytest

from scripts import traffic_gen as gen
from scripts.evaluate import render_markdown, run_evaluation


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    return run_evaluation(tmp_path_factory.mktemp("eval"), bench_packets=0)


def test_every_scenario_detects_its_incidents_without_false_positives(result):
    for r in result["scenarios"]:
        assert r["missed_incidents"] == [], r["scenario"]
        assert r["false_positive_events"] == [], r["scenario"]
        assert r["detected_incidents"] == r["expected_incidents"], r["scenario"]


def test_normal_traffic_raises_no_events(result):
    normal = next(r for r in result["scenarios"] if r["scenario"] == "normal")
    assert normal["events_total"] == 0 and normal["expected_incidents"] == 0


def test_each_attack_scenario_raises_its_rule(result):
    rules = {r["scenario"]: {e["rule"] for e in r["events"]} for r in result["scenarios"]}
    assert rules["rate_spike"] == {"traffic_spike"}
    assert rules["syn_flood"] == {"excessive_connection_attempts"}
    assert rules["port_scan"] == {"possible_port_scan", "unexpected_protocol_or_port"}
    assert rules["host_sweep"] == {"possible_port_scan"}
    assert rules["unexpected_protocol"] == {"unexpected_protocol_or_port"}
    assert rules["unexpected_port"] == {"unexpected_protocol_or_port"}
    assert rules["unexpected_traffic"] == {"unexpected_protocol_or_port"}


def test_totals_and_markdown_report(result):
    assert result["totals"]["scenarios"] == 8
    assert result["totals"]["missed_incidents"] == 0 and result["totals"]["false_positive_events"] == 0
    text = render_markdown(result)
    assert "measured by that run" in text and "| syn_flood |" in text


def test_traffic_generation_is_deterministic():
    import random

    def sample(seed):
        return [(float(p.time), bytes(p)) for p in gen.background(random.Random(seed), 8)]

    assert sample(7) == sample(7)   # same seed -> identical packets and timestamps
    assert sample(7) != sample(8)
