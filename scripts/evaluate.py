"""Reproducible evaluation: generate scenarios, run the pipeline, compare with ground truth.

For every scenario the PCAP is replayed through the complete pipeline into a
fresh temporary database, and the stored events are compared with the injected
ground truth (``traffic_gen.Incident``):

* **expected incidents**: injected behaviours Lattice should flag
* **detected incidents**: expected incidents matched by >= 1 event (same rule,
  matching source if specified, event window overlapping the injection interval)
* **missed**: expected but not detected
* **false positive events**: stored events that match no expected incident

Counts of packets and events are deterministic for a given seed and config.
Processing times are *measured on whatever machine runs this* and will vary.

Usage::

    python -m scripts.evaluate                  # writes evaluation/results.json + RESULTS.md
    python -m scripts.evaluate --bench-packets 0    # skip the throughput run
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from lattice.config import Config, load_config
from lattice.pipeline import process_pcap
from lattice.storage import Storage

from . import traffic_gen as gen


def _matches(event: dict[str, Any], incident: gen.Incident) -> bool:
    if event["rule"] != incident.rule:
        return False
    if incident.src_ip is not None and event["src_ip"] != incident.src_ip:
        return False
    lo, hi = gen.T0 + incident.start, gen.T0 + incident.end
    return event["window_start"] < hi and event["window_end"] > lo


def evaluate_scenario(scenario: gen.Scenario, pcap: Path, config: Config, work: Path) -> dict[str, Any]:
    with Storage(work / f"{scenario.name}.db") as db:
        summary = process_pcap(pcap, config, db)
        events = db.query_events(summary.run_id)
    detected = [i for i in scenario.incidents if any(_matches(e, i) for e in events)]
    missed = [i for i in scenario.incidents if i not in detected]
    false_positives = [e for e in events if not any(_matches(e, i) for i in scenario.incidents)]
    return {
        "scenario": scenario.name,
        "description": scenario.description,
        "packets": summary.packets,
        "windows": summary.windows,
        "expected_incidents": len(scenario.incidents),
        "detected_incidents": len(detected),
        "missed_incidents": [f"{i.rule} ({i.src_ip or 'any'})" for i in missed],
        "events_total": len(events),
        "false_positive_events": [
            {"rule": e["rule"], "src_ip": e["src_ip"], "window_start": e["window_start"] - gen.T0,
             "metric": e["metric"], "observed": e["observed"], "threshold": e["threshold"]}
            for e in false_positives],
        "events": [{"rule": e["rule"], "metric": e["metric"], "severity": e["severity"],
                    "src_ip": e["src_ip"], "t": e["window_start"] - gen.T0,
                    "observed": round(e["observed"], 2), "threshold": round(e["threshold"], 2)}
                   for e in events],
        "suppressed_by_cooldown": summary.suppressed_events,
        "processing_seconds": round(summary.elapsed_seconds, 4),
        "packets_per_second_processed": round(summary.packets_per_second_processed),
    }


def benchmark(packets: int, config: Config, work: Path, seed: int) -> dict[str, Any]:
    from scapy.utils import wrpcap

    pcap = work / "load.pcap"
    wrpcap(str(pcap), gen.build_load(packets, seed))
    with Storage(work / "load.db") as db:
        summary = process_pcap(pcap, config, db)
    return {"packets": summary.packets, "windows": summary.windows, "events": summary.events,
            "file_mib": round(pcap.stat().st_size / 2**20, 2),
            "processing_seconds": round(summary.elapsed_seconds, 3),
            "packets_per_second_processed": round(summary.packets_per_second_processed)}


def run_evaluation(work_dir: Path, samples_dir: Optional[Path] = None, config: Optional[Config] = None,
                   seed: int = 1234, bench_packets: int = 100_000) -> dict[str, Any]:
    config = config or load_config()
    work_dir.mkdir(parents=True, exist_ok=True)
    samples = samples_dir or work_dir / "pcaps"
    paths = gen.write_scenarios(samples, seed)
    results = [evaluate_scenario(sc, paths[sc.name], config, work_dir) for sc in gen.build_scenarios(seed)]
    totals = {
        "scenarios": len(results),
        "packets": sum(r["packets"] for r in results),
        "expected_incidents": sum(r["expected_incidents"] for r in results),
        "detected_incidents": sum(r["detected_incidents"] for r in results),
        "missed_incidents": sum(len(r["missed_incidents"]) for r in results),
        "events_total": sum(r["events_total"] for r in results),
        "false_positive_events": sum(len(r["false_positive_events"]) for r in results),
    }
    out: dict[str, Any] = {
        "seed": seed,
        "measured_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "machine": f"{platform.system()} {platform.release()}, Python {platform.python_version()}",
        "window_seconds": config.window.seconds,
        "scenarios": results,
        "totals": totals,
    }
    if bench_packets > 0:
        out["benchmark"] = benchmark(bench_packets, config, work_dir, seed)
    return out


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Lattice evaluation results",
        "",
        "Generated by `python -m scripts.evaluate`. **These numbers were measured by that run**; "
        "rerun it to regenerate. Packet and event counts are deterministic for the seed; "
        "timings depend on the machine.",
        "",
        f"- Measured: {result['measured_at']} on {result['machine']}",
        f"- Seed: {result['seed']}, window length: {result['window_seconds']:g} s, shipped `config.json` thresholds",
        "",
        "| Scenario | Packets | Expected incidents | Detected | Missed | Events | False-positive events | Time (s) | Pkts/s processed |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in result["scenarios"]:
        lines.append(f"| {r['scenario']} | {r['packets']} | {r['expected_incidents']} | {r['detected_incidents']} "
                     f"| {len(r['missed_incidents'])} | {r['events_total']} | {len(r['false_positive_events'])} "
                     f"| {r['processing_seconds']} | {r['packets_per_second_processed']} |")
    t = result["totals"]
    lines += [
        f"| **total** | {t['packets']} | {t['expected_incidents']} | {t['detected_incidents']} "
        f"| {t['missed_incidents']} | {t['events_total']} | {t['false_positive_events']} | | |",
        "",
        "An *incident* is an injected behaviour; it counts as detected if at least one event with the "
        "expected rule (and source, where specified) overlaps its time interval. One incident can produce "
        "several events (for example both a packet-rate and a byte-rate event, or one per window); "
        "events matching no expected incident are counted as false positives.",
        "",
        "Note that the port-scan scenario *expects* two rules: the probed ports are also outside the "
        "default allowlist, so the unexpected-port rule legitimately fires too.",
        "",
        "## Events per scenario",
        "",
    ]
    for r in result["scenarios"]:
        lines.append(f"### {r['scenario']}: {r['description']}")
        if not r["events"]:
            lines += ["", "No events.", ""]
            continue
        lines += ["", "| t (s) | Rule | Metric | Severity | Source | Observed | Threshold |", "|---:|---|---|---|---|---:|---:|"]
        for e in r["events"]:
            lines.append(f"| {e['t']:g} | {e['rule']} | {e['metric']} | {e['severity']} | {e['src_ip'] or '-'} "
                         f"| {e['observed']:g} | {e['threshold']:g} |")
        if r["missed_incidents"]:
            lines += ["", f"**Missed:** {', '.join(r['missed_incidents'])}"]
        if r["false_positive_events"]:
            lines += ["", f"**False positives:** {json.dumps(r['false_positive_events'])}"]
        lines.append("")
    if "benchmark" in result:
        b = result["benchmark"]
        lines += [
            "## Throughput (single run)", "",
            f"{b['packets']} packets ({b['file_mib']} MiB PCAP, {b['windows']} windows, {b['events']} events) "
            f"processed in {b['processing_seconds']} s, about {b['packets_per_second_processed']} packets/s. "
            "This includes reading and parsing with Scapy, aggregation, detection and SQLite writes. It is a "
            "single measurement on one machine, not a performance guarantee.", ""]
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default="evaluation", help="directory for results.json / RESULTS.md")
    parser.add_argument("--samples", default="samples", help="where to write the scenario PCAPs")
    parser.add_argument("--config", help="config.json to evaluate (default: project config.json)")
    parser.add_argument("--seed", type=int, default=1234)
    parser.add_argument("--bench-packets", type=int, default=100_000, help="0 disables the throughput run")
    args = parser.parse_args(argv)

    out = Path(args.out)
    with tempfile.TemporaryDirectory(prefix="lattice-eval-") as tmp:
        result = run_evaluation(Path(tmp), Path(args.samples), load_config(args.config) if args.config else None,
                                args.seed, args.bench_packets)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out / "RESULTS.md").write_text(render_markdown(result), encoding="utf-8")
    t = result["totals"]
    print(f"{t['detected_incidents']}/{t['expected_incidents']} incidents detected, "
          f"{t['missed_incidents']} missed, {t['false_positive_events']} false-positive events "
          f"across {t['scenarios']} scenarios ({t['packets']} packets). Wrote {out}/RESULTS.md")
    return 0 if t["missed_incidents"] == 0 and t["false_positive_events"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
