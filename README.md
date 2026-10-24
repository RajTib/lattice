# Lattice

A small, **passive** network traffic analysis and anomaly detection tool for small networks and offline PCAP files. It captures or replays packets, extracts header-level features, aggregates them into fixed time windows, applies four configurable rules, stores everything in SQLite and shows it in a Streamlit dashboard.

Lattice is an educational prototype (Computer Networks course project). It **monitors only**: it never blocks, modifies or injects traffic, and it stores headers, not payloads. Events are *indicators of potentially unusual behaviour, not proof of an attack*.

## Architecture

```
Traffic input ─► Capture & parsing ─► Feature extraction ─► Rule-based detection ─► SQLite ─► Streamlit
 (PCAP / live)   capture.py          features.py            detector.py            storage.py   app.py
                 parser.py
```

| Module | Responsibility |
|---|---|
| `lattice/parser.py` | Scapy packet → normalized `PacketRecord` (timestamp, length, protocol, IPs, ports, TCP flags). Downstream code never sees Scapy objects. |
| `lattice/capture.py` | PCAP/PCAPNG reading (sorted, malformed packets counted) and `LiveCapture` (background sniffer, bounded queue, clean stop). |
| `lattice/features.py` | `Aggregator`: fixed windows, rates, protocol mix, per-source SYN/port/host counts, bounded state. |
| `lattice/detector.py` | `Detector`: four rules, severity, cooldown. No I/O. |
| `lattice/storage.py` | SQLite schema, atomic per-window writes, filtered queries, safe reset. |
| `lattice/pipeline.py` | Wires the stages together; PCAP processing with duplicate detection. |
| `lattice/live.py` | `LiveMonitor`: worker thread that owns sniffer, DB connection and pipeline for a live session. |
| `lattice/config.py` | `config.json` loading and strict validation; protocol/port allowlist. |
| `lattice/dashboard_data.py` | Pure functions shaping stored rows for display. |
| `app.py` | Streamlit dashboard (reads the database). |
| `lattice/cli.py` | `python -m lattice …` command line. |
| `scripts/` | Synthetic traffic generator and evaluation runner. |

### Definitions used throughout

* **Packet**: one captured frame that parsed successfully.
* **Connection attempt**: a TCP packet with SYN set and ACK clear. Lattice does no session tracking, so a retransmitted or duplicate SYN counts as another attempt, and it **never claims a connection was established**.
* **Window**: `[start, end)`, aligned to multiples of `window.seconds` on the *packet-timestamp* axis (offline replay never reads the machine clock). Rates divide by the full window length, so a partly filled final window reads low. Gaps become empty windows (zero rates) up to `window.max_gap_windows`; longer gaps are skipped and the detector's baseline is reset. A packet older than the open window (live reordering) is folded into the open window and counted as late.
* Per-source port/host counts (Rules B and C) use **SYN-without-ACK packets only**. Counting all packets would make a server replying to many clients look like a scanner.
* Unsupported protocols are *kept*: they appear as `IP_PROTO_<n>` or `ETHERTYPE_0x….` Only structurally invalid packets (e.g. IPv4 IHL < 5) are skipped, and they are counted in the "skipped packets" statistic.

## Prerequisites

* Python 3.10+ (developed on 3.14)
* Offline analysis, tests and the dashboard need **no** administrator rights and no network access.
* Live capture only: privileges and (on Windows) Npcap. See [Live capture](#live-capture).

## Installation

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate        Linux/macOS:  source .venv/bin/activate
pip install -r requirements.txt
```

## Quick start

```bash
python -m scripts.traffic_gen --out samples        # generate the synthetic sample PCAPs (seeded, reproducible)
python -m lattice --db lattice.db replay samples/*.pcap   # on Windows PowerShell expand with: (Get-ChildItem samples\*.pcap).FullName
streamlit run app.py                               # opens the dashboard; select a run in the sidebar
```

Dashboard tabs: **Overview** (mode, status, totals, latest window, skipped packets), **Traffic analytics** (packets/s, bytes/s, protocol distribution, top sources), **Anomaly events** (filters by rule, severity and time; observed vs. threshold; explanations) and **Input & controls** (PCAP processing, live start/stop, configuration). A banner always states whether the data shown is *historical* or *live*. The dashboard reads persisted data; reruns never reprocess a PCAP.

Set `LATTICE_DB` / `LATTICE_CONFIG` to override the database path or config file.

## Replaying a PCAP

```bash
python -m lattice replay capture.pcap [more.pcapng …] [--config config.json] [--db lattice.db] [--force]
```

A file already processed with identical settings (content hash + window/detection config) is reported as already processed and not stored twice; `--force` replaces the earlier run. Packets are replayed in timestamp order (stable for ties), so results are deterministic.

## Live capture

> Only capture on interfaces and networks you are **authorized** to monitor.

```bash
python -m lattice interfaces                       # lists interfaces and whether capture looks possible
python -m lattice live --interface "Ethernet" --filter "tcp or udp" [--duration 300]
```

Or use the dashboard's *Input & controls* tab (requires ticking an authorization box). Stop with Ctrl+C or the Stop button; stopping joins the sniffer thread, drains the queue, flushes the last window and closes the run record.

| OS | Requirement |
|---|---|
| Windows | Install [Npcap](https://npcap.com) and run from an **Administrator** terminal. Without Npcap, Scapy cannot sniff and Lattice reports this instead of starting. |
| Linux | Root, or `sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python))`. |
| macOS | Access to `/dev/bpf*` (usually root). |

**Verification status:** live capture is covered by tests using a fake sniffer (lifecycle, queue overflow, error paths, no leaked threads) and by a test that the real Scapy sniffer fails cleanly on a nonexistent interface. It has **not** been exercised against a real network, because the development machine had no Npcap. Treat real-traffic behaviour as unverified.

## Configuration reference (`config.json`)

Unknown keys, wrong types and out-of-range values are rejected with the offending key named. Missing keys use the defaults shown. Every rule fires when the observed value is **strictly greater** than its threshold.

| Key | Default | Meaning |
|---|---|---|
| `database.path` | `lattice.db` | SQLite file (`--db` overrides). |
| `capture.interface` / `bpf_filter` | `null` | Default interface and BPF filter for live mode. |
| `capture.queue_size` | 20000 | Live packet queue; overflow is dropped and counted. |
| `window.seconds` | 5 | Window length. |
| `window.max_gap_windows` | 12 | Gaps up to this many windows are filled with empty windows. |
| `window.top_talkers` | 10 | Sources stored per window. |
| `window.max_sources_per_window` | 5000 | Memory bound; extra sources are counted, not tracked. |
| `detection.cooldown_seconds` | 30 | Same (rule, source, metric) is suppressed this long unless severity escalates. `0` disables. |
| `detection.severity.warning_ratio` / `high_ratio` | 2.0 / 5.0 | Severity from `observed ÷ threshold`: **INFO** below `warning_ratio`, **WARNING** from it, **HIGH** from `high_ratio`. |
| `traffic_spike.pps_threshold` / `bps_threshold` | 1000 / 1 000 000 | Absolute packets/s and bytes/s limits (`null` disables). |
| `traffic_spike.moving_average_multiplier` | 4.0 | Fire when a rate exceeds this multiple of the recent average (`null` disables). |
| `traffic_spike.baseline_windows` | 6 | Windows in the moving average. |
| `traffic_spike.min_baseline_windows` | 3 | No relative comparison until this much history exists. |
| `traffic_spike.min_baseline_pps` / `min_baseline_bps` | 1.0 / 100 | Averages below this are ignored (no comparisons against ~zero). |
| `connection_attempts.max_syn_per_source` | 100 | SYN-without-ACK packets per source per window (Rule B). |
| `port_scan.max_distinct_ports` | 20 | Distinct destination ports probed per source per window (Rule C). |
| `port_scan.max_distinct_hosts` | 20 | Distinct destination hosts probed (`null` disables). |
| `unexpected_traffic.max_packets` | 10 | Packets outside the allowlists per window (Rule D). |
| `unexpected_traffic.allowed_protocols` | TCP, UDP, ICMP, ICMPv6, ARP | Anything else (e.g. `IP_PROTO_47`) counts as unexpected. |
| `unexpected_traffic.allowed_ports` | 22, 53, 80, 123, 443 | Ints or ranges like `"8000-8100"`. A TCP/UDP packet conforms if **either** endpoint port is allowed (replies carry the service port as source). |

Each rule also has `"enabled": true|false`. **Tune the allowlist and thresholds to your network**; the defaults are only reasonable for a small office-like environment.

Rules: `traffic_spike`, `excessive_connection_attempts`, `possible_port_scan`, `unexpected_protocol_or_port`. A port scan to ports outside the allowlist legitimately raises both Rule C and Rule D.

## Database

Tables: `runs` (one per replay or live session), `traffic_stats` (per window), `source_stats` (top talkers per window), `events`. Each window's stats, events and the run totals are written in one transaction. `python -m lattice init-db` creates the schema; `python -m lattice --db test.db reset-db --yes` drops and recreates Lattice tables **only** in a file already marked as a Lattice database, and refuses without `--yes`. Use a dedicated `--db` path for experiments.

## Tests

```bash
pytest
```

Tests use synthetic Scapy packets and temporary databases; they need no privileges, interface or internet.

## Evaluation

```bash
python -m scripts.evaluate                 # generates samples/*.pcap, runs them, writes evaluation/RESULTS.md and results.json
python -m scripts.evaluate --bench-packets 0   # skip the throughput run
```

Five seeded scenarios: normal traffic, rate spike, SYN burst, port scan, unexpected port/protocol. The report lists expected incidents, detected incidents, missed incidents, false-positive events and processing speed, **all measured by that run**. See `evaluation/RESULTS.md` for the latest numbers. The scenarios are synthetic and were designed alongside the thresholds, so they show that the rules work as specified, not how they would perform on real traffic.

## Known limitations

* Threshold rules are simple. They miss slow scans, distributed attacks and anything under the thresholds, and they flag legitimate bursts (backups, software updates). They cannot identify every attack.
* Scan detection looks only at TCP SYN-without-ACK. UDP/ICMP sweeps and FIN/NULL/Xmas scans are not detected.
* Rule D's "either port allowed" check can be sidestepped by using an allowed source port.
* No session reconstruction, IP defragmentation, TLS inspection or payload analysis.
* PCAPs are loaded into memory (header fields only) so they can be sorted; very large captures need proportionally more RAM. Throughput is limited by Scapy's parsing (≈6k packets/s measured here).
* Sustained load raises the moving-average baseline, so a long flood stops triggering the *relative* spike rule (the absolute limits still apply).
* The window clock in live mode follows the machine clock when traffic is idle.
* Timestamps are shown in UTC.

## Troubleshooting

* **"Npcap was not found"** (Windows): install Npcap, restart the terminal as Administrator.
* **"Operation not permitted" / "Permission denied"** (Linux/macOS): run with root or grant `cap_net_raw`.
* **Interface name rejected**: copy the name exactly from `python -m lattice interfaces`.
* **"not a Lattice database"**: `database.path` points at some other SQLite file; choose a different path.
* **Dashboard shows "interrupted"**: a live run was marked running but nothing has written for 30 s (the capturing process probably exited). The stored data is still shown.
* **Config error at startup**: the message names the key; fix `config.json`.

## How Lattice differs from Zeek and Snort

Zeek and Snort are mature, production network security monitors: deep protocol analysers, signature/script engines, reassembly of flows, high-rate capture, and large rule ecosystems. Lattice is deliberately tiny: header-level features, four threshold rules, SQLite and a dashboard, meant for learning how traffic statistics and simple anomaly rules work. It is not a replacement for either.
