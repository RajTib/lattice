# Lattice user guide

This guide covers the command-line interface and the Streamlit workflows used to
process captures, inspect stored results, compare runs, and export evidence. For
processing semantics and detector formulas, see the [technical
reference](technical-reference.md). For installation and runtime failures, see
[troubleshooting](troubleshooting.md).

Lattice is passive: it reads packets but never sends, blocks, or modifies
traffic. Only capture interfaces and networks that you are authorized to
monitor. A detection event is a threshold crossing to investigate, not proof of
an attack.

## Prepare the environment

From the repository root, create and activate a virtual environment, then
install the declared dependencies.

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Linux or macOS:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Offline replay needs no capture driver or elevated permission. Live capture has
additional platform requirements described under [live capture](#live-capture).

## Command-line interface

Run `python -m lattice --help` for the installed command summary. Global options
must appear before the subcommand.

```text
python -m lattice [--config PATH] [--db PATH] [-v]
                  {replay,live,interfaces,init-db,reset-db} ...
```

| Global option | Purpose |
|---|---|
| `--config PATH` | Load and validate another JSON configuration instead of the repository `config.json` |
| `--db PATH` | Override `database.path` for this command |
| `-v`, `--verbose` | Enable debug logging |

### Replay PCAP or PCAPNG files

```text
python -m lattice [global options] replay PCAP [PCAP ...] [--force]
```

Process one included capture into a dedicated database:

```powershell
python -m lattice --db lattice.db replay .\samples\normal.pcap
```

Process several files:

```powershell
python -m lattice --db lattice.db replay `
  .\samples\normal.pcap `
  .\samples\rate_spike.pcap `
  .\samples\port_scan.pcap
```

Linux or macOS:

```bash
python -m lattice --db lattice.db replay \
  samples/normal.pcap \
  samples/rate_spike.pcap \
  samples/port_scan.pcap
```

`--force` belongs to the `replay` subcommand. It requests a replacement even if
the same capture was already processed with the same analysis settings:

```bash
python -m lattice --db lattice.db replay capture.pcap --force
```

Without `--force`, Lattice reuses a completed run with the same content and
processing fingerprint. A forced replay keeps the previous completed run until
the replacement finishes successfully.

The command prints the run identifier, packet and byte totals, stored-window
count, event count, skipped packets, cooldown suppressions, and processing time.
If one of several inputs fails, replay continues with the remaining files and
returns a nonzero exit status.

### Discover capture interfaces

```bash
python -m lattice interfaces
```

This command loads the configuration, prints a platform-readiness message, and
lists interfaces visible to Scapy. Enumeration does not start capture. Copy the
exact interface name when using `live`; display names are platform-specific.

### Live capture

```text
python -m lattice [global options] live
                  [--interface NAME] [--filter BPF] [--duration SECONDS]
```

Example bounded session:

```powershell
python -m lattice --db live-check.db live `
  --interface "Wi-Fi" `
  --filter "tcp or udp" `
  --duration 30
```

Omit `--duration` to run until Ctrl+C. Omit `--interface` to use the configured
or Scapy-default interface. BPF syntax and availability depend on the installed
capture backend.

Live capture normally requires:

- Windows: Npcap and an Administrator terminal;
- Linux: root or suitable packet-capture capabilities, commonly `CAP_NET_RAW`
  and `CAP_NET_ADMIN`; or
- macOS: access to the `/dev/bpf*` devices.

A normal stop drains records already in the bounded queue, flushes the last
populated window, and marks the run `stopped`. Queue-overflow drops, malformed
packets, and backend failures are recorded rather than hidden. Automated tests
exercise this lifecycle with a fake sniffer; validate the real driver,
interface, and permissions separately on each deployment host.

### Initialize or reset a database

Create the schema if needed:

```bash
python -m lattice --db lattice.db init-db
```

Delete all stored Lattice runs and recreate the schema:

```bash
python -m lattice --db lattice.db reset-db --yes
```

Reset requires `--yes`. It refuses to alter a non-empty SQLite database that is
not marked as a Lattice database. Treat reset as destructive and back up results
that must be retained.

## Streamlit dashboard

Start the dashboard from the repository root:

```bash
python -m streamlit run app.py
```

The project configuration binds Streamlit to `127.0.0.1`, so open
<http://localhost:8501> on the same computer. The application has no
authentication. Do not expose it to an untrusted network. If remote access is
deliberately required on a trusted network, review the security implications
before overriding the address:

```bash
python -m streamlit run app.py --server.address 0.0.0.0
```

Use environment variables to select another database or configuration before
startup.

Windows PowerShell:

```powershell
$env:LATTICE_DB = "C:\captures\lattice.db"
$env:LATTICE_CONFIG = "C:\captures\config.json"
python -m streamlit run app.py
```

Linux or macOS:

```bash
LATTICE_DB=/data/lattice.db \
LATTICE_CONFIG=/data/config.json \
python -m streamlit run app.py
```

The configuration is cached for the Streamlit process. Restart the dashboard
after changing the configuration file.

### Select a database and run

The sidebar **Data source** expander selects the SQLite database. **Current
run** selects one persisted run from that database. Selecting a historical run
reads stored results; it does not reopen or replay its capture.

The status message distinguishes active, historical, interrupted, partial, and
failed results. Run lifecycle timestamps use the system clock, while traffic
windows use packet timestamps. These time ranges need not match for offline
captures.

### Overview

The **Overview** view answers three questions: how much traffic was processed,
what stood out, and which stored events deserve investigation.

It displays:

- processed packet and byte totals;
- stored-window coverage, which is not processing time;
- detected events, skipped packets, and cooldown suppressions;
- deterministic key findings derived from stored evidence;
- packet rate over time with markers on event-producing windows;
- protocol packet shares;
- significant events; and
- leading retained sources.

Findings are either rule detections or descriptive observations. Descriptive
findings can highlight a material peak, dominant protocol, or concentrated
source, but they do not create detector events or assert malicious intent.

### Traffic analytics

The **Traffic analytics** view provides:

- packet-rate and byte-rate timelines;
- protocol shares across stored windows;
- tracked sources ranked by packets, bytes, or SYN activity; and
- an expandable table of individual window measurements.

Source rows are retained summaries rather than a complete flow ledger. Only
the configured top talkers are stored for each window, and destination diversity
is shown as a per-window maximum.

### Anomaly events

The **Anomaly events** view supports literal search plus rule, severity, and UTC
time filters. Select an event to inspect:

- its readable rule and severity;
- observed measurement, configured threshold, and ratio;
- source or largest contributor, when available;
- destination evidence retained by the detector;
- the rule explanation and a conservative suggested next check; and
- stored traffic immediately before, during, and after the event window.

The interactive result list is capped at 2,000 matching rows. Its displayed
total comes from a separate count query, and export is not restricted by this
interactive cap.

### Captures and history

The **Captures and history** view contains four tools.

#### Analyze capture

Upload a `.pcap` or `.pcapng`, choose an included repository sample, or enter a
path local to the computer running Streamlit.

Uploads are limited to 100 MiB, require a recognized extension and capture-file
signature, and use a temporary file that is deleted after processing. The
persisted source label is the supplied filename rather than the temporary path.
The replay pipeline performs the authoritative framing and packet validation.

Completed duplicate captures are selected from stored results rather than
processed again. Enable the explicit reprocess option only when a replacement
is intended.

#### Compare and export

Run comparison reports stored-window coverage, average and peak packet/byte
rates, stored events per minute, skipped-packet share, and protocol shares. Rate
and frequency measurements are normalized by stored-window coverage so captures
of different durations are not compared using raw totals alone. Partial or
failed comparisons are labelled provisional.

The JSON export contains run metadata, findings, all stored windows, all stored
events, and source summaries. The CSV download is a ZIP containing separate
tables plus a units note. Timestamps are ISO 8601 UTC values, rates are per
second, and local source directory paths are omitted.

Events are exported without the interactive row cap. Source export remains a
summary: the database retains only per-window top talkers, and the dashboard
exports at most 1,000 aggregated source rows.

#### Live capture

Select a Scapy-visible interface, optionally enter a BPF filter, confirm that
you are authorized to monitor the network, and start capture. The page reports
startup or backend errors and exposes a stop control while the worker is active.
No capture begins without the authorization checkbox and an explicit start.

#### Configuration

This section displays the validated configuration used by the dashboard. It is
read-only. Edit the JSON file outside Streamlit and restart the process to apply
changes.

## Run states and counters

| State | Meaning |
|---|---|
| `running` | A worker created the run and has not finalized it; a stale row is presented as interrupted |
| `completed` | Offline replay finished without a recorded reader or storage error |
| `partial` | Usable results were retained, but input reading or window storage was incomplete |
| `stopped` | A live session ended normally |
| `failed` | Processing after run creation or live capture ended with an exception or interruption |

`packets` counts successfully normalized and aggregated packets.
`skipped_packets` combines malformed input and live queue drops. A detection
candidate suppressed by cooldown increments `suppressed_events` but does not
create an event row.

## Practical workflows

### Compare ordinary and injected traffic

```powershell
python -m lattice --db demo.db replay `
  .\samples\normal.pcap `
  .\samples\rate_spike.pcap `
  .\samples\port_scan.pcap
$env:LATTICE_DB = (Resolve-Path .\demo.db).Path
python -m streamlit run app.py
```

Use `normal.pcap` to inspect traffic without detections, then compare it with
the rate-spike or port-scan scenario. These are deterministic synthetic
captures, not examples of general real-world accuracy.

### Preserve a result outside Lattice

1. Select the run in the sidebar.
2. Open **Captures and history**.
3. Choose **Compare and export**.
4. Download JSON for a nested machine-readable record or the CSV ZIP for
   separate tabular files.

Protect captures, databases, and exports as sensitive network metadata even
though Lattice does not persist packet payloads.

## Known display and comparison limits

- Interactive event inspection shows at most 2,000 matching rows.
- Overview findings use at most the first 10,000 stored events and clearly warn
  if a run exceeds that number.
- Run comparison currently derives event frequency from that same 10,000-event
  analysis load, so it can understate events per minute for larger runs.
- Export retrieves the complete event set, but exported source summaries remain
  bounded as described above.
- Dashboard source totals can be lower than overall run totals because
  source-less traffic, source tracking limits, and top-talker persistence all
  reduce retained source detail.
