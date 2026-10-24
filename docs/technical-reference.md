# Lattice technical reference

This document describes the processing semantics implemented by the current Lattice codebase. The [README](../README.md) contains installation and task-oriented usage.

## Packet acquisition and normalization

### Offline input

`lattice.capture.iter_pcap_records` uses Scapy's `PcapReader`, which accepts classic PCAP and PCAPNG files. Before parsing, Lattice walks classic-PCAP record framing or PCAPNG block framing without loading packet data. This catches incomplete records and blocks that Scapy can otherwise accept silently. The reader then yields packets in file order; `load_pcap_records` converts them to `PacketRecord` values and applies a stable ascending timestamp sort.

Lattice distinguishes three outcomes:

- a file with an invalid capture header or that cannot be opened raises `CaptureError` before a run row is created;
- a packet that reaches the parser but has invalid required metadata increments the malformed count and is skipped; and
- broken framing, truncation, or a reader exception after recoverable packets records a read error, preserves processed data, and produces a `partial` run.

Framing checks establish that declared records or blocks are complete; they do not make every contained packet semantically valid. For example, an IPv4 packet declaring TCP but lacking a complete TCP header remains an IP packet with unavailable ports and flags. Structurally invalid required fields, including zero-length frames, are counted as malformed.

### Live input

`LiveCapture` wraps Scapy's `AsyncSniffer` with `store=False`. Its callback normalizes each packet and attempts a non-blocking write to a fixed-size queue. Malformed packets and queue-overflow drops are counted separately. `LiveMonitor` gives the worker its own SQLite connection, periodically advances the aggregator with the system clock, and exposes startup or worker failures to the caller.

Stopping is idempotent. It stops and joins the sniffer, drains records already in the queue, flushes the last populated window, and finalizes the run. Automated tests use a fake sniffer and do not establish that a host's driver, permissions, or interface selection is correct.

### Normalized fields

Each accepted packet becomes a header-only `PacketRecord` containing:

- Unix timestamp and packet length (the PCAP wire length when available,
  otherwise the serialized packet length);
- normalized protocol name;
- source and destination IP addresses, when present;
- source and destination transport ports, when present;
- TCP flags, for parsed TCP headers; and
- IP version, for IPv4 or IPv6.

Protocols are labelled `TCP`, `UDP`, `ICMP`, `ICMPv6`, `ARP`,
`IP_PROTO_<number>`, `ETHERTYPE_0x<type>`, or `OTHER` as appropriate. IPv6
extension headers are traversed before the final next-header value is classified.
Ethernet addresses, payload bytes, TCP sequence state, and application data are
not retained by the pipeline.

## Window aggregation

Windows are epoch-aligned, half-open intervals `[start, end)`. For a configured length `W`, the window index is `floor(timestamp / W)`. A packet exactly on a boundary belongs to the new window.

Each finalized window contains:

- packet and captured-byte totals;
- packet and byte rates, both divided by `W`;
- packet counts by normalized protocol;
- per-source packet and byte totals;
- per-source TCP SYN-without-ACK counts;
- per-source distinct destination ports and hosts for those SYN packets;
- unexpected-packet totals and bounded evidence; and
- late, untracked-source, and post-gap markers.

The final window is stored only when it contains packets. Its rates still divide by the complete configured duration, so a short tail can appear lower than the instantaneous arrival rate.

Offline input is timestamp-sorted before aggregation. In live mode, a packet older than the currently open window is folded into that open window and increments `late_packets`; finalized windows are never reopened.

For gaps no larger than `window.max_gap_windows`, empty windows are materialized with zero counts and rates. A larger gap is skipped, the next populated window is marked `after_gap`, and the detector clears its moving traffic baseline.

### Bounded state and retained source rows

The aggregator tracks at most `window.max_sources_per_window` source addresses. A packet from an additional source still contributes to window, byte, protocol, and unexpected-traffic totals, but not to per-source SYN or scan statistics. It increments `untracked_packets`.

At persistence time, only `window.top_talkers` source rows are kept for each window, ranked by packet count. Consequently:

- detector rules see every source tracked during the live window, not merely the persisted top talkers;
- dashboard source totals are sums of retained rows and can be lower than run totals; and
- dashboard destination diversity is the maximum stored per-window value, not a distinct count across the entire run.

Unexpected-reason keys and unexpected-source contributors also have internal bounds (`64` reasons and `256` sources per window); excess reasons are grouped as `other`. Destination-host sets are capped at 65,536 entries per tracked source and window.

## Detection rules

Rules evaluate finalized `WindowStats`. Every threshold comparison is strict (`>`), so an observed value equal to its threshold does not produce an event.

### Traffic spike

Packet rate and byte rate are evaluated independently. For each metric, a candidate event is produced if at least one enabled condition holds:

```text
observed_rate > absolute_threshold
observed_rate > moving_average_multiplier * recent_average
```

The recent average contains at most `baseline_windows` previous windows and is eligible only after `min_baseline_windows` entries. The relative packet baseline must be at least `min_baseline_pps`; the relative byte baseline must be at least `min_baseline_bps`. This prevents any traffic after a near-zero baseline from looking infinitely large. Empty windows within a short gap participate in history; a long gap resets it.

If absolute and relative limits are both crossed, the stored threshold is the smaller crossed limit. This is the condition exceeded by the largest ratio and therefore the one used for severity and explanation.

### Excessive TCP SYN activity

For each tracked source:

```text
SYN packets with ACK clear > max_syn_per_source
```

The value counts packets, not unique flows, successful handshakes, or established connections. Retransmitted or duplicate SYNs count again. SYN-ACK, ACK-only, UDP, and other packets do not contribute.

### Possible port scan or host sweep

For each tracked source, Lattice separately tests:

```text
distinct destination ports in SYN-without-ACK packets > max_distinct_ports
distinct destination hosts in SYN-without-ACK packets > max_distinct_hosts
```

The host condition can be disabled with `null`. Counts reset at each window boundary. Repeated packets to an already counted destination do not increase distinctness. Both conditions use the `possible_port_scan` rule identifier but store different metrics.

These measurements are consistent with probing; they do not establish intent or whether any connection succeeded.

### Unexpected protocol or port

A packet is unexpected when its normalized protocol is absent from `allowed_protocols`. A TCP or UDP packet with a parsed destination port is also unexpected when neither endpoint port is in `allowed_ports`. Checking both endpoints allows ordinary replies whose service port is the source port, but a sender that deliberately uses an allowed source port can evade this check.

The rule is window-wide:

```text
unexpected packets > max_packets
```

It stores a bounded breakdown of reasons and attributes the event source to the largest recorded contributor when one is available. Non-TCP/UDP packets are governed only by the protocol allowlist. TCP/UDP records without a parsed destination port do not undergo a port check.

## Severity and cooldown

For an admitted candidate, severity uses `ratio = observed / threshold`:

| Condition | Severity |
|---|---|
| `ratio < warning_ratio` | `INFO` |
| `warning_ratio <= ratio < high_ratio` | `WARNING` |
| `ratio >= high_ratio` | `HIGH` |

Cooldown keys are normally `(rule, source, metric)`. Within `cooldown_seconds` of the previous admitted event time, a candidate with equal or lower severity is suppressed; a higher severity is admitted immediately. Event time is the window end, which keeps replay deterministic. Suppressed candidates increment the run's `suppressed_events` total but are not stored as event rows.

The unexpected-traffic condition is window-wide. Its event `src_ip` identifies the largest recorded contributor for investigation, but cooldown deliberately omits that value and uses `(rule, None, metric)`. A changing top contributor therefore does not create duplicate alerts for the same continuing window-level condition.

## Configuration reference

`load_config()` reads the repository `config.json` by default. A missing explicit path is an error; if the built-in default path itself is absent, dataclass defaults are used. JSON objects are merged section by section over defaults. Unknown keys, wrong types, non-finite numbers, invalid ranges, and inconsistent severity or baseline settings raise `ConfigError`.

| Key | Default | Validation and effect |
|---|---:|---|
| `database.path` | `lattice.db` | Non-empty string; CLI `--db` and dashboard `LATTICE_DB` can override it |
| `capture.interface` | `null` | String or `null`; default Scapy interface when null |
| `capture.bpf_filter` | `null` | String or `null`; passed to the live capture backend |
| `capture.queue_size` | `20000` | Integer at least 1 |
| `window.seconds` | `5` | Finite number greater than 0 |
| `window.max_gap_windows` | `12` | Non-negative integer |
| `window.top_talkers` | `10` | Integer at least 1 |
| `window.max_sources_per_window` | `5000` | Integer at least 1 |
| `detection.cooldown_seconds` | `30` | Non-negative finite number |
| `detection.severity.warning_ratio` | `2.0` | Greater than 1 |
| `detection.severity.high_ratio` | `5.0` | Greater than `warning_ratio` |
| `detection.traffic_spike.enabled` | `true` | Boolean |
| `detection.traffic_spike.pps_threshold` | `1000` | Positive number or `null` |
| `detection.traffic_spike.bps_threshold` | `1000000` | Positive number or `null` |
| `detection.traffic_spike.moving_average_multiplier` | `4.0` | Greater than 1 or `null` |
| `detection.traffic_spike.baseline_windows` | `6` | Integer at least 1 |
| `detection.traffic_spike.min_baseline_windows` | `3` | Integer from 1 through `baseline_windows` |
| `detection.traffic_spike.min_baseline_pps` | `1.0` | Positive finite number |
| `detection.traffic_spike.min_baseline_bps` | `100.0` | Positive finite number |
| `detection.connection_attempts.enabled` | `true` | Boolean |
| `detection.connection_attempts.max_syn_per_source` | `100` | Integer at least 1 |
| `detection.port_scan.enabled` | `true` | Boolean |
| `detection.port_scan.max_distinct_ports` | `20` | Integer at least 1 |
| `detection.port_scan.max_distinct_hosts` | `20` | Integer at least 1 or `null` |
| `detection.unexpected_traffic.enabled` | `true` | Boolean |
| `detection.unexpected_traffic.max_packets` | `10` | Integer at least 1 |
| `detection.unexpected_traffic.allowed_protocols` | TCP, UDP, ICMP, ICMPv6, ARP | List whose entries are non-empty strings; an empty list allows no protocols; comparisons are case-insensitive |
| `detection.unexpected_traffic.allowed_ports` | 22, 53, 80, 123, 443 | List of integers, numeric strings, or inclusive ranges such as `"8000-8100"`; endpoints must be 0 through 65535 |

An enabled traffic-spike rule must retain at least one absolute or relative threshold. Each detection category can otherwise be disabled independently.

## Persistence and run lifecycle

Lattice marks its database with SQLite application ID `LATT` and schema version `1`. It refuses a non-empty foreign SQLite database and a Lattice database with an unsupported schema version. File-backed writable connections enable foreign keys and write-ahead logging. Each thread creates its own `Storage` connection.

Offline duplicate lookup reuses only a `completed` run with the same fingerprint.
Partial, failed, running, and stopped runs are never treated as a completed replay.
With `--force`, completed predecessors remain available until the replacement has
completed successfully; they are then removed through cascading foreign keys.

The tables are:

| Table | Stored data |
|---|---|
| `runs` | Mode, source label, fingerprint, lifecycle status, timestamps, aggregate counters, and note |
| `traffic_stats` | One row per stored window, including rates, protocol JSON, and data-quality counters |
| `source_stats` | Retained top source rows associated with a window |
| `events` | Admitted detector events with rule, metric, evidence, threshold, and originating window |

`save_window` inserts the window, retained sources, events, and current run totals in one SQLite transaction. A failed window transaction is logged and increments `storage_errors`; packet processing continues. The run becomes `partial` if the offline reader reported an error or any window failed to store.

User-visible statuses have these meanings:

| Status | Meaning |
|---|---|
| `running` | A run row exists and the worker has not finalized it; an old untouched row is shown as interrupted by the dashboard |
| `completed` | Offline replay finished without a recorded reader or storage error |
| `partial` | Offline replay retained usable results but encountered a reader or storage error |
| `stopped` | Live capture ended normally, including a user-requested stop or duration limit |
| `failed` | Processing after run creation or live capture ended with an exception or interruption; the run can contain data stored before failure |

Run start and finish timestamps use the system clock. Traffic windows and event times use packet timestamps. They describe different concepts and need not span the same duration.

## Dashboard analytics and exports

Dashboard averages and comparison rates divide stored window totals by stored-window coverage. Coverage is the sum of every stored window duration, including materialized empty windows. It is not processing time and can differ from wall-clock capture time.

Protocol shares use counts represented in stored traffic windows. Source rankings sum only retained `source_stats` rows. The overview obtains a bounded event list for interactive display; explicit exports retrieve the complete event set.

Findings also surface incomplete run states, untracked-source packets, and late
live packets as data-quality observations. They do not reconstruct source
statistics that were never tracked or persisted.

The JSON export contains nested run metadata, findings, windows, events, and source summaries. The CSV export is a ZIP with separate CSV files so different row shapes remain explicit. Protocol counts remain available inside each exported traffic-window row. Timestamps are ISO 8601 UTC values and byte rates remain bytes per second. Source labels are reduced to filenames so exports do not disclose local directory paths.

Uploaded files receive a suffix and magic-byte check before Scapy parsing. This is a format guard, not a content-security guarantee. Keep the unauthenticated dashboard in a trusted environment.
