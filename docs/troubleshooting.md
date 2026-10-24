# Lattice troubleshooting

Start with the exact command that failed and rerun it with debug logging when the CLI supports it:

```bash
python -m lattice -v --db lattice.db replay capture.pcap
```

## Installation

### `python` or `streamlit` is not found

Activate the virtual environment in the same terminal used to run Lattice, then install the repository requirements:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

On Linux or macOS, use `source .venv/bin/activate` instead.

### Dependency conflicts

Check the installed environment without changing it:

```bash
python -m pip check
```

If conflicts remain, create a fresh virtual environment and reinstall `requirements.txt`. The repository declares minimum compatible versions rather than a frozen lock file, so record the environment when reproducibility depends on exact third-party versions.

## Capture-file analysis

### `PCAP file not found`

Paths are resolved by the process that runs Lattice. Quote paths containing spaces. For dashboard local-path input, the file must exist on the Streamlit server, not only on a remote browser computer.

### The dashboard rejects an upload

Dashboard uploads must:

- end in `.pcap` or `.pcapng`;
- be non-empty and no larger than 100 MiB; and
- begin with a recognized classic-PCAP or PCAPNG signature.

Passing that check does not guarantee the rest of the file is valid. The replay pipeline next checks PCAP record or PCAPNG block framing, and Scapy parses the contained packets.

### A replay says it reused an existing run

This is duplicate protection. The fingerprint includes capture bytes, processing configuration, and the Lattice processing version. Use `--force` only when an explicit replacement is required:

```bash
python -m lattice --db lattice.db replay capture.pcap --force
```

A changed database path does not change the fingerprint, but duplicate lookup occurs only inside the selected database.

### A run is `partial`

Inspect the run note and the skipped/storage-error counters in the dashboard. A partial run can contain useful windows, but totals and findings are provisional. Common causes are a truncated capture, broken record framing, a reader exception late in a capture, or a failed SQLite window transaction. Lattice does not silently upgrade a partial run to completed.

## Live capture

### Windows: Npcap is unavailable

Install [Npcap](https://npcap.com/), restart the terminal, and run it as Administrator. Then check what Scapy can see:

```bash
python -m lattice interfaces
```

Use the exact reported interface name. If capture remains unavailable, verify Npcap installation and driver state outside Lattice before changing detection settings.

### Linux: permission denied

Run capture only with authorization. Root is the simplest diagnostic. A longer-lived installation may grant the Python executable the packet-capture capabilities required by the host policy, commonly `cap_net_raw` and `cap_net_admin`. Capabilities apply to a specific executable and can disappear after Python upgrades; coordinate this with the system administrator.

### macOS: BPF permission failure

The process needs access to `/dev/bpf*`. Device ownership and group policy vary by macOS release and local security configuration. Confirm access through the host's approved capture tooling and use the interface name shown by `python -m lattice interfaces`.

### A BPF filter fails

The filter is passed to Scapy's capture backend. Syntax and availability depend on the platform and driver. First try the same interface without `--filter`; then reduce the expression to a standard form such as `tcp or udp`. An absent libpcap-compatible backend can prevent BPF compilation even when unfiltered capture works.

### Dropped packets are reported

`capture.queue_size` bounds memory. A drop means the sniffer callback could not enqueue a record immediately; that packet cannot appear in later windows or events. Reduce the capture rate with an appropriate BPF filter, use a less loaded host, or increase the queue cautiously. Increasing the queue raises peak memory and does not fix sustained processing overload.

### Validate live capture manually

Automated tests do not observe a real interface. On the target host and an authorized network:

1. Run `python -m lattice interfaces` and select the intended interface.
2. Start a short bounded session into a dedicated database:

   ```bash
   python -m lattice --db live-check.db live --interface "INTERFACE NAME" --duration 15
   ```

3. Do not generate scans or artificial traffic. Let ordinary authorized activity be captured.
4. Confirm the command exits, reports a `stopped` run, and shows processed/skipped counters.
5. Start `streamlit run app.py` with `LATTICE_DB` pointing to `live-check.db`; verify that windows, protocol counts, and any rule matches are present and plausible.
6. Delete the validation database only after preserving any evidence you need.

This confirms lifecycle and host integration, not detector accuracy.

## Database and dashboard

### `file is an existing SQLite database that is not a Lattice database`

Choose a different `--db` path. Lattice marks owned databases and refuses to create its schema in an unrelated non-empty SQLite file. Do not use `reset-db` as a way to override this safeguard.

### `unsupported Lattice database schema version`

The current code does not perform schema migrations. Keep the database with the Lattice version that created it, or process the original captures into a new database. Do not change SQLite `user_version` manually.

### Dashboard changes to `config.json` do not appear

The dashboard caches configuration for the Streamlit process. Restart Streamlit after editing the file. The dashboard shows the active configuration but does not edit it.

### A historical `running` run appears interrupted

The dashboard treats a `running` row as interrupted when the database has not been written recently, which usually means the capture process exited without finalizing the run. This inference uses database-wide modification time, so another active writer can temporarily delay the interrupted label. Previously stored windows remain available. Start a new run rather than assuming the old worker can be resumed.

### Source totals do not equal packet totals

This is expected when source tracking is truncated, traffic has no source IP, or a source falls outside the per-window persisted top-talkers. Source tables are summaries, not a complete flow ledger. Overall packet and byte totals come from traffic windows.

### Capture duration and stored-window coverage differ

Run start/finish timestamps are wall-clock lifecycle times. Traffic coverage comes from packet-timestamp windows and includes complete fixed window widths. Offline capture timestamps can be historical, and the first or last window may only be partially populated.

## Configuration errors

Lattice names the offending configuration path. Common causes include:

- a misspelled or unknown key;
- a JSON string where a number or boolean is required;
- `null` on a non-nullable setting;
- `min_baseline_windows` greater than `baseline_windows`;
- `high_ratio` less than or equal to `warning_ratio`; or
- enabling traffic-spike detection while setting every spike threshold to `null`.

Validate a configuration without starting capture by listing interfaces with the explicit path:

```bash
python -m lattice --config custom-config.json interfaces
```

This loads and validates the file before the command runs.
