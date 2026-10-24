"""Command line interface: ``python -m lattice <command>``."""
from __future__ import annotations

import argparse
import logging
import sys
import time
from typing import Optional, Sequence

from .capture import CaptureError, list_interfaces, live_capture_status
from .config import Config, ConfigError, load_config
from .live import LiveMonitor
from .pipeline import process_pcap
from .storage import Storage, StorageError, reset_database


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lattice", description="Passive network traffic analysis "
                                     "and anomaly detection.")
    parser.add_argument("--config", help="path to config.json (default: project config.json)")
    parser.add_argument("--db", help="SQLite database path (overrides config database.path)")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    replay = sub.add_parser("replay", help="process one or more PCAP/PCAPNG files")
    replay.add_argument("pcaps", nargs="+")
    replay.add_argument("--force", action="store_true",
                        help="reprocess files already processed with the same settings")

    live = sub.add_parser("live", help="capture live traffic (needs privileges; authorized networks only)")
    live.add_argument("--interface", "-i", help="interface name (see `interfaces`)")
    live.add_argument("--filter", dest="bpf_filter", help="BPF capture filter, e.g. 'tcp or udp'")
    live.add_argument("--duration", type=float, help="stop after this many seconds (default: until Ctrl+C)")

    sub.add_parser("interfaces", help="list capture interfaces and live-capture readiness")
    sub.add_parser("init-db", help="create the database schema if it does not exist")
    reset = sub.add_parser("reset-db", help="DROP and recreate all Lattice tables in the database")
    reset.add_argument("--yes", action="store_true", help="required confirmation")
    return parser


def _cmd_replay(args: argparse.Namespace, config: Config, db: str) -> int:
    code = 0
    with Storage(db) as storage:
        for path in args.pcaps:
            try:
                s = process_pcap(path, config, storage, force=args.force)
            except CaptureError as exc:
                print(f"{path}: ERROR {exc}", file=sys.stderr)
                code = 1
                continue
            tag = "already processed (use --force to redo)" if s.duplicate else f"{s.elapsed_seconds:.2f}s"
            print(f"{path}: run {s.run_id}: {s.packets} packets, {s.bytes} bytes, {s.windows} windows, "
                  f"{s.events} events, {s.skipped_packets} skipped, {s.suppressed_events} suppressed "
                  f"[{tag}]")
            if s.note:
                print(f"  note: {s.note}")
    return code


def _cmd_live(args: argparse.Namespace, config: Config, db: str) -> int:
    status = live_capture_status()
    print(status.message)
    if not status.available:
        return 2
    monitor = LiveMonitor(config, db_path=db)
    try:
        run_id = monitor.start(args.interface, args.bpf_filter)
    except (CaptureError, StorageError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"Monitoring (run {run_id}). Press Ctrl+C to stop.")
    deadline = time.monotonic() + args.duration if args.duration else None
    try:
        while monitor.running and (deadline is None or time.monotonic() < deadline):
            time.sleep(0.25)
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        monitor.stop()
    state = monitor.state()
    if state.error:
        print(f"ERROR: {state.error}", file=sys.stderr)
        return 2
    print("Stopped. Results are in the database; open the dashboard to view them.")
    return 0


def _cmd_interfaces() -> int:
    status = live_capture_status()
    print(status.message, "\n")
    for iface in list_interfaces():
        print(f"{iface.name}\t{iface.description}")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        config = load_config(args.config)
        db = args.db or config.database_path
        if args.command == "replay":
            return _cmd_replay(args, config, db)
        if args.command == "live":
            return _cmd_live(args, config, db)
        if args.command == "interfaces":
            return _cmd_interfaces()
        if args.command == "init-db":
            Storage(db).close()
            print(f"database ready: {db}")
            return 0
        if args.command == "reset-db":
            reset_database(db, confirm=args.yes)
            print(f"database reset: {db}")
            return 0
    except (ConfigError, StorageError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 1
