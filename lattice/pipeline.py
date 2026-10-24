"""Glue between the stages: records -> windows -> events -> SQLite.

``Pipeline`` is source-agnostic (PCAP replay and live capture both feed it).
Storage failures are counted and logged but never interrupt packet processing.
"""
from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import Callable, Iterable, Optional

from .capture import CaptureError, load_pcap_records
from .config import AllowList, Config
from .detector import Detector
from .features import Aggregator
from .models import IngestStats, PacketRecord, RunSummary, WindowStats
from .storage import Storage, StorageError

log = logging.getLogger(__name__)


class Pipeline:
    """Feeds records through aggregation and detection and persists each window."""

    def __init__(self, config: Config, storage: Storage, run_id: int,
                 ingest: Callable[[], IngestStats]) -> None:
        self._config = config
        self._storage = storage
        self._run_id = run_id
        self._ingest = ingest
        self.aggregator = Aggregator(config.window, AllowList.from_config(config.detection.unexpected_traffic))
        self.detector = Detector(config.detection)
        self.packets = 0
        self.bytes = 0
        self.windows = 0
        self.events = 0
        self.storage_errors = 0
        self.last_window: Optional[WindowStats] = None

    def feed(self, record: PacketRecord) -> None:
        for window in self.aggregator.add(record):
            self._handle(window)

    def tick(self, now: float) -> None:
        """Advance the window clock without a packet (live mode)."""
        for window in self.aggregator.advance(now):
            self._handle(window)

    def finish(self) -> None:
        for window in self.aggregator.flush():
            self._handle(window)

    def totals(self) -> dict[str, int]:
        return {
            "packets": self.packets, "bytes": self.bytes, "windows": self.windows,
            "events": self.events, "suppressed_events": self.detector.suppressed,
            "skipped_packets": self._ingest().skipped, "storage_errors": self.storage_errors,
        }

    def _handle(self, window: WindowStats) -> None:
        events = self.detector.evaluate(window)
        self.packets += window.packets
        self.bytes += window.bytes
        self.windows += 1
        self.events += len(events)
        self.last_window = window
        try:
            self._storage.save_window(self._run_id, window, events,
                                      self._config.window.top_talkers, self.totals())
        except StorageError as exc:
            self.storage_errors += 1
            log.error("window %.3f not stored: %s", window.start, exc)


def pcap_fingerprint(path: str | Path, config: Config) -> str:
    """Identify "this file processed with these settings" so reruns can be skipped."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
    except FileNotFoundError:
        raise CaptureError(f"PCAP file not found: {path}") from None
    except OSError as exc:
        raise CaptureError(f"cannot read {path}: {exc}") from exc
    digest.update(config.processing_fingerprint().encode("utf-8"))
    return digest.hexdigest()


def process_records(records: Iterable[PacketRecord], config: Config, storage: Storage,
                    run_id: int, ingest: IngestStats) -> Pipeline:
    pipeline = Pipeline(config, storage, run_id, lambda: ingest)
    for record in records:
        pipeline.feed(record)
    pipeline.finish()
    return pipeline


def process_pcap(path: str | Path, config: Config, storage: Storage, *,
                 force: bool = False) -> RunSummary:
    """Replay one PCAP through the full pipeline and store the results.

    A file already processed with identical settings is not processed again
    (``summary.duplicate`` is True) unless ``force`` is set, in which case the
    earlier run is replaced.
    """
    file = Path(path)
    fingerprint = pcap_fingerprint(file, config)
    existing = storage.find_completed_run(fingerprint)
    if existing is not None and not force:
        return _summary_from_row(existing, duplicate=True)

    started = time.perf_counter()
    ingest = IngestStats()
    records = load_pcap_records(file, ingest)  # raises CaptureError before any run row exists

    while existing is not None:  # force: replace every earlier completed run of this input
        storage.delete_run(existing["id"])
        existing = storage.find_completed_run(fingerprint)

    run_id = storage.start_run("pcap", str(file.resolve()), fingerprint)
    try:
        pipeline = process_records(records, config, storage, run_id, ingest)
    except Exception as exc:
        storage.finish_run(run_id, "failed", {"packets": 0, "bytes": 0, "windows": 0, "events": 0,
                                              "suppressed_events": 0, "skipped_packets": ingest.skipped,
                                              "storage_errors": 0}, note=f"{type(exc).__name__}: {exc}")
        raise
    notes = []
    if ingest.read_error:
        notes.append(f"file ended early: {ingest.read_error}")
    if pipeline.storage_errors:
        notes.append(f"{pipeline.storage_errors} window(s) could not be stored")
    note = "; ".join(notes)
    storage.finish_run(run_id, "completed", pipeline.totals(), note)

    totals = pipeline.totals()
    return RunSummary(
        run_id=run_id, source=str(file), mode="pcap", status="completed",
        packets=totals["packets"], bytes=totals["bytes"], skipped_packets=totals["skipped_packets"],
        windows=totals["windows"], events=totals["events"], suppressed_events=totals["suppressed_events"],
        storage_errors=totals["storage_errors"], elapsed_seconds=time.perf_counter() - started, note=note)


def _summary_from_row(row: dict, *, duplicate: bool) -> RunSummary:
    elapsed = (row["finished_at"] or row["started_at"]) - row["started_at"]
    return RunSummary(
        run_id=row["id"], source=row["source"], mode=row["mode"], status=row["status"],
        packets=row["packets"], bytes=row["bytes"], skipped_packets=row["skipped_packets"],
        windows=row["windows"], events=row["events"], suppressed_events=row["suppressed_events"],
        storage_errors=row["storage_errors"], elapsed_seconds=elapsed, duplicate=duplicate,
        note=row["note"])
