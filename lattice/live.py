"""Background live monitoring with a clean start/stop lifecycle.

One worker thread owns the sniffer, the SQLite connection and the pipeline for
the session. ``stop()`` signals the worker, joins it, and the worker stops the
sniffer, drains the queue, flushes the last window and closes the run record, so
nothing keeps running afterwards.

Only monitor interfaces and networks you are authorized to monitor. Capture
needs OS privileges (see README); failures are reported, never hidden.
"""
from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .capture import CaptureError, LiveCapture
from .config import Config
from .pipeline import Pipeline
from .storage import Storage, StorageError

log = logging.getLogger(__name__)

_POLL_SECONDS = 0.5
_START_TIMEOUT = 15.0


@dataclass(frozen=True)
class MonitorState:
    running: bool
    run_id: Optional[int]
    interface: Optional[str]
    error: Optional[str]


class LiveMonitor:
    def __init__(self, config: Config, db_path: Optional[str] = None,
                 sniffer_factory: Optional[Callable[..., Any]] = None) -> None:
        self._config = config
        self._db_path = db_path or config.database_path
        self._sniffer_factory = sniffer_factory
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._run_id: Optional[int] = None
        self._interface: Optional[str] = None
        self._error: Optional[str] = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def state(self) -> MonitorState:
        return MonitorState(self.running, self._run_id, self._interface, self._error)

    def start(self, interface: Optional[str] = None, bpf_filter: Optional[str] = None) -> int:
        """Start monitoring and return the run id. Raises on capture/storage failure."""
        if self.running:
            raise CaptureError("live monitoring is already running")
        self._stop.clear()
        self._ready.clear()
        self._run_id = None
        self._error = None
        self._interface = interface or self._config.capture.interface
        flt = bpf_filter if bpf_filter is not None else self._config.capture.bpf_filter
        self._thread = threading.Thread(target=self._work, args=(self._interface, flt),
                                        name="lattice-live", daemon=True)
        self._thread.start()
        if not self._ready.wait(_START_TIMEOUT):
            self.stop()
            raise CaptureError("live monitoring did not start in time")
        if self._error is not None:
            self._thread.join(5.0)
            raise CaptureError(self._error)
        assert self._run_id is not None
        return self._run_id

    def stop(self, timeout: float = 15.0) -> None:
        """Stop monitoring and wait for the worker to finish. Safe to call repeatedly."""
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)
            if thread.is_alive():
                log.error("live worker did not exit within %.0fs", timeout)

    # -- worker --------------------------------------------------------------

    def _work(self, interface: Optional[str], bpf_filter: Optional[str]) -> None:
        capture = LiveCapture(interface, bpf_filter, self._config.capture.queue_size,
                              self._sniffer_factory)
        storage: Optional[Storage] = None
        pipeline: Optional[Pipeline] = None
        status, note = "stopped", ""
        try:
            capture.start()
            storage = Storage(self._db_path)
            self._run_id = storage.start_run("live", interface or "default",
                                             note=f"filter={bpf_filter or 'none'}")
            pipeline = Pipeline(self._config, storage, self._run_id, capture.snapshot_stats)
            pipeline.tick(time.time())  # anchor the first window to "now"
            self._ready.set()
            status, note = self._loop(capture, pipeline)
        except (CaptureError, StorageError) as exc:
            self._error = str(exc)
            status, note = "failed", str(exc)
            log.error("live monitoring failed: %s", exc)
        except Exception as exc:
            # A live worker must never disappear without closing its run and
            # exposing the failure to the caller/dashboard.
            self._error = f"{type(exc).__name__}: {exc}"
            status, note = "failed", self._error
            log.exception("unexpected live monitoring failure")
        finally:
            capture.stop()
            if pipeline is not None:
                try:
                    self._drain(capture, pipeline)
                    pipeline.finish()
                except Exception as exc:
                    cleanup_error = f"{type(exc).__name__}: {exc}"
                    self._error = self._error or cleanup_error
                    status = "failed"
                    note = f"{note}; finalization failed: {cleanup_error}" if note else cleanup_error
                    log.exception("could not drain or finalize live pipeline")
            if storage is not None and self._run_id is not None:
                try:
                    stats = capture.snapshot_stats()
                    totals = pipeline.totals() if pipeline is not None else {
                        "packets": 0, "bytes": 0, "windows": 0, "events": 0,
                        "suppressed_events": 0, "skipped_packets": stats.skipped, "storage_errors": 0}
                    storage.finish_run(self._run_id, status, totals, note)
                except StorageError as exc:
                    log.error("could not close run %s: %s", self._run_id, exc)
                storage.close()
            self._ready.set()  # unblock start() if we failed before becoming ready

    def _loop(self, capture: LiveCapture, pipeline: Pipeline) -> tuple[str, str]:
        while not self._stop.is_set():
            try:
                pipeline.feed(capture.records.get(timeout=_POLL_SECONDS))
            except queue.Empty:
                pipeline.tick(time.time())
            if capture.error:
                self._error = capture.error
                return "failed", f"capture stopped unexpectedly: {capture.error}"
            if not capture.running and not self._stop.is_set():
                self._error = "capture backend stopped unexpectedly"
                return "failed", self._error
        return "stopped", ""

    @staticmethod
    def _drain(capture: LiveCapture, pipeline: Pipeline) -> None:
        while True:
            try:
                pipeline.feed(capture.records.get_nowait())
            except queue.Empty:
                return
