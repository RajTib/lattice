"""Live capture lifecycle, tested with a fake sniffer (no privileges, no network)."""
import threading
import time

import pytest

from lattice.capture import CaptureError, LiveCapture, list_interfaces, live_capture_status
from lattice.live import LiveMonitor
from lattice.storage import Storage

from factories import eth, make_config, stamp, tcp_packet

from scapy.layers.inet import IP, TCP


class FakeSniffer:
    """Mimics AsyncSniffer: a real thread that runs until stop() is called."""

    instances: list = []

    def __init__(self, **kwargs):
        self.prn = kwargs["prn"]
        self.kwargs = kwargs
        self.running = False
        self.exception = None
        self.thread = None
        self._stop = threading.Event()
        FakeSniffer.instances.append(self)

    def start(self):
        self.thread = threading.Thread(target=self._run, name="fake-sniffer", daemon=True)
        self.thread.start()

    def _run(self):
        self.running = True
        self._stop.wait()
        self.running = False

    def stop(self, join=True):
        self._stop.set()
        if join:
            self.thread.join()

    def emit(self, pkt):
        self.prn(pkt)


class FailingSniffer(FakeSniffer):
    def _run(self):
        self.exception = PermissionError("Operation not permitted")


@pytest.fixture(autouse=True)
def _reset_instances():
    FakeSniffer.instances.clear()


def alive(name):
    return [t for t in threading.enumerate() if t.name == name]


def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_capture_passes_options_and_queues_parsed_records():
    cap = LiveCapture("eth9", "tcp port 80", 100, FakeSniffer)
    cap.start()
    sniffer = FakeSniffer.instances[0]
    assert sniffer.kwargs["iface"] == "eth9" and sniffer.kwargs["filter"] == "tcp port 80"
    assert sniffer.kwargs["store"] is False                      # packets are not retained by Scapy
    sniffer.emit(tcp_packet(1.0, dport=80))
    sniffer.emit(stamp(eth() / IP(ihl=2) / TCP(), 2.0))          # malformed
    rec = cap.records.get_nowait()
    assert rec.dst_port == 80
    stats = cap.snapshot_stats()
    assert (stats.seen, stats.parsed, stats.malformed, stats.dropped) == (2, 1, 1, 0)
    cap.stop()


def test_full_queue_drops_are_counted():
    cap = LiveCapture(None, None, 2, FakeSniffer)
    cap.start()
    for i in range(5):
        FakeSniffer.instances[0].emit(tcp_packet(float(i)))
    stats = cap.snapshot_stats()
    assert (stats.parsed, stats.dropped, stats.skipped) == (2, 3, 3)
    cap.stop()


def test_stop_joins_the_sniffer_thread_and_is_idempotent():
    cap = LiveCapture(None, None, 10, FakeSniffer)
    cap.start()
    assert cap.running and alive("fake-sniffer")
    cap.stop()
    cap.stop()
    assert not cap.running and not alive("fake-sniffer")


def test_start_failure_is_reported_with_guidance_and_cleans_up():
    cap = LiveCapture("eth9", None, 10, FailingSniffer)
    with pytest.raises(CaptureError, match="PermissionError"):
        cap.start()
    assert not cap.running and not alive("fake-sniffer")
    assert "PermissionError" in cap.error


def test_double_start_is_rejected():
    cap = LiveCapture(None, None, 10, FakeSniffer)
    cap.start()
    with pytest.raises(CaptureError, match="already"):
        cap.start()
    cap.stop()


def test_real_sniffer_with_bad_interface_fails_cleanly():
    """Uses Scapy's real AsyncSniffer: must raise CaptureError, never hang or leak threads."""
    before = threading.active_count()
    cap = LiveCapture("lattice-no-such-interface0", None, 10)
    with pytest.raises(CaptureError):
        cap.start(startup_timeout=3.0)
    assert not cap.running
    assert wait_for(lambda: threading.active_count() <= before)


def test_environment_helpers_do_not_raise():
    status = live_capture_status()
    assert isinstance(status.available, bool) and status.message
    assert isinstance(list_interfaces(), list)


# -- LiveMonitor ---------------------------------------------------------------------

def monitor_config():
    return make_config({"window": {"seconds": 1}, "capture": {"queue_size": 1000}})


def test_monitor_records_a_session_and_shuts_down_cleanly(tmp_path):
    db = str(tmp_path / "live.db")
    monitor = LiveMonitor(monitor_config(), db, sniffer_factory=FakeSniffer)
    run_id = monitor.start("fake0", "tcp")
    assert monitor.running and monitor.state().run_id == run_id
    sniffer = FakeSniffer.instances[0]
    now = time.time()
    for i in range(30):
        sniffer.emit(tcp_packet(now + i * 0.01, "10.0.0.1", "10.0.0.2", 50000, 443, "A"))
    assert wait_for(lambda: Storage(db, read_only=True).get_run(run_id)["windows"] >= 1, 8.0)

    monitor.stop()
    assert not monitor.running
    assert not alive("lattice-live") and not alive("fake-sniffer")   # nothing left running
    with Storage(db, read_only=True) as s:
        run = s.get_run(run_id)
        assert (run["mode"], run["status"], run["packets"]) == ("live", "stopped", 30)
        assert run["finished_at"] is not None
        assert sum(w["packets"] for w in s.query_windows(run_id)) == 30


def test_stop_is_safe_when_never_started_or_called_twice(tmp_path):
    monitor = LiveMonitor(monitor_config(), str(tmp_path / "x.db"), sniffer_factory=FakeSniffer)
    monitor.stop()
    monitor.start("fake0")
    monitor.stop()
    monitor.stop()
    assert not monitor.running


def test_monitor_can_be_restarted_after_stopping(tmp_path):
    db = str(tmp_path / "x.db")
    monitor = LiveMonitor(monitor_config(), db, sniffer_factory=FakeSniffer)
    first = monitor.start("fake0")
    monitor.stop()
    second = monitor.start("fake0")
    monitor.stop()
    assert first != second
    with Storage(db, read_only=True) as s:
        assert [r["status"] for r in s.list_runs()] == ["stopped", "stopped"]


def test_monitor_cannot_start_twice(tmp_path):
    monitor = LiveMonitor(monitor_config(), str(tmp_path / "x.db"), sniffer_factory=FakeSniffer)
    monitor.start("fake0")
    with pytest.raises(CaptureError, match="already running"):
        monitor.start("fake0")
    monitor.stop()


def test_monitor_start_failure_creates_no_run_and_leaves_no_threads(tmp_path):
    db = str(tmp_path / "x.db")
    monitor = LiveMonitor(monitor_config(), db, sniffer_factory=FailingSniffer)
    with pytest.raises(CaptureError, match="PermissionError"):
        monitor.start("fake0")
    assert wait_for(lambda: not monitor.running)
    assert not alive("fake-sniffer")
    assert "PermissionError" in monitor.state().error
    import os
    assert not os.path.exists(db) or Storage(db, read_only=True).list_runs() == []


def test_monitor_marks_run_failed_if_capture_dies_midway(tmp_path):
    db = str(tmp_path / "x.db")
    monitor = LiveMonitor(monitor_config(), db, sniffer_factory=FakeSniffer)
    run_id = monitor.start("fake0")
    FakeSniffer.instances[0].exception = OSError("interface went away")
    assert wait_for(lambda: not monitor.running, 8.0)
    with Storage(db, read_only=True) as s:
        run = s.get_run(run_id)
    assert run["status"] == "failed" and "interface went away" in run["note"]
    assert "interface went away" in monitor.state().error
