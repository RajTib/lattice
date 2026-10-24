"""SQLite persistence for runs, per-window traffic statistics and detection events.

Schema (all tables created with ``IF NOT EXISTS``):

* ``runs``          one row per PCAP replay or live session (progress + totals)
* ``traffic_stats`` one row per finalized window (rates, protocol distribution)
* ``source_stats``  top talkers per window (child of ``traffic_stats``)
* ``events``        detection events (child of ``runs``)

Every write for a window (stats, top talkers, events, run progress) happens in
one transaction, so a failure never leaves a half-written window. All SQL uses
bound parameters; the only text spliced into SQL comes from fixed whitelists.

A SQLite connection belongs to the thread that created it. Create one
``Storage`` per thread (the live worker and the dashboard each do).
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

from .models import Event, WindowStats

log = logging.getLogger(__name__)

# "LATT": marks a file as a Lattice database so reset never touches foreign files.
APPLICATION_ID = 0x4C415454
SCHEMA_VERSION = 1

_TABLES = ("events", "source_stats", "traffic_stats", "runs")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    mode              TEXT    NOT NULL,
    source            TEXT    NOT NULL,
    fingerprint       TEXT,
    status            TEXT    NOT NULL,
    started_at        REAL    NOT NULL,
    finished_at       REAL,
    packets           INTEGER NOT NULL DEFAULT 0,
    bytes             INTEGER NOT NULL DEFAULT 0,
    skipped_packets   INTEGER NOT NULL DEFAULT 0,
    windows           INTEGER NOT NULL DEFAULT 0,
    events            INTEGER NOT NULL DEFAULT 0,
    suppressed_events INTEGER NOT NULL DEFAULT 0,
    storage_errors    INTEGER NOT NULL DEFAULT 0,
    note              TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_runs_fingerprint ON runs(fingerprint);

CREATE TABLE IF NOT EXISTS traffic_stats (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id              INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    window_start        REAL    NOT NULL,
    window_end          REAL    NOT NULL,
    packets             INTEGER NOT NULL,
    bytes               INTEGER NOT NULL,
    packets_per_second  REAL    NOT NULL,
    bytes_per_second    REAL    NOT NULL,
    protocol_counts     TEXT    NOT NULL,
    untracked_packets   INTEGER NOT NULL DEFAULT 0,
    late_packets        INTEGER NOT NULL DEFAULT 0,
    unexpected_packets  INTEGER NOT NULL DEFAULT 0,
    UNIQUE (run_id, window_start)
);
CREATE INDEX IF NOT EXISTS idx_traffic_run_time ON traffic_stats(run_id, window_start);

CREATE TABLE IF NOT EXISTS source_stats (
    window_id       INTEGER NOT NULL REFERENCES traffic_stats(id) ON DELETE CASCADE,
    src_ip          TEXT    NOT NULL,
    packets         INTEGER NOT NULL,
    bytes           INTEGER NOT NULL,
    syn_attempts    INTEGER NOT NULL,
    distinct_ports  INTEGER NOT NULL,
    distinct_hosts  INTEGER NOT NULL,
    PRIMARY KEY (window_id, src_ip)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    window_id     INTEGER REFERENCES traffic_stats(id) ON DELETE CASCADE,
    ts            REAL    NOT NULL,
    rule          TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    metric        TEXT    NOT NULL DEFAULT '',
    src_ip        TEXT,
    dst_info      TEXT,
    observed      REAL    NOT NULL,
    threshold     REAL    NOT NULL,
    explanation   TEXT    NOT NULL,
    window_start  REAL    NOT NULL,
    window_end    REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_run_ts ON events(run_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_rule ON events(rule);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
"""

_SOURCE_SORT = {"packets": "packets", "bytes": "bytes", "syn_attempts": "syn_attempts"}


class StorageError(RuntimeError):
    """Raised for database failures; the message is safe to show to users."""


def _rows(cursor: sqlite3.Cursor) -> list[dict[str, Any]]:
    return [dict(r) for r in cursor.fetchall()]


class Storage:
    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        self.path = str(path)
        self.read_only = read_only
        self._conn = self._connect()
        if not read_only:
            self.init_schema()

    # -- connection management ---------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        in_memory = self.path == ":memory:"
        try:
            if self.read_only:
                file = Path(self.path)
                if not file.is_file():
                    raise StorageError(f"database not found: {file}")
                conn = sqlite3.connect(f"{file.resolve().as_uri()}?mode=ro", uri=True, timeout=10)
            else:
                if not in_memory:
                    Path(self.path).resolve().parent.mkdir(parents=True, exist_ok=True)
                conn = sqlite3.connect(self.path, timeout=10)
            conn.row_factory = sqlite3.Row
            self._check_ownership(conn)  # before any pragma that would modify a foreign file
            conn.execute("PRAGMA foreign_keys = ON")
            if not self.read_only and not in_memory:
                conn.execute("PRAGMA journal_mode = WAL")  # readers don't block the writer
            return conn
        except sqlite3.Error as exc:
            raise StorageError(f"cannot open database {self.path}: {exc}") from exc

    @staticmethod
    def _check_ownership(conn: sqlite3.Connection) -> None:
        app_id = conn.execute("PRAGMA application_id").fetchone()[0]
        if app_id == APPLICATION_ID:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version != SCHEMA_VERSION:
                conn.close()
                raise StorageError(f"unsupported Lattice database schema version {version}; "
                                   f"this build supports version {SCHEMA_VERSION}")
            return
        has_tables = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' LIMIT 1"
        ).fetchone()
        if has_tables:
            conn.close()
            raise StorageError("file is an existing SQLite database that is not a Lattice database; "
                               "refusing to use it")

    def init_schema(self) -> None:
        try:
            self._conn.executescript(_SCHEMA)
            self._conn.execute(f"PRAGMA application_id = {APPLICATION_ID}")  # constant, not user input
            self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self._conn.commit()
        except sqlite3.Error as exc:
            raise StorageError(f"cannot initialise schema: {exc}") from exc

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Storage":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- writes --------------------------------------------------------------

    def start_run(self, mode: str, source: str, fingerprint: Optional[str] = None, note: str = "") -> int:
        try:
            with self._conn:
                cur = self._conn.execute(
                    "INSERT INTO runs (mode, source, fingerprint, status, started_at, note) "
                    "VALUES (?, ?, ?, 'running', ?, ?)",
                    (mode, source, fingerprint, time.time(), note))
            return int(cur.lastrowid)
        except sqlite3.Error as exc:
            raise StorageError(f"cannot start run: {exc}") from exc

    def save_window(self, run_id: int, ws: WindowStats, events: Sequence[Event], top_n: int,
                    totals: dict[str, int]) -> int:
        """Persist one window, its top talkers, its events and the run totals atomically."""
        try:
            with self._conn:
                cur = self._conn.execute(
                    "INSERT INTO traffic_stats (run_id, window_start, window_end, packets, bytes, "
                    "packets_per_second, bytes_per_second, protocol_counts, untracked_packets, "
                    "late_packets, unexpected_packets) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (run_id, ws.start, ws.end, ws.packets, ws.bytes, ws.packets_per_second,
                     ws.bytes_per_second, json.dumps(ws.protocol_counts, sort_keys=True),
                     ws.untracked_packets, ws.late_packets, ws.unexpected_total))
                window_id = int(cur.lastrowid)
                self._conn.executemany(
                    "INSERT INTO source_stats (window_id, src_ip, packets, bytes, syn_attempts, "
                    "distinct_ports, distinct_hosts) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    [(window_id, ip, s.packets, s.bytes, s.syn_attempts, s.distinct_ports, s.distinct_hosts)
                     for ip, s in ws.top_sources(top_n)])
                self._conn.executemany(
                    "INSERT INTO events (run_id, window_id, ts, rule, severity, metric, src_ip, "
                    "dst_info, observed, threshold, explanation, window_start, window_end) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [(run_id, window_id, e.timestamp, e.rule, e.severity.value, e.metric, e.src_ip,
                      e.dst_info, e.observed, e.threshold, e.explanation, e.window_start, e.window_end)
                     for e in events])
                self._conn.execute(
                    "UPDATE runs SET packets = ?, bytes = ?, skipped_packets = ?, windows = ?, "
                    "events = ?, suppressed_events = ?, storage_errors = ? WHERE id = ?",
                    (totals["packets"], totals["bytes"], totals["skipped_packets"], totals["windows"],
                     totals["events"], totals["suppressed_events"], totals["storage_errors"], run_id))
            return window_id
        except sqlite3.Error as exc:
            raise StorageError(f"cannot save window {ws.start}: {exc}") from exc

    def finish_run(self, run_id: int, status: str, totals: dict[str, int], note: str = "") -> None:
        try:
            with self._conn:
                self._conn.execute(
                    "UPDATE runs SET status = ?, finished_at = ?, packets = ?, bytes = ?, "
                    "skipped_packets = ?, windows = ?, events = ?, suppressed_events = ?, "
                    "storage_errors = ?, note = ? WHERE id = ?",
                    (status, time.time(), totals["packets"], totals["bytes"], totals["skipped_packets"],
                     totals["windows"], totals["events"], totals["suppressed_events"],
                     totals["storage_errors"], note, run_id))
        except sqlite3.Error as exc:
            raise StorageError(f"cannot finish run {run_id}: {exc}") from exc

    def delete_run(self, run_id: int) -> None:
        try:
            with self._conn:
                self._conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))  # children cascade
        except sqlite3.Error as exc:
            raise StorageError(f"cannot delete run {run_id}: {exc}") from exc

    # -- reads ---------------------------------------------------------------

    def _query(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        try:
            return _rows(self._conn.execute(sql, tuple(params)))
        except sqlite3.Error as exc:
            raise StorageError(f"query failed: {exc}") from exc

    def list_runs(self) -> list[dict[str, Any]]:
        return self._query("SELECT * FROM runs ORDER BY id DESC")

    def get_run(self, run_id: int) -> Optional[dict[str, Any]]:
        rows = self._query("SELECT * FROM runs WHERE id = ?", (run_id,))
        return rows[0] if rows else None

    def find_completed_run(self, fingerprint: str) -> Optional[dict[str, Any]]:
        rows = self._query("SELECT * FROM runs WHERE fingerprint = ? AND status = 'completed' "
                           "ORDER BY id DESC LIMIT 1", (fingerprint,))
        return rows[0] if rows else None

    @staticmethod
    def _time_clause(start: Optional[float], end: Optional[float], column_lo: str,
                     column_hi: str) -> tuple[str, list[Any]]:
        clause, params = "", []
        if start is not None:
            clause += f" AND {column_hi} > ?"  # columns are fixed literals from callers below
            params.append(start)
        if end is not None:
            clause += f" AND {column_lo} < ?"
            params.append(end)
        return clause, params

    def query_windows(self, run_id: int, start: Optional[float] = None,
                      end: Optional[float] = None) -> list[dict[str, Any]]:
        """Windows overlapping ``(start, end)`` in chronological order."""
        clause, params = self._time_clause(start, end, "window_start", "window_end")
        rows = self._query("SELECT * FROM traffic_stats WHERE run_id = ?" + clause +
                           " ORDER BY window_start", [run_id, *params])
        for row in rows:
            try:
                counts = json.loads(row["protocol_counts"])
            except (json.JSONDecodeError, TypeError) as exc:
                raise StorageError(f"invalid protocol counts in traffic window {row['id']}: {exc}") from exc
            if not isinstance(counts, dict) or not all(
                    isinstance(protocol, str) and isinstance(count, int) and count >= 0
                    for protocol, count in counts.items()):
                raise StorageError(f"invalid protocol counts in traffic window {row['id']}")
            row["protocol_counts"] = counts
        return rows

    @staticmethod
    def _event_filter(run_id: Optional[int], start: Optional[float], end: Optional[float],
                      rules: Optional[Sequence[str]], severities: Optional[Sequence[str]],
                      search: Optional[str] = None) \
            -> tuple[list[str], list[Any]]:
        clauses, params = ["1 = 1"], []
        if run_id is not None:
            clauses.append("run_id = ?")
            params.append(run_id)
        if start is not None:
            clauses.append("ts >= ?")
            params.append(start)
        if end is not None:
            clauses.append("ts <= ?")
            params.append(end)
        for column, values in (("rule", rules), ("severity", severities)):
            if values is not None:
                if not values:
                    clauses.append("0 = 1")  # an empty selection matches nothing
                    continue
                clauses.append(f"{column} IN ({', '.join('?' * len(values))})")
                params.extend(values)
        if search and search.strip():
            searchable = " || ' ' || ".join(
                f"COALESCE({column}, '')" for column in
                ("rule", "severity", "metric", "src_ip", "dst_info", "explanation"))
            clauses.append(f"INSTR(LOWER({searchable}), LOWER(?)) > 0")
            params.append(search.strip())
        return clauses, params

    def query_events(self, run_id: Optional[int] = None, start: Optional[float] = None,
                     end: Optional[float] = None, rules: Optional[Sequence[str]] = None,
                     severities: Optional[Sequence[str]] = None,
                     limit: Optional[int] = 1000,
                     search: Optional[str] = None) -> list[dict[str, Any]]:
        """Return filtered events in stable timestamp order.

        ``search`` is a literal, case-insensitive substring match across the
        human-readable event fields. Passing ``limit=None`` returns every
        matching row, which is intended for explicit exports rather than
        interactive tables.
        """
        clauses, params = self._event_filter(run_id, start, end, rules, severities, search)
        sql = "SELECT * FROM events WHERE " + " AND ".join(clauses) + " ORDER BY ts, id"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(int(limit))
        return self._query(sql, params)

    def count_events(self, run_id: Optional[int] = None, start: Optional[float] = None,
                     end: Optional[float] = None, rules: Optional[Sequence[str]] = None,
                     severities: Optional[Sequence[str]] = None,
                     search: Optional[str] = None) -> int:
        """Count events using the same filters as :meth:`query_events`."""
        clauses, params = self._event_filter(run_id, start, end, rules, severities, search)
        return int(self._query("SELECT COUNT(*) AS n FROM events WHERE " + " AND ".join(clauses),
                               params)[0]["n"])

    def top_sources(self, run_id: int, start: Optional[float] = None, end: Optional[float] = None,
                    by: str = "packets", limit: int = 10) -> list[dict[str, Any]]:
        """Sources ranked by summed ``packets``/``bytes``/``syn_attempts`` over the stored top talkers."""
        column = _SOURCE_SORT.get(by)
        if column is None:
            raise ValueError(f"by must be one of {sorted(_SOURCE_SORT)}, got {by!r}")
        clause, params = self._time_clause(start, end, "t.window_start", "t.window_end")
        return self._query(
            "SELECT s.src_ip AS src_ip, SUM(s.packets) AS packets, SUM(s.bytes) AS bytes, "
            "SUM(s.syn_attempts) AS syn_attempts, MAX(s.distinct_ports) AS max_distinct_ports, "
            "MAX(s.distinct_hosts) AS max_distinct_hosts FROM source_stats s "
            "JOIN traffic_stats t ON t.id = s.window_id WHERE t.run_id = ?" + clause +
            f" GROUP BY s.src_ip ORDER BY {column} DESC, s.src_ip LIMIT ?",
            [run_id, *params, int(limit)])

    def protocol_totals(self, run_id: int, start: Optional[float] = None,
                        end: Optional[float] = None) -> dict[str, int]:
        totals: dict[str, int] = {}
        for window in self.query_windows(run_id, start, end):
            for proto, n in window["protocol_counts"].items():
                totals[proto] = totals.get(proto, 0) + n
        return dict(sorted(totals.items(), key=lambda kv: (-kv[1], kv[0])))

    def time_bounds(self, run_id: int) -> Optional[tuple[float, float]]:
        row = self._query("SELECT MIN(window_start) AS lo, MAX(window_end) AS hi "
                          "FROM traffic_stats WHERE run_id = ?", (run_id,))[0]
        return (row["lo"], row["hi"]) if row["lo"] is not None else None


def reset_database(path: str | Path, *, confirm: bool = False) -> None:
    """Drop and recreate all Lattice tables in ``path``.

    Refuses unless ``confirm=True`` and refuses to touch any existing SQLite
    file that is not already marked as a Lattice database. Use a dedicated
    path (``--db``) for tests so real data is never at risk.
    """
    if not confirm:
        raise StorageError("refusing to reset the database without confirm=True (--yes on the CLI)")
    file = Path(path)
    if file.exists() and file.stat().st_size > 0:
        try:
            probe = sqlite3.connect(f"{file.resolve().as_uri()}?mode=ro", uri=True)
            try:
                app_id = probe.execute("PRAGMA application_id").fetchone()[0]
            finally:
                probe.close()
        except sqlite3.Error as exc:
            raise StorageError(f"{file} is not a readable SQLite database: {exc}") from exc
        if app_id != APPLICATION_ID:
            raise StorageError(f"{file} is not a Lattice database; refusing to reset it")
        conn = sqlite3.connect(str(file), timeout=10)
        try:
            with conn:
                for table in _TABLES:  # fixed names, children first
                    conn.execute(f"DROP TABLE IF EXISTS {table}")
        except sqlite3.Error as exc:
            raise StorageError(f"cannot reset {file}: {exc}") from exc
        finally:
            conn.close()
    Storage(file).close()
