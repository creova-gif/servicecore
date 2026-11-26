from __future__ import annotations

import os
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from servicecore.schemas import AuditBundle, AuditEvent, MonitorSchedule

__all__ = [
    "AuditStore",
    "InMemoryAuditStore",
    "SQLiteAuditStore",
]


class AuditStore(Protocol):
    """Tenant-scoped persistence abstraction for AuditBundle records."""

    def save(self, bundle: AuditBundle) -> None:
        """Persist or overwrite an AuditBundle under its org_id and audit_id."""
        ...

    def get(self, org_id: str, audit_id: str) -> AuditBundle | None:
        """Fetch an AuditBundle strictly scoped to org_id, or None if not found."""
        ...

    def delete_audit(self, org_id: str, audit_id: str) -> bool:
        """Delete an AuditBundle strictly scoped to org_id; return True if deleted."""
        ...

    def list_for_org(self, org_id: str, limit: int = 50, offset: int = 0) -> list[AuditBundle]:
        """List AuditBundles belonging to org_id with pagination."""
        ...

    def save_monitor(self, monitor: MonitorSchedule) -> None:
        """Persist or overwrite a MonitorSchedule under its org_id and monitor_id."""
        ...

    def get_monitor(self, org_id: str, monitor_id: str) -> MonitorSchedule | None:
        """Fetch a MonitorSchedule strictly scoped to org_id, or None if not found."""
        ...

    def list_monitors_for_org(
        self, org_id: str, limit: int = 50, offset: int = 0
    ) -> list[MonitorSchedule]:
        """List MonitorSchedules belonging to org_id with pagination."""
        ...

    def delete_monitor(self, org_id: str, monitor_id: str) -> bool:
        """Delete a MonitorSchedule strictly scoped to org_id; return True if deleted."""
        ...

    def record_event(self, event: AuditEvent) -> None:
        """Persist an immutable AuditEvent for an audit."""
        ...

    def list_events(
        self, org_id: str, audit_id: str, *, limit: int = 50, offset: int = 0
    ) -> list[AuditEvent]:
        """List AuditEvents for an audit strictly scoped to org_id in chronological order."""
        ...

    def get_stats(self) -> dict[str, int]:
        """Return aggregate store counts for observability."""
        ...


class InMemoryAuditStore:
    """In-memory AuditStore keyed by (org_id, audit_id) for strict tenant isolation."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._bundles: dict[tuple[str, str], AuditBundle] = {}
        self._monitors: dict[tuple[str, str], MonitorSchedule] = {}
        self._events: dict[tuple[str, str], list[AuditEvent]] = {}

    def save(self, bundle: AuditBundle) -> None:
        with self._lock:
            self._bundles[(bundle.org_id, bundle.audit_id)] = bundle

    def get(self, org_id: str, audit_id: str) -> AuditBundle | None:
        with self._lock:
            return self._bundles.get((org_id, audit_id))

    def delete_audit(self, org_id: str, audit_id: str) -> bool:
        with self._lock:
            deleted = self._bundles.pop((org_id, audit_id), None) is not None
            if deleted:
                self._events.pop((org_id, audit_id), None)
            return deleted

    def list_for_org(self, org_id: str, limit: int = 50, offset: int = 0) -> list[AuditBundle]:
        with self._lock:
            items = [
                bundle
                for (stored_org_id, _), bundle in self._bundles.items()
                if stored_org_id == org_id
            ]
            return items[offset : offset + limit]

    def save_monitor(self, monitor: MonitorSchedule) -> None:
        with self._lock:
            self._monitors[(monitor.org_id, monitor.monitor_id)] = monitor

    def get_monitor(self, org_id: str, monitor_id: str) -> MonitorSchedule | None:
        with self._lock:
            return self._monitors.get((org_id, monitor_id))

    def list_monitors_for_org(
        self, org_id: str, limit: int = 50, offset: int = 0
    ) -> list[MonitorSchedule]:
        with self._lock:
            items = [
                monitor
                for (stored_org_id, _), monitor in self._monitors.items()
                if stored_org_id == org_id
            ]
            return items[offset : offset + limit]

    def delete_monitor(self, org_id: str, monitor_id: str) -> bool:
        with self._lock:
            return self._monitors.pop((org_id, monitor_id), None) is not None

    def record_event(self, event: AuditEvent) -> None:
        """Persist an immutable AuditEvent in memory under self._lock."""
        with self._lock:
            self._events.setdefault((event.org_id, event.audit_id), []).append(event)

    def list_events(
        self, org_id: str, audit_id: str, *, limit: int = 50, offset: int = 0
    ) -> list[AuditEvent]:
        """List AuditEvents for an audit strictly scoped to org_id in chronological order."""
        with self._lock:
            items = sorted(
                self._events.get((org_id, audit_id), []),
                key=lambda event: event.created_at_utc,
            )
            return items[offset : offset + limit]

    def get_stats(self) -> dict[str, int]:
        """Return aggregate store counts for observability."""
        with self._lock:
            return {
                "total_audits": len(self._bundles),
                "total_monitors": len(self._monitors),
                "processed_stripe_events": 0,
            }


class SQLiteAuditStore:
    """SQLite-backed AuditStore with composite (org_id, audit_id) primary key."""

    def __init__(self, db_path: str | os.PathLike[str]) -> None:
        self._db_path = os.fspath(db_path)
        self._lock = threading.RLock()
        self._memory_conn: sqlite3.Connection | None = None
        if self._db_path == ":memory:":
            self._memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
        else:
            Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        if self._memory_conn is not None:
            conn = self._memory_conn
        else:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _close_if_ephemeral(self, conn: sqlite3.Connection) -> None:
        if self._memory_conn is None:
            conn.close()

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS audits (
                            org_id TEXT NOT NULL,
                            audit_id TEXT NOT NULL,
                            updated_at_utc TEXT NOT NULL,
                            bundle_json TEXT NOT NULL,
                            PRIMARY KEY (org_id, audit_id)
                        )
                        """
                    )
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS stripe_events (
                            event_id TEXT PRIMARY KEY,
                            processed_at_utc TEXT NOT NULL
                        )
                        """
                    )
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS monitors (
                            org_id TEXT NOT NULL,
                            monitor_id TEXT NOT NULL,
                            updated_at_utc TEXT NOT NULL,
                            monitor_json TEXT NOT NULL,
                            PRIMARY KEY (org_id, monitor_id)
                        )
                        """
                    )
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS audit_events (
                            event_id TEXT PRIMARY KEY,
                            org_id TEXT NOT NULL,
                            audit_id TEXT NOT NULL,
                            created_at_utc TEXT NOT NULL,
                            event_json TEXT NOT NULL
                        )
                        """
                    )
                    conn.execute(
                        """
                        CREATE INDEX IF NOT EXISTS idx_audit_events_org_audit_created
                        ON audit_events (org_id, audit_id, created_at_utc)
                        """
                    )
            finally:
                self._close_if_ephemeral(conn)

    def save(self, bundle: AuditBundle) -> None:
        """Persist or overwrite an AuditBundle under its (org_id, audit_id) key."""
        updated_at_utc = datetime.now(UTC).isoformat()
        bundle_json = bundle.model_dump_json()
        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO audits (org_id, audit_id, updated_at_utc, bundle_json)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(org_id, audit_id) DO UPDATE SET
                            updated_at_utc = excluded.updated_at_utc,
                            bundle_json = excluded.bundle_json
                        """,
                        (bundle.org_id, bundle.audit_id, updated_at_utc, bundle_json),
                    )
            finally:
                self._close_if_ephemeral(conn)

    def get(self, org_id: str, audit_id: str) -> AuditBundle | None:
        """Fetch an AuditBundle strictly scoped to org_id, or None if not found."""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT bundle_json FROM audits WHERE org_id = ? AND audit_id = ?",
                    (org_id, audit_id),
                ).fetchone()
            finally:
                self._close_if_ephemeral(conn)
        if row is None:
            return None
        return AuditBundle.model_validate_json(row[0])

    def delete_audit(self, org_id: str, audit_id: str) -> bool:
        """Delete an AuditBundle strictly scoped to org_id; return True if deleted."""
        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    conn.execute(
                        "DELETE FROM audit_events WHERE org_id = ? AND audit_id = ?",
                        (org_id, audit_id),
                    )
                    cursor = conn.execute(
                        "DELETE FROM audits WHERE org_id = ? AND audit_id = ?",
                        (org_id, audit_id),
                    )
                    return cursor.rowcount > 0
            finally:
                self._close_if_ephemeral(conn)

    def list_for_org(self, org_id: str, limit: int = 50, offset: int = 0) -> list[AuditBundle]:
        """List AuditBundles belonging to org_id, newest updated first, with pagination."""
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT bundle_json FROM audits
                    WHERE org_id = ?
                    ORDER BY updated_at_utc DESC, audit_id ASC
                    LIMIT ? OFFSET ?
                    """,
                    (org_id, limit, offset),
                ).fetchall()
            finally:
                self._close_if_ephemeral(conn)
        return [AuditBundle.model_validate_json(row[0]) for row in rows]

    def record_stripe_event(self, event_id: str) -> bool:
        """Record a processed Stripe event_id; return True if new, False if duplicate."""
        processed_at_utc = datetime.now(UTC).isoformat()
        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    cursor = conn.execute(
                        """
                        INSERT OR IGNORE INTO stripe_events (event_id, processed_at_utc)
                        VALUES (?, ?)
                        """,
                        (event_id, processed_at_utc),
                    )
                    return cursor.rowcount == 1
            finally:
                self._close_if_ephemeral(conn)

    def save_monitor(self, monitor: MonitorSchedule) -> None:
        """Persist or overwrite a MonitorSchedule under its (org_id, monitor_id) key."""
        updated_at_utc = datetime.now(UTC).isoformat()
        monitor_json = monitor.model_dump_json()
        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO monitors (org_id, monitor_id, updated_at_utc, monitor_json)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(org_id, monitor_id) DO UPDATE SET
                            updated_at_utc = excluded.updated_at_utc,
                            monitor_json = excluded.monitor_json
                        """,
                        (monitor.org_id, monitor.monitor_id, updated_at_utc, monitor_json),
                    )
            finally:
                self._close_if_ephemeral(conn)

    def get_monitor(self, org_id: str, monitor_id: str) -> MonitorSchedule | None:
        """Fetch a MonitorSchedule strictly scoped to org_id, or None if not found."""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT monitor_json FROM monitors WHERE org_id = ? AND monitor_id = ?",
                    (org_id, monitor_id),
                ).fetchone()
            finally:
                self._close_if_ephemeral(conn)
        if row is None:
            return None
        return MonitorSchedule.model_validate_json(row[0])

    def list_monitors_for_org(
        self, org_id: str, limit: int = 50, offset: int = 0
    ) -> list[MonitorSchedule]:
        """List MonitorSchedules belonging to org_id, newest updated first, with pagination."""
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT monitor_json FROM monitors
                    WHERE org_id = ?
                    ORDER BY updated_at_utc DESC, monitor_id ASC
                    LIMIT ? OFFSET ?
                    """,
                    (org_id, limit, offset),
                ).fetchall()
            finally:
                self._close_if_ephemeral(conn)
        return [MonitorSchedule.model_validate_json(row[0]) for row in rows]

    def delete_monitor(self, org_id: str, monitor_id: str) -> bool:
        """Delete a MonitorSchedule strictly scoped to org_id; return True if deleted."""
        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    cursor = conn.execute(
                        "DELETE FROM monitors WHERE org_id = ? AND monitor_id = ?",
                        (org_id, monitor_id),
                    )
                    return cursor.rowcount > 0
            finally:
                self._close_if_ephemeral(conn)

    def record_event(self, event: AuditEvent) -> None:
        """Persist an immutable AuditEvent in SQLite."""
        created_at_utc = event.created_at_utc.isoformat()
        event_json = event.model_dump_json()
        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO audit_events (
                            event_id, org_id, audit_id, created_at_utc, event_json
                        )
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (event.event_id, event.org_id, event.audit_id, created_at_utc, event_json),
                    )
            finally:
                self._close_if_ephemeral(conn)

    def list_events(
        self, org_id: str, audit_id: str, *, limit: int = 50, offset: int = 0
    ) -> list[AuditEvent]:
        """List AuditEvents for an audit strictly scoped to org_id in chronological order."""
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT event_json FROM audit_events
                    WHERE org_id = ? AND audit_id = ?
                    ORDER BY created_at_utc ASC, rowid ASC
                    LIMIT ? OFFSET ?
                    """,
                    (org_id, audit_id, limit, offset),
                ).fetchall()
            finally:
                self._close_if_ephemeral(conn)
        return [AuditEvent.model_validate_json(row[0]) for row in rows]

    def get_stats(self) -> dict[str, int]:
        """Return aggregate store counts for observability."""
        with self._lock:
            conn = self._connect()
            try:
                total_audits = int(conn.execute("SELECT COUNT(*) FROM audits").fetchone()[0])
                total_monitors = int(conn.execute("SELECT COUNT(*) FROM monitors").fetchone()[0])
                processed_stripe_events = int(
                    conn.execute("SELECT COUNT(*) FROM stripe_events").fetchone()[0]
                )
            finally:
                self._close_if_ephemeral(conn)
        return {
            "total_audits": total_audits,
            "total_monitors": total_monitors,
            "processed_stripe_events": processed_stripe_events,
        }

    def backup(self, dest_path: Path | str) -> Path:
        """Create an online SQLite backup at dest_path and verify its integrity."""
        dest = Path(dest_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            src_conn = self._connect()
            dst_conn: sqlite3.Connection | None = None
            try:
                dst_conn = sqlite3.connect(dest)
                src_conn.backup(dst_conn)
                integrity = dst_conn.execute("PRAGMA integrity_check;").fetchone()
                if integrity != ("ok",):
                    raise RuntimeError(f"SQLite backup integrity check failed: {integrity!r}")
            finally:
                if dst_conn is not None:
                    dst_conn.close()
                self._close_if_ephemeral(src_conn)
        return dest
