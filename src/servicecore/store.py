from __future__ import annotations

import os
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from servicecore.schemas import AuditBundle, MonitorSchedule

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

    def list_for_org(self, org_id: str) -> list[AuditBundle]:
        """List all AuditBundles belonging to org_id."""
        ...

    def save_monitor(self, monitor: MonitorSchedule) -> None:
        """Persist or overwrite a MonitorSchedule under its org_id and monitor_id."""
        ...

    def get_monitor(self, org_id: str, monitor_id: str) -> MonitorSchedule | None:
        """Fetch a MonitorSchedule strictly scoped to org_id, or None if not found."""
        ...

    def list_monitors_for_org(self, org_id: str) -> list[MonitorSchedule]:
        """List all MonitorSchedules belonging to org_id."""
        ...


class InMemoryAuditStore:
    """In-memory AuditStore keyed by (org_id, audit_id) for strict tenant isolation."""

    def __init__(self) -> None:
        self._bundles: dict[tuple[str, str], AuditBundle] = {}
        self._monitors: dict[tuple[str, str], MonitorSchedule] = {}

    def save(self, bundle: AuditBundle) -> None:
        self._bundles[(bundle.org_id, bundle.audit_id)] = bundle

    def get(self, org_id: str, audit_id: str) -> AuditBundle | None:
        return self._bundles.get((org_id, audit_id))

    def list_for_org(self, org_id: str) -> list[AuditBundle]:
        return [
            bundle
            for (stored_org_id, _), bundle in self._bundles.items()
            if stored_org_id == org_id
        ]

    def save_monitor(self, monitor: MonitorSchedule) -> None:
        self._monitors[(monitor.org_id, monitor.monitor_id)] = monitor

    def get_monitor(self, org_id: str, monitor_id: str) -> MonitorSchedule | None:
        return self._monitors.get((org_id, monitor_id))

    def list_monitors_for_org(self, org_id: str) -> list[MonitorSchedule]:
        return [
            monitor
            for (stored_org_id, _), monitor in self._monitors.items()
            if stored_org_id == org_id
        ]


class SQLiteAuditStore:
    """SQLite-backed AuditStore with composite (org_id, audit_id) primary key."""

    def __init__(self, db_path: str | os.PathLike[str]) -> None:
        self._db_path = os.fspath(db_path)
        self._lock = threading.Lock()
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

    def list_for_org(self, org_id: str) -> list[AuditBundle]:
        """List all AuditBundles belonging to org_id, newest updated first."""
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT bundle_json FROM audits
                    WHERE org_id = ?
                    ORDER BY updated_at_utc DESC, audit_id ASC
                    """,
                    (org_id,),
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

    def list_monitors_for_org(self, org_id: str) -> list[MonitorSchedule]:
        """List all MonitorSchedules belonging to org_id, newest updated first."""
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT monitor_json FROM monitors
                    WHERE org_id = ?
                    ORDER BY updated_at_utc DESC, monitor_id ASC
                    """,
                    (org_id,),
                ).fetchall()
            finally:
                self._close_if_ephemeral(conn)
        return [MonitorSchedule.model_validate_json(row[0]) for row in rows]
