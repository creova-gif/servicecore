from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from servicecore.alerts import run_due_monitors
from servicecore.cli import run_audit
from servicecore.exporter import (
    diff_bundles,
    export_github_issues,
    render_report_html,
    sign_bundle,
    verify_bundle,
)
from servicecore.github_publisher import PublishedIssue, publish_bundle_to_github
from servicecore.sarif import export_sarif
from servicecore.scanners import ScannerBackend
from servicecore.schemas import (
    AuditBundle,
    DiffReport,
    EvidenceMismatchError,
    FindingReview,
    MonitorRunResult,
    MonitorSchedule,
    ScannerError,
    SSRFBlockedError,
    UnsignedFindingError,
)
from servicecore.synthesizer import ClaudeSynthesizer, sanitize_html_snippet, validate_patch_binding

__all__ = [
    "AuditStore",
    "CreateAuditRequest",
    "CreateMonitorRequest",
    "DevTokenResponse",
    "ExportResponse",
    "HealthcheckResponse",
    "InMemoryAuditStore",
    "PublishGitHubRequest",
    "PublishGitHubResponse",
    "RunDueMonitorsRequest",
    "SQLiteAuditStore",
    "TenantContext",
    "UpdateFindingReviewRequest",
    "WebhookResponse",
    "create_app",
    "get_current_tenant",
    "mint_auth_token",
]

_DEV_FALLBACK_SECRET = "servicecore-dev-insecure-secret-do-not-use-in-prod"
_DEFAULT_CORS_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:3100",
    "http://localhost:3105",
]


class TenantContext(BaseModel):
    """Authenticated tenant identity extracted from a signed bearer token."""

    org_id: str = Field(min_length=1)
    sub: str = Field(min_length=1)


class HealthcheckResponse(BaseModel):
    """Liveness probe response."""

    status: Literal["ok"] = "ok"


class CreateAuditRequest(BaseModel):
    """Request body for triggering a new accessibility/compliance audit."""

    target_url: str = Field(min_length=1)
    audit_price_usd: float = Field(gt=0.0, default=1500.0)
    crawl: bool = False
    max_pages: int = Field(default=5, ge=1, le=20)
    max_pdfs: int = Field(default=5, ge=0, le=20)


class CreateMonitorRequest(BaseModel):
    """Request body for creating a recurring monitoring schedule."""

    target_url: str = Field(min_length=1)
    cadence_hours: int = Field(default=24, ge=1, le=720)
    crawl: bool = False
    max_pages: int = Field(default=5, ge=1, le=20)
    max_pdfs: int = Field(default=5, ge=0, le=20)


class RunDueMonitorsRequest(BaseModel):
    """Request body for running all due monitors for the authenticated tenant."""

    webhook_url: str | None = None


class UpdateFindingReviewRequest(BaseModel):
    """Request body for human-in-the-loop triage of a single finding."""

    status: Literal["APPROVED", "REJECTED", "EDITED"]
    rejection_reason: str | None = None
    edited_after_snippet: str | None = None


class ExportResponse(BaseModel):
    """Certified export payload returned after bundle sign-off and digest verification."""

    audit_id: str = Field(min_length=1)
    evidence_digest: str = Field(min_length=64, max_length=64)
    html_report: str
    github_issues_markdown: str


class PublishGitHubRequest(BaseModel):
    """Request body for publishing certified audit findings as GitHub issues."""

    repo: str = Field(min_length=1)
    github_token: str = Field(min_length=1)


class PublishGitHubResponse(BaseModel):
    """Summary of GitHub issues created from a certified audit bundle."""

    audit_id: str = Field(min_length=1)
    issues_created: int = Field(ge=0)
    issues: list[PublishedIssue]


class WebhookResponse(BaseModel):
    """Acknowledgement returned by the Stripe webhook endpoint."""

    status: Literal["processed", "duplicate"]


class DevTokenResponse(BaseModel):
    """Local development bearer token response."""

    token: str = Field(min_length=1)
    org_id: str = Field(min_length=1)


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
            return self._memory_conn
        return sqlite3.connect(self._db_path, check_same_thread=False)

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


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode((segment + padding).encode("ascii"))


def mint_auth_token(org_id: str, sub: str, secret: str) -> str:
    """Mint an HMAC-SHA256 signed bearer token encoding org_id and sub."""
    if not org_id.strip() or not sub.strip():
        raise ValueError("org_id and sub must be non-empty")
    if not secret:
        raise ValueError("secret must be non-empty")
    payload_bytes = json.dumps(
        {"org_id": org_id, "sub": sub},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    payload_b64 = _b64url_encode(payload_bytes)
    sig = hmac.new(secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).digest()
    return f"{payload_b64}.{_b64url_encode(sig)}"


def _resolve_auth_secret(configured_secret: str | None = None) -> str | None:
    if configured_secret:
        return configured_secret
    env_secret = os.environ.get("SERVICECORE_AUTH_SECRET")
    if env_secret:
        return env_secret
    if os.environ.get("SERVICECORE_DEV_MODE") == "1":
        return _DEV_FALLBACK_SECRET
    return None


def _verify_auth_token(token: str, secret: str) -> TenantContext:
    parts = token.split(".")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token format",
        )
    payload_b64, sig_b64 = parts
    try:
        provided_sig = _b64url_decode(sig_b64)
        expected_sig = hmac.new(
            secret.encode("utf-8"),
            payload_b64.encode("ascii"),
            hashlib.sha256,
        ).digest()
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed bearer token signature",
        ) from exc

    if not hmac.compare_digest(provided_sig, expected_sig):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token signature",
        )

    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        if not isinstance(payload, dict):
            raise TypeError("Token payload must be a JSON object")
        return TenantContext.model_validate(payload)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token payload",
        ) from exc


def get_current_tenant(
    request: Request,
    authorization: str | None = Header(default=None),
) -> TenantContext:
    """FastAPI dependency that authenticates the caller and returns TenantContext."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
        )
    token = authorization[len("Bearer ") :].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Empty bearer token",
        )

    configured = getattr(request.app.state, "auth_secret", None)
    secret = _resolve_auth_secret(configured if isinstance(configured, str) else None)
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication secret is not configured",
        )
    return _verify_auth_token(token, secret)


def _verify_stripe_signature(raw_body: bytes, sig_header: str | None, secret: str) -> bool:
    if not sig_header or not secret:
        return False

    timestamp: str | None = None
    v1_signatures: list[str] = []
    for item in sig_header.split(","):
        key, sep, value = item.strip().partition("=")
        if not sep:
            continue
        if key == "t":
            timestamp = value
        elif key == "v1":
            v1_signatures.append(value)

    if not timestamp or not v1_signatures:
        return False

    signed_payload = f"{timestamp}.".encode() + raw_body
    expected_sig = hmac.new(
        secret.encode("utf-8"),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    return any(hmac.compare_digest(expected_sig, candidate) for candidate in v1_signatures)


CurrentTenant = Annotated[TenantContext, Depends(get_current_tenant)]


def _resolve_cors_origins(allow_origins: list[str] | None = None) -> list[str]:
    if allow_origins is not None:
        return allow_origins
    env_origins = os.environ.get("SERVICECORE_CORS_ORIGINS", "")
    parsed = [origin.strip() for origin in env_origins.split(",") if origin.strip()]
    return parsed if parsed else list(_DEFAULT_CORS_ORIGINS)


def create_app(
    *,
    auth_secret: str | None = None,
    stripe_webhook_secret: str | None = None,
    store: AuditStore | None = None,
    scanner: ScannerBackend | None = None,
    synthesizer: ClaudeSynthesizer | None = None,
    allow_origins: list[str] | None = None,
) -> FastAPI:
    """Build and configure the ServiceCore FastAPI application."""
    app = FastAPI(title="ServiceCore Compliance API", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_resolve_cors_origins(allow_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.auth_secret = auth_secret
    app.state.stripe_webhook_secret = stripe_webhook_secret
    if store is not None:
        resolved_store: AuditStore = store
    else:
        db_path = os.environ.get("SERVICECORE_DB_PATH")
        resolved_store = SQLiteAuditStore(db_path) if db_path else InMemoryAuditStore()
    app.state.store = resolved_store
    app.state.scanner = scanner
    app.state.synthesizer = synthesizer
    app.state.processed_stripe_events = set()

    @app.get("/healthcheck", response_model=HealthcheckResponse)
    @app.get("/healthz", response_model=HealthcheckResponse)
    def healthcheck_endpoint() -> HealthcheckResponse:
        return HealthcheckResponse(status="ok")

    @app.post("/dev/token", response_model=DevTokenResponse)
    def dev_token_endpoint() -> DevTokenResponse:
        if os.environ.get("SERVICECORE_DEV_MODE") != "1":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Not found",
            )
        return DevTokenResponse(
            token=mint_auth_token(
                "org_dev",
                "reviewer@servicecore.local",
                _DEV_FALLBACK_SECRET,
            ),
            org_id="org_dev",
        )

    @app.get("/audits", response_model=list[AuditBundle])
    def list_audits_endpoint(
        request: Request,
        tenant: CurrentTenant,
    ) -> list[AuditBundle]:
        active_store: AuditStore = request.app.state.store
        return active_store.list_for_org(tenant.org_id)

    @app.post("/audits", response_model=AuditBundle, status_code=status.HTTP_201_CREATED)
    def create_audit_endpoint(
        body: CreateAuditRequest,
        request: Request,
        tenant: CurrentTenant,
    ) -> AuditBundle:
        active_scanner: ScannerBackend | None = getattr(request.app.state, "scanner", None)
        active_synth: ClaudeSynthesizer | None = getattr(request.app.state, "synthesizer", None)
        try:
            bundle = run_audit(
                body.target_url,
                scanner=active_scanner,
                synthesizer=active_synth,
                audit_price_usd=body.audit_price_usd,
                crawl=body.crawl,
                max_pages=body.max_pages,
                max_pdfs=body.max_pdfs,
            )
        except ScannerError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

        scoped_bundle = bundle.model_copy(update={"org_id": tenant.org_id})
        active_store: AuditStore = request.app.state.store
        active_store.save(scoped_bundle)
        return scoped_bundle

    @app.get("/audits/{audit_id}", response_model=AuditBundle)
    def get_audit_endpoint(
        audit_id: str,
        request: Request,
        tenant: CurrentTenant,
    ) -> AuditBundle:
        active_store: AuditStore = request.app.state.store
        bundle = active_store.get(tenant.org_id, audit_id)
        if bundle is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        return bundle

    @app.get("/audits/{audit_id}/diff", response_model=DiffReport)
    def diff_audit_endpoint(
        audit_id: str,
        baseline_id: str,
        request: Request,
        tenant: CurrentTenant,
    ) -> DiffReport:
        active_store: AuditStore = request.app.state.store
        current = active_store.get(tenant.org_id, audit_id)
        if current is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        baseline = active_store.get(tenant.org_id, baseline_id)
        if baseline is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Baseline audit not found",
            )
        return diff_bundles(baseline, current)

    @app.post("/monitors", response_model=MonitorSchedule, status_code=status.HTTP_201_CREATED)
    def create_monitor_endpoint(
        body: CreateMonitorRequest,
        request: Request,
        tenant: CurrentTenant,
    ) -> MonitorSchedule:
        active_store: AuditStore = request.app.state.store
        monitor = MonitorSchedule(
            monitor_id=f"mon-{uuid.uuid4().hex[:12]}",
            org_id=tenant.org_id,
            target_url=body.target_url,
            cadence_hours=body.cadence_hours,
            crawl=body.crawl,
            max_pages=body.max_pages,
            max_pdfs=body.max_pdfs,
        )
        active_store.save_monitor(monitor)
        return monitor

    @app.get("/monitors", response_model=list[MonitorSchedule])
    def list_monitors_endpoint(
        request: Request,
        tenant: CurrentTenant,
    ) -> list[MonitorSchedule]:
        active_store: AuditStore = request.app.state.store
        return active_store.list_monitors_for_org(tenant.org_id)

    @app.post("/monitors/{monitor_id}/run", response_model=MonitorRunResult)
    def run_monitor_endpoint(
        monitor_id: str,
        request: Request,
        tenant: CurrentTenant,
    ) -> MonitorRunResult:
        active_store: AuditStore = request.app.state.store
        monitor = active_store.get_monitor(tenant.org_id, monitor_id)
        if monitor is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Monitor not found")

        active_scanner: ScannerBackend | None = getattr(request.app.state, "scanner", None)
        active_synth: ClaudeSynthesizer | None = getattr(request.app.state, "synthesizer", None)
        try:
            bundle = run_audit(
                monitor.target_url,
                scanner=active_scanner,
                synthesizer=active_synth,
                crawl=monitor.crawl,
                max_pages=monitor.max_pages,
                max_pdfs=monitor.max_pdfs,
            )
        except ScannerError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

        scoped_bundle = bundle.model_copy(update={"org_id": tenant.org_id})
        active_store.save(scoped_bundle)

        diff: DiffReport | None = None
        if monitor.baseline_audit_id is not None:
            baseline = active_store.get(tenant.org_id, monitor.baseline_audit_id)
            if baseline is not None:
                diff = diff_bundles(baseline, scoped_bundle)

        updated_monitor = monitor.model_copy(
            update={
                "baseline_audit_id": scoped_bundle.audit_id,
                "last_run_at_utc": datetime.now(UTC),
            }
        )
        active_store.save_monitor(updated_monitor)
        return MonitorRunResult(monitor=updated_monitor, audit=scoped_bundle, diff=diff)

    @app.post("/monitors/run-due", response_model=list[MonitorRunResult])
    def run_due_monitors_endpoint(
        request: Request,
        tenant: CurrentTenant,
        body: RunDueMonitorsRequest | None = None,
    ) -> list[MonitorRunResult]:
        active_store: AuditStore = request.app.state.store
        active_scanner: ScannerBackend | None = getattr(request.app.state, "scanner", None)
        active_synth: ClaudeSynthesizer | None = getattr(request.app.state, "synthesizer", None)
        webhook_url = body.webhook_url if body is not None else None
        try:
            return run_due_monitors(
                active_store,
                tenant.org_id,
                scanner=active_scanner,
                synthesizer=active_synth,
                webhook_url=webhook_url,
            )
        except SSRFBlockedError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        except ScannerError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    @app.patch("/audits/{audit_id}/findings/{finding_id}", response_model=AuditBundle)
    def update_finding_review_endpoint(
        audit_id: str,
        finding_id: str,
        body: UpdateFindingReviewRequest,
        request: Request,
        tenant: CurrentTenant,
    ) -> AuditBundle:
        active_store: AuditStore = request.app.state.store
        bundle = active_store.get(tenant.org_id, audit_id)
        if bundle is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")

        findings_by_id = {f.finding_id: f for f in bundle.findings}
        if finding_id not in findings_by_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

        updated_patches = list(bundle.patches)
        if body.edited_after_snippet is not None:
            try:
                sanitize_html_snippet(body.edited_after_snippet)
            except EvidenceMismatchError as exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=str(exc),
                ) from exc

            new_patches = []
            for patch in updated_patches:
                if patch.finding_id == finding_id and patch.patch_kind == "html_diff":
                    candidate = patch.model_copy(
                        update={
                            "after_snippet": body.edited_after_snippet,
                            "synthesized_by": "human_edit",
                        }
                    )
                    try:
                        validate_patch_binding(candidate, findings_by_id)
                    except EvidenceMismatchError as exc:
                        raise HTTPException(
                            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail=str(exc),
                        ) from exc
                    new_patches.append(candidate)
                else:
                    new_patches.append(patch)
            updated_patches = new_patches

        try:
            new_review = FindingReview(
                finding_id=finding_id,
                status=body.status,
                rejection_reason=body.rejection_reason,
                reviewer_id=tenant.sub,
                signed_at_utc=datetime.now(UTC),
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc

        updated_reviews = [r for r in bundle.reviews if r.finding_id != finding_id]
        updated_reviews.append(new_review)

        updated_bundle = bundle.model_copy(
            update={
                "patches": updated_patches,
                "reviews": updated_reviews,
                "reviewer_id": None,
                "signed_at_utc": None,
                "evidence_digest": None,
            }
        )
        active_store.save(updated_bundle)
        return updated_bundle

    def _sign_and_verify_audit(
        active_store: AuditStore,
        org_id: str,
        audit_id: str,
        reviewer_id: str,
    ) -> AuditBundle:
        """Load, sign, verify, and persist an audit bundle for certified export."""
        bundle = active_store.get(org_id, audit_id)
        if bundle is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")

        try:
            signed_bundle = sign_bundle(bundle, reviewer_id=reviewer_id)
        except UnsignedFindingError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        except EvidenceMismatchError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc

        try:
            ok, reason = verify_bundle(signed_bundle)
        except EvidenceMismatchError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        if not ok:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=reason)

        active_store.save(signed_bundle)
        return signed_bundle

    @app.post("/audits/{audit_id}/export", response_model=ExportResponse)
    def export_audit_endpoint(
        audit_id: str,
        request: Request,
        tenant: CurrentTenant,
    ) -> ExportResponse:
        active_store: AuditStore = request.app.state.store
        signed_bundle = _sign_and_verify_audit(active_store, tenant.org_id, audit_id, tenant.sub)
        html_report = render_report_html(signed_bundle, draft=False)
        github_md = export_github_issues(signed_bundle)
        return ExportResponse(
            audit_id=signed_bundle.audit_id,
            evidence_digest=signed_bundle.evidence_digest or "",
            html_report=html_report,
            github_issues_markdown=github_md,
        )

    @app.post("/audits/{audit_id}/export/pdf")
    def export_audit_pdf_endpoint(
        audit_id: str,
        request: Request,
        tenant: CurrentTenant,
    ) -> Response:
        active_store: AuditStore = request.app.state.store
        signed_bundle = _sign_and_verify_audit(active_store, tenant.org_id, audit_id, tenant.sub)
        try:
            html_report = render_report_html(signed_bundle, draft=False)
        except UnsignedFindingError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        except EvidenceMismatchError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc

        # Deferred import so non-PDF workflows and unsigned checks do not require native pango/gobject at import time.
        import weasyprint

        pdf_bytes: bytes = weasyprint.HTML(string=html_report).write_pdf()
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="servicecore-{audit_id}.pdf"',
                "X-Evidence-Digest": signed_bundle.evidence_digest or "",
            },
        )

    @app.get("/audits/{audit_id}/export/sarif")
    def export_audit_sarif_endpoint(
        audit_id: str,
        request: Request,
        tenant: CurrentTenant,
    ) -> dict[str, Any]:
        active_store: AuditStore = request.app.state.store
        signed_bundle = _sign_and_verify_audit(active_store, tenant.org_id, audit_id, tenant.sub)
        try:
            return export_sarif(signed_bundle)
        except UnsignedFindingError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    @app.post("/audits/{audit_id}/publish/github", response_model=PublishGitHubResponse)
    def publish_github_endpoint(
        audit_id: str,
        body: PublishGitHubRequest,
        request: Request,
        tenant: CurrentTenant,
    ) -> PublishGitHubResponse:
        active_store: AuditStore = request.app.state.store
        signed_bundle = _sign_and_verify_audit(active_store, tenant.org_id, audit_id, tenant.sub)
        github_client: httpx.Client | None = getattr(request.app.state, "github_client", None)
        try:
            issues = publish_bundle_to_github(
                signed_bundle,
                repo=body.repo,
                token=body.github_token,
                client=github_client,
            )
        except UnsignedFindingError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"GitHub API request failed: {exc}",
            ) from exc

        return PublishGitHubResponse(
            audit_id=signed_bundle.audit_id,
            issues_created=len(issues),
            issues=issues,
        )

    @app.post("/webhooks/stripe", response_model=WebhookResponse)
    async def stripe_webhook_endpoint(
        request: Request,
        stripe_signature: str | None = Header(default=None, alias="Stripe-Signature"),
    ) -> WebhookResponse:
        raw_body = await request.body()
        configured_secret: str | None = getattr(request.app.state, "stripe_webhook_secret", None)
        webhook_secret = configured_secret or os.environ.get("STRIPE_WEBHOOK_SECRET", "")
        if not _verify_stripe_signature(raw_body, stripe_signature, webhook_secret):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Stripe signature",
            )

        try:
            event: Any = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid webhook JSON payload",
            ) from exc

        if not isinstance(event, dict) or not isinstance(event.get("id"), str) or not event["id"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Webhook payload missing event id",
            )

        event_id: str = event["id"]
        active_store = getattr(request.app.state, "store", None)
        if active_store is not None and hasattr(active_store, "record_stripe_event"):
            if not active_store.record_stripe_event(event_id):
                return WebhookResponse(status="duplicate")
            return WebhookResponse(status="processed")

        seen_events: set[str] = request.app.state.processed_stripe_events
        if event_id in seen_events:
            return WebhookResponse(status="duplicate")

        seen_events.add(event_id)
        return WebhookResponse(status="processed")

    return app
