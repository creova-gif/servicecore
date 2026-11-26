from __future__ import annotations

import json
import logging
import os
import time
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Literal

import httpx
from fastapi import FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from servicecore.alerts import run_due_monitors
from servicecore.auth import (
    _DEV_FALLBACK_SECRET,
    TenantContext,
    get_current_tenant,
    mint_auth_token,
)
from servicecore.auth import (
    CurrentTenant as CurrentTenant,  # noqa: PLC0414
)
from servicecore.auth import (
    SlidingWindowRateLimiter as SlidingWindowRateLimiter,  # noqa: PLC0414
)
from servicecore.auth import (
    _resolve_auth_secret as _resolve_auth_secret,  # noqa: PLC0414
)
from servicecore.auth import (
    _verify_auth_token as _verify_auth_token,  # noqa: PLC0414
)
from servicecore.auth import (
    _verify_stripe_signature as _verify_stripe_signature,  # noqa: PLC0414
)
from servicecore.cli import run_audit
from servicecore.exporter import (
    diff_bundles,
    export_csv,
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
from servicecore.store import AuditStore, InMemoryAuditStore, SQLiteAuditStore
from servicecore.synthesizer import ClaudeSynthesizer, sanitize_html_snippet, validate_patch_binding

__all__ = [
    "AuditStore",
    "CreateAuditRequest",
    "CreateMonitorRequest",
    "DeleteResponse",
    "DevTokenResponse",
    "ExportResponse",
    "HealthcheckResponse",
    "InMemoryAuditStore",
    "MetricsResponse",
    "PublishGitHubRequest",
    "PublishGitHubResponse",
    "RunDueMonitorsRequest",
    "SQLiteAuditStore",
    "TenantContext",
    "UpdateFindingReviewRequest",
    "UpdateMonitorRequest",
    "WebhookResponse",
    "create_app",
    "get_current_tenant",
    "mint_auth_token",
]

_DEFAULT_CORS_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:3100",
    "http://localhost:3105",
]
_api_logger = logging.getLogger("servicecore.api")


class HealthcheckResponse(BaseModel):
    """Liveness probe response."""

    status: Literal["ok"] = "ok"


class ReadinessResponse(BaseModel):
    """Readiness probe response."""

    status: Literal["ready"] = "ready"


class MetricsResponse(BaseModel):
    """Operational metrics snapshot for observability."""

    total_audits: int = Field(ge=0)
    total_monitors: int = Field(ge=0)
    processed_stripe_events: int = Field(ge=0)
    uptime_seconds: float = Field(ge=0.0)


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


class UpdateMonitorRequest(BaseModel):
    """Request body for updating a monitoring schedule."""

    enabled: bool | None = None
    cadence_hours: int | None = Field(default=None, ge=1, le=720)
    crawl: bool | None = None


class DeleteResponse(BaseModel):
    """Response payload for resource deletion."""

    deleted: bool = True


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


def _enforce_rate_limit(request: Request, key: str) -> None:
    limiter: SlidingWindowRateLimiter | None = getattr(request.app.state, "rate_limiter", None)
    if limiter is None:
        return
    allowed, retry_after = limiter.allow(key)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )


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
    rate_limit_per_minute: int | None = None,
) -> FastAPI:
    """Build and configure the ServiceCore FastAPI application."""
    started_at = time.monotonic()
    app = FastAPI(title="ServiceCore Compliance API", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_resolve_cors_origins(allow_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def security_headers_middleware(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        start = time.monotonic()
        response = await call_next(request)
        duration_ms = round((time.monotonic() - start) * 1000.0, 3)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if request.url.path.startswith(("/audits", "/monitors", "/dev/token")):
            response.headers["Cache-Control"] = "no-store"
        _api_logger.info(
            json.dumps(
                {
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                },
                separators=(",", ":"),
            )
        )
        return response

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
    app.state.rate_limiter = (
        SlidingWindowRateLimiter(rate_limit_per_minute)
        if rate_limit_per_minute is not None
        else None
    )

    @app.get("/healthcheck", response_model=HealthcheckResponse)
    @app.get("/healthz", response_model=HealthcheckResponse)
    def healthcheck_endpoint() -> HealthcheckResponse:
        return HealthcheckResponse(status="ok")

    @app.get("/readyz", response_model=ReadinessResponse)
    def readiness_endpoint(request: Request) -> ReadinessResponse:
        active_store = getattr(request.app.state, "store", None)
        if isinstance(active_store, SQLiteAuditStore):
            try:
                with active_store._lock:
                    conn = active_store._connect()
                    try:
                        conn.execute("SELECT 1;").fetchone()
                    finally:
                        active_store._close_if_ephemeral(conn)
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Database readiness check failed",
                ) from exc
        return ReadinessResponse(status="ready")

    @app.get("/metrics", response_model=MetricsResponse)
    def metrics_endpoint(request: Request) -> MetricsResponse:
        active_store: AuditStore = request.app.state.store
        stats = active_store.get_stats()
        in_mem_stripe = len(getattr(request.app.state, "processed_stripe_events", set()))
        processed_stripe = stats.get("processed_stripe_events", 0) + in_mem_stripe
        return MetricsResponse(
            total_audits=stats.get("total_audits", 0),
            total_monitors=stats.get("total_monitors", 0),
            processed_stripe_events=processed_stripe,
            uptime_seconds=round(time.monotonic() - started_at, 3),
        )

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
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ) -> list[AuditBundle]:
        active_store: AuditStore = request.app.state.store
        return active_store.list_for_org(tenant.org_id, limit=limit, offset=offset)

    @app.post("/audits", response_model=AuditBundle, status_code=status.HTTP_201_CREATED)
    def create_audit_endpoint(
        body: CreateAuditRequest,
        request: Request,
        tenant: CurrentTenant,
    ) -> AuditBundle:
        _enforce_rate_limit(request, tenant.org_id)
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

    @app.delete("/audits/{audit_id}", response_model=DeleteResponse)
    def delete_audit_endpoint(
        audit_id: str,
        request: Request,
        tenant: CurrentTenant,
    ) -> DeleteResponse:
        active_store: AuditStore = request.app.state.store
        if not active_store.delete_audit(tenant.org_id, audit_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
        return DeleteResponse(deleted=True)

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
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ) -> list[MonitorSchedule]:
        active_store: AuditStore = request.app.state.store
        return active_store.list_monitors_for_org(tenant.org_id, limit=limit, offset=offset)

    @app.patch("/monitors/{monitor_id}", response_model=MonitorSchedule)
    def update_monitor_endpoint(
        monitor_id: str,
        body: UpdateMonitorRequest,
        request: Request,
        tenant: CurrentTenant,
    ) -> MonitorSchedule:
        active_store: AuditStore = request.app.state.store
        monitor = active_store.get_monitor(tenant.org_id, monitor_id)
        if monitor is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Monitor not found")

        updates: dict[str, Any] = {}
        if body.enabled is not None:
            updates["enabled"] = body.enabled
        if body.cadence_hours is not None:
            updates["cadence_hours"] = body.cadence_hours
        if body.crawl is not None:
            updates["crawl"] = body.crawl

        updated = monitor.model_copy(update=updates) if updates else monitor
        if updates:
            active_store.save_monitor(updated)
        return updated

    @app.delete("/monitors/{monitor_id}", response_model=DeleteResponse)
    def delete_monitor_endpoint(
        monitor_id: str,
        request: Request,
        tenant: CurrentTenant,
    ) -> DeleteResponse:
        active_store: AuditStore = request.app.state.store
        if not active_store.delete_monitor(tenant.org_id, monitor_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Monitor not found")
        return DeleteResponse(deleted=True)

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
        _enforce_rate_limit(request, tenant.org_id)
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
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
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
                            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
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
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
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

    @app.get("/audits/{audit_id}/export/csv")
    def export_audit_csv_endpoint(
        audit_id: str,
        request: Request,
        tenant: CurrentTenant,
    ) -> Response:
        active_store: AuditStore = request.app.state.store
        signed_bundle = _sign_and_verify_audit(active_store, tenant.org_id, audit_id, tenant.sub)
        try:
            csv_text = export_csv(signed_bundle)
        except UnsignedFindingError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        return Response(
            content=csv_text,
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="servicecore-{audit_id}.csv"',
                "X-Evidence-Digest": signed_bundle.evidence_digest or "",
            },
        )

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
