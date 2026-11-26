from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import httpx
from pydantic import BaseModel, Field

from servicecore.cli import run_audit
from servicecore.exporter import diff_bundles
from servicecore.scanners import ScannerBackend, validate_public_url
from servicecore.schemas import (
    AuditBundle,
    DiffReport,
    MonitorRunResult,
    MonitorSchedule,
)
from servicecore.synthesizer import ClaudeSynthesizer

if TYPE_CHECKING:
    from servicecore.api import AuditStore

__all__ = [
    "RegressionAlertPayload",
    "build_regression_alert",
    "dispatch_webhook_alert",
    "run_due_monitors",
    "sign_webhook_payload",
    "verify_webhook_signature",
]


class RegressionAlertPayload(BaseModel):
    """Webhook alert payload emitted when a scheduled monitor detects new regressions."""

    monitor_id: str = Field(min_length=1)
    org_id: str = Field(min_length=1)
    target_url: str = Field(min_length=1)
    audit_id: str = Field(min_length=1)
    baseline_audit_id: str = Field(min_length=1)
    new_regressions_count: int = Field(ge=0)
    rule_ids: list[str] = Field(default_factory=list)
    triggered_at_utc: datetime
    text: str = Field(min_length=1)


def _ensure_utc(dt: datetime) -> datetime:
    """Normalize a datetime to timezone-aware UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def build_regression_alert(
    monitor: MonitorSchedule,
    diff: DiffReport,
    audit: AuditBundle,
    *,
    now: datetime | None = None,
) -> RegressionAlertPayload:
    """Build a structured regression alert payload from a monitor diff and audit bundle."""
    triggered_at = _ensure_utc(now) if now is not None else datetime.now(UTC)
    rule_ids = list(dict.fromkeys(item.rule_id for item in diff.new_regressions))
    new_regressions_count = len(diff.new_regressions)
    rules_summary = ", ".join(rule_ids) if rule_ids else "none"
    text = (
        f"Accessibility regression alert for {monitor.target_url} "
        f"(monitor {monitor.monitor_id}): {new_regressions_count} new regression(s) "
        f"in audit {audit.audit_id} vs baseline {diff.baseline_audit_id} "
        f"[rules: {rules_summary}]."
    )
    return RegressionAlertPayload(
        monitor_id=monitor.monitor_id,
        org_id=monitor.org_id,
        target_url=monitor.target_url,
        audit_id=audit.audit_id,
        baseline_audit_id=diff.baseline_audit_id,
        new_regressions_count=new_regressions_count,
        rule_ids=rule_ids,
        triggered_at_utc=triggered_at,
        text=text,
    )


def sign_webhook_payload(
    raw_body: bytes,
    secret: str,
    *,
    timestamp: str | None = None,
) -> str:
    """Compute an HMAC-SHA256 signature header value for a raw webhook request body."""
    signed_payload = (
        f"{timestamp}.".encode() + raw_body if timestamp is not None else raw_body
    )
    return "sha256=" + hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()


def verify_webhook_signature(
    raw_body: bytes,
    signature_header: str | None,
    secret: str,
    *,
    timestamp_header: str | None = None,
    max_age_seconds: int = 300,
    now: int | None = None,
) -> bool:
    """Verify an incoming X-ServiceCore-Signature-256 header in constant time."""
    if not signature_header or not secret:
        return False
    if timestamp_header is not None:
        try:
            ts = int(timestamp_header)
        except ValueError:
            return False
        current_now = int(time.time()) if now is None else now
        if abs(current_now - ts) > max_age_seconds:
            return False
        expected = sign_webhook_payload(raw_body, secret, timestamp=timestamp_header)
        return hmac.compare_digest(signature_header, expected)
    expected = sign_webhook_payload(raw_body, secret)
    return hmac.compare_digest(signature_header, expected)


def dispatch_webhook_alert(
    webhook_url: str,
    payload: RegressionAlertPayload,
    *,
    signing_secret: str | None = None,
    client: httpx.Client | None = None,
) -> bool:
    """Validate webhook_url against SSRF and POST the alert payload, returning True on 2xx."""
    validated_url = validate_public_url(webhook_url)
    body_bytes = json.dumps(
        payload.model_dump(mode="json"), separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    secret = signing_secret if signing_secret is not None else os.environ.get("SERVICECORE_WEBHOOK_SECRET")
    ts = str(int(time.time()))
    headers = {
        "Content-Type": "application/json",
        "X-ServiceCore-Event": "monitor.regression",
        "X-ServiceCore-Timestamp": ts,
    }
    if secret:
        headers["X-ServiceCore-Signature-256"] = sign_webhook_payload(
            body_bytes, secret, timestamp=ts
        )
    if client is not None:
        response = client.post(validated_url, content=body_bytes, headers=headers)
        return bool(response.is_success)
    with httpx.Client(timeout=10.0) as managed_client:
        response = managed_client.post(validated_url, content=body_bytes, headers=headers)
        return bool(response.is_success)


def run_due_monitors(
    store: AuditStore,
    org_id: str,
    *,
    scanner: ScannerBackend | None = None,
    synthesizer: ClaudeSynthesizer | None = None,
    now: datetime | None = None,
    webhook_url: str | None = None,
    webhook_secret: str | None = None,
    client: httpx.Client | None = None,
) -> list[MonitorRunResult]:
    """Execute all enabled monitors for org_id whose cadence has elapsed."""
    if webhook_url is not None:
        validate_public_url(webhook_url)

    current_now = _ensure_utc(now) if now is not None else datetime.now(UTC)
    results: list[MonitorRunResult] = []

    for monitor in store.list_monitors_for_org(org_id):
        if not monitor.enabled:
            continue
        if monitor.last_run_at_utc is not None:
            elapsed = current_now - _ensure_utc(monitor.last_run_at_utc)
            if elapsed < timedelta(hours=monitor.cadence_hours):
                continue

        bundle = run_audit(
            monitor.target_url,
            scanner=scanner,
            synthesizer=synthesizer,
            crawl=monitor.crawl,
            max_pages=monitor.max_pages,
            max_pdfs=monitor.max_pdfs,
        )
        scoped_bundle = bundle.model_copy(update={"org_id": org_id})
        store.save(scoped_bundle)

        diff: DiffReport | None = None
        if monitor.baseline_audit_id is not None:
            baseline = store.get(org_id, monitor.baseline_audit_id)
            if baseline is not None:
                diff = diff_bundles(baseline, scoped_bundle)

        updated_monitor = monitor.model_copy(
            update={
                "baseline_audit_id": scoped_bundle.audit_id,
                "last_run_at_utc": current_now,
            }
        )
        store.save_monitor(updated_monitor)

        if webhook_url is not None and diff is not None and diff.new_regressions:
            alert = build_regression_alert(
                updated_monitor,
                diff,
                scoped_bundle,
                now=current_now,
            )
            dispatch_webhook_alert(
                webhook_url,
                alert,
                signing_secret=webhook_secret,
                client=client,
            )

        results.append(MonitorRunResult(monitor=updated_monitor, audit=scoped_bundle, diff=diff))

    return results
