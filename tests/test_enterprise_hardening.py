from __future__ import annotations

import concurrent.futures
import csv
import io
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import servicecore.api as api_mod
import servicecore.auth as auth_mod
from servicecore.api import InMemoryAuditStore, create_app, mint_auth_token
from servicecore.exporter import export_csv, sign_bundle
from servicecore.schemas import (
    AuditBundle,
    AuditTelemetry,
    FindingEvidence,
    FindingReview,
    RemediationPatch,
    SeverityLevel,
    UnsignedFindingError,
)
from servicecore.store import SQLiteAuditStore

_AUTH_SECRET = "enterprise-hardening-test-secret-32b"


class _StubScanner:
    def scan(self, target: str) -> list[FindingEvidence]:
        return [
            FindingEvidence(
                finding_id="f-hardening-1",
                source="axe-core",
                rule_id="image-alt",
                severity="critical",
                wcag_criterion="WCAG 2.1 SC 1.1.1 Non-text Content",
                aoda_section="AODA IASR s.14(4)",
                target_url=target,
                target_selector="img.logo",
                raw_snippet='<img class="logo" src="/logo.png">',
                component_fingerprint="fp-logo-img",
                raw_scanner_sha256="b" * 64,
                description="Logo image missing alt text",
            )
        ]


class _StubSynthesizer:
    def synthesize(
        self, findings: list[FindingEvidence]
    ) -> tuple[list[RemediationPatch], int, int]:
        patches = [
            RemediationPatch(
                finding_id=f.finding_id,
                rule_id=f.rule_id,
                target_selector=f.target_selector,
                patch_kind="html_diff",
                before_snippet=f.raw_snippet,
                after_snippet='<img class="logo" src="/logo.png" alt="Company logo">',
                wcag_criterion=f.wcag_criterion,
                aoda_section=f.aoda_section,
                component_fingerprint=f.component_fingerprint,
                synthesized_by="deterministic_template",
            )
            for f in findings
        ]
        return (patches, 10, 5)


def _make_client(*, rate_limit_per_minute: int | None = None) -> TestClient:
    app = create_app(
        auth_secret=_AUTH_SECRET,
        scanner=_StubScanner(),
        synthesizer=_StubSynthesizer(),  # type: ignore[arg-type]
        rate_limit_per_minute=rate_limit_per_minute,
    )
    return TestClient(app)


def test_expired_bearer_token_returns_401() -> None:
    client = _make_client()
    expired_token = mint_auth_token(
        org_id="org_expired",
        sub="user@example.com",
        secret=_AUTH_SECRET,
        ttl_seconds=-10,
    )
    resp = client.get(
        "/audits",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Token expired"

    valid_token = mint_auth_token(
        org_id="org_valid",
        sub="user@example.com",
        secret=_AUTH_SECRET,
        ttl_seconds=60,
    )
    ok_resp = client.get(
        "/audits",
        headers={"Authorization": f"Bearer {valid_token}"},
    )
    assert ok_resp.status_code == 200


def test_security_headers_and_request_id_on_responses() -> None:
    client = _make_client()

    resp = client.get("/healthcheck")
    assert resp.status_code == 200
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert resp.headers["X-Request-ID"]

    custom_id = "req-trace-12345"
    propagated = client.get("/healthcheck", headers={"X-Request-ID": custom_id})
    assert propagated.status_code == 200
    assert propagated.headers["X-Request-ID"] == custom_id
    assert propagated.headers["X-Content-Type-Options"] == "nosniff"
    assert propagated.headers["X-Frame-Options"] == "DENY"
    assert propagated.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_sliding_window_rate_limiter_returns_429_with_retry_after() -> None:
    client = _make_client(rate_limit_per_minute=2)
    token = mint_auth_token(org_id="org_rate", sub="user@example.com", secret=_AUTH_SECRET)
    headers = {"Authorization": f"Bearer {token}"}

    r1 = client.post("/audits", json={"target_url": "https://example.com"}, headers=headers)
    assert r1.status_code == 201

    r2 = client.post("/monitors/run-due", json={}, headers=headers)
    assert r2.status_code == 200

    r3 = client.post("/audits", json={"target_url": "https://example.com"}, headers=headers)
    assert r3.status_code == 429
    assert "Retry-After" in r3.headers
    assert int(r3.headers["Retry-After"]) >= 1

    r4 = client.post("/monitors/run-due", json={}, headers=headers)
    assert r4.status_code == 429
    assert int(r4.headers["Retry-After"]) >= 1


def test_sqlite_audit_store_enables_wal_mode(tmp_path: Path) -> None:
    db_file = tmp_path / "audits.db"
    store = SQLiteAuditStore(db_file)
    conn = store._connect()
    try:
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        busy_timeout = conn.execute("PRAGMA busy_timeout;").fetchone()[0]
        synchronous = conn.execute("PRAGMA synchronous;").fetchone()[0]
    finally:
        store._close_if_ephemeral(conn)

    assert str(journal_mode).lower() == "wal"
    assert busy_timeout == 5000
    # PRAGMA synchronous=NORMAL corresponds to integer 1 in SQLite.
    assert synchronous == 1


def test_readyz_returns_200_when_healthy(tmp_path: Path) -> None:
    mem_client = _make_client()
    mem_resp = mem_client.get("/readyz")
    assert mem_resp.status_code == 200
    assert mem_resp.json() == {"status": "ready"}

    sqlite_store = SQLiteAuditStore(tmp_path / "ready.db")
    sqlite_app = create_app(
        auth_secret=_AUTH_SECRET,
        store=sqlite_store,
        scanner=_StubScanner(),
        synthesizer=_StubSynthesizer(),  # type: ignore[arg-type]
    )
    sqlite_client = TestClient(sqlite_app)
    sqlite_resp = sqlite_client.get("/readyz")
    assert sqlite_resp.status_code == 200
    assert sqlite_resp.json() == {"status": "ready"}


def test_readyz_returns_503_when_sqlite_check_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sqlite_store = SQLiteAuditStore(tmp_path / "broken.db")
    sqlite_app = create_app(
        auth_secret=_AUTH_SECRET,
        store=sqlite_store,
        scanner=_StubScanner(),
        synthesizer=_StubSynthesizer(),  # type: ignore[arg-type]
    )

    def _boom() -> object:
        raise OSError("db unavailable")

    monkeypatch.setattr(sqlite_store, "_connect", _boom)

    client = TestClient(sqlite_app)
    resp = client.get("/readyz")
    assert resp.status_code == 503


def test_servicecore_auth_direct_imports_and_reexports() -> None:
    assert auth_mod.TenantContext is api_mod.TenantContext
    assert auth_mod.mint_auth_token is api_mod.mint_auth_token
    assert auth_mod.get_current_tenant is api_mod.get_current_tenant
    assert auth_mod._verify_auth_token is api_mod._verify_auth_token
    assert auth_mod._resolve_auth_secret is api_mod._resolve_auth_secret
    assert auth_mod._verify_stripe_signature is api_mod._verify_stripe_signature
    assert auth_mod.SlidingWindowRateLimiter is api_mod.SlidingWindowRateLimiter
    assert auth_mod.CurrentTenant is api_mod.CurrentTenant

    token = auth_mod.mint_auth_token("org_direct", "sub_direct", _AUTH_SECRET)
    tenant = auth_mod._verify_auth_token(token, _AUTH_SECRET)
    assert tenant == auth_mod.TenantContext(org_id="org_direct", sub="sub_direct")


def test_structured_json_request_logging(caplog: pytest.LogCaptureFixture) -> None:
    client = _make_client()
    with caplog.at_level(logging.INFO, logger="servicecore.api"):
        resp = client.get("/readyz", headers={"X-Request-ID": "req-log-42"})
    assert resp.status_code == 200

    api_records = [r for r in caplog.records if r.name == "servicecore.api"]
    assert api_records
    payload = json.loads(api_records[-1].getMessage())
    assert payload["request_id"] == "req-log-42"
    assert payload["method"] == "GET"
    assert payload["path"] == "/readyz"
    assert payload["status_code"] == 200
    assert isinstance(payload["duration_ms"], (int, float))
    assert payload["duration_ms"] >= 0


def test_audits_and_monitors_pagination_and_limit_bounds() -> None:
    client = _make_client()
    token = mint_auth_token(org_id="org_page", sub="user@example.com", secret=_AUTH_SECRET)
    headers = {"Authorization": f"Bearer {token}"}

    a1 = client.post("/audits", json={"target_url": "https://a1.example.com"}, headers=headers)
    a2 = client.post("/audits", json={"target_url": "https://a2.example.com"}, headers=headers)
    assert a1.status_code == 201 and a2.status_code == 201

    all_audits = client.get("/audits", headers=headers).json()
    assert len(all_audits) == 2

    paged_audits = client.get("/audits?limit=1&offset=1", headers=headers)
    assert paged_audits.status_code == 200
    assert len(paged_audits.json()) == 1
    assert paged_audits.json()[0]["audit_id"] == all_audits[1]["audit_id"]

    m1 = client.post("/monitors", json={"target_url": "https://example.com/m1"}, headers=headers)
    m2 = client.post("/monitors", json={"target_url": "https://example.com/m2"}, headers=headers)
    assert m1.status_code == 201 and m2.status_code == 201

    all_monitors = client.get("/monitors", headers=headers).json()
    assert len(all_monitors) == 2

    paged_monitors = client.get("/monitors?limit=1&offset=1", headers=headers)
    assert paged_monitors.status_code == 200
    assert len(paged_monitors.json()) == 1
    assert paged_monitors.json()[0]["monitor_id"] == all_monitors[1]["monitor_id"]

    assert client.get("/audits?limit=201", headers=headers).status_code == 422
    assert client.get("/monitors?limit=201", headers=headers).status_code == 422


def test_metrics_endpoint_returns_live_counts_and_uptime() -> None:
    client = _make_client()
    token = mint_auth_token(org_id="org_metrics", sub="user@example.com", secret=_AUTH_SECRET)
    headers = {"Authorization": f"Bearer {token}"}

    initial = client.get("/metrics")
    assert initial.status_code == 200
    assert initial.json()["total_audits"] == 0
    assert initial.json()["total_monitors"] == 0
    assert initial.json()["processed_stripe_events"] == 0
    assert initial.json()["uptime_seconds"] >= 0.0

    assert (
        client.post("/audits", json={"target_url": "https://m.example.com"}, headers=headers).status_code
        == 201
    )
    assert (
        client.post("/monitors", json={"target_url": "https://example.com"}, headers=headers).status_code
        == 201
    )

    after = client.get("/metrics")
    assert after.status_code == 200
    body = after.json()
    assert body["total_audits"] == 1
    assert body["total_monitors"] == 1
    assert body["processed_stripe_events"] == 0
    assert body["uptime_seconds"] >= 0.0


def test_patch_and_delete_monitor_with_tenant_isolation() -> None:
    client = _make_client()
    org_a_headers = {
        "Authorization": f"Bearer {mint_auth_token(org_id='org_a', sub='a@example.com', secret=_AUTH_SECRET)}"
    }
    org_b_headers = {
        "Authorization": f"Bearer {mint_auth_token(org_id='org_b', sub='b@example.com', secret=_AUTH_SECRET)}"
    }

    created = client.post(
        "/monitors",
        json={"target_url": "https://example.com/mon", "cadence_hours": 24, "crawl": False},
        headers=org_a_headers,
    )
    assert created.status_code == 201
    monitor_id = created.json()["monitor_id"]

    # Cross-tenant PATCH and DELETE must return 404
    assert (
        client.patch(
            f"/monitors/{monitor_id}",
            json={"enabled": False},
            headers=org_b_headers,
        ).status_code
        == 404
    )
    assert client.delete(f"/monitors/{monitor_id}", headers=org_b_headers).status_code == 404

    # Same-tenant PATCH updates fields
    patched = client.patch(
        f"/monitors/{monitor_id}",
        json={"enabled": False, "cadence_hours": 12, "crawl": True},
        headers=org_a_headers,
    )
    assert patched.status_code == 200
    patched_body = patched.json()
    assert patched_body["enabled"] is False
    assert patched_body["cadence_hours"] == 12
    assert patched_body["crawl"] is True

    # Same-tenant DELETE succeeds and removes monitor
    deleted = client.delete(f"/monitors/{monitor_id}", headers=org_a_headers)
    assert deleted.status_code == 200
    assert deleted.json() == {"deleted": True}
    assert client.delete(f"/monitors/{monitor_id}", headers=org_a_headers).status_code == 404
    assert client.get("/monitors", headers=org_a_headers).json() == []


def test_export_csv_escapes_formula_injection_and_skips_rejected() -> None:
    ts = datetime(2026, 11, 26, 12, 0, 0, tzinfo=UTC)
    findings = [
        FindingEvidence(
            finding_id="f-inject-eq",
            source="axe-core",
            rule_id="=CMD|'/C calc'!A0",
            severity="critical",
            wcag_criterion="+SUM(1,1)",
            aoda_section="-2+3",
            target_url="https://example.com/@admin",
            target_selector="@SUM(1,2)",
            raw_snippet="<img>",
            component_fingerprint="\tcmd",
            raw_scanner_sha256="a" * 64,
            description="\rpayload",
        ),
        FindingEvidence(
            finding_id="f-inject-ws",
            source="axe-core",
            rule_id="  =HYPERLINK(\"https://evil.example\")",
            severity="serious",
            wcag_criterion="WCAG 2.1 SC 1.1.1",
            aoda_section="AODA IASR s.14(4)",
            target_url="https://example.com",
            target_selector="\r\nimg.hero",
            raw_snippet="<img>",
            component_fingerprint="fp-ws",
            raw_scanner_sha256="c" * 64,
        ),
        FindingEvidence(
            finding_id="f-rejected",
            source="axe-core",
            rule_id="color-contrast",
            severity="minor",
            wcag_criterion="WCAG 2.1 SC 1.4.3",
            aoda_section="AODA IASR s.14(4)",
            target_url="https://example.com",
            target_selector="p.muted",
            raw_snippet="<p>",
            component_fingerprint="fp-rejected",
            raw_scanner_sha256="d" * 64,
        ),
    ]
    reviews = [
        FindingReview(
            finding_id="f-inject-eq",
            status="APPROVED",
            reviewer_id="rev@example.com",
            signed_at_utc=ts,
        ),
        FindingReview(
            finding_id="f-inject-ws",
            status="EDITED",
            reviewer_id="rev@example.com",
            signed_at_utc=ts,
        ),
        FindingReview(
            finding_id="f-rejected",
            status="REJECTED",
            rejection_reason="False positive",
        ),
    ]
    unsigned = AuditBundle(
        audit_id="audit-csv-1",
        org_id="org_csv",
        target_url="https://example.com",
        findings=findings,
        reviews=reviews,
    )
    with pytest.raises(UnsignedFindingError):
        export_csv(unsigned)

    signed = sign_bundle(unsigned, reviewer_id="rev@example.com", signed_at_utc=ts)
    csv_text = export_csv(signed)
    assert "\r\n" in csv_text

    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(rows) == 2
    assert [r["finding_id"] for r in rows] == ["f-inject-eq", "f-inject-ws"]

    first = rows[0]
    assert first["rule_id"] == "'=CMD|'/C calc'!A0"
    assert first["wcag_criterion"] == "'+SUM(1,1)"
    assert first["aoda_section"] == "'-2+3"
    assert first["target_selector"] == "'@SUM(1,2)"
    assert first["component_fingerprint"] == "'\tcmd"
    assert first["target_url"] == "https://example.com/@admin"
    assert first["evidence_digest"] == signed.evidence_digest

    second = rows[1]
    assert second["rule_id"] == "'  =HYPERLINK(\"https://evil.example\")"
    assert second["target_selector"] == "'\r\nimg.hero"


def test_get_audit_export_csv_endpoint_enforces_signoff() -> None:
    client = _make_client()
    token = mint_auth_token(org_id="org_csv_api", sub="reviewer@example.com", secret=_AUTH_SECRET)
    headers = {"Authorization": f"Bearer {token}"}

    created = client.post("/audits", json={"target_url": "https://csv.example.com"}, headers=headers)
    assert created.status_code == 201
    audit_id = created.json()["audit_id"]
    finding_id = created.json()["findings"][0]["finding_id"]

    # Unsigned audit -> 409
    unsigned_resp = client.get(f"/audits/{audit_id}/export/csv", headers=headers)
    assert unsigned_resp.status_code == 409

    # Approve finding -> 200 text/csv
    approve = client.patch(
        f"/audits/{audit_id}/findings/{finding_id}",
        json={"status": "APPROVED"},
        headers=headers,
    )
    assert approve.status_code == 200

    csv_resp = client.get(f"/audits/{audit_id}/export/csv", headers=headers)
    assert csv_resp.status_code == 200
    assert csv_resp.headers["content-type"] == "text/csv; charset=utf-8"
    assert (
        csv_resp.headers["content-disposition"]
        == f'attachment; filename="servicecore-{audit_id}.csv"'
    )
    assert len(csv_resp.headers["x-evidence-digest"]) == 64

    rows = list(csv.DictReader(io.StringIO(csv_resp.text)))
    assert len(rows) == 1
    assert rows[0]["finding_id"] == finding_id
    assert rows[0]["review_status"] == "APPROVED"
    assert rows[0]["evidence_digest"] == csv_resp.headers["x-evidence-digest"]


def test_sqlite_concurrent_writes_with_wal_and_rlock(tmp_path: Path) -> None:
    store = SQLiteAuditStore(tmp_path / "concurrent.db")

    def _save_one(idx: int) -> str:
        audit_id = f"audit-concurrent-{idx:02d}"
        bundle = AuditBundle(
            audit_id=audit_id,
            org_id="org_concurrent",
            target_url=f"https://example.com/page-{idx}",
        )
        store.save(bundle)
        return audit_id

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(_save_one, idx) for idx in range(24)]
        saved_ids = [fut.result() for fut in futures]

    assert len(saved_ids) == 24
    listed = store.list_for_org("org_concurrent", limit=50)
    assert len(listed) == 24
    assert store.get_stats()["total_audits"] == 24
    for audit_id in saved_ids:
        loaded = store.get("org_concurrent", audit_id)
        assert loaded is not None
        assert loaded.audit_id == audit_id


def test_delete_audit_with_tenant_isolation() -> None:
    client = _make_client()
    token_a = mint_auth_token(org_id="org_del_a", sub="a@example.com", secret=_AUTH_SECRET)
    token_b = mint_auth_token(org_id="org_del_b", sub="b@example.com", secret=_AUTH_SECRET)
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    created = client.post("/audits", json={"target_url": "https://del.example.com"}, headers=headers_a)
    assert created.status_code == 201
    audit_id = created.json()["audit_id"]

    cross_tenant_del = client.delete(f"/audits/{audit_id}", headers=headers_b)
    assert cross_tenant_del.status_code == 404

    owner_del = client.delete(f"/audits/{audit_id}", headers=headers_a)
    assert owner_del.status_code == 200
    assert owner_del.json() == {"deleted": True}

    after_get = client.get(f"/audits/{audit_id}", headers=headers_a)
    assert after_get.status_code == 404

    second_del = client.delete(f"/audits/{audit_id}", headers=headers_a)
    assert second_del.status_code == 404


def test_cache_control_no_store_on_tenant_endpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SERVICECORE_DEV_MODE", "1")
    client = _make_client()
    token = mint_auth_token(org_id="org_cache", sub="user@example.com", secret=_AUTH_SECRET)
    headers = {"Authorization": f"Bearer {token}"}

    audits_resp = client.get("/audits", headers=headers)
    assert audits_resp.status_code == 200
    assert audits_resp.headers.get("Cache-Control") == "no-store"

    monitors_resp = client.get("/monitors", headers=headers)
    assert monitors_resp.status_code == 200
    assert monitors_resp.headers.get("Cache-Control") == "no-store"

    dev_token_resp = client.post("/dev/token")
    assert dev_token_resp.status_code == 200
    assert dev_token_resp.headers.get("Cache-Control") == "no-store"

    health_resp = client.get("/healthcheck")
    assert health_resp.status_code == 200
    assert "Cache-Control" not in health_resp.headers


def test_create_monitor_blocks_ssrf_at_creation() -> None:
    client = _make_client()
    token = mint_auth_token(org_id="org_ssrf_mon", sub="user@example.com", secret=_AUTH_SECRET)
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.post(
        "/monitors",
        json={"target_url": "http://127.0.0.1/internal"},
        headers=headers,
    )
    assert resp.status_code == 422


def test_request_body_size_limit_returns_413() -> None:
    client = _make_client()
    token = mint_auth_token(org_id="org_size", sub="user@example.com", secret=_AUTH_SECRET)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    oversized_url = "https://example.com/" + ("a" * 1_048_576)
    payload = json.dumps({"target_url": oversized_url})
    assert len(payload.encode("utf-8")) > 1_048_576

    resp = client.post("/audits", content=payload, headers=headers)
    assert resp.status_code == 413
    assert resp.json()["detail"] == "Request body exceeds 1 MiB limit"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert resp.headers["X-Request-ID"]
    assert resp.headers["Cache-Control"] == "no-store"


def test_get_audit_summary_counts_and_cross_tenant_404() -> None:
    store = InMemoryAuditStore()
    app = create_app(
        store=store,
        auth_secret=_AUTH_SECRET,
        scanner=_StubScanner(),
        synthesizer=_StubSynthesizer(),  # type: ignore[arg-type]
    )
    client = TestClient(app)
    token_a = mint_auth_token(org_id="org_sum_a", sub="a@example.com", secret=_AUTH_SECRET)
    token_b = mint_auth_token(org_id="org_sum_b", sub="b@example.com", secret=_AUTH_SECRET)
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    now = datetime(2026, 2, 1, 12, 0, tzinfo=UTC)
    severities: tuple[SeverityLevel, ...] = (
        "critical",
        "critical",
        "serious",
        "serious",
        "moderate",
    )
    findings = [
        FindingEvidence(
            finding_id=f"f-sum-{idx}",
            source="axe-core",
            rule_id="image-alt",
            severity=severity,
            wcag_criterion="WCAG 2.1 SC 1.1.1 Non-text Content",
            aoda_section="AODA IASR s.14(4)",
            target_url="https://summary.example.com",
            target_selector=f"img.item-{idx}",
            raw_snippet=f'<img class="item-{idx}" src="/{idx}.png">',
            component_fingerprint=f"fp-sum-{idx}",
            raw_scanner_sha256="c" * 64,
        )
        for idx, severity in enumerate(severities, start=1)
    ]
    reviews = [
        FindingReview(finding_id="f-sum-1", status="PENDING"),
        FindingReview(
            finding_id="f-sum-2", status="APPROVED", reviewer_id="rev-1", signed_at_utc=now
        ),
        FindingReview(
            finding_id="f-sum-3", status="APPROVED", reviewer_id="rev-1", signed_at_utc=now
        ),
        FindingReview(
            finding_id="f-sum-4", status="EDITED", reviewer_id="rev-1", signed_at_utc=now
        ),
        FindingReview(
            finding_id="f-sum-5", status="REJECTED", rejection_reason="False positive"
        ),
    ]
    unsigned_bundle = AuditBundle(
        audit_id="aud-summary-unsigned",
        org_id="org_sum_a",
        target_url="https://summary.example.com",
        created_at_utc=now,
        findings=findings,
        reviews=reviews,
        telemetry=AuditTelemetry(
            scan_duration_ms=250,
            llm_input_tokens=100,
            llm_output_tokens=50,
            llm_cost_usd=0.05,
            audit_price_usd=1500.0,
            estimated_gross_margin_pct=99.9967,
        ),
    )
    store.save(unsigned_bundle)

    resp = client.get("/audits/aud-summary-unsigned/summary", headers=headers_a)
    assert resp.status_code == 200
    body = resp.json()
    assert body["audit_id"] == "aud-summary-unsigned"
    assert body["org_id"] == "org_sum_a"
    assert body["target_url"] == "https://summary.example.com"
    assert body["total_findings"] == 5
    assert body["pending_count"] == 1
    assert body["approved_count"] == 2
    assert body["edited_count"] == 1
    assert body["rejected_count"] == 1
    assert body["critical_count"] == 2
    assert body["serious_count"] == 2
    assert body["signed"] is False
    assert body["evidence_digest"] is None
    assert body["llm_cost_usd"] == pytest.approx(0.05)
    assert body["estimated_gross_margin_pct"] == pytest.approx(99.9967)

    # Cross-tenant access must return 404
    cross_resp = client.get("/audits/aud-summary-unsigned/summary", headers=headers_b)
    assert cross_resp.status_code == 404

    # Signed bundle reflects signed=True and evidence_digest
    signed_reviews = [
        FindingReview(
            finding_id="f-sum-1", status="APPROVED", reviewer_id="rev-1", signed_at_utc=now
        ),
        *reviews[1:],
    ]
    signed_bundle = sign_bundle(
        unsigned_bundle.model_copy(
            update={"audit_id": "aud-summary-signed", "reviews": signed_reviews}
        ),
        reviewer_id="rev-1",
        signed_at_utc=now,
    )
    store.save(signed_bundle)

    signed_resp = client.get("/audits/aud-summary-signed/summary", headers=headers_a)
    assert signed_resp.status_code == 200
    signed_body = signed_resp.json()
    assert signed_body["pending_count"] == 0
    assert signed_body["approved_count"] == 3
    assert signed_body["signed"] is True
    assert signed_body["evidence_digest"] == signed_bundle.evidence_digest


def test_bulk_review_approves_evidence_bound_and_enforces_422_and_404() -> None:
    store = InMemoryAuditStore()
    app = create_app(
        auth_secret=_AUTH_SECRET,
        store=store,
        scanner=_StubScanner(),
        synthesizer=_StubSynthesizer(),  # type: ignore[arg-type]
    )
    client = TestClient(app)
    token_a = mint_auth_token(org_id="org_bulk_a", sub="reviewer@a.com", secret=_AUTH_SECRET)
    token_b = mint_auth_token(org_id="org_bulk_b", sub="reviewer@b.com", secret=_AUTH_SECRET)
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    now = datetime(2026, 2, 1, 12, 0, tzinfo=UTC)
    findings = [
        FindingEvidence(
            finding_id=f"f-bulk-{idx}",
            source="axe-core",
            rule_id="image-alt",
            severity="critical",
            wcag_criterion="WCAG 2.1 SC 1.1.1 Non-text Content",
            aoda_section="AODA IASR s.14(4)",
            target_url="https://bulk.example.com",
            target_selector=f"img.bulk-{idx}",
            raw_snippet=f'<img class="bulk-{idx}" src="/{idx}.png">',
            component_fingerprint=f"fp-bulk-{idx}",
            raw_scanner_sha256="d" * 64,
        )
        for idx in range(1, 5)
    ]
    patches = [
        # f-bulk-1: valid evidence-bound patch
        RemediationPatch(
            finding_id="f-bulk-1",
            rule_id="image-alt",
            target_selector="img.bulk-1",
            patch_kind="html_diff",
            before_snippet='<img class="bulk-1" src="/1.png">',
            after_snippet='<img class="bulk-1" src="/1.png" alt="Bulk 1">',
            wcag_criterion="WCAG 2.1 SC 1.1.1 Non-text Content",
            aoda_section="AODA IASR s.14(4)",
            component_fingerprint="fp-bulk-1",
            synthesized_by="deterministic_template",
        ),
        # f-bulk-2: mismatched selector -> EvidenceMismatchError
        RemediationPatch(
            finding_id="f-bulk-2",
            rule_id="image-alt",
            target_selector="img.wrong-selector",
            patch_kind="html_diff",
            before_snippet='<img class="bulk-2" src="/2.png">',
            after_snippet='<img class="bulk-2" src="/2.png" alt="Bulk 2">',
            wcag_criterion="WCAG 2.1 SC 1.1.1 Non-text Content",
            aoda_section="AODA IASR s.14(4)",
            component_fingerprint="fp-bulk-2",
            synthesized_by="deterministic_template",
        ),
        # f-bulk-3: no patch at all
        # f-bulk-4: valid patch, but already REJECTED
        RemediationPatch(
            finding_id="f-bulk-4",
            rule_id="image-alt",
            target_selector="img.bulk-4",
            patch_kind="html_diff",
            before_snippet='<img class="bulk-4" src="/4.png">',
            after_snippet='<img class="bulk-4" src="/4.png" alt="Bulk 4">',
            wcag_criterion="WCAG 2.1 SC 1.1.1 Non-text Content",
            aoda_section="AODA IASR s.14(4)",
            component_fingerprint="fp-bulk-4",
            synthesized_by="deterministic_template",
        ),
    ]
    reviews = [
        FindingReview(finding_id="f-bulk-1", status="PENDING"),
        FindingReview(finding_id="f-bulk-2", status="PENDING"),
        FindingReview(finding_id="f-bulk-3", status="PENDING"),
        FindingReview(finding_id="f-bulk-4", status="REJECTED", rejection_reason="Out of scope"),
    ]
    bundle = AuditBundle(
        audit_id="aud-bulk-1",
        org_id="org_bulk_a",
        target_url="https://bulk.example.com",
        created_at_utc=now,
        findings=findings,
        patches=patches,
        reviews=reviews,
        telemetry=AuditTelemetry(scan_duration_ms=100),
    )
    store.save(bundle)

    # Cross-tenant isolation returns 404
    cross_resp = client.post(
        "/audits/aud-bulk-1/findings/bulk-review",
        headers=headers_b,
        json={"status": "APPROVED"},
    )
    assert cross_resp.status_code == 404

    # finding_ids=None approves only PENDING evidence-bound findings (f-bulk-1)
    auto_resp = client.post(
        "/audits/aud-bulk-1/findings/bulk-review",
        headers=headers_a,
        json={"status": "APPROVED"},
    )
    assert auto_resp.status_code == 200
    reviews_after = {r["finding_id"]: r for r in auto_resp.json()["reviews"]}
    assert reviews_after["f-bulk-1"]["status"] == "APPROVED"
    assert reviews_after["f-bulk-1"]["reviewer_id"] == "reviewer@a.com"
    assert reviews_after["f-bulk-1"]["signed_at_utc"] is not None
    assert reviews_after["f-bulk-2"]["status"] == "PENDING"
    assert reviews_after["f-bulk-3"]["status"] == "PENDING"
    assert reviews_after["f-bulk-4"]["status"] == "REJECTED"

    # Explicitly targeting a mismatched finding_id returns 422
    mismatch_resp = client.post(
        "/audits/aud-bulk-1/findings/bulk-review",
        headers=headers_a,
        json={"status": "APPROVED", "finding_ids": ["f-bulk-2"]},
    )
    assert mismatch_resp.status_code == 422

    # Explicitly targeting an unpatched finding_id returns 422
    unpatched_resp = client.post(
        "/audits/aud-bulk-1/findings/bulk-review",
        headers=headers_a,
        json={"status": "APPROVED", "finding_ids": ["f-bulk-3"]},
    )
    assert unpatched_resp.status_code == 422

    # Unknown finding_id returns 404
    unknown_resp = client.post(
        "/audits/aud-bulk-1/findings/bulk-review",
        headers=headers_a,
        json={"status": "APPROVED", "finding_ids": ["f-does-not-exist"]},
    )
    assert unknown_resp.status_code == 404


def test_audit_trail_events_chronological_and_tenant_isolated(tmp_path: Path) -> None:
    store = SQLiteAuditStore(tmp_path / "events.db")
    app = create_app(
        auth_secret=_AUTH_SECRET,
        store=store,
        scanner=_StubScanner(),
        synthesizer=_StubSynthesizer(),  # type: ignore[arg-type]
    )
    client = TestClient(app)
    token_a = mint_auth_token(org_id="org_events_a", sub="alice@a.com", secret=_AUTH_SECRET)
    token_b = mint_auth_token(org_id="org_events_b", sub="bob@b.com", secret=_AUTH_SECRET)
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # 1. Create audit -> audit.created
    create_resp = client.post(
        "/audits",
        headers=headers_a,
        json={"target_url": "https://events.example.com"},
    )
    assert create_resp.status_code == 201
    audit_id = create_resp.json()["audit_id"]
    finding_id = create_resp.json()["findings"][0]["finding_id"]

    # 2. Review finding -> finding.reviewed
    review_resp = client.patch(
        f"/audits/{audit_id}/findings/{finding_id}",
        headers=headers_a,
        json={"status": "APPROVED"},
    )
    assert review_resp.status_code == 200

    # 3. Export audit -> audit.exported
    export_resp = client.post(f"/audits/{audit_id}/export", headers=headers_a)
    assert export_resp.status_code == 200

    # 4. Chronological events returned for owning tenant
    events_resp = client.get(f"/audits/{audit_id}/events", headers=headers_a)
    assert events_resp.status_code == 200
    events = events_resp.json()
    assert [e["action"] for e in events] == [
        "audit.created",
        "finding.reviewed",
        "audit.exported",
    ]
    assert all(e["org_id"] == "org_events_a" for e in events)
    assert all(e["audit_id"] == audit_id for e in events)
    assert all(e["actor_sub"] == "alice@a.com" for e in events)
    timestamps = [datetime.fromisoformat(e["created_at_utc"]) for e in events]
    assert timestamps == sorted(timestamps)

    # 5. Pagination works
    page_resp = client.get(f"/audits/{audit_id}/events?limit=1&offset=1", headers=headers_a)
    assert page_resp.status_code == 200
    page = page_resp.json()
    assert len(page) == 1
    assert page[0]["action"] == "finding.reviewed"

    # 6. Cross-tenant isolation returns 404
    cross_resp = client.get(f"/audits/{audit_id}/events", headers=headers_b)
    assert cross_resp.status_code == 404

    # 7. Missing audit returns 404
    missing_resp = client.get("/audits/aud-does-not-exist/events", headers=headers_a)
    assert missing_resp.status_code == 404


def test_delete_audit_cascades_events_in_memory_and_sqlite(tmp_path: Path) -> None:
    # 1. InMemoryAuditStore
    mem_store = InMemoryAuditStore()
    mem_app = create_app(
        auth_secret=_AUTH_SECRET,
        store=mem_store,
        scanner=_StubScanner(),
        synthesizer=_StubSynthesizer(),  # type: ignore[arg-type]
    )
    mem_client = TestClient(mem_app)
    token = mint_auth_token(org_id="org_cascade", sub="alice@example.com", secret=_AUTH_SECRET)
    headers = {"Authorization": f"Bearer {token}"}

    create_resp = mem_client.post(
        "/audits", headers=headers, json={"target_url": "https://cascade.example.com"}
    )
    assert create_resp.status_code == 201
    mem_audit_id = create_resp.json()["audit_id"]
    assert len(mem_store.list_events("org_cascade", mem_audit_id)) == 1

    del_resp = mem_client.delete(f"/audits/{mem_audit_id}", headers=headers)
    assert del_resp.status_code == 200
    assert mem_store.list_events("org_cascade", mem_audit_id) == []
    assert ("org_cascade", mem_audit_id) not in mem_store._events

    # 2. SQLiteAuditStore
    sqlite_store = SQLiteAuditStore(tmp_path / "cascade.db")
    sqlite_app = create_app(
        auth_secret=_AUTH_SECRET,
        store=sqlite_store,
        scanner=_StubScanner(),
        synthesizer=_StubSynthesizer(),  # type: ignore[arg-type]
    )
    sqlite_client = TestClient(sqlite_app)

    create_resp_2 = sqlite_client.post(
        "/audits", headers=headers, json={"target_url": "https://cascade.example.com"}
    )
    assert create_resp_2.status_code == 201
    sql_audit_id = create_resp_2.json()["audit_id"]
    assert len(sqlite_store.list_events("org_cascade", sql_audit_id)) == 1

    del_resp_2 = sqlite_client.delete(f"/audits/{sql_audit_id}", headers=headers)
    assert del_resp_2.status_code == 200
    assert sqlite_store.list_events("org_cascade", sql_audit_id) == []

    conn = sqlite_store._connect()
    try:
        remaining = conn.execute(
            "SELECT COUNT(*) FROM audit_events WHERE org_id = ? AND audit_id = ?",
            ("org_cascade", sql_audit_id),
        ).fetchone()[0]
    finally:
        sqlite_store._close_if_ephemeral(conn)
    assert remaining == 0


def test_rate_limit_from_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SERVICECORE_RATE_LIMIT_PER_MINUTE", "2")
    client = _make_client()
    token = mint_auth_token(org_id="org_env_rate", sub="user@example.com", secret=_AUTH_SECRET)
    headers = {"Authorization": f"Bearer {token}"}

    r1 = client.post("/audits", json={"target_url": "https://example.com"}, headers=headers)
    assert r1.status_code == 201

    r2 = client.post("/monitors/run-due", json={}, headers=headers)
    assert r2.status_code == 200

    r3 = client.post("/audits", json={"target_url": "https://example.com"}, headers=headers)
    assert r3.status_code == 429

    monkeypatch.setenv("SERVICECORE_RATE_LIMIT_PER_MINUTE", "invalid")
    with pytest.raises(ValueError, match="SERVICECORE_RATE_LIMIT_PER_MINUTE"):
        create_app(auth_secret=_AUTH_SECRET)

    monkeypatch.setenv("SERVICECORE_RATE_LIMIT_PER_MINUTE", "0")
    with pytest.raises(ValueError, match="positive integer"):
        create_app(auth_secret=_AUTH_SECRET)


def test_enable_docs_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SERVICECORE_DEV_MODE", raising=False)
    monkeypatch.delenv("SERVICECORE_ENABLE_DOCS", raising=False)

    disabled_client = TestClient(create_app(auth_secret=_AUTH_SECRET, enable_docs=False))
    assert disabled_client.get("/docs").status_code == 404
    assert disabled_client.get("/redoc").status_code == 404

    default_client = TestClient(create_app(auth_secret=_AUTH_SECRET))
    assert default_client.get("/docs").status_code == 404

    enabled_client = TestClient(create_app(auth_secret=_AUTH_SECRET, enable_docs=True))
    assert enabled_client.get("/docs").status_code == 200
    assert enabled_client.get("/redoc").status_code == 200

    monkeypatch.setenv("SERVICECORE_ENABLE_DOCS", "1")
    env_enabled_client = TestClient(create_app(auth_secret=_AUTH_SECRET))
    assert env_enabled_client.get("/docs").status_code == 200


def test_prometheus_metrics_endpoint() -> None:
    client = _make_client()
    token = mint_auth_token(org_id="org_prom", sub="user@example.com", secret=_AUTH_SECRET)
    headers = {"Authorization": f"Bearer {token}"}

    # Create one audit and one monitor so counters/gauges are non-zero
    audit_resp = client.post(
        "/audits", json={"target_url": "https://example.com"}, headers=headers
    )
    assert audit_resp.status_code == 201
    monitor_resp = client.post(
        "/monitors", json={"target_url": "https://example.com"}, headers=headers
    )
    assert monitor_resp.status_code == 201

    resp = client.get("/metrics/prometheus")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/plain; version=0.0.4; charset=utf-8"

    body = resp.text
    for metric_name in (
        "servicecore_audits_total",
        "servicecore_monitors_total",
        "servicecore_stripe_events_total",
        "servicecore_uptime_seconds",
    ):
        assert f"# HELP {metric_name} " in body
        assert f"# TYPE {metric_name} " in body

    assert "servicecore_audits_total 1\n" in body
    assert "servicecore_monitors_total 1\n" in body
    assert "servicecore_stripe_events_total 0\n" in body
    assert "servicecore_uptime_seconds " in body
