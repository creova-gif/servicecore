from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import servicecore.api as api_mod
import servicecore.auth as auth_mod
from servicecore.api import create_app, mint_auth_token
from servicecore.schemas import FindingEvidence, RemediationPatch
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
