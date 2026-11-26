from __future__ import annotations

import hashlib
import hmac
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import httpx
import pytest
from fastapi.testclient import TestClient

from servicecore.api import InMemoryAuditStore, SQLiteAuditStore, create_app, mint_auth_token
from servicecore.github_publisher import publish_bundle_to_github
from servicecore.schemas import (
    AuditBundle,
    FindingEvidence,
    RemediationPatch,
    UnsignedFindingError,
)

_AUTH_SECRET = "test-auth-secret-32-bytes-minimum"
_STRIPE_SECRET = "whsec_test_stripe_secret"


class _MockScanner:
    def scan(self, target: str) -> list[FindingEvidence]:
        return [
            FindingEvidence(
                finding_id="f-1",
                source="axe-core",
                rule_id="image-alt",
                severity="critical",
                wcag_criterion="WCAG 2.1 SC 1.1.1 Non-text Content",
                aoda_section="AODA IASR s.14(4)",
                target_url=target,
                target_selector="img.hero",
                raw_snippet='<img class="hero" src="/hero.png">',
                component_fingerprint="fp-hero-img",
                raw_scanner_sha256="a" * 64,
                description="Hero image missing alt text",
            )
        ]


class _MockSynthesizer:
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
                after_snippet='<img class="hero" src="/hero.png" alt="Company hero">',
                wcag_criterion=f.wcag_criterion,
                aoda_section=f.aoda_section,
                component_fingerprint=f.component_fingerprint,
                synthesized_by="deterministic_template",
            )
            for f in findings
        ]
        return (patches, 100, 50)


def _make_client() -> TestClient:
    app = create_app(
        auth_secret=_AUTH_SECRET,
        stripe_webhook_secret=_STRIPE_SECRET,
        scanner=_MockScanner(),
        synthesizer=_MockSynthesizer(),  # type: ignore[arg-type]
    )
    return TestClient(app)


def _auth_header(org_id: str, sub: str = "user-1") -> dict[str, str]:
    token = mint_auth_token(org_id=org_id, sub=sub, secret=_AUTH_SECRET)
    return {"Authorization": f"Bearer {token}"}


def _sign_stripe_payload(raw_body: bytes, timestamp: str = "1700000000") -> str:
    signed = f"{timestamp}.".encode() + raw_body
    sig = hmac.new(_STRIPE_SECRET.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={sig}"


def test_healthcheck() -> None:
    client = _make_client()
    resp = client.get("/healthcheck")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}

    healthz_resp = client.get("/healthz")
    assert healthz_resp.status_code == 200
    assert healthz_resp.json() == {"status": "ok"}


def test_cross_tenant_idor_protection() -> None:
    client = _make_client()
    org_a_headers = _auth_header("org-a", sub="alice")
    org_b_headers = _auth_header("org-b", sub="bob")

    create_resp = client.post(
        "/audits",
        json={"target_url": "https://example.com"},
        headers=org_a_headers,
    )
    assert create_resp.status_code == 201
    audit_id = create_resp.json()["audit_id"]
    assert create_resp.json()["org_id"] == "org-a"

    # Org-B cannot GET, PATCH, or POST export on Org-A's audit
    assert client.get(f"/audits/{audit_id}", headers=org_b_headers).status_code == 404
    assert (
        client.patch(
            f"/audits/{audit_id}/findings/f-1",
            json={"status": "APPROVED"},
            headers=org_b_headers,
        ).status_code
        == 404
    )
    assert client.post(f"/audits/{audit_id}/export", headers=org_b_headers).status_code == 404


def test_triage_and_export_gate() -> None:
    client = _make_client()
    headers = _auth_header("org-a", sub="reviewer-1")

    create_resp = client.post(
        "/audits",
        json={"target_url": "https://example.com"},
        headers=headers,
    )
    assert create_resp.status_code == 201
    audit_id = create_resp.json()["audit_id"]

    # Export fails with 409 while finding is PENDING
    blocked_export = client.post(f"/audits/{audit_id}/export", headers=headers)
    assert blocked_export.status_code == 409

    # PATCH with <script> XSS vector is rejected with 422
    xss_patch = client.patch(
        f"/audits/{audit_id}/findings/f-1",
        json={
            "status": "EDITED",
            "edited_after_snippet": '<img src="/hero.png"><script>alert(1)</script>',
        },
        headers=headers,
    )
    assert xss_patch.status_code == 422

    # PATCH APPROVED succeeds
    approve_resp = client.patch(
        f"/audits/{audit_id}/findings/f-1",
        json={"status": "APPROVED"},
        headers=headers,
    )
    assert approve_resp.status_code == 200
    assert approve_resp.json()["reviews"][0]["status"] == "APPROVED"

    # Export succeeds with 64-char SHA-256 evidence_digest
    export_resp = client.post(f"/audits/{audit_id}/export", headers=headers)
    assert export_resp.status_code == 200
    data = export_resp.json()
    assert data["audit_id"] == audit_id
    assert len(data["evidence_digest"]) == 64
    assert "CERTIFIED ACCESSIBILITY CONFORMANCE REPORT" in data["html_report"]
    assert "image-alt" in data["github_issues_markdown"]


def test_stripe_webhook_signature_and_idempotency() -> None:
    client = _make_client()
    payload = json.dumps({"id": "evt_12345", "type": "checkout.session.completed"}).encode("utf-8")

    # Invalid signature -> 400
    bad_resp = client.post(
        "/webhooks/stripe",
        content=payload,
        headers={"Stripe-Signature": "t=1700000000,v1=deadbeef"},
    )
    assert bad_resp.status_code == 400

    # Valid signature -> 200 processed
    valid_sig = _sign_stripe_payload(payload)
    ok_resp = client.post(
        "/webhooks/stripe",
        content=payload,
        headers={"Stripe-Signature": valid_sig},
    )
    assert ok_resp.status_code == 200
    assert ok_resp.json() == {"status": "processed"}

    # Replay same event.id -> 200 duplicate
    replay_resp = client.post(
        "/webhooks/stripe",
        content=payload,
        headers={"Stripe-Signature": valid_sig},
    )
    assert replay_resp.status_code == 200
    assert replay_resp.json() == {"status": "duplicate"}


def test_stripe_webhook_idempotency_persists_across_sqlite_instances(tmp_path: Path) -> None:
    db_path = tmp_path / "stripe_idempotency.db"
    payload = json.dumps({"id": "evt_durable_001", "type": "checkout.session.completed"}).encode(
        "utf-8"
    )
    sig = _sign_stripe_payload(payload)

    app_1 = create_app(
        auth_secret=_AUTH_SECRET,
        stripe_webhook_secret=_STRIPE_SECRET,
        store=SQLiteAuditStore(db_path),
        scanner=_MockScanner(),
        synthesizer=_MockSynthesizer(),  # type: ignore[arg-type]
    )
    client_1 = TestClient(app_1)
    first_resp = client_1.post(
        "/webhooks/stripe",
        content=payload,
        headers={"Stripe-Signature": sig},
    )
    assert first_resp.status_code == 200
    assert first_resp.json() == {"status": "processed"}

    app_2 = create_app(
        auth_secret=_AUTH_SECRET,
        stripe_webhook_secret=_STRIPE_SECRET,
        store=SQLiteAuditStore(db_path),
        scanner=_MockScanner(),
        synthesizer=_MockSynthesizer(),  # type: ignore[arg-type]
    )
    client_2 = TestClient(app_2)
    second_resp = client_2.post(
        "/webhooks/stripe",
        content=payload,
        headers={"Stripe-Signature": sig},
    )
    assert second_resp.status_code == 200
    assert second_resp.json() == {"status": "duplicate"}


def _sample_bundle(org_id: str, audit_id: str) -> AuditBundle:
    finding = FindingEvidence(
        finding_id="f-1",
        source="axe-core",
        rule_id="image-alt",
        severity="critical",
        wcag_criterion="WCAG 2.1 SC 1.1.1 Non-text Content",
        aoda_section="AODA IASR s.14(4)",
        target_url="https://example.com",
        target_selector="img.hero",
        raw_snippet='<img class="hero" src="/hero.png">',
        component_fingerprint="fp-hero-img",
        raw_scanner_sha256="a" * 64,
        description="Hero image missing alt text",
    )
    patch = RemediationPatch(
        finding_id="f-1",
        rule_id="image-alt",
        target_selector="img.hero",
        patch_kind="html_diff",
        before_snippet=finding.raw_snippet,
        after_snippet='<img class="hero" src="/hero.png" alt="Hero">',
        wcag_criterion=finding.wcag_criterion,
        aoda_section=finding.aoda_section,
        component_fingerprint=finding.component_fingerprint,
        synthesized_by="deterministic_template",
    )
    return AuditBundle(
        audit_id=audit_id,
        org_id=org_id,
        target_url="https://example.com",
        created_at_utc=datetime(2026, 1, 1, tzinfo=UTC),
        findings=[finding],
        patches=[patch],
    )


def test_sqlite_audit_store_persistence_and_tenant_isolation(tmp_path: Path) -> None:
    db_file = tmp_path / "servicecore.db"
    store_1 = SQLiteAuditStore(db_file)
    bundle_a1 = _sample_bundle("org-a", "aud-1")
    bundle_b1 = _sample_bundle("org-b", "aud-1")
    bundle_a2 = _sample_bundle("org-a", "aud-2")

    store_1.save(bundle_a1)
    store_1.save(bundle_b1)
    store_1.save(bundle_a2)

    # Re-instantiate against the same SQLite file to verify persistence
    store_2 = SQLiteAuditStore(db_file)
    loaded_a1 = store_2.get("org-a", "aud-1")
    assert loaded_a1 is not None
    assert loaded_a1.org_id == "org-a"
    assert loaded_a1.audit_id == "aud-1"
    assert store_2.get("org-c", "aud-1") is None

    org_a_list = store_2.list_for_org("org-a")
    assert {b.audit_id for b in org_a_list} == {"aud-1", "aud-2"}
    assert all(b.org_id == "org-a" for b in org_a_list)

    org_b_list = store_2.list_for_org("org-b")
    assert [b.audit_id for b in org_b_list] == ["aud-1"]
    assert org_b_list[0].org_id == "org-b"


def test_list_audits_endpoint_tenant_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_file = tmp_path / "api.db"
    monkeypatch.setenv("SERVICECORE_DB_PATH", str(db_file))
    app = create_app(
        auth_secret=_AUTH_SECRET,
        stripe_webhook_secret=_STRIPE_SECRET,
        scanner=_MockScanner(),
        synthesizer=_MockSynthesizer(),  # type: ignore[arg-type]
    )
    assert isinstance(app.state.store, SQLiteAuditStore)
    client = TestClient(app)

    org_a_headers = _auth_header("org-a", sub="alice")
    org_b_headers = _auth_header("org-b", sub="bob")

    resp_a = client.post("/audits", json={"target_url": "https://a.example.com"}, headers=org_a_headers)
    resp_b = client.post("/audits", json={"target_url": "https://b.example.com"}, headers=org_b_headers)
    assert resp_a.status_code == 201
    assert resp_b.status_code == 201

    list_a = client.get("/audits", headers=org_a_headers)
    assert list_a.status_code == 200
    data_a = list_a.json()
    assert len(data_a) == 1
    assert data_a[0]["org_id"] == "org-a"
    assert data_a[0]["audit_id"] == resp_a.json()["audit_id"]

    list_b = client.get("/audits", headers=org_b_headers)
    assert list_b.status_code == 200
    data_b = list_b.json()
    assert len(data_b) == 1
    assert data_b[0]["org_id"] == "org-b"
    assert data_b[0]["audit_id"] == resp_b.json()["audit_id"]


def test_dev_token_endpoint_gated_by_dev_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SERVICECORE_DEV_MODE", raising=False)
    monkeypatch.delenv("SERVICECORE_AUTH_SECRET", raising=False)

    client = TestClient(
        create_app(
            scanner=_MockScanner(),
            synthesizer=_MockSynthesizer(),  # type: ignore[arg-type]
        )
    )
    assert client.post("/dev/token").status_code == 404

    monkeypatch.setenv("SERVICECORE_DEV_MODE", "1")
    dev_resp = client.post("/dev/token")
    assert dev_resp.status_code == 200
    payload = dev_resp.json()
    assert payload["org_id"] == "org_dev"
    assert isinstance(payload["token"], str) and payload["token"]

    # Returned token works for authenticated endpoints in dev mode
    audits_resp = client.get(
        "/audits",
        headers={"Authorization": f"Bearer {payload['token']}"},
    )
    assert audits_resp.status_code == 200
    assert audits_resp.json() == []


def test_cors_preflight_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SERVICECORE_CORS_ORIGINS", raising=False)
    default_client = _make_client()

    ok_preflight = default_client.options(
        "/audits",
        headers={
            "Origin": "http://localhost:3105",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization",
        },
    )
    assert ok_preflight.status_code == 200
    assert ok_preflight.headers.get("access-control-allow-origin") == "http://localhost:3105"

    monkeypatch.setenv("SERVICECORE_CORS_ORIGINS", "https://workbench.example.com")
    custom_client = _make_client()
    custom_preflight = custom_client.options(
        "/audits",
        headers={
            "Origin": "https://workbench.example.com",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert custom_preflight.status_code == 200
    assert (
        custom_preflight.headers.get("access-control-allow-origin")
        == "https://workbench.example.com"
    )


def test_export_pdf_gate_and_certified_response(monkeypatch: pytest.MonkeyPatch) -> None:
    rendered_html: list[str] = []

    class _FakeHTML:
        def __init__(self, *, string: str) -> None:
            self._string = string

        def write_pdf(self) -> bytes:
            rendered_html.append(self._string)
            return b"%PDF-1.4\n%certified\n"

    fake_weasyprint = ModuleType("weasyprint")
    cast(Any, fake_weasyprint).HTML = _FakeHTML
    monkeypatch.setitem(sys.modules, "weasyprint", fake_weasyprint)

    client = _make_client()
    org_a_headers = _auth_header("org-a", sub="reviewer-1")
    org_b_headers = _auth_header("org-b", sub="reviewer-2")

    create_resp = client.post(
        "/audits",
        json={"target_url": "https://example.com"},
        headers=org_a_headers,
    )
    assert create_resp.status_code == 201
    audit_id = create_resp.json()["audit_id"]

    # Cross-tenant PDF export is blocked with 404
    assert client.post(f"/audits/{audit_id}/export/pdf", headers=org_b_headers).status_code == 404

    # Unsigned finding blocks certified PDF export with 409
    blocked_pdf = client.post(f"/audits/{audit_id}/export/pdf", headers=org_a_headers)
    assert blocked_pdf.status_code == 409

    # Sign finding via APPROVED triage
    approve_resp = client.patch(
        f"/audits/{audit_id}/findings/f-1",
        json={"status": "APPROVED"},
        headers=org_a_headers,
    )
    assert approve_resp.status_code == 200

    # Certified PDF export succeeds with 200, application/pdf, %PDF- bytes, and X-Evidence-Digest
    pdf_resp = client.post(f"/audits/{audit_id}/export/pdf", headers=org_a_headers)
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"].startswith("application/pdf")
    assert (
        pdf_resp.headers["content-disposition"]
        == f'attachment; filename="servicecore-{audit_id}.pdf"'
    )
    digest = pdf_resp.headers.get("x-evidence-digest")
    assert digest is not None and len(digest) == 64
    assert pdf_resp.content.startswith(b"%PDF-")
    assert len(rendered_html) == 1
    assert "CERTIFIED ACCESSIBILITY CONFORMANCE REPORT" in rendered_html[0]
    assert digest in rendered_html[0]


def _make_finding(
    finding_id: str,
    *,
    rule_id: str,
    selector: str,
    fingerprint: str,
    raw_snippet: str = '<img class="hero" src="/hero.png">',
) -> FindingEvidence:
    return FindingEvidence(
        finding_id=finding_id,
        source="axe-core",
        rule_id=rule_id,
        severity="critical",
        wcag_criterion="WCAG 2.1 SC 1.1.1 Non-text Content",
        aoda_section="AODA IASR s.14(4)",
        target_url="https://example.com",
        target_selector=selector,
        raw_snippet=raw_snippet,
        component_fingerprint=fingerprint,
        raw_scanner_sha256="a" * 64,
        description=f"Finding {finding_id}",
    )


def test_audit_diff_endpoint_and_cross_tenant_baseline_isolation() -> None:
    store = InMemoryAuditStore()
    f_fixed = _make_finding(
        "f-fixed",
        rule_id="image-alt",
        selector="img.old",
        fingerprint="fp-fixed",
    )
    f_persist = _make_finding(
        "f-persist",
        rule_id="color-contrast",
        selector="button.cta",
        fingerprint="fp-persist",
    )
    f_new = _make_finding(
        "f-new",
        rule_id="label",
        selector="input.email",
        fingerprint="fp-new",
    )

    baseline = AuditBundle(
        audit_id="aud-base",
        org_id="org-a",
        target_url="https://example.com",
        created_at_utc=datetime(2026, 1, 1, tzinfo=UTC),
        findings=[f_fixed, f_persist],
    )
    current = AuditBundle(
        audit_id="aud-curr",
        org_id="org-a",
        target_url="https://example.com",
        created_at_utc=datetime(2026, 1, 2, tzinfo=UTC),
        findings=[f_persist, f_new],
    )
    other_org_baseline = AuditBundle(
        audit_id="aud-foreign-base",
        org_id="org-b",
        target_url="https://other.example.com",
        created_at_utc=datetime(2026, 1, 1, tzinfo=UTC),
        findings=[f_fixed],
    )
    store.save(baseline)
    store.save(current)
    store.save(other_org_baseline)

    app = create_app(
        auth_secret=_AUTH_SECRET,
        stripe_webhook_secret=_STRIPE_SECRET,
        store=store,
        scanner=_MockScanner(),
        synthesizer=_MockSynthesizer(),  # type: ignore[arg-type]
    )
    client = TestClient(app)
    org_a_headers = _auth_header("org-a", sub="alice")

    diff_resp = client.get(
        "/audits/aud-curr/diff",
        params={"baseline_id": "aud-base"},
        headers=org_a_headers,
    )
    assert diff_resp.status_code == 200
    report = diff_resp.json()
    assert report["baseline_audit_id"] == "aud-base"
    assert report["current_audit_id"] == "aud-curr"
    assert [item["component_fingerprint"] for item in report["new_regressions"]] == ["fp-new"]
    assert [item["component_fingerprint"] for item in report["fixed"]] == ["fp-fixed"]
    assert [item["component_fingerprint"] for item in report["persistent"]] == ["fp-persist"]

    # Cross-tenant baseline_id is blocked with 404
    cross_tenant_resp = client.get(
        "/audits/aud-curr/diff",
        params={"baseline_id": "aud-foreign-base"},
        headers=org_a_headers,
    )
    assert cross_tenant_resp.status_code == 404


def test_publish_github_gate_and_mock_transport() -> None:
    captured_requests: list[tuple[str, dict[str, Any], str]] = []
    issue_counter = 0

    def _handler(request: httpx.Request) -> httpx.Response:
        nonlocal issue_counter
        issue_counter += 1
        payload = json.loads(request.content.decode("utf-8"))
        captured_requests.append(
            (str(request.url), payload, request.headers.get("authorization", ""))
        )
        return httpx.Response(
            201,
            json={
                "number": 40 + issue_counter,
                "html_url": f"https://github.com/acme/web/issues/{40 + issue_counter}",
                "title": payload["title"],
            },
        )

    app = create_app(
        auth_secret=_AUTH_SECRET,
        stripe_webhook_secret=_STRIPE_SECRET,
        scanner=_MockScanner(),
        synthesizer=_MockSynthesizer(),  # type: ignore[arg-type]
    )
    app.state.github_client = httpx.Client(transport=httpx.MockTransport(_handler))
    client = TestClient(app)
    headers = _auth_header("org-a", sub="reviewer-1")

    create_resp = client.post(
        "/audits",
        json={"target_url": "https://example.com"},
        headers=headers,
    )
    assert create_resp.status_code == 201
    audit_id = create_resp.json()["audit_id"]

    # Unsigned bundle cannot be published directly or via API
    unsigned_bundle = AuditBundle.model_validate(create_resp.json())
    with pytest.raises(UnsignedFindingError):
        publish_bundle_to_github(
            unsigned_bundle,
            repo="acme/web",
            token="ghp_test_token",
            client=app.state.github_client,
        )

    blocked_resp = client.post(
        f"/audits/{audit_id}/publish/github",
        json={"repo": "acme/web", "github_token": "ghp_test_token"},
        headers=headers,
    )
    assert blocked_resp.status_code == 409
    assert captured_requests == []

    # Approve finding, then publish succeeds
    approve_resp = client.patch(
        f"/audits/{audit_id}/findings/f-1",
        json={"status": "APPROVED"},
        headers=headers,
    )
    assert approve_resp.status_code == 200

    pub_resp = client.post(
        f"/audits/{audit_id}/publish/github",
        json={"repo": "acme/web", "github_token": "ghp_test_token"},
        headers=headers,
    )
    assert pub_resp.status_code == 200
    data = pub_resp.json()
    assert data["audit_id"] == audit_id
    assert data["issues_created"] == 1
    assert len(data["issues"]) == 1
    assert data["issues"][0]["finding_id"] == "f-1"
    assert data["issues"][0]["issue_number"] == 41
    assert data["issues"][0]["html_url"] == "https://github.com/acme/web/issues/41"

    assert len(captured_requests) == 1
    req_url, req_payload, auth_hdr = captured_requests[0]
    assert req_url == "https://api.github.com/repos/acme/web/issues"
    assert auth_hdr == "Bearer ghp_test_token"
    assert "WCAG 2.1 SC 1.1.1" in req_payload["body"]
    assert "AODA IASR s.14(4)" in req_payload["body"]
    assert "fp-hero-img" in req_payload["body"]
    assert "a" * 64 in req_payload["body"]
    assert "alt=&quot;Company hero&quot;" in req_payload["body"]


def test_monitors_create_list_and_cross_tenant_isolation(tmp_path: Path) -> None:
    db_path = tmp_path / "monitors.db"
    app = create_app(
        auth_secret=_AUTH_SECRET,
        stripe_webhook_secret=_STRIPE_SECRET,
        store=SQLiteAuditStore(db_path),
        scanner=_MockScanner(),
        synthesizer=_MockSynthesizer(),  # type: ignore[arg-type]
    )
    client = TestClient(app)
    org_a_headers = _auth_header("org-a", sub="alice")
    org_b_headers = _auth_header("org-b", sub="bob")

    create_resp = client.post(
        "/monitors",
        json={
            "target_url": "https://example.com",
            "cadence_hours": 12,
            "crawl": True,
            "max_pages": 8,
            "max_pdfs": 2,
        },
        headers=org_a_headers,
    )
    assert create_resp.status_code == 201
    monitor = create_resp.json()
    monitor_id = monitor["monitor_id"]
    assert monitor["org_id"] == "org-a"
    assert monitor["target_url"] == "https://example.com"
    assert monitor["cadence_hours"] == 12
    assert monitor["crawl"] is True
    assert monitor["max_pages"] == 8
    assert monitor["max_pdfs"] == 2
    assert monitor["baseline_audit_id"] is None
    assert monitor["last_run_at_utc"] is None
    assert monitor["enabled"] is True

    list_a = client.get("/monitors", headers=org_a_headers)
    assert list_a.status_code == 200
    assert len(list_a.json()) == 1
    assert list_a.json()[0]["monitor_id"] == monitor_id

    list_b = client.get("/monitors", headers=org_b_headers)
    assert list_b.status_code == 200
    assert list_b.json() == []

    # Cross-tenant POST /monitors/{monitor_id}/run returns 404
    cross_run = client.post(f"/monitors/{monitor_id}/run", headers=org_b_headers)
    assert cross_run.status_code == 404


def test_monitor_run_sets_baseline_and_computes_diff() -> None:
    class _StatefulScanner:
        def __init__(self) -> None:
            self.call_count = 0

        def scan(self, target: str) -> list[FindingEvidence]:
            self.call_count += 1
            if self.call_count == 1:
                return [
                    FindingEvidence(
                        finding_id="f-persist",
                        source="axe-core",
                        rule_id="image-alt",
                        severity="critical",
                        wcag_criterion="WCAG 2.1 SC 1.1.1",
                        aoda_section="AODA IASR s.14(4)",
                        target_url=target,
                        target_selector="img.logo",
                        raw_snippet='<img class="logo" src="/logo.png">',
                        component_fingerprint="fp-persist",
                        raw_scanner_sha256="a" * 64,
                        description="Logo missing alt",
                    ),
                    FindingEvidence(
                        finding_id="f-fixed",
                        source="axe-core",
                        rule_id="label",
                        severity="serious",
                        wcag_criterion="WCAG 2.1 SC 1.3.1",
                        aoda_section="AODA IASR s.14(4)",
                        target_url=target,
                        target_selector="input.email",
                        raw_snippet='<input class="email" type="email">',
                        component_fingerprint="fp-fixed",
                        raw_scanner_sha256="b" * 64,
                        description="Input missing label",
                    ),
                ]
            return [
                FindingEvidence(
                    finding_id="f-persist",
                    source="axe-core",
                    rule_id="image-alt",
                    severity="critical",
                    wcag_criterion="WCAG 2.1 SC 1.1.1",
                    aoda_section="AODA IASR s.14(4)",
                    target_url=target,
                    target_selector="img.logo",
                    raw_snippet='<img class="logo" src="/logo.png">',
                    component_fingerprint="fp-persist",
                    raw_scanner_sha256="a" * 64,
                    description="Logo missing alt",
                ),
                FindingEvidence(
                    finding_id="f-new",
                    source="axe-core",
                    rule_id="button-name",
                    severity="serious",
                    wcag_criterion="WCAG 2.1 SC 4.1.2",
                    aoda_section="AODA IASR s.14(4)",
                    target_url=target,
                    target_selector="button.submit",
                    raw_snippet='<button class="submit"></button>',
                    component_fingerprint="fp-new",
                    raw_scanner_sha256="c" * 64,
                    description="Button missing accessible name",
                ),
            ]

    app = create_app(
        auth_secret=_AUTH_SECRET,
        stripe_webhook_secret=_STRIPE_SECRET,
        scanner=_StatefulScanner(),
        synthesizer=_MockSynthesizer(),  # type: ignore[arg-type]
    )
    client = TestClient(app)
    headers = _auth_header("org-a", sub="alice")

    create_resp = client.post(
        "/monitors",
        json={"target_url": "https://example.com"},
        headers=headers,
    )
    assert create_resp.status_code == 201
    monitor_id = create_resp.json()["monitor_id"]

    # Run 1 sets baseline with diff=None
    run1_resp = client.post(f"/monitors/{monitor_id}/run", headers=headers)
    assert run1_resp.status_code == 200
    run1 = run1_resp.json()
    assert run1["diff"] is None
    audit_1_id = run1["audit"]["audit_id"]
    assert run1["monitor"]["baseline_audit_id"] == audit_1_id
    assert run1["monitor"]["last_run_at_utc"] is not None

    # Run 2 compares against Run 1 and updates baseline to Run 2
    run2_resp = client.post(f"/monitors/{monitor_id}/run", headers=headers)
    assert run2_resp.status_code == 200
    run2 = run2_resp.json()
    audit_2_id = run2["audit"]["audit_id"]
    assert run2["monitor"]["baseline_audit_id"] == audit_2_id
    assert run2["diff"] is not None
    assert run2["diff"]["baseline_audit_id"] == audit_1_id
    assert run2["diff"]["current_audit_id"] == audit_2_id
    assert [item["component_fingerprint"] for item in run2["diff"]["new_regressions"]] == [
        "fp-new"
    ]
    assert [item["component_fingerprint"] for item in run2["diff"]["fixed"]] == ["fp-fixed"]
    assert [item["component_fingerprint"] for item in run2["diff"]["persistent"]] == [
        "fp-persist"
    ]
