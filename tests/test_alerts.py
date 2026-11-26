from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from servicecore.alerts import (
    RegressionAlertPayload,
    build_regression_alert,
    dispatch_webhook_alert,
    run_due_monitors,
)
from servicecore.api import InMemoryAuditStore, create_app, mint_auth_token
from servicecore.schemas import (
    AuditBundle,
    DiffItem,
    DiffReport,
    FindingEvidence,
    MonitorSchedule,
    RemediationPatch,
    SSRFBlockedError,
)

_AUTH_SECRET = "test-auth-secret-32-bytes-minimum"
_STRIPE_SECRET = "whsec_test_stripe_secret"
_PUBLIC_WEBHOOK_URL = "https://93.184.216.34/hook"


def _make_finding(
    *,
    finding_id: str,
    rule_id: str,
    fingerprint: str,
    target_url: str,
    selector: str = "img.hero",
) -> FindingEvidence:
    return FindingEvidence(
        finding_id=finding_id,
        source="axe-core",
        rule_id=rule_id,
        severity="critical",
        wcag_criterion="WCAG 2.1 SC 1.1.1",
        aoda_section="AODA IASR s.14(4)",
        target_url=target_url,
        target_selector=selector,
        raw_snippet='<img class="hero" src="/hero.png">',
        component_fingerprint=fingerprint,
        raw_scanner_sha256="a" * 64,
        description="Missing accessible attribute",
    )


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
                after_snippet='<img class="hero" src="/hero.png" alt="Hero">',
                wcag_criterion=f.wcag_criterion,
                aoda_section=f.aoda_section,
                component_fingerprint=f.component_fingerprint,
                synthesized_by="deterministic_template",
            )
            for f in findings
        ]
        return patches, 10, 10


class _SequenceScanner:
    def __init__(self, sequences: list[list[FindingEvidence]]) -> None:
        self._sequences = sequences
        self.call_count = 0

    def scan(self, target: str) -> list[FindingEvidence]:
        idx = min(self.call_count, len(self._sequences) - 1)
        self.call_count += 1
        return self._sequences[idx]


def test_dispatch_webhook_alert_blocks_loopback_ssrf() -> None:
    payload = RegressionAlertPayload(
        monitor_id="mon-1",
        org_id="org-a",
        target_url="https://example.com",
        audit_id="aud-2",
        baseline_audit_id="aud-1",
        new_regressions_count=1,
        rule_ids=["image-alt"],
        triggered_at_utc=datetime(2026, 1, 2, 12, 0, tzinfo=UTC),
        text="Regression detected",
    )
    with pytest.raises(SSRFBlockedError):
        dispatch_webhook_alert("http://127.0.0.1/hook", payload)


def test_dispatch_webhook_alert_posts_payload_via_mock_transport() -> None:
    captured: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(200, json={"ok": True})

    payload = RegressionAlertPayload(
        monitor_id="mon-1",
        org_id="org-a",
        target_url="https://example.com",
        audit_id="aud-2",
        baseline_audit_id="aud-1",
        new_regressions_count=2,
        rule_ids=["image-alt", "button-name"],
        triggered_at_utc=datetime(2026, 1, 2, 12, 0, tzinfo=UTC),
        text="2 regressions detected",
    )
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        ok = dispatch_webhook_alert(_PUBLIC_WEBHOOK_URL, payload, client=client)
    assert ok is True
    assert len(captured) == 1
    assert captured[0]["monitor_id"] == "mon-1"
    assert captured[0]["new_regressions_count"] == 2
    assert captured[0]["rule_ids"] == ["image-alt", "button-name"]

    def error_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="server error")

    with httpx.Client(transport=httpx.MockTransport(error_handler)) as client:
        ok_err = dispatch_webhook_alert(_PUBLIC_WEBHOOK_URL, payload, client=client)
    assert ok_err is False


def test_build_regression_alert_extracts_unique_rules_and_counts() -> None:
    now = datetime(2026, 1, 3, 8, 30, tzinfo=UTC)
    monitor = MonitorSchedule(
        monitor_id="mon-abc",
        org_id="org-a",
        target_url="https://example.com",
    )
    audit = AuditBundle(
        audit_id="aud-curr",
        org_id="org-a",
        target_url="https://example.com",
    )
    diff = DiffReport(
        baseline_audit_id="aud-base",
        current_audit_id="aud-curr",
        new_regressions=[
            DiffItem(
                component_fingerprint="fp-1",
                rule_id="image-alt",
                status="NEW_REGRESSION",
                target_selector="img.a",
                target_url="https://example.com",
            ),
            DiffItem(
                component_fingerprint="fp-2",
                rule_id="image-alt",
                status="NEW_REGRESSION",
                target_selector="img.b",
                target_url="https://example.com",
            ),
            DiffItem(
                component_fingerprint="fp-3",
                rule_id="button-name",
                status="NEW_REGRESSION",
                target_selector="button.go",
                target_url="https://example.com",
            ),
        ],
    )
    payload = build_regression_alert(monitor, diff, audit, now=now)
    assert payload.monitor_id == "mon-abc"
    assert payload.org_id == "org-a"
    assert payload.audit_id == "aud-curr"
    assert payload.baseline_audit_id == "aud-base"
    assert payload.new_regressions_count == 3
    assert payload.rule_ids == ["image-alt", "button-name"]
    assert payload.triggered_at_utc == now
    assert "3 new regression(s)" in payload.text


def test_run_due_monitors_respects_cadence_enabled_and_regression_webhook() -> None:
    store = InMemoryAuditStore()
    t0 = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)

    due_first = MonitorSchedule(
        monitor_id="mon-due-first",
        org_id="org-a",
        target_url="https://example.com/a",
        cadence_hours=24,
        last_run_at_utc=None,
        enabled=True,
    )
    not_due = MonitorSchedule(
        monitor_id="mon-not-due",
        org_id="org-a",
        target_url="https://example.com/b",
        cadence_hours=24,
        last_run_at_utc=t0 - timedelta(hours=12),
        enabled=True,
    )
    disabled = MonitorSchedule(
        monitor_id="mon-disabled",
        org_id="org-a",
        target_url="https://example.com/c",
        cadence_hours=1,
        last_run_at_utc=None,
        enabled=False,
    )
    store.save_monitor(due_first)
    store.save_monitor(not_due)
    store.save_monitor(disabled)

    f1 = _make_finding(
        finding_id="f-1",
        rule_id="image-alt",
        fingerprint="fp-1",
        target_url="https://example.com/a",
    )
    f2 = _make_finding(
        finding_id="f-2",
        rule_id="button-name",
        fingerprint="fp-2",
        target_url="https://example.com/a",
        selector="button.submit",
    )
    scanner = _SequenceScanner([[f1], [f1], [f1, f2]])
    synth = _MockSynthesizer()

    posted_alerts: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        posted_alerts.append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(202)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        # Run 1 at t0: only mon-due-first runs; diff is None -> no webhook
        res1 = run_due_monitors(
            store,
            "org-a",
            scanner=scanner,
            synthesizer=synth,  # type: ignore[arg-type]
            now=t0,
            webhook_url=_PUBLIC_WEBHOOK_URL,
            client=client,
        )
        assert [r.monitor.monitor_id for r in res1] == ["mon-due-first"]
        assert res1[0].diff is None
        assert posted_alerts == []

        # Run 2 at t0 + 24h: mon-due-first (no new regressions) and mon-not-due (now 36h elapsed) run;
        # neither has new regressions -> still no webhook
        t1 = t0 + timedelta(hours=24)
        res2 = run_due_monitors(
            store,
            "org-a",
            scanner=scanner,
            synthesizer=synth,  # type: ignore[arg-type]
            now=t1,
            webhook_url=_PUBLIC_WEBHOOK_URL,
            client=client,
        )
        assert {r.monitor.monitor_id for r in res2} == {"mon-due-first", "mon-not-due"}
        assert posted_alerts == []

        # Run 3 at t1 + 24h: scanner returns f1 + f2 -> new regression on button-name -> webhook fires
        t2 = t1 + timedelta(hours=24)
        res3 = run_due_monitors(
            store,
            "org-a",
            scanner=scanner,
            synthesizer=synth,  # type: ignore[arg-type]
            now=t2,
            webhook_url=_PUBLIC_WEBHOOK_URL,
            client=client,
        )
        assert len(res3) == 2
        assert len(posted_alerts) >= 1
        assert any(alert["rule_ids"] == ["button-name"] for alert in posted_alerts)


def test_post_monitors_run_due_endpoint_and_ssrf_422() -> None:
    f1 = _make_finding(
        finding_id="f-1",
        rule_id="image-alt",
        fingerprint="fp-1",
        target_url="https://example.com",
    )
    app = create_app(
        auth_secret=_AUTH_SECRET,
        stripe_webhook_secret=_STRIPE_SECRET,
        scanner=_SequenceScanner([[f1]]),
        synthesizer=_MockSynthesizer(),  # type: ignore[arg-type]
    )
    client = TestClient(app)
    org_a_headers = {
        "Authorization": f"Bearer {mint_auth_token('org-a', 'alice', _AUTH_SECRET)}"
    }
    org_b_headers = {
        "Authorization": f"Bearer {mint_auth_token('org-b', 'bob', _AUTH_SECRET)}"
    }

    create_resp = client.post(
        "/monitors",
        json={"target_url": "https://example.com", "cadence_hours": 12},
        headers=org_a_headers,
    )
    assert create_resp.status_code == 201
    mon_id = create_resp.json()["monitor_id"]

    # SSRF-blocked webhook_url returns 422
    ssrf_resp = client.post(
        "/monitors/run-due",
        json={"webhook_url": "http://127.0.0.1/hook"},
        headers=org_a_headers,
    )
    assert ssrf_resp.status_code == 422

    # Org B has no monitors, returns empty list
    org_b_resp = client.post("/monitors/run-due", json={}, headers=org_b_headers)
    assert org_b_resp.status_code == 200
    assert org_b_resp.json() == []

    # Org A runs its due monitor
    run_resp = client.post("/monitors/run-due", headers=org_a_headers)
    assert run_resp.status_code == 200
    payload = run_resp.json()
    assert len(payload) == 1
    assert payload[0]["monitor"]["monitor_id"] == mon_id
    assert payload[0]["monitor"]["baseline_audit_id"] == payload[0]["audit"]["audit_id"]

    # Calling immediately again skips the monitor since cadence_hours=12 hasn't elapsed
    run_again_resp = client.post("/monitors/run-due", json={}, headers=org_a_headers)
    assert run_again_resp.status_code == 200
    assert run_again_resp.json() == []
