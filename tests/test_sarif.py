from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from servicecore.api import create_app, mint_auth_token
from servicecore.exporter import sign_bundle
from servicecore.sarif import export_sarif
from servicecore.schemas import (
    AuditBundle,
    FindingEvidence,
    FindingReview,
    RemediationPatch,
    SeverityLevel,
    UnsignedFindingError,
)

_AUTH_SECRET = "test-auth-secret-32-bytes-minimum"
_STRIPE_SECRET = "whsec_test_stripe_secret"


def _make_finding(
    finding_id: str,
    *,
    rule_id: str = "image-alt",
    severity: SeverityLevel = "critical",
    selector: str = "img.hero",
    fingerprint: str = "fp-hero-img",
) -> FindingEvidence:
    return FindingEvidence(
        finding_id=finding_id,
        source="axe-core",
        rule_id=rule_id,
        severity=severity,
        wcag_criterion="WCAG 2.1 SC 1.1.1 Non-text Content",
        aoda_section="AODA IASR s.14(4)",
        target_url="https://example.com/home",
        target_selector=selector,
        raw_snippet='<img class="hero" src="/hero.png">',
        component_fingerprint=fingerprint,
        raw_scanner_sha256="a" * 64,
        description=f"Issue for {rule_id}",
    )


def _make_approved_bundle(findings: list[FindingEvidence], reviews: list[FindingReview]) -> AuditBundle:
    bundle = AuditBundle(
        audit_id="audit-sarif-1",
        org_id="org-a",
        target_url="https://example.com/home",
        findings=findings,
        reviews=reviews,
    )
    return sign_bundle(bundle, reviewer_id="reviewer-1", signed_at_utc=datetime.now(UTC))


def test_export_sarif_rejects_unsigned_bundle() -> None:
    finding = _make_finding("f-1")
    unsigned_bundle = AuditBundle(
        audit_id="audit-unsigned",
        org_id="org-a",
        target_url="https://example.com/home",
        findings=[finding],
        reviews=[FindingReview(finding_id="f-1", status="PENDING")],
    )
    with pytest.raises(UnsignedFindingError):
        export_sarif(unsigned_bundle)

    signed = _make_approved_bundle(
        [finding],
        [
            FindingReview(
                finding_id="f-1",
                status="APPROVED",
                reviewer_id="reviewer-1",
                signed_at_utc=datetime.now(UTC),
            )
        ],
    )
    tampered = signed.model_copy(update={"evidence_digest": "0" * 64})
    with pytest.raises(UnsignedFindingError, match="Evidence digest mismatch"):
        export_sarif(tampered)


def test_export_sarif_maps_severities_and_omits_rejected() -> None:
    now = datetime.now(UTC)
    findings = [
        _make_finding("f-crit", rule_id="r-crit", severity="critical", selector="#c", fingerprint="fp-c"),
        _make_finding("f-ser", rule_id="r-ser", severity="serious", selector="#s", fingerprint="fp-s"),
        _make_finding("f-mod", rule_id="r-mod", severity="moderate", selector="#m", fingerprint="fp-m"),
        _make_finding("f-min", rule_id="r-min", severity="minor", selector="#n", fingerprint="fp-n"),
        _make_finding("f-rej", rule_id="r-rej", severity="critical", selector="#x", fingerprint="fp-x"),
    ]
    reviews = [
        FindingReview(finding_id="f-crit", status="APPROVED", reviewer_id="rev-1", signed_at_utc=now),
        FindingReview(finding_id="f-ser", status="EDITED", reviewer_id="rev-1", signed_at_utc=now),
        FindingReview(finding_id="f-mod", status="APPROVED", reviewer_id="rev-1", signed_at_utc=now),
        FindingReview(finding_id="f-min", status="APPROVED", reviewer_id="rev-1", signed_at_utc=now),
        FindingReview(finding_id="f-rej", status="REJECTED", rejection_reason="False positive"),
    ]
    bundle = _make_approved_bundle(findings, reviews)

    sarif = export_sarif(bundle)

    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "ServiceCore"
    assert driver["semanticVersion"] == "0.1.0"
    assert [r["id"] for r in driver["rules"]] == ["r-crit", "r-ser", "r-mod", "r-min"]

    results = run["results"]
    assert len(results) == 4
    levels_by_rule = {r["ruleId"]: r["level"] for r in results}
    assert levels_by_rule == {
        "r-crit": "error",
        "r-ser": "error",
        "r-mod": "warning",
        "r-min": "note",
    }

    first = results[0]
    assert first["message"]["text"] == "Issue for r-crit"
    assert first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "https://example.com/home"
    assert first["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] == "#c"
    assert first["properties"] == {
        "wcag_criterion": "WCAG 2.1 SC 1.1.1 Non-text Content",
        "aoda_section": "AODA IASR s.14(4)",
        "component_fingerprint": "fp-c",
        "raw_scanner_sha256": "a" * 64,
        "evidence_digest": bundle.evidence_digest,
    }


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
                after_snippet='<img class="hero" src="/hero.png" alt="Hero">',
                wcag_criterion=f.wcag_criterion,
                aoda_section=f.aoda_section,
                component_fingerprint=f.component_fingerprint,
                synthesized_by="deterministic_template",
            )
            for f in findings
        ]
        return (patches, 10, 5)


def _auth_header(org_id: str, sub: str = "user-1") -> dict[str, str]:
    token = mint_auth_token(org_id=org_id, sub=sub, secret=_AUTH_SECRET)
    return {"Authorization": f"Bearer {token}"}


def test_get_export_sarif_endpoint_gate_and_success() -> None:
    app = create_app(
        auth_secret=_AUTH_SECRET,
        stripe_webhook_secret=_STRIPE_SECRET,
        scanner=_MockScanner(),
        synthesizer=_MockSynthesizer(),  # type: ignore[arg-type]
    )
    client = TestClient(app)
    org_a_headers = _auth_header("org-a")
    org_b_headers = _auth_header("org-b")

    create_resp = client.post(
        "/audits",
        json={"target_url": "https://example.com"},
        headers=org_a_headers,
    )
    assert create_resp.status_code == 201
    audit_id = create_resp.json()["audit_id"]

    # Cross-tenant SARIF export returns 404
    assert client.get(f"/audits/{audit_id}/export/sarif", headers=org_b_headers).status_code == 404

    # Unsigned finding blocks SARIF export with 409
    blocked = client.get(f"/audits/{audit_id}/export/sarif", headers=org_a_headers)
    assert blocked.status_code == 409

    # Approve the finding
    approve_resp = client.patch(
        f"/audits/{audit_id}/findings/f-1",
        json={"status": "APPROVED"},
        headers=org_a_headers,
    )
    assert approve_resp.status_code == 200

    # Certified SARIF export succeeds with 200
    sarif_resp = client.get(f"/audits/{audit_id}/export/sarif", headers=org_a_headers)
    assert sarif_resp.status_code == 200
    payload = sarif_resp.json()
    assert payload["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "ServiceCore"
    assert payload["runs"][0]["results"][0]["ruleId"] == "image-alt"
    assert payload["runs"][0]["results"][0]["level"] == "error"
    assert payload["runs"][0]["results"][0]["properties"]["evidence_digest"]
