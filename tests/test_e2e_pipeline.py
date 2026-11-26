from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from fastapi.testclient import TestClient

from servicecore.api import InMemoryAuditStore, create_app, mint_auth_token
from servicecore.exporter import verify_bundle
from servicecore.schemas import AuditBundle, FindingEvidence
from servicecore.synthesizer import ClaudeSynthesizer

_AUTH_SECRET = "e2e-test-auth-secret-32-bytes-min"


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class _FakeScannerBackend:
    """Deterministic ScannerBackend returning two axe-core findings and one pypdf finding."""

    def scan(self, target: str) -> list[FindingEvidence]:
        return [
            FindingEvidence(
                finding_id="f-img-1",
                source="axe-core",
                rule_id="image-alt",
                severity="critical",
                wcag_criterion="WCAG 2.1 SC 1.1.1 Non-text Content",
                aoda_section="AODA IASR s.14(4)",
                target_url=target,
                target_selector="img.hero-banner",
                raw_snippet='<img class="hero-banner" src="/banner.png">',
                component_fingerprint="fp-img-hero-banner",
                raw_scanner_sha256=_sha256_hex("axe:image-alt:img.hero-banner"),
                description="Hero banner image is missing an alt attribute.",
            ),
            FindingEvidence(
                finding_id="f-btn-2",
                source="axe-core",
                rule_id="button-name",
                severity="serious",
                wcag_criterion="WCAG 2.1 SC 4.1.2 Name, Role, Value",
                aoda_section="AODA IASR s.14(4)",
                target_url=target,
                target_selector="button.submit-icon",
                raw_snippet='<button class="submit-icon" type="button"></button>',
                component_fingerprint="fp-btn-submit-icon",
                raw_scanner_sha256=_sha256_hex("axe:button-name:button.submit-icon"),
                description="Icon button has no accessible name.",
            ),
            FindingEvidence(
                finding_id="f-pdf-3",
                source="pypdf",
                rule_id="PDF_MISSING_TITLE",
                severity="moderate",
                wcag_criterion="WCAG 2.1 SC 2.4.2 Page Titled (PDF/UA-1 7.1)",
                aoda_section="AODA IASR s.14(4)",
                target_url=f"{target}/brochure.pdf",
                target_selector="document:/Catalog",
                raw_snippet="/Info << /Title () >>",
                component_fingerprint="fp-pdf-missing-title",
                raw_scanner_sha256=_sha256_hex("pypdf:PDF_MISSING_TITLE:/Catalog"),
                description="PDF document metadata is missing a non-empty /Title entry.",
            ),
        ]


@dataclass(frozen=True)
class _FakeTextBlock:
    text: str


@dataclass(frozen=True)
class _FakeUsage:
    input_tokens: int
    output_tokens: int


@dataclass(frozen=True)
class _FakeMessageResponse:
    content: list[_FakeTextBlock]
    usage: _FakeUsage


class _FakeAnthropicMessages:
    """Stubbed Anthropic Messages API returning evidence-bound RemediationPatch JSON."""

    def create(
        self,
        *,
        model: str,
        max_tokens: int,
        messages: list[dict[str, str]],
        **_: Any,
    ) -> _FakeMessageResponse:
        del model, max_tokens
        prompt = messages[0]["content"]
        if "f-img-1" in prompt:
            payload: dict[str, Any] = {
                "finding_id": "f-img-1",
                "rule_id": "image-alt",
                "target_selector": "img.hero-banner",
                "patch_kind": "html_diff",
                "before_snippet": '<img class="hero-banner" src="/banner.png">',
                "after_snippet": '<img class="hero-banner" src="/banner.png" alt="ServiceCore compliance overview">',
                "wcag_criterion": "WCAG 2.1 SC 1.1.1 Non-text Content",
                "aoda_section": "AODA IASR s.14(4)",
                "component_fingerprint": "fp-img-hero-banner",
            }
        elif "f-btn-2" in prompt:
            payload = {
                "finding_id": "f-btn-2",
                "rule_id": "button-name",
                "target_selector": "button.submit-icon",
                "patch_kind": "html_diff",
                "before_snippet": '<button class="submit-icon" type="button"></button>',
                "after_snippet": '<button class="submit-icon" type="button" aria-label="Submit"></button>',
                "wcag_criterion": "WCAG 2.1 SC 4.1.2 Name, Role, Value",
                "aoda_section": "AODA IASR s.14(4)",
                "component_fingerprint": "fp-btn-submit-icon",
            }
        else:
            payload = {
                "finding_id": "f-pdf-3",
                "rule_id": "PDF_MISSING_TITLE",
                "target_selector": "document:/Catalog",
                "patch_kind": "pdf_tag_action",
                "pdf_remediation_steps": [
                    "Set a descriptive Document Title in PDF /Info and /ViewerPreferences.",
                ],
                "wcag_criterion": "WCAG 2.1 SC 2.4.2 Page Titled (PDF/UA-1 7.1)",
                "aoda_section": "AODA IASR s.14(4)",
                "component_fingerprint": "fp-pdf-missing-title",
            }
        return _FakeMessageResponse(
            content=[_FakeTextBlock(text=json.dumps(payload))],
            usage=_FakeUsage(input_tokens=120, output_tokens=60),
        )


class _FakeAnthropicClient:
    def __init__(self) -> None:
        self.messages = _FakeAnthropicMessages()


def test_e2e_audit_review_and_certified_export() -> None:
    """Exercise POST /audits -> PATCH findings (APPROVED & EDITED) -> POST /export -> verify_bundle."""
    store = InMemoryAuditStore()
    synthesizer = ClaudeSynthesizer(client=_FakeAnthropicClient())
    app = create_app(
        auth_secret=_AUTH_SECRET,
        store=store,
        scanner=_FakeScannerBackend(),
        synthesizer=synthesizer,
    )
    client = TestClient(app)

    token = mint_auth_token(org_id="org_e2e", sub="reviewer_e2e", secret=_AUTH_SECRET)
    headers = {"Authorization": f"Bearer {token}"}

    create_resp = client.post(
        "/audits",
        json={"target_url": "https://example.org", "audit_price_usd": 1500.0},
        headers=headers,
    )
    assert create_resp.status_code == 201
    created = create_resp.json()
    audit_id: str = created["audit_id"]
    assert len(created["findings"]) == 3
    assert len(created["patches"]) == 3
    assert all(p["synthesized_by"] == "claude" for p in created["patches"])
    assert created["telemetry"]["llm_input_tokens"] == 360
    assert created["telemetry"]["llm_output_tokens"] == 180

    # Export must be blocked until every non-rejected finding is reviewed.
    blocked_export = client.post(f"/audits/{audit_id}/export", headers=headers)
    assert blocked_export.status_code == 409

    # Approve first finding (image-alt) and PDF finding (PDF_MISSING_TITLE).
    approve_img = client.patch(
        f"/audits/{audit_id}/findings/f-img-1",
        json={"status": "APPROVED"},
        headers=headers,
    )
    assert approve_img.status_code == 200

    approve_pdf = client.patch(
        f"/audits/{audit_id}/findings/f-pdf-3",
        json={"status": "APPROVED"},
        headers=headers,
    )
    assert approve_pdf.status_code == 200

    # Edit second finding (button-name) with a custom accessible label.
    edited_snippet = '<button class="submit-icon" type="button" aria-label="Submit audit form"></button>'
    edit_btn = client.patch(
        f"/audits/{audit_id}/findings/f-btn-2",
        json={"status": "EDITED", "edited_after_snippet": edited_snippet},
        headers=headers,
    )
    assert edit_btn.status_code == 200
    edited_payload = edit_btn.json()
    edited_patches = [p for p in edited_payload["patches"] if p["finding_id"] == "f-btn-2"]
    assert len(edited_patches) == 1
    assert edited_patches[0]["synthesized_by"] == "human_edit"
    assert edited_patches[0]["after_snippet"] == edited_snippet

    # Certified export succeeds and matches verify_bundle on the persisted AuditBundle.
    export_resp = client.post(f"/audits/{audit_id}/export", headers=headers)
    assert export_resp.status_code == 200
    export_data = export_resp.json()
    assert len(export_data["evidence_digest"]) == 64
    assert "ServiceCore" in export_data["html_report"]
    assert "Submit audit form" in export_data["html_report"]
    assert "image-alt" in export_data["github_issues_markdown"]
    assert "button-name" in export_data["github_issues_markdown"]
    assert "PDF_MISSING_TITLE" in export_data["github_issues_markdown"]

    get_resp = client.get(f"/audits/{audit_id}", headers=headers)
    assert get_resp.status_code == 200
    bundle = AuditBundle.model_validate(get_resp.json())
    ok, reason = verify_bundle(bundle)
    assert (ok, reason) == (True, "OK")
    assert bundle.evidence_digest == export_data["evidence_digest"]
