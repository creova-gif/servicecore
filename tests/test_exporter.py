from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

from servicecore.exporter import (
    compute_evidence_digest,
    diff_bundles,
    export_github_issues,
    export_pdf,
    render_report_html,
    sign_bundle,
    verify_bundle,
)
from servicecore.schemas import (
    AuditBundle,
    FindingEvidence,
    FindingReview,
    RemediationPatch,
    UnsignedFindingError,
)


def _make_finding(
    finding_id: str = "f-1",
    *,
    rule_id: str = "image-alt",
    component_fingerprint: str = "fp-1",
    raw_snippet: str = '<img src="/logo.png">',
) -> FindingEvidence:
    return FindingEvidence(
        finding_id=finding_id,
        source="axe-core",
        rule_id=rule_id,
        severity="serious",
        wcag_criterion="WCAG 2.1 SC 1.1.1 Non-text Content",
        aoda_section="AODA IASR s.14(4)",
        target_url="https://example.com",
        target_selector="img.logo",
        raw_snippet=raw_snippet,
        component_fingerprint=component_fingerprint,
        raw_scanner_sha256="b" * 64,
        description="Image missing alt attribute",
    )


def _make_patch(finding: FindingEvidence) -> RemediationPatch:
    return RemediationPatch(
        finding_id=finding.finding_id,
        rule_id=finding.rule_id,
        target_selector=finding.target_selector,
        patch_kind="html_diff",
        before_snippet=finding.raw_snippet,
        after_snippet='<img src="/logo.png" alt="ServiceCore logo">',
        wcag_criterion=finding.wcag_criterion,
        aoda_section=finding.aoda_section,
        component_fingerprint=finding.component_fingerprint,
        synthesized_by="claude",
    )


def _make_bundle(
    audit_id: str = "audit-001",
    *,
    status: str = "APPROVED",
    findings: list[FindingEvidence] | None = None,
) -> AuditBundle:
    f_list = findings if findings is not None else [_make_finding()]
    ts = datetime(2026, 11, 26, 12, 0, 0, tzinfo=UTC)
    reviews: list[FindingReview] = []
    for f in f_list:
        if status in ("APPROVED", "EDITED"):
            reviews.append(
                FindingReview(
                    finding_id=f.finding_id,
                    status=status,  # type: ignore[arg-type]
                    reviewer_id="rev-alice",
                    signed_at_utc=ts,
                )
            )
        elif status == "REJECTED":
            reviews.append(
                FindingReview(
                    finding_id=f.finding_id,
                    status="REJECTED",
                    rejection_reason="False positive",
                )
            )
        else:
            reviews.append(FindingReview(finding_id=f.finding_id, status="PENDING"))

    return AuditBundle(
        audit_id=audit_id,
        org_id="org-acme",
        target_url="https://example.com",
        created_at_utc=ts,
        findings=f_list,
        patches=[_make_patch(f) for f in f_list],
        reviews=reviews,
    )


def test_compute_evidence_digest_is_deterministic() -> None:
    findings = [_make_finding("f-1"), _make_finding("f-2", component_fingerprint="fp-2")]
    ts = datetime(2026, 11, 26, 12, 0, 0, tzinfo=UTC)

    d1 = compute_evidence_digest(findings, "rev-alice", ts)
    d2 = compute_evidence_digest(findings, "rev-alice", ts)
    assert d1 == d2
    assert len(d1) == 64


def test_sign_and_verify_bundle_valid_and_tamper_detection() -> None:
    bundle = _make_bundle(status="APPROVED")
    ts = datetime(2026, 11, 26, 12, 0, 0, tzinfo=UTC)
    signed = sign_bundle(bundle, "rev-alice", signed_at_utc=ts)

    ok, reason = verify_bundle(signed)
    assert (ok, reason) == (True, "OK")

    # 1-char tamper in raw_snippet must fail verification
    tampered_finding = signed.findings[0].model_copy(
        update={"raw_snippet": '<img src="/logo.png" >'}
    )
    tampered = signed.model_copy(update={"findings": [tampered_finding]})
    ok_tampered, reason_tampered = verify_bundle(tampered)
    assert ok_tampered is False
    assert "mismatch" in reason_tampered.lower()


def test_sign_bundle_raises_on_pending_finding() -> None:
    bundle = _make_bundle(status="PENDING")
    with pytest.raises(UnsignedFindingError):
        sign_bundle(bundle, "rev-alice")


def test_diff_bundles_detects_new_fixed_and_persistent() -> None:
    f_fixed = _make_finding("f-fixed", component_fingerprint="fp-fixed")
    f_persist = _make_finding("f-persist", component_fingerprint="fp-persist")
    f_new = _make_finding("f-new", component_fingerprint="fp-new")

    baseline = _make_bundle("audit-base", findings=[f_fixed, f_persist])
    current = _make_bundle("audit-curr", findings=[f_persist, f_new])

    report = diff_bundles(baseline, current)
    assert report.baseline_audit_id == "audit-base"
    assert report.current_audit_id == "audit-curr"
    assert [i.component_fingerprint for i in report.new_regressions] == ["fp-new"]
    assert [i.component_fingerprint for i in report.fixed] == ["fp-fixed"]
    assert [i.component_fingerprint for i in report.persistent] == ["fp-persist"]
    assert report.new_regressions[0].status == "NEW_REGRESSION"
    assert report.fixed[0].status == "FIXED"
    assert report.persistent[0].status == "PERSISTENT"


def test_export_github_issues_escapes_html_and_includes_citations() -> None:
    bundle = _make_bundle(status="APPROVED")
    md = export_github_issues(bundle)
    assert "- [ ] Remediate `img.logo` on `https://example.com`" in md
    assert "WCAG 2.1 SC 1.1.1 Non-text Content" in md
    assert "AODA IASR s.14(4)" in md
    assert "&lt;img src=&quot;/logo.png&quot;&gt;" in md
    assert "&lt;img src=&quot;/logo.png&quot; alt=&quot;ServiceCore logo&quot;&gt;" in md


def test_export_pdf_certified_blocked_when_unsigned_and_draft_succeeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    written: list[tuple[str, Path]] = []

    class _FakeHTML:
        def __init__(self, *, string: str) -> None:
            self._string = string

        def write_pdf(self, target: Path) -> None:
            written.append((self._string, target))
            target.write_bytes(b"%PDF-1.4\n%fake\n")

    fake_weasyprint = ModuleType("weasyprint")
    cast(Any, fake_weasyprint).HTML = _FakeHTML
    monkeypatch.setitem(sys.modules, "weasyprint", fake_weasyprint)

    unsigned = _make_bundle(status="PENDING")
    with pytest.raises(UnsignedFindingError):
        export_pdf(unsigned, tmp_path / "certified_fail.pdf", draft=False)

    draft_path = export_pdf(unsigned, tmp_path / "draft.pdf", draft=True)
    assert draft_path.exists()
    assert "DRAFT — NOT FOR COMPLIANCE USE" in written[-1][0]

    signed = sign_bundle(_make_bundle(status="APPROVED"), "rev-alice")
    cert_path = export_pdf(signed, tmp_path / "certified_ok.pdf", draft=False)
    assert cert_path.exists()
    assert signed.evidence_digest is not None
    assert signed.evidence_digest in written[-1][0]
    assert "DRAFT — NOT FOR COMPLIANCE USE" not in render_report_html(signed, draft=False)
