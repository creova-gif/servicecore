from __future__ import annotations

import argparse
import hashlib
import sys
from collections.abc import Sequence
from pathlib import Path

from servicecore.cli import run_audit
from servicecore.exporter import export_github_issues, render_report_html, verify_bundle
from servicecore.schemas import AuditBundle, FindingEvidence, RemediationPatch
from servicecore.synthesizer import ClaudeSynthesizer, lookup_wcag_aoda, validate_patch_binding

PARTNER_REVIEWER_ID = "partner-reviewer@servicecore.local"
DEFAULT_TARGET_URL = "https://partner-demo.servicecore.local"


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class _DemoPartnerScanner:
    """Deterministic offline fixture scanner emitting HTML and PDF/UA findings."""

    def scan(self, target: str) -> list[FindingEvidence]:
        base = target.rstrip("/")
        return [
            FindingEvidence(
                finding_id="f-demo-img-1",
                source="axe-core",
                rule_id="image-alt",
                severity="critical",
                wcag_criterion="WCAG 2.1 SC 1.1.1 Non-text Content",
                aoda_section="AODA IASR s.14(4)",
                target_url=base,
                target_selector="img.hero-banner",
                raw_snippet='<img class="hero-banner" src="/assets/hero.png">',
                component_fingerprint="fp-demo-hero-banner",
                raw_scanner_sha256=_sha256_hex("demo:axe:image-alt:img.hero-banner"),
                description="Hero banner image is missing an alt attribute.",
            ),
            FindingEvidence(
                finding_id="f-demo-btn-2",
                source="axe-core",
                rule_id="button-name",
                severity="serious",
                wcag_criterion="WCAG 2.1 SC 4.1.2 Name, Role, Value",
                aoda_section="AODA IASR s.14(4)",
                target_url=base,
                target_selector="button.nav-menu-toggle",
                raw_snippet='<button class="nav-menu-toggle" type="button"></button>',
                component_fingerprint="fp-demo-nav-menu-toggle",
                raw_scanner_sha256=_sha256_hex("demo:axe:button-name:button.nav-menu-toggle"),
                description="Navigation toggle button has no accessible name.",
            ),
            FindingEvidence(
                finding_id="f-demo-pdf-3",
                source="pypdf",
                rule_id="PDF_MISSING_TITLE",
                severity="moderate",
                wcag_criterion="WCAG 2.1 SC 2.4.2 Page Titled (PDF/UA-1 7.1)",
                aoda_section="AODA IASR s.14(4)",
                target_url=f"{base}/docs/annual-accessibility-plan.pdf",
                target_selector="document:/Catalog",
                raw_snippet="/Info << /Title () >>",
                component_fingerprint="fp-demo-pdf-missing-title",
                raw_scanner_sha256=_sha256_hex("demo:pypdf:PDF_MISSING_TITLE:/Catalog"),
                description="PDF document metadata is missing a non-empty /Title entry.",
            ),
        ]


class _DemoPartnerSynthesizer(ClaudeSynthesizer):
    """Offline deterministic patch synthesizer requiring no external API key."""

    def __init__(self) -> None:
        super().__init__(client=None)
        self._client = None

    def synthesize(self, findings: list[FindingEvidence]) -> tuple[list[RemediationPatch], int, int]:
        findings_by_id = {f.finding_id: f for f in findings}
        patches: list[RemediationPatch] = []

        for finding in findings:
            wcag, aoda = lookup_wcag_aoda(finding.rule_id)
            if finding.source == "axe-core":
                after_snippet = (
                    '<img class="hero-banner" src="/assets/hero.png" '
                    'alt="ServiceCore accessibility compliance overview">'
                    if finding.rule_id == "image-alt"
                    else '<button class="nav-menu-toggle" type="button" '
                    'aria-label="Toggle navigation menu"></button>'
                )
                patch = RemediationPatch(
                    finding_id=finding.finding_id,
                    rule_id=finding.rule_id,
                    target_selector=finding.target_selector,
                    patch_kind="html_diff",
                    before_snippet=finding.raw_snippet,
                    after_snippet=after_snippet,
                    wcag_criterion=wcag,
                    aoda_section=aoda,
                    component_fingerprint=finding.component_fingerprint,
                    synthesized_by="deterministic_template",
                )
            else:
                patch = RemediationPatch(
                    finding_id=finding.finding_id,
                    rule_id=finding.rule_id,
                    target_selector=finding.target_selector,
                    patch_kind="pdf_tag_action",
                    pdf_remediation_steps=[
                        "Set a descriptive Document Title in File > Properties > Description > Title.",
                        "Enable Show: Document Title under Initial View > Window Options.",
                    ],
                    wcag_criterion=wcag,
                    aoda_section=aoda,
                    component_fingerprint=finding.component_fingerprint,
                    synthesized_by="deterministic_template",
                )
            validate_patch_binding(patch, findings_by_id)
            patches.append(patch)

        return (patches, 0, 0)


def run_partner_demo(
    out_dir: Path,
    *,
    target: str = DEFAULT_TARGET_URL,
) -> AuditBundle:
    """Run an offline design-partner audit, verify its digest, and write demo artifacts."""
    bundle = run_audit(
        target,
        scanner=_DemoPartnerScanner(),
        synthesizer=_DemoPartnerSynthesizer(),
        reviewer_id=PARTNER_REVIEWER_ID,
    )

    ok, reason = verify_bundle(bundle)
    if not ok:
        raise RuntimeError(f"Certified bundle verification failed: {reason}")

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "audit_bundle.json").write_text(
        bundle.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    (out_dir / "certified_report.html").write_text(
        render_report_html(bundle, draft=False),
        encoding="utf-8",
    )
    (out_dir / "github_issues.md").write_text(
        export_github_issues(bundle),
        encoding="utf-8",
    )
    return bundle


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser for the offline design-partner demo."""
    parser = argparse.ArgumentParser(
        prog="demo_partner_audit",
        description="Run a deterministic, offline design-partner accessibility audit demo.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("./demo-output"),
        help="Directory where audit_bundle.json, certified_report.html, and github_issues.md are written.",
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET_URL,
        help="Target URL label recorded in the demo audit bundle.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for the offline design-partner audit demo."""
    args = build_parser().parse_args(argv)
    bundle = run_partner_demo(out_dir=args.out_dir, target=args.target)
    signed_count = sum(1 for r in bundle.reviews if r.status in ("APPROVED", "EDITED"))

    margin_pct = (
        bundle.telemetry.estimated_gross_margin_pct if bundle.telemetry is not None else 0.0
    )

    print(f"Audit ID:              {bundle.audit_id}")
    print(f"Verified Digest:       {bundle.evidence_digest}")
    print(f"Findings Signed:       {signed_count}/{len(bundle.findings)}")
    print(f"Estimated Gross Margin:{margin_pct: .2f}%")
    print(f"Artifacts Written To:  {args.out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
