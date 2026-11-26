from __future__ import annotations

import csv
import hashlib
import html
import io
import json
from datetime import UTC, datetime
from pathlib import Path

from servicecore.schemas import (
    AuditBundle,
    DiffItem,
    DiffReport,
    FindingEvidence,
    FindingReview,
    RemediationPatch,
    UnsignedFindingError,
)

__all__ = [
    "canonical_evidence_json",
    "compute_evidence_digest",
    "diff_bundles",
    "export_csv",
    "export_github_issues",
    "export_pdf",
    "render_report_html",
    "sign_bundle",
    "verify_bundle",
]


def _normalize_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def canonical_evidence_json(
    findings: list[FindingEvidence],
    reviewer_id: str,
    signed_at_utc: datetime,
) -> str:
    """Serialize findings and sign-off metadata into deterministic canonical JSON."""
    payload = {
        "findings": [f.model_dump(mode="json") for f in findings],
        "reviewer_id": reviewer_id,
        "signed_at_utc": _normalize_utc(signed_at_utc).isoformat(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_evidence_digest(
    findings: list[FindingEvidence],
    reviewer_id: str,
    signed_at_utc: datetime,
) -> str:
    """Compute the SHA-256 hex digest over canonical evidence JSON."""
    canonical = canonical_evidence_json(findings, reviewer_id, signed_at_utc)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _check_all_non_rejected_signed(bundle: AuditBundle) -> tuple[bool, str]:
    reviews_by_id: dict[str, FindingReview] = {r.finding_id: r for r in bundle.reviews}
    for finding in bundle.findings:
        review = reviews_by_id.get(finding.finding_id)
        if review is None:
            return (False, f"Finding {finding.finding_id!r} has no review record")
        if review.status == "REJECTED":
            continue
        if review.status not in ("APPROVED", "EDITED"):
            return (
                False,
                f"Finding {finding.finding_id!r} has status {review.status!r}; expected APPROVED or EDITED",
            )
    return (True, "OK")


def sign_bundle(
    bundle: AuditBundle,
    reviewer_id: str,
    signed_at_utc: datetime | None = None,
) -> AuditBundle:
    """Sign an AuditBundle after verifying all non-rejected findings are APPROVED or EDITED."""
    if not reviewer_id.strip():
        raise UnsignedFindingError("reviewer_id must be non-empty")

    ok, reason = _check_all_non_rejected_signed(bundle)
    if not ok:
        raise UnsignedFindingError(reason)

    ts = _normalize_utc(signed_at_utc or datetime.now(UTC))
    digest = compute_evidence_digest(bundle.findings, reviewer_id, ts)
    return bundle.model_copy(
        update={
            "reviewer_id": reviewer_id,
            "signed_at_utc": ts,
            "evidence_digest": digest,
        }
    )


def verify_bundle(bundle: AuditBundle) -> tuple[bool, str]:
    """Verify bundle sign-off metadata, finding review states, and evidence SHA-256 digest."""
    if not bundle.reviewer_id or bundle.signed_at_utc is None or not bundle.evidence_digest:
        return (False, "Bundle is missing reviewer_id, signed_at_utc, or evidence_digest")

    ok, reason = _check_all_non_rejected_signed(bundle)
    if not ok:
        return (False, reason)

    expected_digest = compute_evidence_digest(
        bundle.findings,
        bundle.reviewer_id,
        bundle.signed_at_utc,
    )
    if expected_digest != bundle.evidence_digest:
        return (False, "Evidence digest mismatch: bundle contents were modified after signing")

    return (True, "OK")


def _active_findings_by_fingerprint(bundle: AuditBundle) -> dict[str, FindingEvidence]:
    rejected_ids = {r.finding_id for r in bundle.reviews if r.status == "REJECTED"}
    result: dict[str, FindingEvidence] = {}
    for finding in bundle.findings:
        if finding.finding_id in rejected_ids:
            continue
        if finding.component_fingerprint not in result:
            result[finding.component_fingerprint] = finding
    return result


def diff_bundles(baseline: AuditBundle, current: AuditBundle) -> DiffReport:
    """Compare non-rejected findings by component_fingerprint between baseline and current."""
    base_map = _active_findings_by_fingerprint(baseline)
    curr_map = _active_findings_by_fingerprint(current)

    base_fps = set(base_map.keys())
    curr_fps = set(curr_map.keys())

    new_regressions = [
        DiffItem(
            component_fingerprint=fp,
            rule_id=curr_map[fp].rule_id,
            status="NEW_REGRESSION",
            target_selector=curr_map[fp].target_selector,
            target_url=curr_map[fp].target_url,
        )
        for fp in sorted(curr_fps - base_fps)
    ]
    fixed = [
        DiffItem(
            component_fingerprint=fp,
            rule_id=base_map[fp].rule_id,
            status="FIXED",
            target_selector=base_map[fp].target_selector,
            target_url=base_map[fp].target_url,
        )
        for fp in sorted(base_fps - curr_fps)
    ]
    persistent = [
        DiffItem(
            component_fingerprint=fp,
            rule_id=curr_map[fp].rule_id,
            status="PERSISTENT",
            target_selector=curr_map[fp].target_selector,
            target_url=curr_map[fp].target_url,
        )
        for fp in sorted(base_fps & curr_fps)
    ]

    return DiffReport(
        baseline_audit_id=baseline.audit_id,
        current_audit_id=current.audit_id,
        new_regressions=new_regressions,
        fixed=fixed,
        persistent=persistent,
    )


def _safe_markdown_code(text: str) -> str:
    """HTML-escape snippet text and neutralize triple backticks for safe GitHub markdown."""
    return html.escape(text, quote=True).replace("```", "`\u200b``")


def export_github_issues(bundle: AuditBundle) -> str:
    """Render approved/edited findings and patches as developer-ready GitHub issue markdown."""
    reviews_by_id = {r.finding_id: r for r in bundle.reviews}
    patches_by_id: dict[str, RemediationPatch] = {p.finding_id: p for p in bundle.patches}

    blocks: list[str] = [
        f"# Accessibility Remediation Issues — `{bundle.audit_id}`",
        "",
        f"Target: `{bundle.target_url}`",
        "",
    ]

    exported_count = 0
    for finding in bundle.findings:
        review = reviews_by_id.get(finding.finding_id)
        if review is None or review.status not in ("APPROVED", "EDITED"):
            continue
        exported_count += 1
        patch = patches_by_id.get(finding.finding_id)

        blocks.extend(
            [
                f"## [{finding.severity.upper()}] {finding.rule_id} (`{finding.finding_id}`)",
                "",
                f"- [ ] Remediate `{finding.target_selector}` on `{finding.target_url}`",
                f"- **WCAG:** {html.escape(finding.wcag_criterion, quote=True)}",
                f"- **AODA:** {html.escape(finding.aoda_section, quote=True)}",
                f"- **Review Status:** {review.status}",
                "",
            ]
        )

        if patch is not None and patch.patch_kind == "html_diff":
            before = _safe_markdown_code(patch.before_snippet or "")
            after = _safe_markdown_code(patch.after_snippet or "")
            blocks.extend(
                [
                    "**Before:**",
                    "```html",
                    before,
                    "```",
                    "",
                    "**After:**",
                    "```html",
                    after,
                    "```",
                    "",
                ]
            )
        elif patch is not None and patch.patch_kind == "pdf_tag_action":
            blocks.append("**PDF Remediation Steps:**")
            for step in patch.pdf_remediation_steps:
                blocks.append(f"- [ ] {html.escape(step, quote=True)}")
            blocks.append("")

    if exported_count == 0:
        blocks.append("_No approved or edited findings to export._")
        blocks.append("")

    return "\n".join(blocks)


def render_report_html(bundle: AuditBundle, *, draft: bool = False) -> str:
    """Render an editorial HTML compliance report (certificate, summary, and patchbook)."""
    if not draft:
        ok, reason = verify_bundle(bundle)
        if not ok:
            raise UnsignedFindingError(reason)

    rejected_ids = {r.finding_id for r in bundle.reviews if r.status == "REJECTED"}
    active_findings = [f for f in bundle.findings if f.finding_id not in rejected_ids]
    patches_by_id = {p.finding_id: p for p in bundle.patches}
    reviews_by_id = {r.finding_id: r for r in bundle.reviews}

    if draft:
        cert_banner = '<div class="watermark">DRAFT — NOT FOR COMPLIANCE USE</div>'
        digest_html = "<p><strong>Status:</strong> DRAFT (Unsigned)</p>"
    else:
        cert_banner = '<div class="certified">CERTIFIED ACCESSIBILITY CONFORMANCE REPORT</div>'
        digest_html = (
            f"<p><strong>Evidence Digest (SHA-256):</strong> "
            f"<code>{html.escape(bundle.evidence_digest or '', quote=True)}</code></p>"
            f"<p><strong>Reviewer:</strong> {html.escape(bundle.reviewer_id or '', quote=True)}</p>"
            f"<p><strong>Signed At (UTC):</strong> "
            f"{html.escape(bundle.signed_at_utc.isoformat() if bundle.signed_at_utc else '', quote=True)}</p>"
        )

    summary_rows = "\n".join(
        (
            "<tr>"
            f"<td>{html.escape(f.finding_id, quote=True)}</td>"
            f"<td>{html.escape(f.rule_id, quote=True)}</td>"
            f"<td>{html.escape(f.severity, quote=True)}</td>"
            f"<td>{html.escape(f.wcag_criterion, quote=True)}</td>"
            f"<td>{html.escape(f.aoda_section, quote=True)}</td>"
            f"<td>{html.escape(reviews_by_id[f.finding_id].status if f.finding_id in reviews_by_id else 'PENDING', quote=True)}</td>"
            "</tr>"
        )
        for f in active_findings
    )

    patch_sections: list[str] = []
    for f in active_findings:
        patch = patches_by_id.get(f.finding_id)
        if patch is None:
            patch_body = "<p><em>No patch synthesized.</em></p>"
        elif patch.patch_kind == "html_diff":
            patch_body = (
                "<h4>Before</h4>"
                f"<pre><code>{html.escape(patch.before_snippet or '', quote=True)}</code></pre>"
                "<h4>After</h4>"
                f"<pre><code>{html.escape(patch.after_snippet or '', quote=True)}</code></pre>"
            )
        else:
            steps_li = "".join(f"<li>{html.escape(s, quote=True)}</li>" for s in patch.pdf_remediation_steps)
            patch_body = f"<h4>PDF Remediation Steps</h4><ol>{steps_li}</ol>"

        patch_sections.append(
            "<article class=\"patch-entry\">"
            f"<h3>{html.escape(f.rule_id, quote=True)} — {html.escape(f.finding_id, quote=True)}</h3>"
            f"<p><strong>Selector:</strong> <code>{html.escape(f.target_selector, quote=True)}</code></p>"
            f"<p><strong>Citation:</strong> {html.escape(f.wcag_criterion, quote=True)} | "
            f"{html.escape(f.aoda_section, quote=True)}</p>"
            f"{patch_body}"
            "</article>"
        )

    patchbook_html = "\n".join(patch_sections) if patch_sections else "<p>No active findings.</p>"

    return (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "<meta charset=\"utf-8\">\n"
        f"<title>Audit Report — {html.escape(bundle.audit_id, quote=True)}</title>\n"
        "<style>"
        "@page { size: letter; margin: 0.75in; }"
        ".page-break { page-break-before: always; }"
        ".watermark { color: #b91c1c; font-weight: bold; font-size: 18pt; border: 2px solid #b91c1c; padding: 8px; }"
        ".certified { color: #065f46; font-weight: bold; font-size: 16pt; border: 2px solid #065f46; padding: 8px; }"
        "table { width: 100%; border-collapse: collapse; margin-top: 12px; }"
        "th, td { border: 1px solid #d1d5db; padding: 6px; text-align: left; font-size: 9pt; }"
        "pre { background: #f3f4f6; padding: 8px; overflow-wrap: anywhere; font-size: 8.5pt; }"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        "<section class=\"certificate\">\n"
        f"{cert_banner}\n"
        f"<h1>Accessibility Conformance Certificate</h1>\n"
        f"<p><strong>Audit ID:</strong> {html.escape(bundle.audit_id, quote=True)}</p>\n"
        f"<p><strong>Organization:</strong> {html.escape(bundle.org_id, quote=True)}</p>\n"
        f"<p><strong>Target:</strong> {html.escape(bundle.target_url, quote=True)}</p>\n"
        f"{digest_html}\n"
        "</section>\n"
        "<section class=\"page-break summary\">\n"
        "<h2>Component Summary</h2>\n"
        "<table>\n"
        "<thead><tr><th>Finding</th><th>Rule</th><th>Severity</th><th>WCAG</th><th>AODA</th><th>Review</th></tr></thead>\n"
        f"<tbody>{summary_rows}</tbody>\n"
        "</table>\n"
        "</section>\n"
        "<section class=\"page-break patchbook\">\n"
        "<h2>Remediation Patchbook</h2>\n"
        f"{patchbook_html}\n"
        "</section>\n"
        "</body>\n"
        "</html>\n"
    )


def export_pdf(
    bundle: AuditBundle,
    output_path: Path,
    *,
    draft: bool = False,
) -> Path:
    """Render the audit report HTML and write a PDF via WeasyPrint."""
    if not draft:
        ok, reason = verify_bundle(bundle)
        if not ok:
            raise UnsignedFindingError(reason)

    report_html = render_report_html(bundle, draft=draft)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Deferred import so non-PDF workflows and unsigned checks do not require native pango/gobject at import time.
    import weasyprint

    weasyprint.HTML(string=report_html).write_pdf(output_path)
    return output_path


_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_CSV_COLUMNS = (
    "finding_id",
    "rule_id",
    "severity",
    "wcag_criterion",
    "aoda_section",
    "review_status",
    "source",
    "target_url",
    "target_selector",
    "component_fingerprint",
    "raw_scanner_sha256",
    "evidence_digest",
)


def _sanitize_csv_cell(value: str) -> str:
    """Prefix formula-triggering cells with an apostrophe to prevent CSV formula injection."""
    if value.startswith(_CSV_FORMULA_PREFIXES) or value.lstrip().startswith(_CSV_FORMULA_PREFIXES):
        return f"'{value}"
    return value


def export_csv(bundle: AuditBundle) -> str:
    """Export verified, non-rejected audit findings as RFC 4180 CSV."""
    ok, reason = verify_bundle(bundle)
    if not ok:
        raise UnsignedFindingError(reason)

    reviews_by_id: dict[str, FindingReview] = {r.finding_id: r for r in bundle.reviews}
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow(_CSV_COLUMNS)

    digest = bundle.evidence_digest or ""
    for finding in bundle.findings:
        review = reviews_by_id.get(finding.finding_id)
        review_status = review.status if review is not None else "PENDING"
        if review_status == "REJECTED":
            continue
        row = (
            finding.finding_id,
            finding.rule_id,
            finding.severity,
            finding.wcag_criterion,
            finding.aoda_section,
            review_status,
            finding.source,
            finding.target_url,
            finding.target_selector,
            finding.component_fingerprint,
            finding.raw_scanner_sha256,
            digest,
        )
        writer.writerow([_sanitize_csv_cell(cell) for cell in row])

    return buf.getvalue()
