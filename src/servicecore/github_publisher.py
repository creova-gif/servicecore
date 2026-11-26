from __future__ import annotations

import html
import re

import httpx
from pydantic import BaseModel, Field

from servicecore.exporter import verify_bundle
from servicecore.schemas import (
    AuditBundle,
    FindingEvidence,
    RemediationPatch,
    UnsignedFindingError,
)

__all__ = [
    "PublishedIssue",
    "publish_bundle_to_github",
]

_REPO_PATTERN = re.compile(r"^[\w.-]+/[\w.-]+$")


class PublishedIssue(BaseModel):
    """Metadata for a GitHub issue created from a certified finding."""

    finding_id: str = Field(min_length=1)
    issue_number: int = Field(ge=1)
    html_url: str = Field(min_length=1)
    title: str = Field(min_length=1)


def _safe_markdown_code(text: str) -> str:
    """HTML-escape snippet text and neutralize triple backticks for safe GitHub markdown."""
    return html.escape(text, quote=True).replace("```", "`\u200b``")


def _format_issue_title(finding: FindingEvidence) -> str:
    return f"[{finding.severity.upper()}] {finding.rule_id}: {finding.target_selector}"


def _format_issue_body(
    bundle: AuditBundle,
    finding: FindingEvidence,
    patch: RemediationPatch | None,
) -> str:
    lines: list[str] = [
        f"## Accessibility Finding `{finding.finding_id}`",
        "",
        f"- **Audit ID:** `{bundle.audit_id}`",
        f"- **Target URL:** `{finding.target_url}`",
        f"- **Target Selector:** `{finding.target_selector}`",
        f"- **Rule ID:** `{finding.rule_id}` ({finding.source})",
        f"- **Severity:** `{finding.severity}`",
        f"- **WCAG Criterion:** {html.escape(finding.wcag_criterion, quote=True)}",
        f"- **AODA Section:** {html.escape(finding.aoda_section, quote=True)}",
        f"- **Component Fingerprint:** `{finding.component_fingerprint}`",
        "",
        "### Description",
        html.escape(finding.description, quote=True),
        "",
        "### Certification & Evidence Receipt",
        f"- **Bundle Evidence SHA-256:** `{bundle.evidence_digest}`",
        f"- **Raw Scanner SHA-256:** `{finding.raw_scanner_sha256}`",
        f"- **Reviewer:** `{bundle.reviewer_id}`",
        f"- **Signed At (UTC):** `{bundle.signed_at_utc.isoformat() if bundle.signed_at_utc else ''}`",
        "",
    ]

    if patch is not None and patch.patch_kind == "html_diff":
        before = _safe_markdown_code(patch.before_snippet or "")
        after = _safe_markdown_code(patch.after_snippet or "")
        lines.extend(
            [
                "### Remediation Patch (`html_diff`)",
                "",
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
        lines.append("### Remediation Patch (`pdf_tag_action`)")
        lines.append("")
        for step in patch.pdf_remediation_steps:
            lines.append(f"- [ ] {html.escape(step, quote=True)}")
        lines.append("")

    return "\n".join(lines)


def _post_issues(
    bundle: AuditBundle,
    *,
    repo: str,
    token: str,
    client: httpx.Client,
) -> list[PublishedIssue]:
    rejected_ids = {r.finding_id for r in bundle.reviews if r.status == "REJECTED"}
    patches_by_id = {p.finding_id: p for p in bundle.patches}
    endpoint = f"https://api.github.com/repos/{repo}/issues"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    published: list[PublishedIssue] = []
    for finding in bundle.findings:
        if finding.finding_id in rejected_ids:
            continue

        title = _format_issue_title(finding)
        body = _format_issue_body(bundle, finding, patches_by_id.get(finding.finding_id))
        payload = {
            "title": title,
            "body": body,
            "labels": ["accessibility", f"severity:{finding.severity}", finding.rule_id],
        }
        resp = client.post(endpoint, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        published.append(
            PublishedIssue(
                finding_id=finding.finding_id,
                issue_number=int(data["number"]),
                html_url=str(data["html_url"]),
                title=str(data.get("title", title)),
            )
        )

    return published


def publish_bundle_to_github(
    bundle: AuditBundle,
    *,
    repo: str,
    token: str,
    client: httpx.Client | None = None,
) -> list[PublishedIssue]:
    """Publish active findings from a verified AuditBundle as GitHub issues."""
    if not _REPO_PATTERN.match(repo):
        raise ValueError(f"Invalid GitHub repo {repo!r}; expected 'owner/repo'")
    if not token.strip():
        raise ValueError("GitHub token must be non-empty")

    ok, reason = verify_bundle(bundle)
    if not ok:
        raise UnsignedFindingError(reason)

    if client is not None:
        return _post_issues(bundle, repo=repo, token=token, client=client)

    with httpx.Client(timeout=15.0) as managed_client:
        return _post_issues(bundle, repo=repo, token=token, client=managed_client)
