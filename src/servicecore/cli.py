from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from collections.abc import Sequence
from pathlib import Path

from servicecore.crawler import CrawlConfig, SiteCrawlScanner
from servicecore.exporter import (
    diff_bundles,
    export_github_issues,
    export_pdf,
    sign_bundle,
    verify_bundle,
)
from servicecore.sarif import export_sarif
from servicecore.scanners import PdfUaInspector, ScannerBackend, WebAxeScanner
from servicecore.schemas import (
    AuditBundle,
    AuditTelemetry,
    FindingEvidence,
    FindingReview,
    ScannerError,
    UnsignedFindingError,
)
from servicecore.synthesizer import ClaudeSynthesizer, deduplicate_findings

__all__ = ["build_parser", "main", "run_audit"]


def _select_scanner(
    target: str,
    *,
    crawl: bool = False,
    max_pages: int = 5,
    max_pdfs: int = 5,
) -> ScannerBackend:
    if target.lower().split("?", 1)[0].endswith(".pdf"):
        return PdfUaInspector()
    if crawl:
        return SiteCrawlScanner(config=CrawlConfig(max_pages=max_pages, max_pdfs=max_pdfs))
    return WebAxeScanner()


def _estimate_llm_cost(input_tokens: int, output_tokens: int) -> float:
    return round((input_tokens * 3.0 + output_tokens * 15.0) / 1_000_000.0, 6)


def run_audit(
    target: str,
    *,
    scanner: ScannerBackend | None = None,
    synthesizer: ClaudeSynthesizer | None = None,
    audit_price_usd: float = 1500.0,
    reviewer_id: str | None = None,
    crawl: bool = False,
    max_pages: int = 5,
    max_pdfs: int = 5,
) -> AuditBundle:
    """Execute end-to-end scan, deduplication, synthesis, and optional sign-off."""
    t0 = time.monotonic()
    active_scanner = scanner or _select_scanner(
        target,
        crawl=crawl,
        max_pages=max_pages,
        max_pdfs=max_pdfs,
    )
    raw_findings: list[FindingEvidence] = active_scanner.scan(target)
    deduped = deduplicate_findings(raw_findings)

    active_synth = synthesizer or ClaudeSynthesizer()
    patches, in_tok, out_tok = active_synth.synthesize(deduped)

    duration_ms = max(0, int((time.monotonic() - t0) * 1000))
    llm_cost = _estimate_llm_cost(in_tok, out_tok)
    margin_pct = round(((audit_price_usd - llm_cost) / audit_price_usd) * 100.0, 2)

    reviews = [FindingReview(finding_id=f.finding_id) for f in deduped]
    bundle = AuditBundle(
        audit_id=f"aud-{uuid.uuid4().hex[:12]}",
        target_url=target,
        findings=deduped,
        patches=patches,
        reviews=reviews,
        telemetry=AuditTelemetry(
            scan_duration_ms=duration_ms,
            llm_input_tokens=in_tok,
            llm_output_tokens=out_tok,
            llm_cost_usd=llm_cost,
            audit_price_usd=audit_price_usd,
            estimated_gross_margin_pct=margin_pct,
        ),
    )

    if reviewer_id:
        from datetime import UTC, datetime

        now = datetime.now(UTC)
        approved_reviews = [
            FindingReview(
                finding_id=f.finding_id,
                status="APPROVED",
                reviewer_id=reviewer_id,
                signed_at_utc=now,
            )
            for f in deduped
        ]
        bundle = sign_bundle(
            bundle.model_copy(update={"reviews": approved_reviews}),
            reviewer_id=reviewer_id,
            signed_at_utc=now,
        )
    return bundle


def build_parser() -> argparse.ArgumentParser:
    """Construct the ServiceCore CLI argument parser."""
    parser = argparse.ArgumentParser(prog="servicecore", description="ServiceCore compliance audit CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    audit_p = sub.add_parser("audit", help="Run accessibility/compliance audit on a URL or PDF")
    audit_p.add_argument("target", help="Target http(s) URL or local .pdf path")
    audit_p.add_argument("--out", type=Path, default=Path("bundle.json"), help="Output AuditBundle JSON path")
    audit_p.add_argument("--pdf", type=Path, default=None, help="Optional PDF report output path")
    audit_p.add_argument("--draft", action="store_true", help="Allow draft watermarked PDF without sign-off")
    audit_p.add_argument(
        "--format",
        choices=["json", "github-issues"],
        default="json",
        help="Stdout summary format",
    )
    audit_p.add_argument("--sign-reviewer", default=None, help="Auto-sign all findings as reviewer ID")
    audit_p.add_argument("--crawl", action="store_true", help="Crawl same-origin pages and linked PDFs")
    audit_p.add_argument("--max-pages", type=int, default=5, help="Maximum pages to crawl when --crawl is set")
    audit_p.add_argument("--max-pdfs", type=int, default=5, help="Maximum PDFs to inspect when --crawl is set")

    verify_p = sub.add_parser("verify", help="Verify canonical SHA-256 evidence_digest of an AuditBundle")
    verify_p.add_argument("bundle_path", type=Path, help="Path to AuditBundle JSON")

    diff_p = sub.add_parser("diff", help="Compare baseline and current AuditBundle snapshots")
    diff_p.add_argument("baseline_path", type=Path, help="Baseline AuditBundle JSON")
    diff_p.add_argument("current_path", type=Path, help="Current AuditBundle JSON")

    sarif_p = sub.add_parser("sarif", help="Export a signed AuditBundle to SARIF 2.1.0 JSON")
    sarif_p.add_argument("bundle_path", type=Path, help="Path to AuditBundle JSON")
    sarif_p.add_argument("--out", type=Path, default=None, help="Optional SARIF output path")
    return parser


def _load_bundle(path: Path) -> AuditBundle:
    return AuditBundle.model_validate_json(path.read_text(encoding="utf-8"))


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint returning POSIX exit codes."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "audit":
        try:
            bundle = run_audit(
                args.target,
                reviewer_id=args.sign_reviewer,
                crawl=args.crawl,
                max_pages=args.max_pages,
                max_pdfs=args.max_pdfs,
            )
        except ScannerError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        args.out.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")
        if args.pdf is not None:
            try:
                export_pdf(bundle, args.pdf, draft=args.draft)
            except UnsignedFindingError as exc:
                print(f"BLOCKED: {exc}", file=sys.stderr)
                return 1
        if args.format == "github-issues":
            print(export_github_issues(bundle))
        else:
            t = bundle.telemetry
            margin = f"{t.estimated_gross_margin_pct:.2f}%" if t else "n/a"
            print(
                json.dumps(
                    {
                        "audit_id": bundle.audit_id,
                        "findings": len(bundle.findings),
                        "signed": bundle.evidence_digest is not None,
                        "estimated_gross_margin": margin,
                    }
                )
            )
        return 0

    if args.command == "verify":
        try:
            bundle = _load_bundle(args.bundle_path)
        except (OSError, ValueError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        ok, reason = verify_bundle(bundle)
        if ok:
            print(f"VERIFIED {bundle.audit_id} sha256:{bundle.evidence_digest}")
            return 0
        print(f"ERROR: {reason}", file=sys.stderr)
        return 1

    if args.command == "diff":
        try:
            baseline = _load_bundle(args.baseline_path)
            current = _load_bundle(args.current_path)
        except (OSError, ValueError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        report = diff_bundles(baseline, current)
        print(report.model_dump_json(indent=2))
        return 0

    if args.command == "sarif":
        try:
            bundle = _load_bundle(args.bundle_path)
            sarif_doc = export_sarif(bundle)
            payload = json.dumps(sarif_doc, indent=2)
            if args.out is not None:
                args.out.write_text(payload, encoding="utf-8")
            else:
                print(payload)
        except (OSError, ValueError, UnsignedFindingError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
