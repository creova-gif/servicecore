from __future__ import annotations

import time
from dataclasses import dataclass

from evals.corpus import BenchmarkSiteFixture, build_smb_benchmark_corpus
from servicecore.exporter import sign_bundle, verify_bundle
from servicecore.scanners import PdfUaInspector, WebAxeScanner
from servicecore.schemas import AuditBundle, FindingEvidence, FindingReview
from servicecore.synthesizer import ClaudeSynthesizer, deduplicate_findings

__all__ = ["BenchmarkResult", "run_smb_benchmark"]


@dataclass(frozen=True)
class BenchmarkResult:
    """Aggregated precision, unverified-claim, and turnaround metrics."""

    sites_evaluated: int
    precision: float
    recall: float
    unverified_claims: int
    total_duration_ms: int


def run_smb_benchmark(
    fixtures: list[BenchmarkSiteFixture] | None = None,
) -> BenchmarkResult:
    """Run the deterministic 5-site SMB benchmark and verify 0 unverified claims."""
    corpus = fixtures if fixtures is not None else build_smb_benchmark_corpus()
    web_scanner = WebAxeScanner()
    pdf_inspector = PdfUaInspector()
    synth = ClaudeSynthesizer()

    true_positives = 0
    predicted_total = 0
    expected_total = 0
    unverified_claims = 0

    t0 = time.monotonic()
    for item in corpus:
        findings: list[FindingEvidence]
        if item.kind == "html":
            findings = web_scanner.scan_html(item.html, item.target_url, axe_results=item.axe_results)
        else:
            findings = pdf_inspector.scan_bytes(item.pdf_bytes, item.target_url)

        deduped = deduplicate_findings(findings)
        patches, _, _ = synth.synthesize(deduped)

        evidence_ids = {f.finding_id for f in deduped}
        for patch in patches:
            if patch.finding_id not in evidence_ids:
                unverified_claims += 1

        reviews = [
            FindingReview(
                finding_id=f.finding_id,
                status="APPROVED",
                reviewer_id="eval-reviewer",
                signed_at_utc=AuditBundle(audit_id="tmp", target_url=item.target_url).created_at_utc,
            )
            for f in deduped
        ]
        bundle = sign_bundle(
            AuditBundle(
                audit_id=f"eval-{item.name}",
                target_url=item.target_url,
                findings=deduped,
                patches=patches,
                reviews=reviews,
            ),
            reviewer_id="eval-reviewer",
        )
        ok, _ = verify_bundle(bundle)
        if not ok:
            unverified_claims += 1

        predicted_rules = {f.rule_id for f in deduped}
        true_positives += len(predicted_rules & item.expected_rule_ids)
        predicted_total += len(predicted_rules)
        expected_total += len(item.expected_rule_ids)

    total_ms = max(0, int((time.monotonic() - t0) * 1000))
    precision = true_positives / predicted_total if predicted_total else 1.0
    recall = true_positives / expected_total if expected_total else 1.0
    return BenchmarkResult(
        sites_evaluated=len(corpus),
        precision=precision,
        recall=recall,
        unverified_claims=unverified_claims,
        total_duration_ms=total_ms,
    )
