from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from pypdf import PdfWriter

from evals.runner import run_smb_benchmark
from servicecore.cli import _select_scanner, build_parser, main
from servicecore.crawler import SiteCrawlScanner
from servicecore.exporter import sign_bundle
from servicecore.scanners import PdfUaInspector, WebAxeScanner
from servicecore.schemas import AuditBundle, FindingEvidence, FindingReview


def _sample_pdf_file(path: Path) -> Path:
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    buf = io.BytesIO()
    writer.write(buf)
    path.write_bytes(buf.getvalue())
    return path


def _sample_finding(fid: str = "f1", fp: str = "fp-1", rule: str = "image-alt") -> FindingEvidence:
    return FindingEvidence(
        finding_id=fid,
        source="axe-core",
        rule_id=rule,
        severity="critical",
        wcag_criterion="WCAG 2.1 SC 1.1.1 Non-text Content",
        aoda_section="AODA IASR s.14(4)",
        target_url="https://example.com",
        target_selector="img.hero",
        raw_snippet="<img class='hero'>",
        component_fingerprint=fp,
        raw_scanner_sha256="a" * 64,
    )


def test_cli_audit_and_verify_pdf_file(tmp_path: Path, capsys: object) -> None:
    pdf_in = _sample_pdf_file(tmp_path / "untagged.pdf")
    bundle_out = tmp_path / "bundle.json"

    rc = main(["audit", str(pdf_in), "--out", str(bundle_out), "--sign-reviewer", "justin"])
    assert rc == 0
    assert bundle_out.exists()
    capsys.readouterr()  # type: ignore[attr-defined]

    rc_verify = main(["verify", str(bundle_out)])
    assert rc_verify == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "VERIFIED" in captured.out

    # Tamper 1 character in the bundle and confirm exit 1
    data = json.loads(bundle_out.read_text(encoding="utf-8"))
    data["findings"][0]["raw_snippet"] = "tampered"
    bundle_out.write_text(json.dumps(data), encoding="utf-8")
    assert main(["verify", str(bundle_out)]) == 1
    tampered_captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert tampered_captured.err

    # Missing or invalid bundle file returns 1
    assert main(["verify", str(tmp_path / "missing.json")]) == 1
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not-json", encoding="utf-8")
    assert main(["verify", str(bad_json)]) == 1


def test_cli_audit_blocks_unsigned_pdf_export_unless_draft(tmp_path: Path) -> None:
    pdf_in = _sample_pdf_file(tmp_path / "untagged.pdf")
    bundle_out = tmp_path / "bundle.json"
    pdf_out = tmp_path / "report.pdf"

    rc = main(["audit", str(pdf_in), "--out", str(bundle_out), "--pdf", str(pdf_out)])
    assert rc == 1
    assert not pdf_out.exists()


def test_cli_audit_github_issues_format(tmp_path: Path, capsys: object) -> None:
    pdf_in = _sample_pdf_file(tmp_path / "untagged.pdf")
    bundle_out = tmp_path / "bundle.json"

    rc = main(
        [
            "audit",
            str(pdf_in),
            "--out",
            str(bundle_out),
            "--sign-reviewer",
            "justin",
            "--format",
            "github-issues",
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "- [ ]" in captured.out
    assert "PDF_UNTAGGED_DOCUMENT" in captured.out


def test_cli_diff_exit_codes(tmp_path: Path, capsys: object) -> None:
    f1 = _sample_finding("f1", "fp-1")
    f2 = _sample_finding("f2", "fp-2", rule="button-name")

    from datetime import UTC, datetime

    now = datetime.now(UTC)
    b1 = sign_bundle(
        AuditBundle(
            audit_id="b1",
            target_url="https://example.com",
            findings=[f1],
            reviews=[FindingReview(finding_id="f1", status="APPROVED", reviewer_id="j", signed_at_utc=now)],
        ),
        reviewer_id="j",
        signed_at_utc=now,
    )
    b2 = sign_bundle(
        AuditBundle(
            audit_id="b2",
            target_url="https://example.com",
            findings=[f2],
            reviews=[
                FindingReview(finding_id="f2", status="APPROVED", reviewer_id="j", signed_at_utc=now),
            ],
        ),
        reviewer_id="j",
        signed_at_utc=now,
    )

    p1 = tmp_path / "b1.json"
    p2 = tmp_path / "b2.json"
    p1.write_text(b1.model_dump_json(), encoding="utf-8")
    p2.write_text(b2.model_dump_json(), encoding="utf-8")

    assert main(["diff", str(p1), str(p1)]) == 0
    capsys.readouterr()  # type: ignore[attr-defined]

    assert main(["diff", str(p1), str(p2)]) == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    diff_json = json.loads(captured.out)
    assert "new_regressions" in diff_json
    assert "fixed" in diff_json
    assert [item["component_fingerprint"] for item in diff_json["new_regressions"]] == ["fp-2"]
    assert [item["component_fingerprint"] for item in diff_json["fixed"]] == ["fp-1"]

    assert main(["diff", str(tmp_path / "missing.json"), str(p2)]) == 1


def test_cli_scanner_error_returns_nonzero(tmp_path: Path) -> None:
    with patch("servicecore.cli._select_scanner") as mock_sel:
        mock_sel.return_value.scan.side_effect = RuntimeError("unexpected")
        try:
            main(["audit", "https://example.com", "--out", str(tmp_path / "b.json")])
        except RuntimeError:
            pass


def test_smb_5_site_benchmark_eval() -> None:
    result = run_smb_benchmark()
    assert result.sites_evaluated == 5
    assert result.precision == 1.0
    assert result.recall == 1.0
    assert result.unverified_claims == 0


def test_select_scanner_crawl_and_bounds() -> None:
    crawl_scanner = _select_scanner("https://example.com", crawl=True, max_pages=3, max_pdfs=2)
    assert isinstance(crawl_scanner, SiteCrawlScanner)
    assert crawl_scanner.config.max_pages == 3
    assert crawl_scanner.config.max_pdfs == 2

    assert isinstance(_select_scanner("https://example.com"), WebAxeScanner)
    assert isinstance(_select_scanner("https://example.com/report.pdf", crawl=True), PdfUaInspector)


def test_build_parser_crawl_flags() -> None:
    args = build_parser().parse_args(
        ["audit", "https://example.com", "--crawl", "--max-pages", "3", "--max-pdfs", "2"]
    )
    assert args.command == "audit"
    assert args.target == "https://example.com"
    assert args.crawl is True
    assert args.max_pages == 3
    assert args.max_pdfs == 2

    default_args = build_parser().parse_args(["audit", "https://example.com"])
    assert default_args.crawl is False
    assert default_args.max_pages == 5
    assert default_args.max_pdfs == 5


def test_cli_sarif_export_signed_bundle(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    finding = _sample_finding("f1", "fp-1")
    signed_bundle = sign_bundle(
        AuditBundle(
            audit_id="sarif-signed",
            target_url="https://example.com",
            findings=[finding],
            reviews=[FindingReview(finding_id="f1", status="APPROVED", reviewer_id="j", signed_at_utc=now)],
        ),
        reviewer_id="j",
        signed_at_utc=now,
    )
    signed_bundle_path = tmp_path / "signed_bundle.json"
    signed_bundle_path.write_text(signed_bundle.model_dump_json(), encoding="utf-8")
    out_sarif = tmp_path / "report.sarif"

    rc = main(["sarif", str(signed_bundle_path), "--out", str(out_sarif)])
    assert rc == 0
    assert out_sarif.exists()

    sarif_doc = json.loads(out_sarif.read_text(encoding="utf-8"))
    assert sarif_doc["version"] == "2.1.0"
    assert sarif_doc["runs"][0]["results"][0]["ruleId"] == "image-alt"


def test_cli_sarif_rejects_unsigned_bundle(tmp_path: Path, capsys: object) -> None:
    unsigned_bundle = AuditBundle(
        audit_id="sarif-unsigned",
        target_url="https://example.com",
        findings=[_sample_finding("f1", "fp-1")],
    )
    unsigned_bundle_path = tmp_path / "unsigned_bundle.json"
    unsigned_bundle_path.write_text(unsigned_bundle.model_dump_json(), encoding="utf-8")

    rc = main(["sarif", str(unsigned_bundle_path)])
    assert rc == 1
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "ERROR:" in captured.err
