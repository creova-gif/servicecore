from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

from servicecore.exporter import verify_bundle
from servicecore.schemas import AuditBundle


def _load_demo_module() -> ModuleType:
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "demo_partner_audit.py"
    spec = importlib.util.spec_from_file_location("demo_partner_audit", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_run_partner_demo_creates_verified_artifacts(tmp_path: Path) -> None:
    demo = _load_demo_module()
    bundle: AuditBundle = demo.run_partner_demo(out_dir=tmp_path)

    bundle_path = tmp_path / "audit_bundle.json"
    report_path = tmp_path / "certified_report.html"
    issues_path = tmp_path / "github_issues.md"

    assert bundle_path.is_file()
    assert report_path.is_file()
    assert issues_path.is_file()

    assert bundle.reviewer_id == demo.PARTNER_REVIEWER_ID
    assert bundle.evidence_digest is not None
    assert len(bundle.findings) == 3

    ok, reason = verify_bundle(bundle)
    assert (ok, reason) == (True, "OK")

    loaded = AuditBundle.model_validate(json.loads(bundle_path.read_text(encoding="utf-8")))
    assert verify_bundle(loaded) == (True, "OK")

    report_html = report_path.read_text(encoding="utf-8")
    assert "CERTIFIED ACCESSIBILITY CONFORMANCE REPORT" in report_html
    assert "Evidence Digest (SHA-256)" in report_html
    assert bundle.evidence_digest in report_html

    issues_md = issues_path.read_text(encoding="utf-8")
    assert bundle.audit_id in issues_md
    assert "image-alt" in issues_md
    assert "PDF_MISSING_TITLE" in issues_md


def test_demo_partner_cli_main_prints_summary(tmp_path: Path) -> None:
    demo = _load_demo_module()
    exit_code: int = demo.main(["--out-dir", str(tmp_path)])
    assert exit_code == 0
    assert (tmp_path / "audit_bundle.json").is_file()
    assert (tmp_path / "certified_report.html").is_file()
    assert (tmp_path / "github_issues.md").is_file()
