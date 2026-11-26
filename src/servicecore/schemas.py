from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

__all__ = [
    "AuditBundle",
    "AuditTelemetry",
    "CorruptPdfError",
    "DiffItem",
    "DiffReport",
    "DiffStatus",
    "EncryptedPdfError",
    "EvidenceMismatchError",
    "FindingEvidence",
    "FindingReview",
    "MonitorRunResult",
    "MonitorSchedule",
    "PatchKind",
    "RemediationPatch",
    "ReviewStatus",
    "SSRFBlockedError",
    "ScannerBlockedError",
    "ScannerError",
    "ScannerSource",
    "ScannerTimeoutError",
    "SeverityLevel",
    "UnsignedFindingError",
]

ScannerSource = Literal["axe-core", "pypdf"]
SeverityLevel = Literal["critical", "serious", "moderate", "minor"]
PatchKind = Literal["html_diff", "pdf_tag_action"]
ReviewStatus = Literal["PENDING", "APPROVED", "REJECTED", "EDITED"]
DiffStatus = Literal["NEW_REGRESSION", "FIXED", "PERSISTENT"]


class ScannerError(Exception):
    """Base error for deterministic scanner failures."""


class SSRFBlockedError(ScannerError):
    """Raised when a target URL or redirect resolves to a disallowed scheme or non-global IP."""


class ScannerBlockedError(ScannerError):
    """Raised when a target returns HTTP 403/429/503 or a bot-challenge page."""


class ScannerTimeoutError(ScannerError):
    """Raised when a browser or network scan exceeds its bounded timeout."""


class EncryptedPdfError(ScannerError):
    """Raised when a PDF remains encrypted after empty-password decryption attempt."""


class CorruptPdfError(ScannerError):
    """Raised when a PDF fails magic-byte validation or structure parsing."""


class EvidenceMismatchError(ValueError):
    """Raised when an AI-synthesized patch references an unverified rule or selector."""


class UnsignedFindingError(RuntimeError):
    """Raised when certified export is attempted while any non-rejected finding is unsigned."""


class FindingEvidence(BaseModel):
    """Deterministic, immutable finding captured by axe-core or pypdf."""

    finding_id: str = Field(min_length=1)
    source: ScannerSource
    rule_id: str = Field(min_length=1)
    severity: SeverityLevel = "serious"
    wcag_criterion: str = Field(min_length=1)
    aoda_section: str = Field(min_length=1)
    target_url: str = Field(min_length=1)
    target_selector: str = Field(min_length=1)
    raw_snippet: str
    component_fingerprint: str = Field(min_length=1)
    raw_scanner_sha256: str = Field(min_length=64, max_length=64)
    description: str = ""


class RemediationPatch(BaseModel):
    """Structured remediation bound to a verified FindingEvidence record."""

    finding_id: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    target_selector: str = Field(min_length=1)
    patch_kind: PatchKind
    before_snippet: str | None = None
    after_snippet: str | None = None
    pdf_remediation_steps: list[str] = Field(default_factory=list)
    wcag_criterion: str = Field(min_length=1)
    aoda_section: str = Field(min_length=1)
    component_fingerprint: str = Field(min_length=1)
    synthesized_by: Literal["claude", "deterministic_template", "human_edit"] = "claude"

    @model_validator(mode="after")
    def _validate_patch_payload(self) -> RemediationPatch:
        if self.patch_kind == "html_diff":
            if not self.before_snippet or not self.after_snippet:
                raise ValueError("html_diff patches require non-empty before_snippet and after_snippet")
        elif not self.pdf_remediation_steps:
            raise ValueError("pdf_tag_action patches require at least one remediation step")
        return self


class FindingReview(BaseModel):
    """Human sign-off state for a single deduplicated finding."""

    finding_id: str = Field(min_length=1)
    status: ReviewStatus = "PENDING"
    rejection_reason: str | None = None
    reviewer_id: str | None = None
    signed_at_utc: datetime | None = None

    @model_validator(mode="after")
    def _validate_signoff(self) -> FindingReview:
        if self.status in ("APPROVED", "EDITED") and (not self.reviewer_id or self.signed_at_utc is None):
            raise ValueError(f"{self.status} finding requires reviewer_id and signed_at_utc")
        if self.status == "REJECTED" and not self.rejection_reason:
            raise ValueError("REJECTED finding requires rejection_reason")
        return self


class AuditTelemetry(BaseModel):
    """Deterministic cost & gross-margin telemetry per audit run (EXP-04)."""

    scan_duration_ms: int = Field(ge=0)
    llm_input_tokens: int = Field(ge=0, default=0)
    llm_output_tokens: int = Field(ge=0, default=0)
    llm_cost_usd: float = Field(ge=0.0, default=0.0)
    audit_price_usd: float = Field(gt=0.0, default=1500.0)
    estimated_gross_margin_pct: float = 100.0


class AuditBundle(BaseModel):
    """Canonical signed audit artifact exported as JSON and certified PDF."""

    audit_id: str = Field(min_length=1)
    org_id: str = Field(min_length=1, default="local")
    target_url: str = Field(min_length=1)
    created_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    findings: list[FindingEvidence] = Field(default_factory=list)
    patches: list[RemediationPatch] = Field(default_factory=list)
    reviews: list[FindingReview] = Field(default_factory=list)
    reviewer_id: str | None = None
    signed_at_utc: datetime | None = None
    evidence_digest: str | None = None
    telemetry: AuditTelemetry | None = None


class DiffItem(BaseModel):
    """Single component-level regression/resolution item between two snapshots."""

    component_fingerprint: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    status: DiffStatus
    target_selector: str = Field(min_length=1)
    target_url: str = Field(min_length=1)


class DiffReport(BaseModel):
    """Baseline vs. current audit diff summary for $299/mo monitoring (EXP-03)."""

    baseline_audit_id: str = Field(min_length=1)
    current_audit_id: str = Field(min_length=1)
    new_regressions: list[DiffItem] = Field(default_factory=list)
    fixed: list[DiffItem] = Field(default_factory=list)
    persistent: list[DiffItem] = Field(default_factory=list)


class MonitorSchedule(BaseModel):
    """Recurring compliance monitoring schedule configuration and state."""

    monitor_id: str = Field(min_length=1)
    org_id: str = Field(min_length=1)
    target_url: str = Field(min_length=1)
    cadence_hours: int = Field(default=24, ge=1, le=720)
    crawl: bool = False
    max_pages: int = Field(default=5, ge=1, le=20)
    max_pdfs: int = Field(default=5, ge=0, le=20)
    baseline_audit_id: str | None = None
    last_run_at_utc: datetime | None = None
    enabled: bool = True


class MonitorRunResult(BaseModel):
    """Result of executing a scheduled monitor run, with optional baseline diff."""

    monitor: MonitorSchedule
    audit: AuditBundle
    diff: DiffReport | None = None
