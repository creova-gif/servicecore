export type ScannerSource = "axe-core" | "pypdf";

export type SeverityLevel = "critical" | "serious" | "moderate" | "minor";

export type PatchKind = "html_diff" | "pdf_tag_action";

export type ReviewStatus = "PENDING" | "APPROVED" | "REJECTED" | "EDITED";

export type WorkbenchViewState =
  | "loading"
  | "empty"
  | "error"
  | "success"
  | "partial";

export interface FindingEvidence {
  finding_id: string;
  source: ScannerSource;
  rule_id: string;
  severity: SeverityLevel;
  wcag_criterion: string;
  aoda_section: string;
  target_url: string;
  target_selector: string;
  raw_snippet: string;
  component_fingerprint: string;
  raw_scanner_sha256: string;
  description: string;
  affected_pages?: number;
}

export interface RemediationPatch {
  finding_id: string;
  rule_id: string;
  target_selector: string;
  patch_kind: PatchKind;
  before_snippet: string | null;
  after_snippet: string | null;
  pdf_remediation_steps: string[];
  wcag_criterion: string;
  aoda_section: string;
  component_fingerprint: string;
  synthesized_by: "claude" | "deterministic_template" | "human_edit";
}

export interface FindingReview {
  finding_id: string;
  status: ReviewStatus;
  rejection_reason: string | null;
  reviewer_id: string | null;
  signed_at_utc: string | null;
}

export interface AuditTelemetry {
  scan_duration_ms: number;
  llm_input_tokens: number;
  llm_output_tokens: number;
  llm_cost_usd: number;
  audit_price_usd: number;
  estimated_gross_margin_pct: number;
}

export interface AuditBundle {
  audit_id: string;
  org_id: string;
  target_url: string;
  created_at_utc: string;
  findings: FindingEvidence[];
  patches: RemediationPatch[];
  reviews: FindingReview[];
  reviewer_id: string | null;
  signed_at_utc: string | null;
  evidence_digest: string | null;
  telemetry: AuditTelemetry | null;
}

export type DiffStatus = "NEW_REGRESSION" | "FIXED" | "PERSISTENT";

export interface DiffItem {
  component_fingerprint: string;
  rule_id: string;
  status: DiffStatus;
  target_selector: string;
  target_url: string;
}

export interface DiffReport {
  baseline_audit_id: string;
  current_audit_id: string;
  new_regressions: DiffItem[];
  fixed: DiffItem[];
  persistent: DiffItem[];
}

export interface PublishedIssue {
  finding_id: string;
  issue_number: number;
  html_url: string;
  title: string;
}

export interface PublishGitHubResponse {
  audit_id: string;
  issues_created: number;
  issues: PublishedIssue[];
}

export interface MonitorSchedule {
  monitor_id: string;
  org_id: string;
  target_url: string;
  cadence_hours: number;
  crawl: boolean;
  max_pages: number;
  max_pdfs: number;
  baseline_audit_id: string | null;
  last_run_at_utc: string | null;
  enabled: boolean;
}

export interface MonitorRunResult {
  monitor: MonitorSchedule;
  audit: AuditBundle;
  diff: DiffReport | null;
}
