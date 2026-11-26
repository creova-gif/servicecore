import { WorkbenchLayout } from "@/components/WorkbenchLayout";
import type { AuditBundle } from "@/types/audit";

const SAMPLE_AUDIT_BUNDLE: AuditBundle = {
  audit_id: "aud_2026_11_25_municipal_01",
  org_id: "org_toronto_civic",
  target_url: "https://portal.example.ca/services/permits",
  created_at_utc: "2026-11-25T19:00:00Z",
  reviewer_id: null,
  signed_at_utc: null,
  evidence_digest: null,
  telemetry: {
    scan_duration_ms: 1840,
    llm_input_tokens: 4120,
    llm_output_tokens: 980,
    llm_cost_usd: 0.027,
    audit_price_usd: 1500.0,
    estimated_gross_margin_pct: 99.8,
  },
  findings: [
    {
      finding_id: "fnd_001",
      source: "axe-core",
      rule_id: "color-contrast",
      severity: "serious",
      wcag_criterion: "WCAG 1.4.3 Contrast (Minimum)",
      aoda_section: "AODA IASR s. 14(4)",
      target_url: "https://portal.example.ca/services/permits",
      target_selector: "button.permit-submit-secondary",
      raw_snippet:
        '<button class="permit-submit-secondary" style="color:#94A3B8;background:#FFFFFF">Save Draft</button>',
      component_fingerprint: "cmp_btn_secondary_v2",
      raw_scanner_sha256:
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      description:
        "Foreground text #94A3B8 on #FFFFFF has contrast ratio 2.56:1, below the 4.5:1 WCAG 2.2 AA threshold.",
      affected_pages: 42,
    },
    {
      finding_id: "fnd_002",
      source: "axe-core",
      rule_id: "label",
      severity: "critical",
      wcag_criterion: "WCAG 1.3.1 Info and Relationships",
      aoda_section: "AODA IASR s. 14(4)",
      target_url: "https://portal.example.ca/services/permits/apply",
      target_selector: "input#applicant-postal-code",
      raw_snippet:
        '<input id="applicant-postal-code" type="text" placeholder="M5V 2T6" />',
      component_fingerprint: "cmp_postal_input_01",
      raw_scanner_sha256:
        "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
      description:
        "Form input relies solely on placeholder text and has no programmatic <label> or aria-label.",
      affected_pages: 7,
    },
    {
      finding_id: "fnd_003",
      source: "pypdf",
      rule_id: "pdf-ua-struct-tree-missing",
      severity: "critical",
      wcag_criterion: "WCAG 1.3.1 / PDF/UA 7.1",
      aoda_section: "AODA IASR s. 14(2)",
      target_url: "https://portal.example.ca/forms/permit-guide-2026.pdf",
      target_selector: "/Root/StructTreeRoot",
      raw_snippet:
        "PDF Catalog missing /StructTreeRoot and /Lang; 14 pages untagged.",
      component_fingerprint: "pdf_permit_guide_2026",
      raw_scanner_sha256:
        "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
      description:
        "Downloaded PDF lacks a PDF/UA structure tree (/StructTreeRoot) and document language (/Lang).",
      affected_pages: 14,
    },
  ],
  patches: [
    {
      finding_id: "fnd_001",
      rule_id: "color-contrast",
      target_selector: "button.permit-submit-secondary",
      patch_kind: "html_diff",
      before_snippet:
        '<button class="permit-submit-secondary" style="color:#94A3B8;background:#FFFFFF">Save Draft</button>',
      after_snippet:
        '<button class="permit-submit-secondary" style="color:#475569;background:#FFFFFF">Save Draft</button>',
      pdf_remediation_steps: [],
      wcag_criterion: "WCAG 1.4.3 Contrast (Minimum)",
      aoda_section: "AODA IASR s. 14(4)",
      component_fingerprint: "cmp_btn_secondary_v2",
      synthesized_by: "claude",
    },
    {
      finding_id: "fnd_002",
      rule_id: "label",
      target_selector: "input#applicant-postal-code",
      patch_kind: "html_diff",
      before_snippet:
        '<input id="applicant-postal-code" type="text" placeholder="M5V 2T6" />',
      after_snippet:
        '<label for="applicant-postal-code">Postal Code</label>\n<input id="applicant-postal-code" type="text" placeholder="M5V 2T6" />',
      pdf_remediation_steps: [],
      wcag_criterion: "WCAG 1.3.1 Info and Relationships",
      aoda_section: "AODA IASR s. 14(4)",
      component_fingerprint: "cmp_postal_input_01",
      synthesized_by: "claude",
    },
    {
      finding_id: "fnd_003",
      rule_id: "pdf-ua-struct-tree-missing",
      target_selector: "/Root/StructTreeRoot",
      patch_kind: "pdf_tag_action",
      before_snippet: null,
      after_snippet: null,
      pdf_remediation_steps: [
        "Set Document Catalog /Lang to 'en-CA' and embed /MarkInfo << /Marked true >>.",
        "Re-export source document with Tagged PDF enabled to populate /StructTreeRoot (H1-H3, P, Table).",
        "Verify reading order and /Alt text on all figures in Acrobat Preflight / PAC.",
      ],
      wcag_criterion: "WCAG 1.3.1 / PDF/UA 7.1",
      aoda_section: "AODA IASR s. 14(2)",
      component_fingerprint: "pdf_permit_guide_2026",
      synthesized_by: "deterministic_template",
    },
  ],
  reviews: [
    {
      finding_id: "fnd_001",
      status: "PENDING",
      rejection_reason: null,
      reviewer_id: null,
      signed_at_utc: null,
    },
    {
      finding_id: "fnd_002",
      status: "PENDING",
      rejection_reason: null,
      reviewer_id: null,
      signed_at_utc: null,
    },
    {
      finding_id: "fnd_003",
      status: "APPROVED",
      rejection_reason: null,
      reviewer_id: "reviewer@servicecore.local",
      signed_at_utc: "2026-11-25T19:15:00Z",
    },
  ],
};

export default function WorkbenchPage() {
  return <WorkbenchLayout initialBundle={SAMPLE_AUDIT_BUNDLE} />;
}
