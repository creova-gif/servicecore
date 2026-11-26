import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildInitialReviews,
  computeQueueCounts,
  filterFindings,
  isEvidenceBound,
} from "../src/lib/triage";
import type {
  AuditBundle,
  FindingEvidence,
  FindingReview,
  RemediationPatch,
} from "../src/types/audit";

function makeFinding(overrides: Partial<FindingEvidence> = {}): FindingEvidence {
  return {
    finding_id: "f_1",
    source: "axe-core",
    rule_id: "color-contrast",
    severity: "serious",
    wcag_criterion: "1.4.3",
    aoda_section: "IASR 14(4)",
    target_url: "https://example.com",
    target_selector: "button.primary",
    raw_snippet: "<button class='primary'>Submit</button>",
    component_fingerprint: "fp_1",
    raw_scanner_sha256: "sha_1",
    description: "Insufficient color contrast",
    ...overrides,
  };
}

function makePatch(overrides: Partial<RemediationPatch> = {}): RemediationPatch {
  return {
    finding_id: "f_1",
    rule_id: "color-contrast",
    target_selector: "button.primary",
    patch_kind: "html_diff",
    before_snippet: "<button class='primary'>Submit</button>",
    after_snippet: "<button class='primary bg-slate-900'>Submit</button>",
    pdf_remediation_steps: [],
    wcag_criterion: "1.4.3",
    aoda_section: "IASR 14(4)",
    component_fingerprint: "fp_1",
    synthesized_by: "claude",
    ...overrides,
  };
}

function makeReview(overrides: Partial<FindingReview> = {}): FindingReview {
  return {
    finding_id: "f_1",
    status: "PENDING",
    rejection_reason: null,
    reviewer_id: null,
    signed_at_utc: null,
    ...overrides,
  };
}

function makeBundle(overrides: Partial<AuditBundle> = {}): AuditBundle {
  return {
    audit_id: "aud_1",
    org_id: "org_1",
    target_url: "https://example.com",
    created_at_utc: "2026-11-26T00:00:00Z",
    findings: [],
    patches: [],
    reviews: [],
    reviewer_id: null,
    signed_at_utc: null,
    evidence_digest: null,
    telemetry: null,
    ...overrides,
  };
}

describe("buildInitialReviews", () => {
  it("returns empty array when bundle has no findings", () => {
    const bundle = makeBundle({
      reviews: [makeReview({ finding_id: "orphan", status: "APPROVED" })],
    });
    assert.deepEqual(buildInitialReviews(bundle), []);
  });

  it("defaults missing reviews to PENDING and preserves existing reviews by finding_id", () => {
    const existing = makeReview({
      finding_id: "f_2",
      status: "APPROVED",
      reviewer_id: "rev_1",
      signed_at_utc: "2026-11-26T12:00:00Z",
    });
    const bundle = makeBundle({
      findings: [
        makeFinding({ finding_id: "f_1" }),
        makeFinding({ finding_id: "f_2" }),
      ],
      reviews: [existing, makeReview({ finding_id: "orphan", status: "REJECTED" })],
    });

    const result = buildInitialReviews(bundle);
    assert.equal(result.length, 2);
    assert.deepEqual(result[0], {
      finding_id: "f_1",
      status: "PENDING",
      rejection_reason: null,
      reviewer_id: null,
      signed_at_utc: null,
    });
    assert.deepEqual(result[1], existing);
  });
});

describe("computeQueueCounts", () => {
  it("returns all zero counts for empty reviews", () => {
    assert.deepEqual(computeQueueCounts([]), {
      total: 0,
      pending: 0,
      approved: 0,
      edited: 0,
      rejected: 0,
      signed: 0,
    });
  });

  it("aggregates counts for every ReviewStatus and computes signed total", () => {
    const reviews: FindingReview[] = [
      makeReview({ finding_id: "f_1", status: "PENDING" }),
      makeReview({ finding_id: "f_2", status: "PENDING" }),
      makeReview({ finding_id: "f_3", status: "APPROVED" }),
      makeReview({ finding_id: "f_4", status: "EDITED" }),
      makeReview({ finding_id: "f_5", status: "REJECTED" }),
      makeReview({ finding_id: "f_6", status: "APPROVED" }),
    ];

    assert.deepEqual(computeQueueCounts(reviews), {
      total: 6,
      pending: 2,
      approved: 2,
      edited: 1,
      rejected: 1,
      signed: 4,
    });
  });
});

describe("isEvidenceBound", () => {
  it("returns true when patch exists and rule_id matches finding rule_id", () => {
    const finding = makeFinding({ rule_id: "image-alt" });
    const patch = makePatch({ rule_id: "image-alt" });
    assert.equal(isEvidenceBound(finding, patch), true);
  });

  it("returns false when patch rule_id does not match finding rule_id", () => {
    const finding = makeFinding({ rule_id: "image-alt" });
    const patch = makePatch({ rule_id: "color-contrast" });
    assert.equal(isEvidenceBound(finding, patch), false);
  });

  it("returns false when patch is undefined", () => {
    const finding = makeFinding({ rule_id: "image-alt" });
    assert.equal(isEvidenceBound(finding, undefined), false);
  });
});

describe("filterFindings", () => {
  const f1 = makeFinding({
    finding_id: "f_1",
    rule_id: "color-contrast",
    wcag_criterion: "1.4.3",
    aoda_section: "IASR 14(4)",
    source: "axe-core",
    target_selector: "button.primary",
  });
  const f2 = makeFinding({
    finding_id: "f_2",
    rule_id: "image-alt",
    wcag_criterion: "1.1.1",
    aoda_section: "IASR 14(2)",
    source: "axe-core",
    target_selector: "img.hero-banner",
  });
  const f3 = makeFinding({
    finding_id: "f_3",
    rule_id: "pdf-tagged-title",
    wcag_criterion: "2.4.2",
    aoda_section: "IASR 14(6)",
    source: "pypdf",
    target_selector: "/Catalog/StructTreeRoot",
  });
  const f4 = makeFinding({
    finding_id: "f_4",
    rule_id: "label",
    wcag_criterion: "3.3.2",
    aoda_section: "IASR 14(8)",
    source: "axe-core",
    target_selector: "input#email",
  });

  const findings = [f1, f2, f3, f4];
  const reviewMap = new Map<string, FindingReview>([
    ["f_1", makeReview({ finding_id: "f_1", status: "PENDING" })],
    ["f_2", makeReview({ finding_id: "f_2", status: "APPROVED" })],
    ["f_3", makeReview({ finding_id: "f_3", status: "EDITED" })],
    ["f_4", makeReview({ finding_id: "f_4", status: "REJECTED" })],
  ]);

  it("filters by every status pill", () => {
    assert.deepEqual(
      filterFindings(findings, reviewMap, "ALL", "").map((f) => f.finding_id),
      ["f_1", "f_2", "f_3", "f_4"],
    );
    assert.deepEqual(
      filterFindings(findings, reviewMap, "PENDING", "").map((f) => f.finding_id),
      ["f_1"],
    );
    assert.deepEqual(
      filterFindings(findings, reviewMap, "APPROVED", "").map((f) => f.finding_id),
      ["f_2"],
    );
    assert.deepEqual(
      filterFindings(findings, reviewMap, "EDITED", "").map((f) => f.finding_id),
      ["f_3"],
    );
    assert.deepEqual(
      filterFindings(findings, reviewMap, "REJECTED", "").map((f) => f.finding_id),
      ["f_4"],
    );
  });

  it("matches searchQuery across rule_id, wcag_criterion, aoda_section, source, and target_selector", () => {
    assert.deepEqual(
      filterFindings(findings, reviewMap, "ALL", "  IMAGE-ALT ").map((f) => f.finding_id),
      ["f_2"],
    );
    assert.deepEqual(
      filterFindings(findings, reviewMap, "ALL", "1.4.3").map((f) => f.finding_id),
      ["f_1"],
    );
    assert.deepEqual(
      filterFindings(findings, reviewMap, "ALL", "iasr 14(6)").map((f) => f.finding_id),
      ["f_3"],
    );
    assert.deepEqual(
      filterFindings(findings, reviewMap, "ALL", "pypdf").map((f) => f.finding_id),
      ["f_3"],
    );
    assert.deepEqual(
      filterFindings(findings, reviewMap, "ALL", "input#email").map((f) => f.finding_id),
      ["f_4"],
    );
  });

  it("combines status pill filter and searchQuery", () => {
    assert.deepEqual(
      filterFindings(findings, reviewMap, "PENDING", "axe-core").map((f) => f.finding_id),
      ["f_1"],
    );
    assert.deepEqual(
      filterFindings(findings, reviewMap, "APPROVED", "pypdf").map((f) => f.finding_id),
      [],
    );
  });
});
