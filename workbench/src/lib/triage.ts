import type { QueueCounts, QueueFilter } from "@/components/QueuePanel";
import type {
  AuditBundle,
  FindingEvidence,
  FindingReview,
  RemediationPatch,
} from "@/types/audit";

function assertNever(value: never): never {
  throw new Error(`Unhandled discriminated union member: ${String(value)}`);
}

/** Build initial FindingReview entries for every finding in a bundle, defaulting missing ones to PENDING. */
export function buildInitialReviews(bundle: AuditBundle): FindingReview[] {
  const byId = new Map(bundle.reviews.map((r) => [r.finding_id, r]));
  return bundle.findings.map(
    (f) =>
      byId.get(f.finding_id) ?? {
        finding_id: f.finding_id,
        status: "PENDING",
        rejection_reason: null,
        reviewer_id: null,
        signed_at_utc: null,
      },
  );
}

/** Compute queue status counts and signed total from a list of finding reviews. */
export function computeQueueCounts(reviews: FindingReview[]): QueueCounts {
  let pending = 0;
  let approved = 0;
  let rejected = 0;
  let edited = 0;
  for (const review of reviews) {
    switch (review.status) {
      case "PENDING":
        pending += 1;
        break;
      case "APPROVED":
        approved += 1;
        break;
      case "REJECTED":
        rejected += 1;
        break;
      case "EDITED":
        edited += 1;
        break;
      default:
        assertNever(review.status);
    }
  }
  const total = reviews.length;
  const signed = approved + rejected + edited;
  return { total, pending, approved, rejected, edited, signed };
}

/** Return true when a remediation patch exists and its rule_id matches the finding's rule_id. */
export function isEvidenceBound(
  finding: FindingEvidence,
  patch: RemediationPatch | undefined,
): boolean {
  return Boolean(patch && patch.rule_id === finding.rule_id);
}

/** Filter findings by review status pill and case-insensitive search query across key fields. */
export function filterFindings(
  findings: FindingEvidence[],
  reviewMap: Map<string, FindingReview>,
  filter: QueueFilter,
  searchQuery: string,
): FindingEvidence[] {
  const normalizedQuery = searchQuery.trim().toLowerCase();
  return findings.filter((f) => {
    if (filter !== "ALL" && reviewMap.get(f.finding_id)?.status !== filter) {
      return false;
    }
    if (!normalizedQuery) {
      return true;
    }
    return [
      f.rule_id,
      f.wcag_criterion,
      f.aoda_section,
      f.source,
      f.target_selector,
    ].some((field) => field.toLowerCase().includes(normalizedQuery));
  });
}
