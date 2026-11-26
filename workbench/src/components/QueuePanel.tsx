"use client";

import React from "react";
import type {
  FindingEvidence,
  FindingReview,
  ReviewStatus,
  SeverityLevel,
  WorkbenchViewState,
} from "@/types/audit";

export type QueueFilter = "ALL" | ReviewStatus;

export interface QueueCounts {
  total: number;
  pending: number;
  approved: number;
  edited: number;
  rejected: number;
  signed: number;
}

export function assertNever(value: never): never {
  throw new Error(`Unhandled discriminated union member: ${String(value)}`);
}

export function getSeverityMeta(severity: SeverityLevel): {
  label: string;
  className: string;
} {
  switch (severity) {
    case "critical":
      return {
        label: "CRITICAL",
        className:
          "border-[var(--accent-critical)] text-[var(--accent-critical)] bg-red-50",
      };
    case "serious":
      return {
        label: "SERIOUS",
        className:
          "border-[var(--accent-warn)] text-[var(--accent-warn)] bg-amber-50",
      };
    case "moderate":
      return {
        label: "MODERATE",
        className:
          "border-[var(--border-hairline)] text-[var(--ink-primary)] bg-[var(--bg-subtle)]",
      };
    case "minor":
      return {
        label: "MINOR",
        className:
          "border-[var(--border-hairline)] text-[var(--ink-muted)] bg-[var(--bg-surface)]",
      };
    default:
      return assertNever(severity);
  }
}

export function getStatusMeta(status: ReviewStatus): {
  label: string;
  className: string;
} {
  switch (status) {
    case "PENDING":
      return {
        label: "PENDING",
        className:
          "border-[var(--accent-warn)] text-[var(--accent-warn)] bg-amber-50",
      };
    case "APPROVED":
      return {
        label: "APPROVED",
        className:
          "border-[var(--accent-verify)] text-[var(--accent-verify)] bg-emerald-50",
      };
    case "EDITED":
      return {
        label: "EDITED",
        className:
          "border-[var(--accent-verify)] text-[var(--accent-verify)] bg-emerald-50",
      };
    case "REJECTED":
      return {
        label: "REJECTED",
        className:
          "border-[var(--border-hairline)] text-[var(--ink-muted)] bg-[var(--bg-subtle)]",
      };
    default:
      return assertNever(status);
  }
}

export interface QueuePanelProps {
  counts: QueueCounts;
  progressPct: number;
  filter: QueueFilter;
  onFilterChange: (filter: QueueFilter) => void;
  viewState: WorkbenchViewState;
  filteredFindings: FindingEvidence[];
  reviewById: Map<string, FindingReview>;
  activeFindingId: string | null;
  onSelectFinding: (findingId: string) => void;
  onCloseDrawer: () => void;
  closeButtonRef?: React.RefObject<HTMLButtonElement | null>;
}

/**
 * Triage queue panel displaying signing progress, status filter pills, and
 * selectable findings for both the desktop sidebar and mobile drawer.
 */
export function QueuePanel({
  counts,
  progressPct,
  filter,
  onFilterChange,
  viewState,
  filteredFindings,
  reviewById,
  activeFindingId,
  onSelectFinding,
  onCloseDrawer,
  closeButtonRef,
}: QueuePanelProps) {
  return (
    <div className="flex h-full flex-col bg-[var(--bg-surface)] border-r border-[var(--border-hairline)]">
      <div className="flex items-center justify-between border-b border-[var(--border-hairline)] px-4 py-3">
        <div>
          <h2 className="text-base font-semibold tracking-tight text-[var(--ink-primary)]">
            Triage Queue
          </h2>
          <p className="text-xs text-[var(--ink-muted)] font-mono tabular-nums">
            {counts.signed}/{counts.total} signed · {counts.pending} pending
          </p>
        </div>
        <button
          ref={closeButtonRef}
          type="button"
          onClick={onCloseDrawer}
          className="lg:hidden min-h-[44px] min-w-[44px] inline-flex items-center justify-center rounded border border-[var(--border-hairline)] text-sm font-medium text-[var(--ink-primary)] hover:bg-[var(--bg-subtle)]"
          aria-label="Close queue drawer"
        >
          Close
        </button>
      </div>

      {/* Progress bar */}
      <div className="px-4 py-2 border-b border-[var(--border-hairline)]">
        <div
          role="progressbar"
          aria-label="Triage signing progress"
          aria-valuenow={counts.signed}
          aria-valuemin={0}
          aria-valuemax={counts.total}
          className="h-2 w-full overflow-hidden rounded-full bg-[var(--bg-subtle)]"
        >
          <div
            className="h-full transition-all duration-200"
            style={{
              width: `${progressPct}%`,
              backgroundColor:
                counts.pending === 0
                  ? "var(--accent-verify)"
                  : "var(--accent-warn)",
            }}
          />
        </div>
      </div>

      {/* Filter pills */}
      <div
        className="flex flex-wrap gap-1.5 border-b border-[var(--border-hairline)] px-4 py-2.5"
        role="group"
        aria-label="Filter findings by review status"
      >
        {(
          [
            { key: "ALL", label: "All", count: counts.total },
            { key: "PENDING", label: "Pending", count: counts.pending },
            { key: "APPROVED", label: "Approved", count: counts.approved },
            { key: "EDITED", label: "Edited", count: counts.edited },
            { key: "REJECTED", label: "Rejected", count: counts.rejected },
          ] as const
        ).map((pill) => {
          const active = filter === pill.key;
          return (
            <button
              key={pill.key}
              type="button"
              onClick={() => onFilterChange(pill.key)}
              className={`min-h-[44px] lg:min-h-[28px] px-2.5 py-1 rounded text-xs font-medium border transition-colors tabular-nums ${
                active
                  ? "bg-[var(--ink-primary)] text-[var(--bg-surface)] border-[var(--ink-primary)]"
                  : "bg-[var(--bg-surface)] text-[var(--ink-muted)] border-[var(--border-hairline)] hover:bg-[var(--bg-subtle)]"
              }`}
            >
              {pill.label} ({pill.count})
            </button>
          );
        })}
      </div>

      {/* Queue list */}
      <div className="flex-1 overflow-y-auto divide-y divide-[var(--border-hairline)]">
        {viewState === "loading" ? (
          <div className="p-4 space-y-3" aria-label="Loading findings queue">
            <div className="text-xs font-mono text-[var(--ink-muted)]">
              Stage 2/3 · Deduplicating &amp; synthesizing patches...
            </div>
            {[0, 1, 2, 3].map((idx) => (
              <div
                key={idx}
                className="p-3 rounded border border-[var(--border-hairline)] space-y-2"
              >
                <div className="h-4 w-2/3 rounded skeleton-shimmer" />
                <div className="h-3 w-1/2 rounded skeleton-shimmer" />
              </div>
            ))}
          </div>
        ) : filteredFindings.length === 0 ? (
          <div className="p-6 text-sm text-[var(--ink-muted)]">
            No findings match the current filter.
          </div>
        ) : (
          filteredFindings.map((finding) => {
            const rev = reviewById.get(finding.finding_id);
            const status = rev?.status ?? "PENDING";
            const statusMeta = getStatusMeta(status);
            const sevMeta = getSeverityMeta(finding.severity);
            const isSelected = activeFindingId === finding.finding_id;

            return (
              <button
                key={finding.finding_id}
                type="button"
                onClick={() => onSelectFinding(finding.finding_id)}
                aria-current={isSelected ? "true" : undefined}
                className={`w-full text-left px-4 py-3 transition-colors min-h-[44px] ${
                  isSelected
                    ? "bg-[var(--bg-subtle)] border-l-2 border-l-[var(--accent-verify)]"
                    : "bg-[var(--bg-surface)] hover:bg-[var(--bg-canvas)]"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-semibold text-[var(--ink-primary)] truncate">
                    {finding.rule_id}
                  </span>
                  <span
                    className={`shrink-0 rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold ${statusMeta.className}`}
                  >
                    {statusMeta.label}
                  </span>
                </div>
                <div className="mt-1 flex items-center justify-between gap-2 text-xs text-[var(--ink-muted)]">
                  <span className="truncate">{finding.wcag_criterion}</span>
                  <span
                    className={`shrink-0 rounded border px-1.5 py-0.5 font-mono text-[10px] font-medium ${sevMeta.className}`}
                  >
                    {sevMeta.label}
                  </span>
                </div>
                <div className="mt-1 flex items-center justify-between text-[11px] font-mono text-[var(--ink-muted)] tabular-nums">
                  <span className="truncate">{finding.source}</span>
                  {finding.affected_pages ? (
                    <span>{finding.affected_pages} pages</span>
                  ) : null}
                </div>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}
