"use client";

import React from "react";
import type {
  AuditEvent,
  DiffReport,
  FindingEvidence,
  FindingReview,
  PublishedIssue,
  RemediationPatch,
  WorkbenchViewState,
} from "@/types/audit";
import {
  assertNever,
  getSeverityMeta,
  getStatusMeta,
} from "@/components/QueuePanel";

export interface DecisionCanvasProps {
  viewState: WorkbenchViewState;
  errorMessage: string;
  onRetry?: () => void;
  targetUrl: string;
  isLoadingDiff: boolean;
  baselineAuditId: string;
  diffReport: DiffReport | null;
  onClearDiff: () => void;
  exportedDigest: string | null;
  copiedDigest: boolean;
  onCopyDigest: () => void;
  isLiveServerBundle: boolean;
  isDownloadingPdf: boolean;
  onDownloadPdf: () => void;
  isDownloadingSarif: boolean;
  onDownloadSarif: () => void;
  isDownloadingCsv: boolean;
  onDownloadCsv: () => void;
  onDownloadBundleJson: () => void;
  hasHtmlReport: boolean;
  onDownloadHtmlReport: () => void;
  hasGithubIssuesMarkdown: boolean;
  copiedIssues: boolean;
  onCopyGithubIssues: () => void;
  githubRepo: string;
  onGithubRepoChange: (value: string) => void;
  githubToken: string;
  onGithubTokenChange: (value: string) => void;
  isPublishingGitHub: boolean;
  onPublishToGitHub: (event: React.FormEvent<HTMLFormElement>) => void;
  publishError: string | null;
  publishedIssues: PublishedIssue[] | null;
  activeFinding: FindingEvidence | null;
  activeReview: FindingReview | null;
  activePatch: RemediationPatch | null;
  evidenceBindingStatus: "bound" | "mismatch" | "missing";
  onApprove: () => void;
  onEnterEdit: () => void;
  onStartReject: () => void;
  isRejecting: boolean;
  draftRejectionReason: string;
  onDraftRejectionReasonChange: (value: string) => void;
  onConfirmReject: () => void;
  onCancelReject: () => void;
  rejectionInputRef: React.RefObject<HTMLInputElement | null>;
  isEditing: boolean;
  draftAfterSnippet: string;
  onDraftAfterSnippetChange: (value: string) => void;
  draftPdfSteps: string;
  onDraftPdfStepsChange: (value: string) => void;
  onSaveEdit: () => void;
  onCancelEdit: () => void;
  editorRef: React.RefObject<HTMLTextAreaElement | null>;
  auditEvents: AuditEvent[];
}

function splitDiffLines(snippet: string | null): string[] {
  if (!snippet) {
    return [];
  }
  return snippet.split("\n");
}

/**
 * Decision Canvas displaying regression diff summary, certified export banner,
 * Tier 1 verdict/blast-radius card, Tier 2 FindingEvidence receipt, and
 * RemediationPatch diff with inline edit and rejection modes.
 */
export function DecisionCanvas({
  viewState,
  errorMessage,
  onRetry,
  targetUrl,
  isLoadingDiff,
  baselineAuditId,
  diffReport,
  onClearDiff,
  exportedDigest,
  copiedDigest,
  onCopyDigest,
  isLiveServerBundle,
  isDownloadingPdf,
  onDownloadPdf,
  isDownloadingSarif,
  onDownloadSarif,
  isDownloadingCsv,
  onDownloadCsv,
  onDownloadBundleJson,
  hasHtmlReport,
  onDownloadHtmlReport,
  hasGithubIssuesMarkdown,
  copiedIssues,
  onCopyGithubIssues,
  githubRepo,
  onGithubRepoChange,
  githubToken,
  onGithubTokenChange,
  isPublishingGitHub,
  onPublishToGitHub,
  publishError,
  publishedIssues,
  activeFinding,
  activeReview,
  activePatch,
  evidenceBindingStatus,
  onApprove,
  onEnterEdit,
  onStartReject,
  isRejecting,
  draftRejectionReason,
  onDraftRejectionReasonChange,
  onConfirmReject,
  onCancelReject,
  rejectionInputRef,
  isEditing,
  draftAfterSnippet,
  onDraftAfterSnippetChange,
  draftPdfSteps,
  onDraftPdfStepsChange,
  onSaveEdit,
  onCancelEdit,
  editorRef,
  auditEvents,
}: DecisionCanvasProps) {
  const renderCanvasBody = () => {
    switch (viewState) {
      case "loading":
        return (
          <div className="p-6 space-y-6">
            <div className="flex items-center justify-between border border-[var(--border-hairline)] bg-[var(--bg-surface)] rounded p-4">
              <div className="space-y-2 w-1/2">
                <div className="h-5 w-48 rounded skeleton-shimmer" />
                <div className="h-4 w-72 rounded skeleton-shimmer" />
              </div>
              <div className="text-xs font-mono text-[var(--ink-muted)]">
                Scan → Dedup → Synthesize
              </div>
            </div>
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
              <div className="border border-[var(--border-hairline)] bg-[var(--bg-surface)] rounded p-4 space-y-3">
                <div className="h-4 w-40 rounded skeleton-shimmer" />
                <div className="h-28 w-full rounded skeleton-shimmer" />
              </div>
              <div className="border border-[var(--border-hairline)] bg-[var(--bg-surface)] rounded p-4 space-y-3">
                <div className="h-4 w-44 rounded skeleton-shimmer" />
                <div className="h-28 w-full rounded skeleton-shimmer" />
              </div>
            </div>
          </div>
        );

      case "error":
        return (
          <div className="p-6">
            <div
              role="alert"
              className="border border-[var(--accent-critical)] bg-red-50 rounded p-5 space-y-3"
            >
              <div className="flex items-center justify-between gap-4">
                <h2 className="text-base font-semibold text-[var(--accent-critical)]">
                  Audit Engine Error
                </h2>
                <span className="font-mono text-xs text-[var(--accent-critical)]">
                  SCAN_FAILED
                </span>
              </div>
              <p className="text-sm text-[var(--ink-primary)]">{errorMessage}</p>
              {onRetry ? (
                <button
                  type="button"
                  onClick={onRetry}
                  className="min-h-[44px] lg:min-h-[32px] px-4 py-1.5 rounded bg-[var(--accent-critical)] text-white text-sm font-medium hover:opacity-90"
                >
                  Retry Scan
                </button>
              ) : null}
            </div>
          </div>
        );

      case "empty":
        return (
          <div className="p-6">
            <div className="border border-[var(--accent-verify)] bg-emerald-50 rounded p-6 space-y-2">
              <div className="inline-flex items-center gap-2 rounded border border-[var(--accent-verify)] bg-[var(--bg-surface)] px-2.5 py-0.5 text-xs font-mono font-semibold text-[var(--accent-verify)]">
                WCAG 2.2 AA / AODA CLEAN
              </div>
              <h2 className="text-lg font-semibold text-[var(--ink-primary)]">
                Zero accessibility violations detected
              </h2>
              <p className="text-sm text-[var(--ink-muted)]">
                Target <span className="font-mono">{targetUrl}</span>{" "}
                passed deterministic scanner checks with 0 pending findings.
              </p>
            </div>
          </div>
        );

      case "success":
      case "partial": {
        if (!activeFinding || !activeReview) {
          return (
            <div className="p-6">
              <div className="border border-[var(--border-hairline)] bg-[var(--bg-surface)] rounded p-6 text-sm text-[var(--ink-muted)]">
                Select a finding from the queue or clear the active filter to review items.
              </div>
            </div>
          );
        }

        const sevMeta = getSeverityMeta(activeFinding.severity);
        const statusMeta = getStatusMeta(activeReview.status);

        return (
          <div className="p-4 lg:p-6 space-y-5">
            {viewState === "success" ? (
              <div className="border border-[var(--accent-verify)] bg-emerald-50 rounded px-4 py-3 flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  <span className="rounded bg-[var(--accent-verify)] px-2 py-0.5 font-mono text-xs font-semibold text-white">
                    100% SIGNED
                  </span>
                  <span className="text-sm font-medium text-[var(--ink-primary)]">
                    All findings triaged. Certified PDF export is unlocked.
                  </span>
                </div>
                {exportedDigest ? (
                  <div className="flex flex-wrap items-center gap-2">
                    <code className="text-xs font-mono bg-[var(--bg-surface)] border border-[var(--border-hairline)] rounded px-2 py-1 text-[var(--ink-primary)] tabular-nums">
                      sha256:{exportedDigest.slice(0, 16)}…
                    </code>
                    <button
                      type="button"
                      onClick={onCopyDigest}
                      className="min-h-[44px] lg:min-h-[32px] px-2.5 rounded border border-[var(--border-hairline)] bg-[var(--bg-surface)] text-xs font-medium text-[var(--ink-primary)] hover:bg-[var(--bg-subtle)]"
                    >
                      {copiedDigest ? "Copied" : "Copy Digest"}
                    </button>
                    {isLiveServerBundle ? (
                      <>
                        <button
                          type="button"
                          onClick={onDownloadPdf}
                          disabled={isDownloadingPdf}
                          className="min-h-[44px] lg:min-h-[32px] px-2.5 rounded border border-[var(--accent-verify)] bg-[var(--accent-verify)] text-xs font-semibold text-white hover:opacity-90 disabled:opacity-50"
                        >
                          {isDownloadingPdf
                            ? "Downloading PDF..."
                            : "Download Certified PDF"}
                        </button>
                        <button
                          type="button"
                          onClick={onDownloadSarif}
                          disabled={isDownloadingSarif}
                          className="min-h-[44px] lg:min-h-[32px] px-2.5 rounded border border-[var(--accent-verify)] bg-[var(--bg-surface)] text-xs font-semibold text-[var(--accent-verify)] hover:bg-emerald-100 disabled:opacity-50"
                        >
                          {isDownloadingSarif
                            ? "Downloading SARIF..."
                            : "Download SARIF 2.1.0"}
                        </button>
                        <button
                          type="button"
                          onClick={onDownloadCsv}
                          disabled={isDownloadingCsv}
                          className="min-h-[44px] lg:min-h-[32px] px-2.5 rounded border border-[var(--accent-verify)] bg-[var(--bg-surface)] text-xs font-semibold text-[var(--accent-verify)] hover:bg-emerald-100 disabled:opacity-50"
                        >
                          {isDownloadingCsv ? "Downloading CSV..." : "Download CSV"}
                        </button>
                      </>
                    ) : null}
                    <button
                      type="button"
                      onClick={onDownloadBundleJson}
                      className="min-h-[44px] lg:min-h-[32px] px-2.5 rounded border border-[var(--accent-verify)] bg-[var(--bg-surface)] text-xs font-semibold text-[var(--accent-verify)] hover:bg-emerald-100"
                    >
                      Download Bundle JSON
                    </button>
                    {hasHtmlReport ? (
                      <button
                        type="button"
                        onClick={onDownloadHtmlReport}
                        className="min-h-[44px] lg:min-h-[32px] px-2.5 rounded border border-[var(--accent-verify)] bg-[var(--bg-surface)] text-xs font-semibold text-[var(--accent-verify)] hover:bg-emerald-100"
                      >
                        Download HTML Report
                      </button>
                    ) : null}
                    {hasGithubIssuesMarkdown ? (
                      <button
                        type="button"
                        onClick={onCopyGithubIssues}
                        className="min-h-[44px] lg:min-h-[32px] px-2.5 rounded border border-[var(--border-hairline)] bg-[var(--bg-surface)] text-xs font-medium text-[var(--ink-primary)] hover:bg-[var(--bg-subtle)]"
                      >
                        {copiedIssues ? "Copied Issues" : "Copy GitHub Issues"}
                      </button>
                    ) : null}
                  </div>
                ) : null}
                {isLiveServerBundle ? (
                  <div className="w-full pt-2 border-t border-emerald-200 flex flex-col gap-2">
                    <form
                      onSubmit={onPublishToGitHub}
                      className="flex flex-wrap items-center gap-2"
                      aria-label="Publish to GitHub form"
                    >
                      <label htmlFor="github-repo-input" className="sr-only">
                        GitHub repository (owner/repo)
                      </label>
                      <input
                        id="github-repo-input"
                        type="text"
                        required
                        value={githubRepo}
                        onChange={(e) => onGithubRepoChange(e.target.value)}
                        placeholder="owner/repo"
                        disabled={isPublishingGitHub}
                        className="min-h-[36px] lg:min-h-[32px] w-44 rounded border border-[var(--border-hairline)] bg-[var(--bg-surface)] px-2.5 py-1 font-mono text-xs text-[var(--ink-primary)] placeholder:text-[var(--ink-muted)]"
                      />
                      <label htmlFor="github-token-input" className="sr-only">
                        GitHub personal access token
                      </label>
                      <input
                        id="github-token-input"
                        type="password"
                        required
                        autoComplete="off"
                        value={githubToken}
                        onChange={(e) => onGithubTokenChange(e.target.value)}
                        placeholder="githubToken (ghp_...)"
                        disabled={isPublishingGitHub}
                        className="min-h-[36px] lg:min-h-[32px] w-48 rounded border border-[var(--border-hairline)] bg-[var(--bg-surface)] px-2.5 py-1 font-mono text-xs text-[var(--ink-primary)] placeholder:text-[var(--ink-muted)]"
                      />
                      <button
                        type="submit"
                        disabled={
                          isPublishingGitHub ||
                          !githubRepo.trim() ||
                          !githubToken.trim()
                        }
                        className="min-h-[36px] lg:min-h-[32px] px-3 py-1 rounded border border-[var(--accent-verify)] bg-[var(--bg-surface)] text-xs font-semibold text-[var(--accent-verify)] hover:bg-emerald-100 disabled:opacity-40"
                      >
                        {isPublishingGitHub ? "Publishing..." : "Publish to GitHub"}
                      </button>
                    </form>
                    {publishError ? (
                      <p className="text-xs font-mono text-[var(--accent-critical)]">
                        {publishError}
                      </p>
                    ) : null}
                    {publishedIssues ? (
                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        <span className="font-mono font-semibold text-[var(--accent-verify)]">
                          Created {publishedIssues.length} issue
                          {publishedIssues.length === 1 ? "" : "s"}:
                        </span>
                        {publishedIssues.map((issue) => (
                          <a
                            key={issue.finding_id}
                            href={issue.html_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-mono underline text-[var(--ink-primary)] hover:text-[var(--accent-verify)]"
                          >
                            #{issue.issue_number} {issue.title}
                          </a>
                        ))}
                      </div>
                    ) : null}
                  </div>
                ) : null}
              </div>
            ) : null}

            {/* Tier 1: Verdict / Blast-Radius Sticky Header */}
            <section
              aria-label="Finding verdict and blast radius"
              className="border border-[var(--border-hairline)] bg-[var(--bg-surface)] rounded p-4 space-y-3"
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`rounded border px-2 py-0.5 font-mono text-xs font-semibold ${sevMeta.className}`}
                    >
                      {sevMeta.label}
                    </span>
                    <span
                      className={`rounded border px-2 py-0.5 font-mono text-xs font-semibold ${statusMeta.className}`}
                    >
                      {statusMeta.label}
                    </span>
                    <span className="font-mono text-xs text-[var(--ink-muted)]">
                      {activeFinding.wcag_criterion} · {activeFinding.aoda_section}
                    </span>
                    {activeFinding.affected_pages ? (
                      <span className="font-mono text-xs text-[var(--ink-muted)] tabular-nums">
                        · {activeFinding.affected_pages} pages
                      </span>
                    ) : null}
                  </div>
                  <h2 className="text-xl lg:text-2xl font-semibold text-[var(--ink-primary)]">
                    {activeFinding.rule_id}
                  </h2>
                  <p className="text-sm text-[var(--ink-muted)]">
                    {activeFinding.description}
                  </p>
                </div>

                {/* Desktop triage controls */}
                <div className="hidden lg:flex items-center gap-2">
                  <button
                    type="button"
                    aria-keyshortcuts="a"
                    onClick={onApprove}
                    disabled={evidenceBindingStatus === "mismatch"}
                    className="min-h-[36px] px-3 py-1.5 rounded bg-[var(--accent-verify)] text-white text-xs font-semibold hover:opacity-90 disabled:opacity-40"
                  >
                    Approve <kbd className="ml-1 font-mono opacity-80">[a]</kbd>
                  </button>
                  <button
                    type="button"
                    aria-keyshortcuts="e"
                    onClick={onEnterEdit}
                    disabled={!activePatch}
                    className="min-h-[36px] px-3 py-1.5 rounded border border-[var(--border-hairline)] bg-[var(--bg-surface)] text-[var(--ink-primary)] text-xs font-semibold hover:bg-[var(--bg-subtle)] disabled:opacity-40"
                  >
                    Edit <kbd className="ml-1 font-mono text-[var(--ink-muted)]">[e]</kbd>
                  </button>
                  <button
                    type="button"
                    aria-keyshortcuts="r"
                    onClick={onStartReject}
                    className="min-h-[36px] px-3 py-1.5 rounded border border-[var(--accent-critical)] text-[var(--accent-critical)] bg-[var(--bg-surface)] text-xs font-semibold hover:bg-red-50"
                  >
                    Reject <kbd className="ml-1 font-mono opacity-80">[r]</kbd>
                  </button>
                </div>
              </div>
              {activeReview.status === "REJECTED" &&
              activeReview.rejection_reason &&
              !isRejecting ? (
                <p className="text-xs font-mono text-[var(--ink-muted)]">
                  Rejection reason: {activeReview.rejection_reason}
                </p>
              ) : null}
              {isRejecting ? (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    onConfirmReject();
                  }}
                  className="flex flex-wrap items-center gap-2 border-t border-[var(--border-hairline)] pt-3"
                  aria-label="Rejection reason form"
                >
                  <label
                    htmlFor="rejection-reason-input"
                    className="text-xs font-medium text-[var(--ink-primary)]"
                  >
                    Rejection reason (optional):
                  </label>
                  <input
                    id="rejection-reason-input"
                    ref={rejectionInputRef}
                    type="text"
                    value={draftRejectionReason}
                    onChange={(e) => onDraftRejectionReasonChange(e.target.value)}
                    placeholder="Marked out-of-scope / false positive"
                    className="min-h-[44px] lg:min-h-[32px] flex-1 min-w-[200px] rounded border border-[var(--border-hairline)] bg-[var(--bg-canvas)] px-2.5 py-1 text-xs text-[var(--ink-primary)] placeholder:text-[var(--ink-muted)]"
                  />
                  <button
                    type="submit"
                    className="min-h-[44px] lg:min-h-[32px] px-3 py-1 rounded border border-[var(--accent-critical)] bg-[var(--accent-critical)] text-white text-xs font-semibold hover:opacity-90"
                  >
                    Confirm Reject
                  </button>
                  <button
                    type="button"
                    onClick={onCancelReject}
                    className="min-h-[44px] lg:min-h-[32px] px-3 py-1 rounded border border-[var(--border-hairline)] bg-[var(--bg-surface)] text-xs font-medium text-[var(--ink-primary)] hover:bg-[var(--bg-subtle)]"
                  >
                    Cancel
                  </button>
                </form>
              ) : null}
            </section>

            {/* Tier 2: Side-by-side FindingEvidence receipt + RemediationPatch diff */}
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
              {/* Left: Finding Evidence Receipt */}
              <section
                aria-label="Finding evidence receipt"
                className="border border-[var(--border-hairline)] bg-[var(--bg-surface)] rounded flex flex-col"
              >
                <div className="flex items-center justify-between border-b border-[var(--border-hairline)] px-4 py-2.5 bg-[var(--bg-subtle)]">
                  <h3 className="text-xs font-semibold uppercase tracking-wide text-[var(--ink-primary)]">
                    Finding Evidence Receipt
                  </h3>
                  {evidenceBindingStatus === "bound" ? (
                    <span className="rounded border border-[var(--accent-verify)] bg-emerald-50 px-2 py-0.5 font-mono text-[11px] font-semibold text-[var(--accent-verify)]">
                      Evidence Bound
                    </span>
                  ) : evidenceBindingStatus === "mismatch" ? (
                    <span className="rounded border border-[var(--accent-critical)] bg-red-50 px-2 py-0.5 font-mono text-[11px] font-semibold text-[var(--accent-critical)]">
                      Blocked: rule_id mismatch
                    </span>
                  ) : (
                    <span className="rounded border border-[var(--accent-warn)] bg-amber-50 px-2 py-0.5 font-mono text-[11px] font-semibold text-[var(--accent-warn)]">
                      Manual Remediation
                    </span>
                  )}
                </div>

                <dl className="grid grid-cols-[120px_1fr] gap-y-2 gap-x-3 px-4 py-3 text-xs border-b border-[var(--border-hairline)]">
                  <dt className="text-[var(--ink-muted)] font-medium">Engine</dt>
                  <dd className="font-mono text-[var(--ink-primary)]">
                    {activeFinding.source}
                  </dd>
                  <dt className="text-[var(--ink-muted)] font-medium">Selector</dt>
                  <dd className="font-mono text-[var(--ink-primary)] break-all">
                    {activeFinding.target_selector}
                  </dd>
                  <dt className="text-[var(--ink-muted)] font-medium">Target URL</dt>
                  <dd className="font-mono text-[var(--ink-primary)] break-all">
                    {activeFinding.target_url}
                  </dd>
                  <dt className="text-[var(--ink-muted)] font-medium">Fingerprint</dt>
                  <dd className="font-mono text-[var(--ink-primary)]">
                    {activeFinding.component_fingerprint}
                  </dd>
                  <dt className="text-[var(--ink-muted)] font-medium">Raw SHA-256</dt>
                  <dd className="font-mono text-[var(--ink-muted)] break-all tabular-nums">
                    {activeFinding.raw_scanner_sha256}
                  </dd>
                </dl>

                <div className="p-4 flex-1">
                  <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-[var(--ink-muted)]">
                    Captured Raw Snippet
                  </div>
                  <pre className="whitespace-pre-wrap break-all overflow-x-auto rounded border border-[var(--border-hairline)] bg-[var(--bg-canvas)] p-3 font-mono text-xs text-[var(--ink-primary)] leading-relaxed">
                    <code>{activeFinding.raw_snippet}</code>
                  </pre>
                </div>
              </section>

              {/* Right: Remediation Patch Diff */}
              <section
                aria-label="Remediation patch diff"
                className="border border-[var(--border-hairline)] bg-[var(--bg-surface)] rounded flex flex-col"
              >
                <div className="flex items-center justify-between border-b border-[var(--border-hairline)] px-4 py-2.5 bg-[var(--bg-subtle)]">
                  <h3 className="text-xs font-semibold uppercase tracking-wide text-[var(--ink-primary)]">
                    Remediation Patch Diff
                  </h3>
                  <span className="font-mono text-[11px] text-[var(--ink-muted)]">
                    {activePatch
                      ? `${activePatch.patch_kind} · ${activePatch.synthesized_by}`
                      : "no_patch"}
                  </span>
                </div>

                {!activePatch ? (
                  <div className="p-4 text-sm text-[var(--ink-muted)]">
                    No automated patch was synthesized for this finding. Review the raw{" "}
                    <span className="font-mono">FindingEvidence</span> receipt and reject
                    or supply manual guidance.
                  </div>
                ) : isEditing ? (
                  <div className="p-4 space-y-3 flex-1 flex flex-col" data-editor="true">
                    <label
                      htmlFor="patch-inline-editor"
                      className="text-xs font-semibold text-[var(--ink-primary)]"
                    >
                      {activePatch.patch_kind === "html_diff"
                        ? "Edit remediated HTML/ARIA snippet"
                        : "Edit PDF/UA remediation steps (one per line)"}
                    </label>
                    <textarea
                      id="patch-inline-editor"
                      ref={editorRef}
                      data-editor="true"
                      rows={7}
                      value={
                        activePatch.patch_kind === "html_diff"
                          ? draftAfterSnippet
                          : draftPdfSteps
                      }
                      onChange={(e) =>
                        activePatch.patch_kind === "html_diff"
                          ? onDraftAfterSnippetChange(e.target.value)
                          : onDraftPdfStepsChange(e.target.value)
                      }
                      className="w-full flex-1 rounded border border-[var(--border-hairline)] bg-[var(--bg-canvas)] p-3 font-mono text-xs text-[var(--ink-primary)]"
                    />
                    <div className="flex items-center justify-end gap-2">
                      <button
                        type="button"
                        onClick={onCancelEdit}
                        className="min-h-[44px] lg:min-h-[30px] px-3 py-1 rounded border border-[var(--border-hairline)] text-xs font-medium text-[var(--ink-primary)] hover:bg-[var(--bg-subtle)]"
                      >
                        Cancel (Esc)
                      </button>
                      <button
                        type="button"
                        onClick={onSaveEdit}
                        className="min-h-[44px] lg:min-h-[30px] px-3 py-1 rounded bg-[var(--accent-verify)] text-white text-xs font-semibold hover:opacity-90"
                      >
                        Save &amp; Sign (Cmd+Enter)
                      </button>
                    </div>
                  </div>
                ) : activePatch.patch_kind === "html_diff" ? (
                  <div className="p-4 flex-1 space-y-3">
                    <div
                      className="overflow-x-auto rounded border border-[var(--border-hairline)] bg-[var(--bg-canvas)] font-mono text-xs leading-relaxed"
                      role="region"
                      aria-label="Before and after code diff"
                    >
                      {splitDiffLines(activePatch.before_snippet).map((line, idx) => (
                        <div
                          key={`before-${idx}`}
                          className="flex gap-2 bg-red-50/80 px-3 py-1 text-[var(--accent-critical)] border-b border-[var(--border-hairline)]/60"
                        >
                          <span aria-hidden="true" className="select-none font-bold">
                            -
                          </span>
                          <span className="sr-only">Removed:</span>
                          <code className="whitespace-pre-wrap break-all">{line}</code>
                        </div>
                      ))}
                      {splitDiffLines(activePatch.after_snippet).map((line, idx) => (
                        <div
                          key={`after-${idx}`}
                          className="flex gap-2 bg-emerald-50/80 px-3 py-1 text-[var(--accent-verify)] border-b border-[var(--border-hairline)]/60 last:border-b-0"
                        >
                          <span aria-hidden="true" className="select-none font-bold">
                            +
                          </span>
                          <span className="sr-only">Added:</span>
                          <code className="whitespace-pre-wrap break-all">{line}</code>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="p-4 flex-1 space-y-2">
                    <div className="text-[11px] font-semibold uppercase tracking-wide text-[var(--ink-muted)]">
                      PDF/UA Structure-Tree Remediation Steps
                    </div>
                    <ol className="space-y-2 list-decimal list-inside text-sm text-[var(--ink-primary)]">
                      {activePatch.pdf_remediation_steps.map((step, idx) => (
                        <li
                          key={idx}
                          className="rounded border border-[var(--border-hairline)] bg-[var(--bg-canvas)] px-3 py-2 font-mono text-xs"
                        >
                          + {step}
                        </li>
                      ))}
                    </ol>
                  </div>
                )}
              </section>
            </div>
          </div>
        );
      }

      default:
        return assertNever(viewState);
    }
  };

  return (
    <>
      {isLoadingDiff || diffReport ? (
        <div className="px-4 lg:px-6 pt-4">
          <section
            aria-label="Regression diff summary"
            className="flex flex-wrap items-center justify-between gap-3 rounded border border-[var(--border-hairline)] bg-[var(--bg-surface)] px-4 py-2.5 text-xs"
          >
            {isLoadingDiff ? (
              <span className="font-mono text-[var(--ink-muted)]">
                Comparing against baseline {baselineAuditId}...
              </span>
            ) : diffReport ? (
              <>
                <div className="flex flex-wrap items-center gap-2 font-mono tabular-nums">
                  <span className="font-semibold text-[var(--ink-primary)]">
                    Diff vs {diffReport.baseline_audit_id}:
                  </span>
                  <span className="rounded border border-[var(--accent-critical)] bg-red-50 px-2 py-0.5 font-semibold text-[var(--accent-critical)]">
                    +{diffReport.new_regressions.length} new regressions
                  </span>
                  <span className="rounded border border-[var(--accent-verify)] bg-emerald-50 px-2 py-0.5 font-semibold text-[var(--accent-verify)]">
                    -{diffReport.fixed.length} fixed
                  </span>
                  <span className="rounded border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-2 py-0.5 font-semibold text-[var(--ink-primary)]">
                    {diffReport.persistent.length} persistent
                  </span>
                </div>
                <button
                  type="button"
                  onClick={onClearDiff}
                  className="min-h-[44px] lg:min-h-[28px] px-2.5 rounded border border-[var(--border-hairline)] bg-[var(--bg-surface)] font-mono text-[11px] font-semibold text-[var(--ink-primary)] hover:bg-[var(--bg-subtle)]"
                >
                  Clear diff
                </button>
              </>
            ) : null}
          </section>
        </div>
      ) : null}
      {renderCanvasBody()}
      {auditEvents.length > 0 ? (
        <div className="px-4 lg:px-6 pb-6">
          <details className="border border-[var(--border-hairline)] bg-[var(--bg-surface)] rounded">
            <summary className="cursor-pointer select-none px-4 py-2.5 text-xs font-semibold uppercase tracking-wide text-[var(--ink-primary)] bg-[var(--bg-subtle)] hover:opacity-90">
              Chain of Custody ({auditEvents.length})
            </summary>
            <ul className="divide-y divide-[var(--border-hairline)] text-xs">
              {auditEvents.map((event) => (
                <li
                  key={event.event_id}
                  className="px-4 py-2.5 flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1"
                >
                  <div className="flex flex-wrap items-baseline gap-2 min-w-0">
                    <span className="rounded border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 font-mono text-[11px] font-semibold text-[var(--ink-primary)]">
                      {event.action}
                    </span>
                    <span className="font-mono text-[11px] text-[var(--ink-muted)]">
                      {event.actor_sub}
                    </span>
                    <span className="text-[var(--ink-primary)] break-words">
                      {event.detail}
                    </span>
                  </div>
                  <time
                    dateTime={event.created_at_utc}
                    className="font-mono text-[11px] text-[var(--ink-muted)] tabular-nums shrink-0"
                  >
                    {event.created_at_utc}
                  </time>
                </li>
              ))}
            </ul>
          </details>
        </div>
      ) : null}
    </>
  );
}
