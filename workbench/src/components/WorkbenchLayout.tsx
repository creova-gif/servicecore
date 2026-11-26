"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  bootstrapDevToken,
  createAudit,
  createMonitor,
  exportAudit,
  exportAuditPdf,
  exportAuditSarif,
  fetchAuditDiff,
  fetchAudits,
  fetchMonitors,
  patchFindingReview,
  publishAuditToGitHub,
  runDueMonitors,
  runMonitor,
} from "@/lib/api";
import type {
  AuditBundle,
  DiffReport,
  FindingEvidence,
  FindingReview,
  MonitorSchedule,
  PublishedIssue,
  RemediationPatch,
  WorkbenchViewState,
} from "@/types/audit";
import { HeaderBar } from "@/components/HeaderBar";
import { MonitorsPanel } from "@/components/MonitorsPanel";
import {
  assertNever,
  getSeverityMeta,
  getStatusMeta,
  QueuePanel,
  type QueueFilter,
} from "@/components/QueuePanel";

export interface WorkbenchLayoutProps {
  initialBundle: AuditBundle;
  initialState?: WorkbenchViewState;
  errorMessage?: string;
  onRetry?: () => void;
}

type ApiMode = "demo" | "live";

interface ExportArtifacts {
  htmlReport: string;
  githubIssuesMarkdown: string;
}

interface UndoSnapshot {
  findingId: string;
  previousReview: FindingReview;
  previousPatch: RemediationPatch | undefined;
  actionLabel: string;
}

function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) {
    return false;
  }
  const tagName = target.tagName;
  if (tagName === "INPUT" || tagName === "TEXTAREA" || tagName === "SELECT") {
    return true;
  }
  if (target.isContentEditable) {
    return true;
  }
  return Boolean(target.closest("[data-editor]"));
}

function splitDiffLines(snippet: string | null): string[] {
  if (!snippet) {
    return [];
  }
  return snippet.split("\n");
}

function computeMockDigest(bundle: AuditBundle, reviews: FindingReview[]): string {
  const payload = `${bundle.audit_id}:${reviews.map((r) => `${r.finding_id}=${r.status}`).join("|")}`;
  let hash = 2166136261;
  for (let i = 0; i < payload.length; i += 1) {
    hash ^= payload.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  const hex = (hash >>> 0).toString(16).padStart(8, "0");
  return `${hex.repeat(8)}`;
}

async function computeDemoSha256Digest(
  bundle: AuditBundle,
  reviews: FindingReview[],
): Promise<string> {
  const payload = `${bundle.audit_id}:${reviews.map((r) => `${r.finding_id}=${r.status}`).join("|")}`;
  if (typeof window !== "undefined" && window.crypto?.subtle) {
    const encoded = new TextEncoder().encode(payload);
    const digestBuffer = await window.crypto.subtle.digest("SHA-256", encoded);
    return Array.from(new Uint8Array(digestBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
  return computeMockDigest(bundle, reviews);
}

function triggerBlobDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

function buildInitialReviews(bundle: AuditBundle): FindingReview[] {
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

/**
 * Wave 2-3 Review Workbench split-pane triage interface.
 * Implements keyboard-first triage (j/k/a/r/e/u), responsive <1024px drawer,
 * side-by-side FindingEvidence + RemediationPatch diff, and Cost & Margin footer.
 */
export function WorkbenchLayout({
  initialBundle,
  initialState,
  errorMessage = "Scanner engine returned a non-retryable failure.",
  onRetry,
}: WorkbenchLayoutProps) {
  const [bundle, setBundle] = useState<AuditBundle>(initialBundle);
  const [serverAudits, setServerAudits] = useState<AuditBundle[]>([]);
  const [apiMode, setApiMode] = useState<ApiMode>("demo");
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [isServerBundle, setIsServerBundle] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);
  const [newAuditUrl, setNewAuditUrl] = useState("");
  const [crawlEnabled, setCrawlEnabled] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);
  const [isDownloadingSarif, setIsDownloadingSarif] = useState(false);
  const [baselineAuditId, setBaselineAuditId] = useState("");
  const [diffReport, setDiffReport] = useState<DiffReport | null>(null);
  const [isLoadingDiff, setIsLoadingDiff] = useState(false);
  const [githubRepo, setGithubRepo] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [isPublishingGitHub, setIsPublishingGitHub] = useState(false);
  const [publishedIssues, setPublishedIssues] = useState<PublishedIssue[] | null>(null);
  const [publishError, setPublishError] = useState<string | null>(null);
  const [monitors, setMonitors] = useState<MonitorSchedule[]>([]);
  const [monitorsOpen, setMonitorsOpen] = useState(false);
  const [monitorTargetUrl, setMonitorTargetUrl] = useState("");
  const [monitorCadenceHours, setMonitorCadenceHours] = useState(24);
  const [monitorCrawl, setMonitorCrawl] = useState(false);
  const [isCreatingMonitor, setIsCreatingMonitor] = useState(false);
  const [runningMonitorId, setRunningMonitorId] = useState<string | null>(null);
  const [dueWebhookUrl, setDueWebhookUrl] = useState("");
  const [isRunningDueMonitors, setIsRunningDueMonitors] = useState(false);

  const [reviews, setReviews] = useState<FindingReview[]>(() =>
    buildInitialReviews(initialBundle),
  );

  const [patches, setPatches] = useState<RemediationPatch[]>(initialBundle.patches);
  const [filter, setFilter] = useState<QueueFilter>("ALL");
  const [selectedId, setSelectedId] = useState<string | null>(
    initialBundle.findings[0]?.finding_id ?? null,
  );
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [isRejecting, setIsRejecting] = useState(false);
  const [draftRejectionReason, setDraftRejectionReason] = useState("");
  const [draftAfterSnippet, setDraftAfterSnippet] = useState("");
  const [draftPdfSteps, setDraftPdfSteps] = useState("");
  const [announcement, setAnnouncement] = useState("");
  const [undoSnapshot, setUndoSnapshot] = useState<UndoSnapshot | null>(null);
  const [exportState, setExportState] = useState<"idle" | "computing" | "exported">(
    initialBundle.evidence_digest ? "exported" : "idle",
  );
  const [exportedDigest, setExportedDigest] = useState<string | null>(
    initialBundle.evidence_digest,
  );
  const [exportArtifacts, setExportArtifacts] = useState<ExportArtifacts | null>(null);
  const [copiedDigest, setCopiedDigest] = useState(false);
  const [copiedIssues, setCopiedIssues] = useState(false);

  const editorRef = useRef<HTMLTextAreaElement | null>(null);
  const rejectionInputRef = useRef<HTMLInputElement | null>(null);
  const queueTriggerRef = useRef<HTMLButtonElement | null>(null);
  const drawerCloseRef = useRef<HTMLButtonElement | null>(null);
  const wasDrawerOpenRef = useRef(false);
  const undoTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (drawerOpen) {
      wasDrawerOpenRef.current = true;
      requestAnimationFrame(() => {
        drawerCloseRef.current?.focus();
      });
    } else if (wasDrawerOpenRef.current) {
      wasDrawerOpenRef.current = false;
      requestAnimationFrame(() => {
        queueTriggerRef.current?.focus();
      });
    }
  }, [drawerOpen]);

  const loadBundle = useCallback((nextBundle: AuditBundle, serverBacked: boolean) => {
    setBundle(nextBundle);
    setIsServerBundle(serverBacked);
    setReviews(buildInitialReviews(nextBundle));
    setPatches(nextBundle.patches);
    setFilter("ALL");
    setSelectedId(nextBundle.findings[0]?.finding_id ?? null);
    setIsEditing(false);
    setIsRejecting(false);
    setDraftRejectionReason("");
    setUndoSnapshot(null);
    setExportedDigest(nextBundle.evidence_digest);
    setExportState(nextBundle.evidence_digest ? "exported" : "idle");
    setExportArtifacts(null);
    setBaselineAuditId("");
    setDiffReport(null);
    setIsLoadingDiff(false);
    setGithubToken("");
    setPublishedIssues(null);
    setPublishError(null);
    setApiError(null);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    async function connectLiveApi() {
      try {
        const { token } = await bootstrapDevToken(controller.signal);
        const [audits, fetchedMonitors] = await Promise.all([
          fetchAudits(token, controller.signal),
          fetchMonitors(token, controller.signal),
        ]);
        if (!active) {
          return;
        }
        setAuthToken(token);
        setApiMode("live");
        setServerAudits(audits);
        setMonitors(fetchedMonitors);
        if (audits.length > 0) {
          loadBundle(audits[0], true);
        }
      } catch {
        // Backend unreachable or dev mode disabled; stay cleanly in demo mode with zero console errors.
      }
    }

    void connectLiveApi();

    return () => {
      active = false;
      controller.abort();
    };
  }, [loadBundle]);

  const reviewById = useMemo(
    () => new Map(reviews.map((r) => [r.finding_id, r])),
    [reviews],
  );

  const patchById = useMemo(
    () => new Map(patches.map((p) => [p.finding_id, p])),
    [patches],
  );

  const counts = useMemo(() => {
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
  }, [reviews]);

  const viewState: WorkbenchViewState = useMemo(() => {
    if (initialState) {
      return initialState;
    }
    if (bundle.findings.length === 0) {
      return "empty";
    }
    if (counts.pending === 0) {
      return "success";
    }
    return "partial";
  }, [initialState, bundle.findings.length, counts.pending]);

  const filteredFindings = useMemo(() => {
    if (filter === "ALL") {
      return bundle.findings;
    }
    return bundle.findings.filter(
      (f) => reviewById.get(f.finding_id)?.status === filter,
    );
  }, [filter, bundle.findings, reviewById]);

  const activeFinding: FindingEvidence | null = useMemo(() => {
    if (filteredFindings.length === 0) {
      return null;
    }
    return (
      filteredFindings.find((f) => f.finding_id === selectedId) ??
      filteredFindings[0] ??
      null
    );
  }, [filteredFindings, selectedId]);

  const activeReview: FindingReview | null = activeFinding
    ? (reviewById.get(activeFinding.finding_id) ?? null)
    : null;

  const activePatch: RemediationPatch | null = activeFinding
    ? (patchById.get(activeFinding.finding_id) ?? null)
    : null;

  const evidenceBinding = useMemo(() => {
    if (!activeFinding || !activePatch) {
      return { status: "missing" as const, reason: "No synthesized patch attached." };
    }
    if (
      activePatch.rule_id !== activeFinding.rule_id ||
      activePatch.target_selector !== activeFinding.target_selector
    ) {
      return {
        status: "mismatch" as const,
        reason: "Blocked: rule_id mismatch",
      };
    }
    return { status: "bound" as const, reason: "Evidence Bound" };
  }, [activeFinding, activePatch]);

  const scheduleUndoToast = useCallback((snapshot: UndoSnapshot) => {
    if (undoTimerRef.current) {
      clearTimeout(undoTimerRef.current);
    }
    setUndoSnapshot(snapshot);
    undoTimerRef.current = setTimeout(() => {
      setUndoSnapshot(null);
      undoTimerRef.current = null;
    }, 5000);
  }, []);

  useEffect(() => {
    return () => {
      if (undoTimerRef.current) {
        clearTimeout(undoTimerRef.current);
      }
    };
  }, []);

  const advanceToNextPending = useCallback(
    (updatedReviews: FindingReview[], currentId: string) => {
      const idx = bundle.findings.findIndex((f) => f.finding_id === currentId);
      const updatedMap = new Map(updatedReviews.map((r) => [r.finding_id, r]));
      for (let offset = 1; offset <= bundle.findings.length; offset += 1) {
        const candidate =
          bundle.findings[(idx + offset) % bundle.findings.length];
        if (candidate && updatedMap.get(candidate.finding_id)?.status === "PENDING") {
          setSelectedId(candidate.finding_id);
          return;
        }
      }
    },
    [bundle.findings],
  );

  const applyTriage = useCallback(
    (status: "APPROVED" | "REJECTED", customRejectionReason?: string) => {
      if (!activeFinding || !activeReview) {
        return;
      }
      if (status === "APPROVED" && evidenceBinding.status === "mismatch") {
        setAnnouncement("Cannot approve: Evidence binding mismatch.");
        return;
      }

      const findingId = activeFinding.finding_id;
      const previousReview = { ...activeReview };
      const previousSelectedId = selectedId;
      const trimmedReason = customRejectionReason?.trim();
      const rejectionReason =
        status === "REJECTED"
          ? trimmedReason || "Marked out-of-scope / false positive"
          : null;
      const nextReview: FindingReview = {
        finding_id: findingId,
        status,
        rejection_reason: rejectionReason,
        reviewer_id: "reviewer@servicecore.local",
        signed_at_utc: new Date().toISOString(),
      };

      const updated = reviews.map((r) =>
        r.finding_id === findingId ? nextReview : r,
      );
      setReviews(updated);
      setIsRejecting(false);
      setDraftRejectionReason("");
      setExportState("idle");
      setExportedDigest(null);
      setExportArtifacts(null);
      setApiError(null);
      scheduleUndoToast({
        findingId,
        previousReview,
        previousPatch: activePatch ? { ...activePatch } : undefined,
        actionLabel:
          status === "APPROVED"
            ? `Approved ${activeFinding.rule_id}`
            : `Rejected ${activeFinding.rule_id}`,
      });
      setAnnouncement(
        `${status === "APPROVED" ? "Approved" : "Rejected"} ${activeFinding.rule_id} (${activeFinding.wcag_criterion}).`,
      );
      advanceToNextPending(updated, findingId);

      if (apiMode === "live" && authToken && isServerBundle) {
        void patchFindingReview(authToken, bundle.audit_id, findingId, {
          status,
          rejection_reason: rejectionReason,
        })
          .then((serverBundle) => {
            const serverReview = serverBundle.reviews.find(
              (r) => r.finding_id === findingId,
            );
            if (serverReview) {
              setReviews((prev) =>
                prev.map((r) => (r.finding_id === findingId ? serverReview : r)),
              );
            }
          })
          .catch((err: unknown) => {
            setReviews((prev) =>
              prev.map((r) => (r.finding_id === findingId ? previousReview : r)),
            );
            setSelectedId(previousSelectedId);
            setUndoSnapshot((current) =>
              current?.findingId === findingId ? null : current,
            );
            const message =
              err instanceof Error
                ? err.message
                : "Failed to persist review decision.";
            setApiError(`Review update failed for ${activeFinding.rule_id}: ${message}`);
            setAnnouncement(`Error saving review for ${activeFinding.rule_id}: ${message}`);
          });
      }
    },
    [
      activeFinding,
      activeReview,
      activePatch,
      evidenceBinding.status,
      reviews,
      selectedId,
      apiMode,
      authToken,
      isServerBundle,
      bundle.audit_id,
      scheduleUndoToast,
      advanceToNextPending,
    ],
  );

  const handleStartReject = useCallback(() => {
    if (!activeFinding || !activeReview) {
      return;
    }
    setIsEditing(false);
    setDraftRejectionReason(
      activeReview.status === "REJECTED" && activeReview.rejection_reason
        ? activeReview.rejection_reason
        : "",
    );
    setIsRejecting(true);
    setAnnouncement(
      `Enter optional rejection reason for ${activeFinding.rule_id}, or confirm reject.`,
    );
    requestAnimationFrame(() => {
      rejectionInputRef.current?.focus();
    });
  }, [activeFinding, activeReview]);

  const handleEnterEdit = useCallback(() => {
    if (!activeFinding || !activePatch) {
      return;
    }
    setIsRejecting(false);
    setDraftRejectionReason("");
    if (activePatch.patch_kind === "html_diff") {
      setDraftAfterSnippet(activePatch.after_snippet ?? "");
    } else {
      setDraftPdfSteps(activePatch.pdf_remediation_steps.join("\n"));
    }
    setIsEditing(true);
    setAnnouncement(`Editing remediation for ${activeFinding.rule_id}. Press Escape to cancel.`);
    requestAnimationFrame(() => {
      editorRef.current?.focus();
    });
  }, [activeFinding, activePatch]);

  const handleSaveEdit = useCallback(() => {
    if (!activeFinding || !activeReview || !activePatch) {
      return;
    }

    const findingId = activeFinding.finding_id;
    const previousReview = { ...activeReview };
    const previousPatch = { ...activePatch };
    const previousSelectedId = selectedId;

    const updatedPatch: RemediationPatch =
      activePatch.patch_kind === "html_diff"
        ? {
            ...activePatch,
            after_snippet: draftAfterSnippet.trim() || activePatch.after_snippet,
            synthesized_by: "human_edit",
          }
        : {
            ...activePatch,
            pdf_remediation_steps: draftPdfSteps
              .split("\n")
              .map((line) => line.trim())
              .filter(Boolean),
            synthesized_by: "human_edit",
          };

    const nextReview: FindingReview = {
      finding_id: findingId,
      status: "EDITED",
      rejection_reason: null,
      reviewer_id: "reviewer@servicecore.local",
      signed_at_utc: new Date().toISOString(),
    };

    const updatedReviews = reviews.map((r) =>
      r.finding_id === findingId ? nextReview : r,
    );

    setPatches((prev) =>
      prev.map((p) => (p.finding_id === findingId ? updatedPatch : p)),
    );
    setReviews(updatedReviews);
    setIsEditing(false);
    setExportState("idle");
    setExportedDigest(null);
    setExportArtifacts(null);
    setApiError(null);
    scheduleUndoToast({
      findingId,
      previousReview,
      previousPatch,
      actionLabel: `Edited ${activeFinding.rule_id}`,
    });
    setAnnouncement(`Saved edit and signed ${activeFinding.rule_id}.`);
    advanceToNextPending(updatedReviews, findingId);

    if (apiMode === "live" && authToken && isServerBundle) {
      const editedAfterSnippet =
        activePatch.patch_kind === "html_diff" ? updatedPatch.after_snippet : null;
      void patchFindingReview(authToken, bundle.audit_id, findingId, {
        status: "EDITED",
        edited_after_snippet: editedAfterSnippet,
      })
        .then((serverBundle) => {
          const serverReview = serverBundle.reviews.find(
            (r) => r.finding_id === findingId,
          );
          const serverPatch = serverBundle.patches.find(
            (p) => p.finding_id === findingId,
          );
          if (serverReview) {
            setReviews((prev) =>
              prev.map((r) => (r.finding_id === findingId ? serverReview : r)),
            );
          }
          if (serverPatch) {
            setPatches((prev) =>
              prev.map((p) => (p.finding_id === findingId ? serverPatch : p)),
            );
          }
        })
        .catch((err: unknown) => {
          setReviews((prev) =>
            prev.map((r) => (r.finding_id === findingId ? previousReview : r)),
          );
          setPatches((prev) =>
            prev.map((p) => (p.finding_id === findingId ? previousPatch : p)),
          );
          setSelectedId(previousSelectedId);
          setUndoSnapshot((current) =>
            current?.findingId === findingId ? null : current,
          );
          const message =
            err instanceof Error
              ? err.message
              : "Failed to persist edited remediation.";
          setApiError(`Edit save failed for ${activeFinding.rule_id}: ${message}`);
          setAnnouncement(`Error saving edit for ${activeFinding.rule_id}: ${message}`);
        });
    }
  }, [
    activeFinding,
    activeReview,
    activePatch,
    draftAfterSnippet,
    draftPdfSteps,
    reviews,
    selectedId,
    apiMode,
    authToken,
    isServerBundle,
    bundle.audit_id,
    scheduleUndoToast,
    advanceToNextPending,
  ]);

  const handleUndo = useCallback(() => {
    if (!undoSnapshot) {
      return;
    }
    const { findingId, previousReview, previousPatch, actionLabel } = undoSnapshot;
    setReviews((prev) =>
      prev.map((r) => (r.finding_id === findingId ? previousReview : r)),
    );
    if (previousPatch) {
      setPatches((prev) =>
        prev.map((p) => (p.finding_id === findingId ? previousPatch : p)),
      );
    }
    setSelectedId(findingId);
    setAnnouncement(`Undid: ${actionLabel}.`);
    setUndoSnapshot(null);
    if (undoTimerRef.current) {
      clearTimeout(undoTimerRef.current);
      undoTimerRef.current = null;
    }

    if (
      apiMode === "live" &&
      authToken &&
      isServerBundle &&
      previousReview.status !== "PENDING"
    ) {
      void patchFindingReview(authToken, bundle.audit_id, findingId, {
        status: previousReview.status,
        rejection_reason: previousReview.rejection_reason,
        edited_after_snippet:
          previousPatch?.patch_kind === "html_diff"
            ? previousPatch.after_snippet
            : null,
      }).catch((err: unknown) => {
        const message =
          err instanceof Error ? err.message : "Failed to sync undo.";
        setApiError(`Undo sync failed: ${message}`);
      });
    }
  }, [undoSnapshot, apiMode, authToken, isServerBundle, bundle.audit_id]);

  const navigateRelative = useCallback(
    (delta: 1 | -1) => {
      if (filteredFindings.length === 0 || !activeFinding) {
        return;
      }
      const idx = filteredFindings.findIndex(
        (f) => f.finding_id === activeFinding.finding_id,
      );
      const nextIdx =
        (idx + delta + filteredFindings.length) % filteredFindings.length;
      const next = filteredFindings[nextIdx];
      if (next) {
        setSelectedId(next.finding_id);
        setIsEditing(false);
        setIsRejecting(false);
        setDraftRejectionReason("");
        setAnnouncement(
          `Selected finding ${nextIdx + 1} of ${filteredFindings.length}: ${next.rule_id}.`,
        );
      }
    },
    [filteredFindings, activeFinding],
  );

  const handleExport = useCallback(async () => {
    if (counts.pending > 0 || exportState === "computing") {
      return;
    }
    setExportState("computing");
    setApiError(null);
    setAnnouncement("Computing SHA-256 evidence digest and rendering certified PDF.");

    if (apiMode === "live" && authToken && isServerBundle) {
      try {
        const res = await exportAudit(authToken, bundle.audit_id);
        setExportedDigest(res.evidence_digest);
        setExportArtifacts({
          htmlReport: res.html_report,
          githubIssuesMarkdown: res.github_issues_markdown,
        });
        setExportState("exported");
        setAnnouncement("Certified export ready. SHA-256 evidence digest generated.");
      } catch (err: unknown) {
        setExportState("idle");
        const message =
          err instanceof Error ? err.message : "Failed to export certified audit.";
        setApiError(`Export failed: ${message}`);
        setAnnouncement(`Export failed: ${message}`);
      }
      return;
    }

    const digest = await computeDemoSha256Digest(bundle, reviews);
    setExportedDigest(digest);
    setExportArtifacts(null);
    setExportState("exported");
    setAnnouncement("Certified PDF ready. SHA-256 evidence digest generated.");
  }, [
    counts.pending,
    exportState,
    apiMode,
    authToken,
    isServerBundle,
    bundle,
    reviews,
  ]);

  const handleRunNewAudit = useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const targetUrl = newAuditUrl.trim();
      if (!targetUrl || !authToken || isScanning) {
        return;
      }
      setIsScanning(true);
      setApiError(null);
      setAnnouncement(`Running accessibility scan for ${targetUrl}.`);
      try {
        const created = await createAudit(targetUrl, authToken, {
          crawl: crawlEnabled,
        });
        setServerAudits((prev) => [
          created,
          ...prev.filter((item) => item.audit_id !== created.audit_id),
        ]);
        loadBundle(created, true);
        setNewAuditUrl("");
        setAnnouncement(
          `Loaded new audit ${created.audit_id} with ${created.findings.length} findings.`,
        );
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "Failed to run accessibility scan.";
        setApiError(`Scan failed: ${message}`);
        setAnnouncement(`Scan failed: ${message}`);
      } finally {
        setIsScanning(false);
      }
    },
    [newAuditUrl, crawlEnabled, authToken, isScanning, loadBundle],
  );

  const handleCreateMonitor = useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const targetUrl = monitorTargetUrl.trim();
      if (!targetUrl || !authToken || isCreatingMonitor) {
        return;
      }
      setIsCreatingMonitor(true);
      setApiError(null);
      try {
        const created = await createMonitor(targetUrl, authToken, {
          cadenceHours: monitorCadenceHours,
          crawl: monitorCrawl,
        });
        setMonitors((prev) => [
          created,
          ...prev.filter((item) => item.monitor_id !== created.monitor_id),
        ]);
        setMonitorTargetUrl("");
        setMonitorCadenceHours(24);
        setMonitorCrawl(false);
        setAnnouncement(`Created recurring monitor for ${created.target_url}.`);
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "Failed to create monitor.";
        setApiError(`Create monitor failed: ${message}`);
        setAnnouncement(`Create monitor failed: ${message}`);
      } finally {
        setIsCreatingMonitor(false);
      }
    },
    [
      monitorTargetUrl,
      monitorCadenceHours,
      monitorCrawl,
      authToken,
      isCreatingMonitor,
    ],
  );

  const handleRunMonitor = useCallback(
    async (monitor: MonitorSchedule) => {
      if (!authToken || runningMonitorId) {
        return;
      }
      setRunningMonitorId(monitor.monitor_id);
      setApiError(null);
      setAnnouncement(`Running monitor ${monitor.target_url}.`);
      try {
        const result = await runMonitor(monitor.monitor_id, authToken);
        setMonitors((prev) =>
          prev.map((item) =>
            item.monitor_id === result.monitor.monitor_id ? result.monitor : item,
          ),
        );
        setServerAudits((prev) => [
          result.audit,
          ...prev.filter((item) => item.audit_id !== result.audit.audit_id),
        ]);
        loadBundle(result.audit, true);
        if (result.diff) {
          setDiffReport(result.diff);
          setBaselineAuditId(result.diff.baseline_audit_id);
        }
        setAnnouncement(
          `Monitor run complete for ${result.monitor.target_url}: loaded ${result.audit.audit_id}.`,
        );
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "Failed to run monitor.";
        setApiError(`Monitor run failed: ${message}`);
        setAnnouncement(`Monitor run failed: ${message}`);
      } finally {
        setRunningMonitorId(null);
      }
    },
    [authToken, runningMonitorId, loadBundle],
  );

  const handleRunDueMonitors = useCallback(async () => {
    if (!authToken || isRunningDueMonitors || runningMonitorId) {
      return;
    }
    setIsRunningDueMonitors(true);
    setApiError(null);
    setAnnouncement("Running due monitors.");
    try {
      const webhookUrl = dueWebhookUrl.trim() || undefined;
      const results = await runDueMonitors(authToken, { webhookUrl });
      const [refreshedMonitors, refreshedAudits] = await Promise.all([
        fetchMonitors(authToken),
        fetchAudits(authToken),
      ]);
      setMonitors(refreshedMonitors);
      setServerAudits(refreshedAudits);
      if (results.length > 0) {
        const latest = results[results.length - 1];
        loadBundle(latest.audit, true);
        if (latest.diff) {
          setDiffReport(latest.diff);
          setBaselineAuditId(latest.diff.baseline_audit_id);
        }
      }
      setAnnouncement(
        results.length === 1
          ? "Ran 1 due monitor."
          : `Ran ${results.length} due monitors.`,
      );
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to run due monitors.";
      setApiError(`Run due monitors failed: ${message}`);
      setAnnouncement(`Run due monitors failed: ${message}`);
    } finally {
      setIsRunningDueMonitors(false);
    }
  }, [authToken, isRunningDueMonitors, runningMonitorId, dueWebhookUrl, loadBundle]);

  const handlePublishToGitHub = useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const repo = githubRepo.trim();
      const pat = githubToken.trim();
      // Clear ephemeral PAT from memory on submit; never persist to localStorage.
      setGithubToken("");
      if (
        apiMode !== "live" ||
        !authToken ||
        !isServerBundle ||
        isPublishingGitHub ||
        !repo ||
        !pat
      ) {
        return;
      }
      setIsPublishingGitHub(true);
      setPublishError(null);
      setAnnouncement(`Publishing certified findings to ${repo}.`);
      try {
        const result = await publishAuditToGitHub(
          bundle.audit_id,
          repo,
          pat,
          authToken,
        );
        setPublishedIssues(result.issues);
        setAnnouncement(
          `Published ${result.issues_created} GitHub issue${result.issues_created === 1 ? "" : "s"} to ${repo}.`,
        );
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "Failed to publish GitHub issues.";
        setPublishError(message);
        setAnnouncement(`GitHub publish failed: ${message}`);
      } finally {
        setIsPublishingGitHub(false);
      }
    },
    [
      githubRepo,
      githubToken,
      apiMode,
      authToken,
      isServerBundle,
      isPublishingGitHub,
      bundle.audit_id,
    ],
  );

  const handleDownloadHtmlReport = useCallback(() => {
    if (!exportArtifacts?.htmlReport) {
      return;
    }
    const blob = new Blob([exportArtifacts.htmlReport], {
      type: "text/html;charset=utf-8",
    });
    triggerBlobDownload(blob, `${bundle.audit_id}-report.html`);
  }, [exportArtifacts, bundle.audit_id]);

  const handleDownloadPdf = useCallback(async () => {
    if (apiMode !== "live" || !authToken || !isServerBundle || isDownloadingPdf) {
      return;
    }
    setIsDownloadingPdf(true);
    setApiError(null);
    try {
      const { blob, digest } = await exportAuditPdf(bundle.audit_id, authToken);
      if (digest) {
        setExportedDigest(digest);
      }
      triggerBlobDownload(blob, `servicecore-${bundle.audit_id}.pdf`);
      setAnnouncement(
        `Downloaded certified PDF servicecore-${bundle.audit_id}.pdf.`,
      );
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to download certified PDF.";
      setApiError(`PDF download failed: ${message}`);
      setAnnouncement(`PDF download failed: ${message}`);
    } finally {
      setIsDownloadingPdf(false);
    }
  }, [apiMode, authToken, isServerBundle, isDownloadingPdf, bundle.audit_id]);

  const handleDownloadSarif = useCallback(async () => {
    if (apiMode !== "live" || !authToken || !isServerBundle || isDownloadingSarif) {
      return;
    }
    setIsDownloadingSarif(true);
    setApiError(null);
    try {
      const sarif = await exportAuditSarif(bundle.audit_id, authToken);
      const blob = new Blob([JSON.stringify(sarif, null, 2)], {
        type: "application/sarif+json;charset=utf-8",
      });
      triggerBlobDownload(blob, `servicecore-${bundle.audit_id}.sarif.json`);
      setAnnouncement(
        `Downloaded SARIF 2.1.0 report servicecore-${bundle.audit_id}.sarif.json.`,
      );
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to download SARIF report.";
      setApiError(`SARIF download failed: ${message}`);
      setAnnouncement(`SARIF download failed: ${message}`);
    } finally {
      setIsDownloadingSarif(false);
    }
  }, [apiMode, authToken, isServerBundle, isDownloadingSarif, bundle.audit_id]);

  const handleClearDiff = useCallback(() => {
    setBaselineAuditId("");
    setDiffReport(null);
    setIsLoadingDiff(false);
    setAnnouncement("Cleared baseline regression comparison.");
  }, []);

  const handleSelectBaseline = useCallback(
    async (nextBaselineId: string) => {
      setBaselineAuditId(nextBaselineId);
      if (!nextBaselineId) {
        setDiffReport(null);
        return;
      }
      if (apiMode !== "live" || !authToken || !isServerBundle) {
        return;
      }
      setIsLoadingDiff(true);
      setApiError(null);
      try {
        const report = await fetchAuditDiff(
          bundle.audit_id,
          nextBaselineId,
          authToken,
        );
        setDiffReport(report);
        setAnnouncement(
          `Loaded regression diff vs ${nextBaselineId}: ${report.new_regressions.length} new regressions, ${report.fixed.length} fixed, ${report.persistent.length} persistent.`,
        );
      } catch (err: unknown) {
        setDiffReport(null);
        const message =
          err instanceof Error
            ? err.message
            : "Failed to load regression diff.";
        setApiError(`Regression diff failed: ${message}`);
        setAnnouncement(`Regression diff failed: ${message}`);
      } finally {
        setIsLoadingDiff(false);
      }
    },
    [apiMode, authToken, isServerBundle, bundle.audit_id],
  );

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        if (isEditing) {
          event.preventDefault();
          setIsEditing(false);
          setAnnouncement("Exited inline editor.");
          return;
        }
        if (isRejecting) {
          event.preventDefault();
          setIsRejecting(false);
          setDraftRejectionReason("");
          setAnnouncement("Cancelled rejection.");
          return;
        }
        if (drawerOpen) {
          event.preventDefault();
          setDrawerOpen(false);
          return;
        }
      }

      if (isEditing && (event.metaKey || event.ctrlKey) && event.key === "Enter") {
        event.preventDefault();
        handleSaveEdit();
        return;
      }

      if (isEditableTarget(event.target)) {
        return;
      }

      if (event.metaKey || event.ctrlKey || event.altKey) {
        return;
      }

      switch (event.key.toLowerCase()) {
        case "j":
          event.preventDefault();
          navigateRelative(1);
          break;
        case "k":
          event.preventDefault();
          navigateRelative(-1);
          break;
        case "a":
          event.preventDefault();
          applyTriage("APPROVED");
          break;
        case "r":
          event.preventDefault();
          handleStartReject();
          break;
        case "e":
          event.preventDefault();
          handleEnterEdit();
          break;
        case "u":
          if (undoSnapshot) {
            event.preventDefault();
            handleUndo();
          }
          break;
        default:
          break;
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [
    isEditing,
    isRejecting,
    drawerOpen,
    handleSaveEdit,
    navigateRelative,
    applyTriage,
    handleStartReject,
    handleEnterEdit,
    undoSnapshot,
    handleUndo,
  ]);

  const handleSelectFindingFromQueue = useCallback((findingId: string) => {
    setSelectedId(findingId);
    setIsEditing(false);
    setIsRejecting(false);
    setDraftRejectionReason("");
    setDrawerOpen(false);
  }, []);

  const telemetry = bundle.telemetry;
  const progressPct =
    counts.total === 0 ? 100 : Math.round((counts.signed / counts.total) * 100);

  const renderMainCanvas = () => {
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
                Target <span className="font-mono">{bundle.target_url}</span>{" "}
                passed deterministic scanner checks with 0 pending findings.
              </p>
            </div>
          </div>
        );

      case "success":
      case "partial":
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
                      onClick={() => {
                        navigator.clipboard?.writeText(exportedDigest);
                        setCopiedDigest(true);
                        setTimeout(() => setCopiedDigest(false), 2000);
                      }}
                      className="min-h-[44px] lg:min-h-[32px] px-2.5 rounded border border-[var(--border-hairline)] bg-[var(--bg-surface)] text-xs font-medium text-[var(--ink-primary)] hover:bg-[var(--bg-subtle)]"
                    >
                      {copiedDigest ? "Copied" : "Copy Digest"}
                    </button>
                    {apiMode === "live" && authToken && isServerBundle ? (
                      <>
                        <button
                          type="button"
                          onClick={handleDownloadPdf}
                          disabled={isDownloadingPdf}
                          className="min-h-[44px] lg:min-h-[32px] px-2.5 rounded border border-[var(--accent-verify)] bg-[var(--accent-verify)] text-xs font-semibold text-white hover:opacity-90 disabled:opacity-50"
                        >
                          {isDownloadingPdf
                            ? "Downloading PDF..."
                            : "Download Certified PDF"}
                        </button>
                        <button
                          type="button"
                          onClick={handleDownloadSarif}
                          disabled={isDownloadingSarif}
                          className="min-h-[44px] lg:min-h-[32px] px-2.5 rounded border border-[var(--accent-verify)] bg-[var(--bg-surface)] text-xs font-semibold text-[var(--accent-verify)] hover:bg-emerald-100 disabled:opacity-50"
                        >
                          {isDownloadingSarif
                            ? "Downloading SARIF..."
                            : "Download SARIF 2.1.0"}
                        </button>
                      </>
                    ) : null}
                    {exportArtifacts?.htmlReport ? (
                      <button
                        type="button"
                        onClick={handleDownloadHtmlReport}
                        className="min-h-[44px] lg:min-h-[32px] px-2.5 rounded border border-[var(--accent-verify)] bg-[var(--bg-surface)] text-xs font-semibold text-[var(--accent-verify)] hover:bg-emerald-100"
                      >
                        Download HTML Report
                      </button>
                    ) : null}
                    {exportArtifacts?.githubIssuesMarkdown ? (
                      <button
                        type="button"
                        onClick={() => {
                          navigator.clipboard?.writeText(
                            exportArtifacts.githubIssuesMarkdown,
                          );
                          setCopiedIssues(true);
                          setTimeout(() => setCopiedIssues(false), 2000);
                        }}
                        className="min-h-[44px] lg:min-h-[32px] px-2.5 rounded border border-[var(--border-hairline)] bg-[var(--bg-surface)] text-xs font-medium text-[var(--ink-primary)] hover:bg-[var(--bg-subtle)]"
                      >
                        {copiedIssues ? "Copied Issues" : "Copy GitHub Issues"}
                      </button>
                    ) : null}
                  </div>
                ) : null}
                {apiMode === "live" && authToken && isServerBundle ? (
                  <div className="w-full pt-2 border-t border-emerald-200 flex flex-col gap-2">
                    <form
                      onSubmit={handlePublishToGitHub}
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
                        onChange={(e) => setGithubRepo(e.target.value)}
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
                        onChange={(e) => setGithubToken(e.target.value)}
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
                    onClick={() => applyTriage("APPROVED")}
                    disabled={evidenceBinding.status === "mismatch"}
                    className="min-h-[36px] px-3 py-1.5 rounded bg-[var(--accent-verify)] text-white text-xs font-semibold hover:opacity-90 disabled:opacity-40"
                  >
                    Approve <kbd className="ml-1 font-mono opacity-80">[a]</kbd>
                  </button>
                  <button
                    type="button"
                    aria-keyshortcuts="e"
                    onClick={handleEnterEdit}
                    disabled={!activePatch}
                    className="min-h-[36px] px-3 py-1.5 rounded border border-[var(--border-hairline)] bg-[var(--bg-surface)] text-[var(--ink-primary)] text-xs font-semibold hover:bg-[var(--bg-subtle)] disabled:opacity-40"
                  >
                    Edit <kbd className="ml-1 font-mono text-[var(--ink-muted)]">[e]</kbd>
                  </button>
                  <button
                    type="button"
                    aria-keyshortcuts="r"
                    onClick={handleStartReject}
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
                    applyTriage("REJECTED", draftRejectionReason);
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
                    onChange={(e) => setDraftRejectionReason(e.target.value)}
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
                    onClick={() => {
                      setIsRejecting(false);
                      setDraftRejectionReason("");
                      setAnnouncement("Cancelled rejection.");
                    }}
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
                  {evidenceBinding.status === "bound" ? (
                    <span className="rounded border border-[var(--accent-verify)] bg-emerald-50 px-2 py-0.5 font-mono text-[11px] font-semibold text-[var(--accent-verify)]">
                      Evidence Bound
                    </span>
                  ) : evidenceBinding.status === "mismatch" ? (
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
                          ? setDraftAfterSnippet(e.target.value)
                          : setDraftPdfSteps(e.target.value)
                      }
                      className="w-full flex-1 rounded border border-[var(--border-hairline)] bg-[var(--bg-canvas)] p-3 font-mono text-xs text-[var(--ink-primary)]"
                    />
                    <div className="flex items-center justify-end gap-2">
                      <button
                        type="button"
                        onClick={() => setIsEditing(false)}
                        className="min-h-[44px] lg:min-h-[30px] px-3 py-1 rounded border border-[var(--border-hairline)] text-xs font-medium text-[var(--ink-primary)] hover:bg-[var(--bg-subtle)]"
                      >
                        Cancel (Esc)
                      </button>
                      <button
                        type="button"
                        onClick={handleSaveEdit}
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

      default:
        return assertNever(viewState);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-[var(--bg-canvas)] text-[var(--ink-primary)]">
      {/* Screen-reader live announcements */}
      <div className="sr-only" aria-live="polite" aria-atomic="true">
        {announcement}
      </div>

      {/* Top Header */}
      <HeaderBar
        queueTriggerRef={queueTriggerRef}
        drawerOpen={drawerOpen}
        onOpenDrawer={() => setDrawerOpen(true)}
        pendingCount={counts.pending}
        apiMode={apiMode}
        auditId={bundle.audit_id}
        targetUrl={bundle.target_url}
        serverAudits={serverAudits}
        onSwitchAudit={(selectedAudit) => {
          loadBundle(selectedAudit, true);
          setAnnouncement(`Switched to audit ${selectedAudit.audit_id}.`);
        }}
        baselineAuditId={baselineAuditId}
        isLoadingDiff={isLoadingDiff}
        onSelectBaseline={(baselineId) => {
          void handleSelectBaseline(baselineId);
        }}
        newAuditUrl={newAuditUrl}
        onNewAuditUrlChange={setNewAuditUrl}
        crawlEnabled={crawlEnabled}
        onCrawlEnabledChange={setCrawlEnabled}
        isScanning={isScanning}
        onRunNewAudit={handleRunNewAudit}
        monitorsCount={monitors.length}
        monitorsOpen={monitorsOpen}
        onToggleMonitors={() => setMonitorsOpen((prev) => !prev)}
      />

      {/* Main Split-Pane Area */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-[320px_1fr] relative">
        {/* Desktop fixed 320px Queue */}
        <aside
          aria-label="Findings triage queue"
          className="hidden lg:block h-[calc(100vh-116px)] sticky top-[61px]"
        >
          <QueuePanel
            counts={counts}
            progressPct={progressPct}
            filter={filter}
            onFilterChange={setFilter}
            viewState={viewState}
            filteredFindings={filteredFindings}
            reviewById={reviewById}
            activeFindingId={activeFinding?.finding_id ?? null}
            onSelectFinding={handleSelectFindingFromQueue}
            onCloseDrawer={() => setDrawerOpen(false)}
          />
        </aside>

        {/* Mobile/Tablet <1024px collapsible slide-over Queue drawer */}
        {drawerOpen ? (
          <div className="lg:hidden fixed inset-0 z-40 flex">
            <div
              className="fixed inset-0 bg-slate-900/40"
              aria-hidden="true"
              onClick={() => setDrawerOpen(false)}
            />
            <aside
              id="workbench-queue-drawer"
              role="dialog"
              aria-modal="true"
              aria-label="Findings triage queue drawer"
              className="relative z-50 w-80 max-w-[85vw] h-full shadow-lg"
            >
              <QueuePanel
                counts={counts}
                progressPct={progressPct}
                filter={filter}
                onFilterChange={setFilter}
                viewState={viewState}
                filteredFindings={filteredFindings}
                reviewById={reviewById}
                activeFindingId={activeFinding?.finding_id ?? null}
                onSelectFinding={handleSelectFindingFromQueue}
                onCloseDrawer={() => setDrawerOpen(false)}
                closeButtonRef={drawerCloseRef}
              />
            </aside>
          </div>
        ) : null}

        {/* Decision Canvas */}
        <main id="main-content" className="min-w-0 pb-48 lg:pb-16">
          {apiError ? (
            <div className="px-4 lg:px-6 pt-4">
              <div
                role="alert"
                className="flex items-center justify-between gap-3 rounded border border-[var(--accent-critical)] bg-red-50 px-4 py-2.5 text-xs text-[var(--ink-primary)]"
              >
                <span className="font-medium text-[var(--accent-critical)]">
                  {apiError}
                </span>
                <button
                  type="button"
                  onClick={() => setApiError(null)}
                  className="min-h-[44px] lg:min-h-[28px] px-2.5 rounded border border-[var(--accent-critical)] bg-[var(--bg-surface)] font-mono text-[11px] font-semibold text-[var(--accent-critical)] hover:bg-red-100"
                >
                  Dismiss
                </button>
              </div>
            </div>
          ) : null}
          {apiMode === "live" && monitorsOpen ? (
            <MonitorsPanel
              monitors={monitors}
              monitorTargetUrl={monitorTargetUrl}
              onMonitorTargetUrlChange={setMonitorTargetUrl}
              monitorCadenceHours={monitorCadenceHours}
              onMonitorCadenceHoursChange={setMonitorCadenceHours}
              monitorCrawl={monitorCrawl}
              onMonitorCrawlChange={setMonitorCrawl}
              isCreatingMonitor={isCreatingMonitor}
              onCreateMonitor={handleCreateMonitor}
              dueWebhookUrl={dueWebhookUrl}
              onDueWebhookUrlChange={setDueWebhookUrl}
              isRunningDueMonitors={isRunningDueMonitors}
              runningMonitorId={runningMonitorId}
              onRunDueMonitors={handleRunDueMonitors}
              onRunMonitor={(m) => {
                void handleRunMonitor(m);
              }}
              onClose={() => setMonitorsOpen(false)}
            />
          ) : null}
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
                      onClick={handleClearDiff}
                      className="min-h-[44px] lg:min-h-[28px] px-2.5 rounded border border-[var(--border-hairline)] bg-[var(--bg-surface)] font-mono text-[11px] font-semibold text-[var(--ink-primary)] hover:bg-[var(--bg-subtle)]"
                    >
                      Clear diff
                    </button>
                  </>
                ) : null}
              </section>
            </div>
          ) : null}
          {renderMainCanvas()}
        </main>
      </div>

      {/* 5s Undo Toast */}
      {undoSnapshot ? (
        <div
          role="status"
          className="fixed bottom-40 lg:bottom-16 right-4 z-30 flex items-center gap-3 rounded border border-[var(--ink-primary)] bg-[var(--ink-primary)] px-4 py-2.5 text-xs text-[var(--bg-surface)] shadow-sm"
        >
          <span>{undoSnapshot.actionLabel}</span>
          <button
            type="button"
            onClick={handleUndo}
            className="min-h-[44px] lg:min-h-[32px] px-2.5 py-1 rounded bg-[var(--bg-surface)] text-[var(--ink-primary)] font-mono font-semibold"
          >
            Undo [u]
          </button>
        </div>
      ) : null}

      {/* Unified Sticky Bottom Chrome (<1024px action bar stacked cleanly above telemetry footer) */}
      <div className="fixed bottom-0 inset-x-0 z-20 flex flex-col border-t border-[var(--border-hairline)] bg-[var(--bg-surface)]">
        {/* Mobile/Tablet <1024px Sticky Action Bar (>= 44x44px touch targets) */}
        {activeFinding && (viewState === "partial" || viewState === "success") ? (
          <div className="lg:hidden flex items-center justify-around gap-2 border-b border-[var(--border-hairline)] bg-[var(--bg-surface)] px-3 py-2">
            <button
              type="button"
              onClick={() => applyTriage("APPROVED")}
              disabled={evidenceBinding.status === "mismatch"}
              className="flex-1 min-h-[44px] min-w-[44px] rounded bg-[var(--accent-verify)] text-white text-sm font-semibold disabled:opacity-40"
            >
              Approve
            </button>
            <button
              type="button"
              onClick={handleEnterEdit}
              disabled={!activePatch}
              className="flex-1 min-h-[44px] min-w-[44px] rounded border border-[var(--border-hairline)] bg-[var(--bg-surface)] text-[var(--ink-primary)] text-sm font-semibold disabled:opacity-40"
            >
              Edit
            </button>
            <button
              type="button"
              onClick={handleStartReject}
              className="flex-1 min-h-[44px] min-w-[44px] rounded border border-[var(--accent-critical)] bg-[var(--bg-surface)] text-[var(--accent-critical)] text-sm font-semibold"
            >
              Reject
            </button>
          </div>
        ) : null}

        {/* Sticky Bottom Cost & Margin Telemetry Footer + Export Certified PDF */}
        <footer className="flex flex-wrap items-center justify-between gap-2 px-4 py-2 text-xs">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono tabular-nums text-[var(--ink-muted)]">
            <span>
              LLM cost:{" "}
              <strong className="text-[var(--ink-primary)]">
                ${telemetry ? telemetry.llm_cost_usd.toFixed(3) : "0.000"}
              </strong>
            </span>
            <span>
              scan duration:{" "}
              <strong className="text-[var(--ink-primary)]">
                {telemetry
                  ? `${(telemetry.scan_duration_ms / 1000).toFixed(2)}s`
                  : "0.00s"}
              </strong>
            </span>
            <span>
              est. gross margin %:{" "}
              <strong className="text-[var(--accent-verify)]">
                {telemetry
                  ? `${telemetry.estimated_gross_margin_pct.toFixed(1)}%`
                  : "100.0%"}
              </strong>
            </span>
          </div>

          <button
            type="button"
            onClick={handleExport}
            disabled={counts.pending > 0 || exportState === "computing" || viewState === "loading" || viewState === "error"}
            aria-disabled={counts.pending > 0}
            className={`min-h-[44px] lg:min-h-[32px] px-4 py-1.5 rounded font-semibold text-xs font-mono tabular-nums transition-colors ${
              counts.pending === 0 && viewState !== "loading" && viewState !== "error"
                ? "bg-[var(--accent-verify)] text-white hover:opacity-90"
                : "bg-[var(--bg-subtle)] text-[var(--ink-muted)] border border-[var(--border-hairline)] cursor-not-allowed"
            }`}
          >
            {exportState === "computing"
              ? "Computing SHA-256 -> Rendering PDF"
              : counts.pending > 0
                ? `Export Certified PDF (${counts.pending} unsigned)`
                : "Export Certified PDF"}
          </button>
        </footer>
      </div>
    </div>
  );
}
