"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  bootstrapDevToken,
  bulkReviewFindings,
  createAudit,
  createMonitor,
  deleteAudit,
  deleteMonitor,
  exportAudit,
  exportAuditCsv,
  exportAuditPdf,
  exportAuditSarif,
  fetchAuditDiff,
  fetchAuditEvents,
  fetchAudits,
  fetchMonitors,
  patchFindingReview,
  publishAuditToGitHub,
  runDueMonitors,
  runMonitor,
  updateMonitor,
} from "@/lib/api";
import {
  buildInitialReviews,
  computeQueueCounts,
  filterFindings,
  isEvidenceBound,
} from "@/lib/triage";
import { useAuditKeyboardShortcuts } from "@/hooks/useAuditKeyboardShortcuts";
import type {
  AuditBundle,
  AuditEvent,
  DiffReport,
  FindingEvidence,
  FindingReview,
  MonitorSchedule,
  PublishedIssue,
  RemediationPatch,
  WorkbenchViewState,
} from "@/types/audit";
import { DecisionCanvas } from "@/components/DecisionCanvas";
import { HeaderBar } from "@/components/HeaderBar";
import { MonitorsPanel } from "@/components/MonitorsPanel";
import { QueuePanel, type QueueFilter } from "@/components/QueuePanel";

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
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [serverAudits, setServerAudits] = useState<AuditBundle[]>([]);
  const [apiMode, setApiMode] = useState<ApiMode>("demo");
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [isServerBundle, setIsServerBundle] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);
  const [newAuditUrl, setNewAuditUrl] = useState("");
  const [crawlEnabled, setCrawlEnabled] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [isDeletingAudit, setIsDeletingAudit] = useState(false);
  const [isBulkApproving, setIsBulkApproving] = useState(false);
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);
  const [isDownloadingSarif, setIsDownloadingSarif] = useState(false);
  const [isDownloadingCsv, setIsDownloadingCsv] = useState(false);
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
  const [updatingMonitorId, setUpdatingMonitorId] = useState<string | null>(null);
  const [deletingMonitorId, setDeletingMonitorId] = useState<string | null>(null);
  const [dueWebhookUrl, setDueWebhookUrl] = useState("");
  const [isRunningDueMonitors, setIsRunningDueMonitors] = useState(false);

  const [reviews, setReviews] = useState<FindingReview[]>(() =>
    buildInitialReviews(initialBundle),
  );

  const [patches, setPatches] = useState<RemediationPatch[]>(initialBundle.patches);
  const [filter, setFilter] = useState<QueueFilter>("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(
    initialBundle.findings[0]?.finding_id ?? null,
  );
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
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
  const shortcutsTriggerRef = useRef<HTMLButtonElement | null>(null);
  const helpCloseRef = useRef<HTMLButtonElement | null>(null);
  const wasHelpOpenRef = useRef(false);
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

  useEffect(() => {
    if (helpOpen) {
      wasHelpOpenRef.current = true;
      requestAnimationFrame(() => {
        helpCloseRef.current?.focus();
      });
    } else if (wasHelpOpenRef.current) {
      wasHelpOpenRef.current = false;
      requestAnimationFrame(() => {
        shortcutsTriggerRef.current?.focus();
      });
    }
  }, [helpOpen]);

  const loadBundle = useCallback((nextBundle: AuditBundle, serverBacked: boolean) => {
    setBundle(nextBundle);
    setIsServerBundle(serverBacked);
    setReviews(buildInitialReviews(nextBundle));
    setPatches(nextBundle.patches);
    setFilter("ALL");
    setSearchQuery("");
    setHelpOpen(false);
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
    setAuditEvents([]);
  }, []);

  const refreshAuditEvents = useCallback(
    async (auditId: string, token: string | null, signal?: AbortSignal) => {
      if (!token) {
        return;
      }
      try {
        const events = await fetchAuditEvents(auditId, token, signal);
        setAuditEvents(events);
      } catch {
        // Non-fatal: audit trail fetch failures should not block triage or export.
      }
    },
    [],
  );

  useEffect(() => {
    if (apiMode !== "live" || !authToken || !isServerBundle) {
      setAuditEvents([]);
      return;
    }
    const controller = new AbortController();
    void refreshAuditEvents(bundle.audit_id, authToken, controller.signal);
    return () => {
      controller.abort();
    };
  }, [apiMode, authToken, isServerBundle, bundle.audit_id, refreshAuditEvents]);

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

  const pendingBoundFindings = useMemo(() => {
    return bundle.findings.filter((finding) => {
      const review = reviewById.get(finding.finding_id);
      if (review?.status !== "PENDING") {
        return false;
      }
      return isEvidenceBound(finding, patchById.get(finding.finding_id));
    });
  }, [bundle.findings, reviewById, patchById]);

  const pendingBoundCount = pendingBoundFindings.length;

  const counts = useMemo(() => computeQueueCounts(reviews), [reviews]);

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

  const filteredFindings = useMemo(
    () => filterFindings(bundle.findings, reviewById, filter, searchQuery),
    [filter, searchQuery, bundle.findings, reviewById],
  );

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
            void refreshAuditEvents(bundle.audit_id, authToken);
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
      refreshAuditEvents,
    ],
  );

  const handleBulkApproveBound = useCallback(async () => {
    if (pendingBoundFindings.length === 0 || isBulkApproving) {
      return;
    }

    const findingIds = pendingBoundFindings.map((f) => f.finding_id);
    const pendingBoundIds = new Set(findingIds);
    const countLabel = `${findingIds.length} bound finding${findingIds.length === 1 ? "" : "s"}`;

    if (apiMode === "live" && authToken && isServerBundle) {
      setIsBulkApproving(true);
      setApiError(null);
      try {
        const serverBundle = await bulkReviewFindings(
          bundle.audit_id,
          "APPROVED",
          authToken,
          { findingIds },
        );
        const nextReviews = buildInitialReviews(serverBundle);
        setReviews(nextReviews);
        setExportState("idle");
        setExportedDigest(null);
        setExportArtifacts(null);
        setUndoSnapshot(null);
        setAnnouncement(`Approved ${countLabel}.`);
        if (activeFinding && pendingBoundIds.has(activeFinding.finding_id)) {
          advanceToNextPending(nextReviews, activeFinding.finding_id);
        }
        void refreshAuditEvents(bundle.audit_id, authToken);
      } catch (err: unknown) {
        const message =
          err instanceof Error
            ? err.message
            : "Failed to bulk approve bound findings.";
        setApiError(`Bulk approval failed: ${message}`);
        setAnnouncement(`Error bulk approving bound findings: ${message}`);
      } finally {
        setIsBulkApproving(false);
      }
      return;
    }

    const signedAt = new Date().toISOString();
    const updatedReviews = reviews.map((review) =>
      pendingBoundIds.has(review.finding_id)
        ? {
            ...review,
            status: "APPROVED" as const,
            rejection_reason: null,
            reviewer_id: "reviewer@servicecore.local",
            signed_at_utc: signedAt,
          }
        : review,
    );
    setReviews(updatedReviews);
    setIsRejecting(false);
    setDraftRejectionReason("");
    setExportState("idle");
    setExportedDigest(null);
    setExportArtifacts(null);
    setApiError(null);
    setUndoSnapshot(null);
    setAnnouncement(`Approved ${countLabel}.`);
    if (activeFinding && pendingBoundIds.has(activeFinding.finding_id)) {
      advanceToNextPending(updatedReviews, activeFinding.finding_id);
    }
  }, [
    pendingBoundFindings,
    isBulkApproving,
    apiMode,
    authToken,
    isServerBundle,
    bundle.audit_id,
    reviews,
    activeFinding,
    advanceToNextPending,
  ]);

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
          void refreshAuditEvents(bundle.audit_id, authToken);
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
    refreshAuditEvents,
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
        void refreshAuditEvents(bundle.audit_id, authToken);
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

  const handleDeleteAudit = useCallback(
    async (auditId: string) => {
      if (!authToken || isDeletingAudit) {
        return;
      }
      setIsDeletingAudit(true);
      setApiError(null);
      try {
        const result = await deleteAudit(auditId, authToken);
        if (result.deleted) {
          const remainingAudits = serverAudits.filter(
            (item) => item.audit_id !== auditId,
          );
          setServerAudits(remainingAudits);
          if (remainingAudits.length > 0) {
            loadBundle(remainingAudits[0], true);
            setAnnouncement(
              `Deleted audit ${auditId}. Switched to ${remainingAudits[0].audit_id}.`,
            );
          } else {
            loadBundle(initialBundle, false);
            setAnnouncement(
              `Deleted audit ${auditId}. No server audits remaining.`,
            );
          }
        }
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "Failed to delete audit.";
        setApiError(`Delete audit failed: ${message}`);
        setAnnouncement(`Delete audit failed: ${message}`);
      } finally {
        setIsDeletingAudit(false);
      }
    },
    [authToken, isDeletingAudit, serverAudits, loadBundle, initialBundle],
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

  const handleToggleMonitor = useCallback(
    async (monitor: MonitorSchedule) => {
      if (!authToken || updatingMonitorId || deletingMonitorId) {
        return;
      }
      setUpdatingMonitorId(monitor.monitor_id);
      setApiError(null);
      const nextEnabled = !monitor.enabled;
      try {
        const updated = await updateMonitor(
          monitor.monitor_id,
          { enabled: nextEnabled },
          authToken,
        );
        setMonitors((prev) =>
          prev.map((item) =>
            item.monitor_id === updated.monitor_id ? updated : item,
          ),
        );
        setAnnouncement(
          `${updated.enabled ? "Resumed" : "Paused"} monitor for ${updated.target_url}.`,
        );
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "Failed to update monitor.";
        setApiError(`Update monitor failed: ${message}`);
        setAnnouncement(`Update monitor failed: ${message}`);
      } finally {
        setUpdatingMonitorId(null);
      }
    },
    [authToken, updatingMonitorId, deletingMonitorId],
  );

  const handleDeleteMonitor = useCallback(
    async (monitor: MonitorSchedule) => {
      if (!authToken || deletingMonitorId || updatingMonitorId) {
        return;
      }
      setDeletingMonitorId(monitor.monitor_id);
      setApiError(null);
      try {
        const result = await deleteMonitor(monitor.monitor_id, authToken);
        if (result.deleted) {
          setMonitors((prev) =>
            prev.filter((item) => item.monitor_id !== monitor.monitor_id),
          );
          setAnnouncement(`Deleted monitor for ${monitor.target_url}.`);
        }
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "Failed to delete monitor.";
        setApiError(`Delete monitor failed: ${message}`);
        setAnnouncement(`Delete monitor failed: ${message}`);
      } finally {
        setDeletingMonitorId(null);
      }
    },
    [authToken, deletingMonitorId, updatingMonitorId],
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

  const signedExportBundle: AuditBundle = useMemo(
    () => ({
      ...bundle,
      patches,
      reviews,
      evidence_digest: exportedDigest ?? bundle.evidence_digest,
    }),
    [bundle, patches, reviews, exportedDigest],
  );

  const handleDownloadBundleJson = useCallback(() => {
    triggerBlobDownload(
      new Blob([JSON.stringify(signedExportBundle, null, 2)], {
        type: "application/json;charset=utf-8",
      }),
      `servicecore-${bundle.audit_id}.json`,
    );
    setAnnouncement(
      `Downloaded signed AuditBundle JSON servicecore-${bundle.audit_id}.json.`,
    );
  }, [signedExportBundle, bundle.audit_id]);

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
      void refreshAuditEvents(bundle.audit_id, authToken);
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
      void refreshAuditEvents(bundle.audit_id, authToken);
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to download SARIF report.";
      setApiError(`SARIF download failed: ${message}`);
      setAnnouncement(`SARIF download failed: ${message}`);
    } finally {
      setIsDownloadingSarif(false);
    }
  }, [apiMode, authToken, isServerBundle, isDownloadingSarif, bundle.audit_id]);

  const handleDownloadCsv = useCallback(async () => {
    if (apiMode !== "live" || !authToken || !isServerBundle || isDownloadingCsv) {
      return;
    }
    setIsDownloadingCsv(true);
    setApiError(null);
    try {
      const csv = await exportAuditCsv(bundle.audit_id, authToken);
      const blob = new Blob([csv], {
        type: "text/csv;charset=utf-8",
      });
      triggerBlobDownload(blob, `servicecore-${bundle.audit_id}.csv`);
      setAnnouncement(
        `Downloaded CSV report servicecore-${bundle.audit_id}.csv.`,
      );
      void refreshAuditEvents(bundle.audit_id, authToken);
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to download CSV report.";
      setApiError(`CSV download failed: ${message}`);
      setAnnouncement(`CSV download failed: ${message}`);
    } finally {
      setIsDownloadingCsv(false);
    }
  }, [apiMode, authToken, isServerBundle, isDownloadingCsv, bundle.audit_id]);

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

  const handleCancelEdit = useCallback(() => {
    setIsEditing(false);
    setAnnouncement("Exited inline editor.");
  }, []);

  const handleCancelReject = useCallback(() => {
    setIsRejecting(false);
    setDraftRejectionReason("");
    setAnnouncement("Cancelled rejection.");
  }, []);

  useAuditKeyboardShortcuts({
    isEditing,
    isRejecting,
    drawerOpen,
    helpOpen,
    canUndo: Boolean(undoSnapshot),
    onNext: () => navigateRelative(1),
    onPrev: () => navigateRelative(-1),
    onApprove: () => applyTriage("APPROVED"),
    onStartReject: handleStartReject,
    onEnterEdit: handleEnterEdit,
    onSaveEdit: handleSaveEdit,
    onCancelEdit: handleCancelEdit,
    onCancelReject: handleCancelReject,
    onCloseDrawer: () => setDrawerOpen(false),
    onToggleHelp: () => setHelpOpen((prev) => !prev),
    onCloseHelp: () => setHelpOpen(false),
    onUndo: handleUndo,
  });

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
        isDeletingAudit={isDeletingAudit}
        onDeleteAudit={(id) => {
          void handleDeleteAudit(id);
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
        helpOpen={helpOpen}
        onToggleHelp={() => setHelpOpen((prev) => !prev)}
        shortcutsTriggerRef={shortcutsTriggerRef}
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
            searchQuery={searchQuery}
            onSearchQueryChange={setSearchQuery}
            viewState={viewState}
            filteredFindings={filteredFindings}
            reviewById={reviewById}
            activeFindingId={activeFinding?.finding_id ?? null}
            onSelectFinding={handleSelectFindingFromQueue}
            onCloseDrawer={() => setDrawerOpen(false)}
            pendingBoundCount={pendingBoundCount}
            onBulkApproveBound={() => {
              void handleBulkApproveBound();
            }}
            isBulkApproving={isBulkApproving}
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
                searchQuery={searchQuery}
                onSearchQueryChange={setSearchQuery}
                viewState={viewState}
                filteredFindings={filteredFindings}
                reviewById={reviewById}
                activeFindingId={activeFinding?.finding_id ?? null}
                onSelectFinding={handleSelectFindingFromQueue}
                onCloseDrawer={() => setDrawerOpen(false)}
                closeButtonRef={drawerCloseRef}
                pendingBoundCount={pendingBoundCount}
                onBulkApproveBound={() => {
                  void handleBulkApproveBound();
                }}
                isBulkApproving={isBulkApproving}
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
              updatingMonitorId={updatingMonitorId}
              deletingMonitorId={deletingMonitorId}
              onRunDueMonitors={handleRunDueMonitors}
              onRunMonitor={(m) => {
                void handleRunMonitor(m);
              }}
              onToggleMonitor={(m) => {
                void handleToggleMonitor(m);
              }}
              onDeleteMonitor={(m) => {
                void handleDeleteMonitor(m);
              }}
              onClose={() => setMonitorsOpen(false)}
            />
          ) : null}
          <DecisionCanvas
            viewState={viewState}
            errorMessage={errorMessage}
            onRetry={onRetry}
            targetUrl={bundle.target_url}
            isLoadingDiff={isLoadingDiff}
            baselineAuditId={baselineAuditId}
            diffReport={diffReport}
            onClearDiff={handleClearDiff}
            exportedDigest={exportedDigest}
            copiedDigest={copiedDigest}
            onCopyDigest={() => {
              if (!exportedDigest) {
                return;
              }
              navigator.clipboard?.writeText(exportedDigest);
              setCopiedDigest(true);
              setTimeout(() => setCopiedDigest(false), 2000);
            }}
            isLiveServerBundle={apiMode === "live" && Boolean(authToken) && isServerBundle}
            isDownloadingPdf={isDownloadingPdf}
            onDownloadPdf={() => {
              void handleDownloadPdf();
            }}
            isDownloadingSarif={isDownloadingSarif}
            onDownloadSarif={() => {
              void handleDownloadSarif();
            }}
            isDownloadingCsv={isDownloadingCsv}
            onDownloadCsv={() => {
              void handleDownloadCsv();
            }}
            onDownloadBundleJson={handleDownloadBundleJson}
            hasHtmlReport={Boolean(exportArtifacts?.htmlReport)}
            onDownloadHtmlReport={handleDownloadHtmlReport}
            hasGithubIssuesMarkdown={Boolean(exportArtifacts?.githubIssuesMarkdown)}
            copiedIssues={copiedIssues}
            onCopyGithubIssues={() => {
              if (!exportArtifacts?.githubIssuesMarkdown) {
                return;
              }
              navigator.clipboard?.writeText(exportArtifacts.githubIssuesMarkdown);
              setCopiedIssues(true);
              setTimeout(() => setCopiedIssues(false), 2000);
            }}
            githubRepo={githubRepo}
            onGithubRepoChange={setGithubRepo}
            githubToken={githubToken}
            onGithubTokenChange={setGithubToken}
            isPublishingGitHub={isPublishingGitHub}
            onPublishToGitHub={handlePublishToGitHub}
            publishError={publishError}
            publishedIssues={publishedIssues}
            activeFinding={activeFinding}
            activeReview={activeReview}
            activePatch={activePatch}
            evidenceBindingStatus={evidenceBinding.status}
            onApprove={() => applyTriage("APPROVED")}
            onEnterEdit={handleEnterEdit}
            onStartReject={handleStartReject}
            isRejecting={isRejecting}
            draftRejectionReason={draftRejectionReason}
            onDraftRejectionReasonChange={setDraftRejectionReason}
            onConfirmReject={() => applyTriage("REJECTED", draftRejectionReason)}
            onCancelReject={() => {
              setIsRejecting(false);
              setDraftRejectionReason("");
              setAnnouncement("Cancelled rejection.");
            }}
            rejectionInputRef={rejectionInputRef}
            isEditing={isEditing}
            draftAfterSnippet={draftAfterSnippet}
            onDraftAfterSnippetChange={setDraftAfterSnippet}
            draftPdfSteps={draftPdfSteps}
            onDraftPdfStepsChange={setDraftPdfSteps}
            onSaveEdit={handleSaveEdit}
            onCancelEdit={() => setIsEditing(false)}
            editorRef={editorRef}
            auditEvents={auditEvents}
          />
        </main>
      </div>

      {/* Keyboard Shortcuts Reference Modal */}
      {helpOpen ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div
            className="fixed inset-0 bg-slate-900/40"
            aria-hidden="true"
            onClick={() => setHelpOpen(false)}
          />
          <div
            role="dialog"
            aria-modal="true"
            aria-label="Keyboard shortcuts"
            className="relative z-10 w-full max-w-md rounded border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5 shadow-lg"
          >
            <div className="flex items-center justify-between border-b border-[var(--border-hairline)] pb-3">
              <h2 className="text-base font-semibold text-[var(--ink-primary)]">
                Keyboard Shortcuts
              </h2>
              <button
                ref={helpCloseRef}
                type="button"
                onClick={() => setHelpOpen(false)}
                className="min-h-[44px] lg:min-h-[32px] px-2.5 py-1 rounded border border-[var(--border-hairline)] bg-[var(--bg-subtle)] font-mono text-xs font-semibold text-[var(--ink-primary)] hover:bg-[var(--bg-canvas)]"
              >
                Close
              </button>
            </div>
            <dl className="mt-4 space-y-2.5 text-xs">
              {(
                [
                  { keys: ["j", "k"], desc: "Navigate to next / previous finding" },
                  { keys: ["a"], desc: "Approve active finding" },
                  { keys: ["e"], desc: "Edit remediation patch" },
                  { keys: ["r"], desc: "Reject active finding" },
                  { keys: ["u"], desc: "Undo last triage action" },
                  { keys: ["?"], desc: "Toggle shortcuts help" },
                  { keys: ["Esc"], desc: "Close active modal, drawer, or editor" },
                ] as const
              ).map((item) => (
                <div
                  key={item.desc}
                  className="flex items-center justify-between gap-4 border-b border-[var(--border-hairline)] pb-2 last:border-b-0 last:pb-0"
                >
                  <dt className="text-[var(--ink-muted)]">{item.desc}</dt>
                  <dd className="flex items-center gap-1 font-mono font-semibold text-[var(--ink-primary)]">
                    {item.keys.map((k, idx) => (
                      <React.Fragment key={k}>
                        {idx > 0 ? <span className="text-[var(--ink-muted)]">/</span> : null}
                        <kbd className="rounded border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 text-[11px]">
                          {k}
                        </kbd>
                      </React.Fragment>
                    ))}
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        </div>
      ) : null}

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
