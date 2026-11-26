"use client";

import React, { useEffect, useState } from "react";
import type { AuditBundle } from "@/types/audit";

export interface HeaderBarProps {
  queueTriggerRef: React.RefObject<HTMLButtonElement | null>;
  drawerOpen: boolean;
  onOpenDrawer: () => void;
  pendingCount: number;
  apiMode: "demo" | "live";
  auditId: string;
  targetUrl: string;
  serverAudits: AuditBundle[];
  onSwitchAudit: (audit: AuditBundle) => void;
  isDeletingAudit: boolean;
  onDeleteAudit: (auditId: string) => void;
  baselineAuditId: string;
  isLoadingDiff: boolean;
  onSelectBaseline: (baselineId: string) => void;
  newAuditUrl: string;
  onNewAuditUrlChange: (value: string) => void;
  crawlEnabled: boolean;
  onCrawlEnabledChange: (checked: boolean) => void;
  isScanning: boolean;
  onRunNewAudit: (event: React.FormEvent<HTMLFormElement>) => void;
  monitorsCount: number;
  monitorsOpen: boolean;
  onToggleMonitors: () => void;
  helpOpen: boolean;
  onToggleHelp: () => void;
}

/**
 * Sticky top header bar for the Review Workbench: mobile queue drawer trigger,
 * Live API / Demo Mode badge, audit & baseline switchers, New Audit scan form,
 * Monitors toggle, Shortcuts help button, and desktop keyboard shortcut legend.
 */
export function HeaderBar({
  queueTriggerRef,
  drawerOpen,
  onOpenDrawer,
  pendingCount,
  apiMode,
  auditId,
  targetUrl,
  serverAudits,
  onSwitchAudit,
  isDeletingAudit,
  onDeleteAudit,
  baselineAuditId,
  isLoadingDiff,
  onSelectBaseline,
  newAuditUrl,
  onNewAuditUrlChange,
  crawlEnabled,
  onCrawlEnabledChange,
  isScanning,
  onRunNewAudit,
  monitorsCount,
  monitorsOpen,
  onToggleMonitors,
  helpOpen,
  onToggleHelp,
}: HeaderBarProps) {
  const [confirmingDeleteAudit, setConfirmingDeleteAudit] = useState(false);

  useEffect(() => {
    setConfirmingDeleteAudit(false);
  }, [auditId]);

  return (
    <header className="sticky top-0 z-20 flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border-hairline)] bg-[var(--bg-surface)] px-4 py-2.5">
      <div className="flex items-center gap-3 min-w-0">
        <button
          ref={queueTriggerRef}
          type="button"
          onClick={onOpenDrawer}
          aria-expanded={drawerOpen}
          aria-controls="workbench-queue-drawer"
          className="lg:hidden min-h-[44px] min-w-[44px] px-3 rounded border border-[var(--border-hairline)] bg-[var(--bg-subtle)] text-xs font-mono font-semibold text-[var(--ink-primary)] tabular-nums"
        >
          Queue ({pendingCount} pending)
        </button>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-lg lg:text-xl font-semibold tracking-tight text-[var(--ink-primary)] truncate">
              ServiceCore Review Workbench
            </h1>
            <span
              className={`inline-block rounded border px-2 py-0.5 font-mono text-[11px] font-semibold ${
                apiMode === "live"
                  ? "border-[var(--accent-verify)] bg-emerald-50 text-[var(--accent-verify)]"
                  : "border-[var(--border-hairline)] bg-[var(--bg-subtle)] text-[var(--ink-primary)]"
              }`}
            >
              {apiMode === "live" ? "Live API" : "Demo Mode"}
            </span>
            <span className="hidden sm:inline-block rounded border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--ink-muted)]">
              {auditId}
            </span>
          </div>
          <p className="text-xs font-mono text-[var(--ink-muted)] truncate">
            {targetUrl}
          </p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        {apiMode === "live" && serverAudits.length > 0 ? (
          <div className="flex items-center gap-1.5">
            <select
              aria-label="Select audit"
              value={auditId}
              onChange={(e) => {
                const selectedAudit = serverAudits.find(
                  (item) => item.audit_id === e.target.value,
                );
                if (selectedAudit) {
                  onSwitchAudit(selectedAudit);
                }
              }}
              className="min-h-[44px] lg:min-h-[32px] max-w-[220px] rounded border border-[var(--border-hairline)] bg-[var(--bg-canvas)] px-2 py-1 font-mono text-xs text-[var(--ink-primary)]"
            >
              {serverAudits.map((item) => (
                <option key={item.audit_id} value={item.audit_id}>
                  {item.audit_id} — {item.target_url}
                </option>
              ))}
            </select>
            {confirmingDeleteAudit ? (
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  aria-label={`Confirm delete audit ${auditId}`}
                  disabled={isDeletingAudit}
                  onClick={() => {
                    setConfirmingDeleteAudit(false);
                    onDeleteAudit(auditId);
                  }}
                  className="min-h-[44px] lg:min-h-[32px] px-2.5 py-1 rounded border border-[var(--accent-critical)] bg-[var(--accent-critical)] font-mono text-xs font-semibold text-white hover:opacity-90 disabled:opacity-40"
                >
                  {isDeletingAudit ? "Deleting..." : "Confirm Delete"}
                </button>
                <button
                  type="button"
                  disabled={isDeletingAudit}
                  onClick={() => setConfirmingDeleteAudit(false)}
                  className="min-h-[44px] lg:min-h-[32px] px-2.5 py-1 rounded border border-[var(--border-hairline)] bg-[var(--bg-surface)] font-mono text-xs font-semibold text-[var(--ink-primary)] hover:bg-[var(--bg-subtle)] disabled:opacity-40"
                >
                  Cancel
                </button>
              </div>
            ) : (
              <button
                type="button"
                aria-label="Delete selected audit"
                disabled={isDeletingAudit}
                onClick={() => setConfirmingDeleteAudit(true)}
                className="min-h-[44px] lg:min-h-[32px] px-2.5 py-1 rounded border border-[var(--accent-critical)] bg-[var(--bg-surface)] font-mono text-xs font-semibold text-[var(--accent-critical)] hover:bg-red-50 disabled:opacity-40"
              >
                {isDeletingAudit ? "Deleting..." : "Delete"}
              </button>
            )}
          </div>
        ) : null}

        {apiMode === "live" && serverAudits.length >= 2 ? (
          <select
            aria-label="Compare against baseline audit"
            value={baselineAuditId}
            disabled={isLoadingDiff}
            onChange={(e) => {
              onSelectBaseline(e.target.value);
            }}
            className="min-h-[44px] lg:min-h-[32px] max-w-[220px] rounded border border-[var(--border-hairline)] bg-[var(--bg-canvas)] px-2 py-1 font-mono text-xs text-[var(--ink-primary)] disabled:opacity-50"
          >
            <option value="">Compare baseline...</option>
            {serverAudits
              .filter((item) => item.audit_id !== auditId)
              .map((item) => (
                <option key={item.audit_id} value={item.audit_id}>
                  vs {item.audit_id} — {item.target_url}
                </option>
              ))}
          </select>
        ) : null}

        {apiMode === "live" ? (
          <form
            onSubmit={onRunNewAudit}
            className="flex items-center gap-2"
            aria-label="New Audit scan form"
          >
            <label htmlFor="new-audit-url" className="sr-only">
              New Audit target URL
            </label>
            <input
              id="new-audit-url"
              type="url"
              required
              value={newAuditUrl}
              onChange={(e) => onNewAuditUrlChange(e.target.value)}
              placeholder="New Audit: https://..."
              disabled={isScanning}
              className="min-h-[44px] lg:min-h-[32px] w-48 sm:w-64 rounded border border-[var(--border-hairline)] bg-[var(--bg-canvas)] px-2.5 py-1 font-mono text-xs text-[var(--ink-primary)] placeholder:text-[var(--ink-muted)]"
            />
            <label className="inline-flex items-center gap-1.5 text-xs font-mono text-[var(--ink-primary)] cursor-pointer select-none">
              <input
                type="checkbox"
                checked={crawlEnabled}
                onChange={(e) => onCrawlEnabledChange(e.target.checked)}
                disabled={isScanning}
                className="h-3.5 w-3.5 rounded border-[var(--border-hairline)] accent-[var(--accent-verify)]"
              />
              Crawl
            </label>
            <button
              type="submit"
              disabled={isScanning || !newAuditUrl.trim()}
              className="min-h-[44px] lg:min-h-[32px] px-3 py-1 rounded bg-[var(--accent-verify)] text-white text-xs font-semibold hover:opacity-90 disabled:opacity-40"
            >
              {isScanning ? "Scanning..." : "Run Scan"}
            </button>
          </form>
        ) : null}

        {apiMode === "live" ? (
          <button
            type="button"
            onClick={onToggleMonitors}
            aria-expanded={monitorsOpen}
            aria-controls="workbench-monitors-panel"
            className={`min-h-[44px] lg:min-h-[32px] px-2.5 py-1 rounded border font-mono text-xs font-semibold transition-colors ${
              monitorsOpen
                ? "border-[var(--accent-verify)] bg-emerald-50 text-[var(--accent-verify)]"
                : "border-[var(--border-hairline)] bg-[var(--bg-canvas)] text-[var(--ink-primary)] hover:bg-[var(--bg-subtle)]"
            }`}
          >
            Monitors ({monitorsCount})
          </button>
        ) : null}

        <button
          type="button"
          onClick={onToggleHelp}
          aria-expanded={helpOpen}
          aria-haspopup="dialog"
          className={`min-h-[44px] lg:min-h-[32px] px-2.5 py-1 rounded border font-mono text-xs font-semibold transition-colors ${
            helpOpen
              ? "border-[var(--ink-primary)] bg-[var(--ink-primary)] text-[var(--bg-surface)]"
              : "border-[var(--border-hairline)] bg-[var(--bg-canvas)] text-[var(--ink-primary)] hover:bg-[var(--bg-subtle)]"
          }`}
        >
          Shortcuts [?]
        </button>

        <div className="hidden xl:flex items-center gap-3 text-xs font-mono text-[var(--ink-muted)]">
          <span>
            <kbd className="rounded border border-[var(--border-hairline)] px-1">j</kbd>/
            <kbd className="rounded border border-[var(--border-hairline)] px-1">k</kbd>{" "}
            nav
          </span>
          <span>
            <kbd className="rounded border border-[var(--border-hairline)] px-1">a</kbd>{" "}
            approve
          </span>
          <span>
            <kbd className="rounded border border-[var(--border-hairline)] px-1">r</kbd>{" "}
            reject
          </span>
          <span>
            <kbd className="rounded border border-[var(--border-hairline)] px-1">e</kbd>{" "}
            edit
          </span>
          <span>
            <kbd className="rounded border border-[var(--border-hairline)] px-1">u</kbd>{" "}
            undo
          </span>
        </div>
      </div>
    </header>
  );
}
