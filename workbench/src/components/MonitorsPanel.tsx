"use client";

import React from "react";
import type { MonitorSchedule } from "@/types/audit";

export interface MonitorsPanelProps {
  monitors: MonitorSchedule[];
  monitorTargetUrl: string;
  onMonitorTargetUrlChange: (value: string) => void;
  monitorCadenceHours: number;
  onMonitorCadenceHoursChange: (value: number) => void;
  monitorCrawl: boolean;
  onMonitorCrawlChange: (checked: boolean) => void;
  isCreatingMonitor: boolean;
  onCreateMonitor: (event: React.FormEvent<HTMLFormElement>) => void;
  dueWebhookUrl: string;
  onDueWebhookUrlChange: (value: string) => void;
  isRunningDueMonitors: boolean;
  runningMonitorId: string | null;
  onRunDueMonitors: () => void;
  onRunMonitor: (monitor: MonitorSchedule) => void;
  onClose: () => void;
}

/**
 * Recurring monitors management panel for scheduling, listing, and triggering
 * automated accessibility re-scans.
 */
export function MonitorsPanel({
  monitors,
  monitorTargetUrl,
  onMonitorTargetUrlChange,
  monitorCadenceHours,
  onMonitorCadenceHoursChange,
  monitorCrawl,
  onMonitorCrawlChange,
  isCreatingMonitor,
  onCreateMonitor,
  dueWebhookUrl,
  onDueWebhookUrlChange,
  isRunningDueMonitors,
  runningMonitorId,
  onRunDueMonitors,
  onRunMonitor,
  onClose,
}: MonitorsPanelProps) {
  return (
    <div id="workbench-monitors-panel" className="px-4 lg:px-6 pt-4">
      <section
        aria-label="Recurring monitors"
        className="rounded border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-4 space-y-3"
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-xs font-mono font-semibold uppercase tracking-wide text-[var(--ink-primary)]">
            Recurring Monitors ({monitors.length})
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="min-h-[44px] lg:min-h-[28px] px-2.5 rounded border border-[var(--border-hairline)] bg-[var(--bg-surface)] font-mono text-[11px] font-semibold text-[var(--ink-primary)] hover:bg-[var(--bg-subtle)]"
          >
            Close
          </button>
        </div>

        <form
          onSubmit={onCreateMonitor}
          className="flex flex-wrap items-center gap-2 border-b border-[var(--border-hairline)] pb-3"
          aria-label="Create recurring monitor"
        >
          <label htmlFor="monitor-target-url" className="sr-only">
            Monitor target URL
          </label>
          <input
            id="monitor-target-url"
            type="url"
            required
            value={monitorTargetUrl}
            onChange={(e) => onMonitorTargetUrlChange(e.target.value)}
            placeholder="https://example.com"
            disabled={isCreatingMonitor}
            className="min-h-[44px] lg:min-h-[32px] flex-1 min-w-[200px] rounded border border-[var(--border-hairline)] bg-[var(--bg-canvas)] px-2.5 py-1 font-mono text-xs text-[var(--ink-primary)] placeholder:text-[var(--ink-muted)]"
          />
          <label
            htmlFor="monitor-cadence-hours"
            className="inline-flex items-center gap-1.5 text-xs font-mono text-[var(--ink-muted)]"
          >
            Every
            <input
              id="monitor-cadence-hours"
              type="number"
              min={1}
              max={720}
              value={monitorCadenceHours}
              onChange={(e) =>
                onMonitorCadenceHoursChange(
                  Math.max(1, Number(e.target.value) || 24),
                )
              }
              disabled={isCreatingMonitor}
              className="min-h-[44px] lg:min-h-[32px] w-16 rounded border border-[var(--border-hairline)] bg-[var(--bg-canvas)] px-2 py-1 font-mono text-xs text-[var(--ink-primary)] tabular-nums"
            />
            h
          </label>
          <label className="inline-flex items-center gap-1.5 text-xs font-mono text-[var(--ink-primary)] cursor-pointer select-none">
            <input
              type="checkbox"
              checked={monitorCrawl}
              onChange={(e) => onMonitorCrawlChange(e.target.checked)}
              disabled={isCreatingMonitor}
              className="h-3.5 w-3.5 rounded border-[var(--border-hairline)] accent-[var(--accent-verify)]"
            />
            Crawl
          </label>
          <button
            type="submit"
            disabled={isCreatingMonitor || !monitorTargetUrl.trim()}
            className="min-h-[44px] lg:min-h-[32px] px-3 py-1 rounded bg-[var(--accent-verify)] text-white text-xs font-semibold hover:opacity-90 disabled:opacity-40"
          >
            {isCreatingMonitor ? "Adding..." : "Add Monitor"}
          </button>
        </form>

        <div
          className="flex flex-wrap items-center gap-2 border-b border-[var(--border-hairline)] pb-3"
          role="group"
          aria-label="Run due monitors"
        >
          <span className="font-mono text-[11px] font-semibold uppercase tracking-wide text-[var(--ink-muted)]">
            Run Due Monitors
          </span>
          <label htmlFor="monitor-due-webhook-url" className="sr-only">
            Optional webhook URL for due monitors
          </label>
          <input
            id="monitor-due-webhook-url"
            type="url"
            value={dueWebhookUrl}
            onChange={(e) => onDueWebhookUrlChange(e.target.value)}
            placeholder="Optional webhook URL (https://...)"
            disabled={isRunningDueMonitors}
            className="min-h-[44px] lg:min-h-[32px] flex-1 min-w-[200px] rounded border border-[var(--border-hairline)] bg-[var(--bg-canvas)] px-2.5 py-1 font-mono text-xs text-[var(--ink-primary)] placeholder:text-[var(--ink-muted)]"
          />
          <button
            type="button"
            onClick={onRunDueMonitors}
            disabled={isRunningDueMonitors || runningMonitorId !== null}
            className="min-h-[44px] lg:min-h-[32px] px-3 py-1 rounded border border-[var(--border-hairline)] bg-[var(--bg-surface)] font-mono text-xs font-semibold text-[var(--ink-primary)] hover:bg-[var(--bg-subtle)] disabled:opacity-40"
          >
            {isRunningDueMonitors ? "Running Due..." : "Run Due"}
          </button>
        </div>

        {monitors.length === 0 ? (
          <p className="text-xs font-mono text-[var(--ink-muted)]">
            No recurring monitors configured yet.
          </p>
        ) : (
          <ul className="divide-y divide-[var(--border-hairline)]">
            {monitors.map((m) => {
              const isRunning = runningMonitorId === m.monitor_id;
              return (
                <li
                  key={m.monitor_id}
                  className="flex flex-wrap items-center justify-between gap-3 py-2 text-xs"
                >
                  <div className="min-w-0 space-y-0.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono font-semibold text-[var(--ink-primary)] truncate">
                        {m.target_url}
                      </span>
                      <span className="rounded border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--ink-muted)] tabular-nums">
                        Every {m.cadence_hours}h
                      </span>
                      {m.crawl ? (
                        <span className="rounded border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--ink-primary)]">
                          Crawl
                        </span>
                      ) : null}
                    </div>
                    <p className="font-mono text-[11px] text-[var(--ink-muted)]">
                      {m.last_run_at_utc
                        ? `Last run: ${m.last_run_at_utc}`
                        : "Never run"}
                      {m.baseline_audit_id
                        ? ` · Baseline: ${m.baseline_audit_id}`
                        : ""}
                    </p>
                  </div>
                  <button
                    type="button"
                    disabled={runningMonitorId !== null}
                    onClick={() => onRunMonitor(m)}
                    className="min-h-[44px] lg:min-h-[28px] px-3 py-1 rounded border border-[var(--accent-verify)] bg-emerald-50 font-mono text-[11px] font-semibold text-[var(--accent-verify)] hover:bg-emerald-100 disabled:opacity-40"
                  >
                    {isRunning ? "Running..." : "Run Now"}
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </section>
    </div>
  );
}
