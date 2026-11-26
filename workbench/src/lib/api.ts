import type {
  AuditBundle,
  DiffReport,
  MonitorRunResult,
  MonitorSchedule,
  PublishGitHubResponse,
  ReviewStatus,
} from "@/types/audit";

export interface DevTokenResponse {
  token: string;
  org_id: string;
}

export interface CreateAuditOptions {
  crawl?: boolean;
  maxPages?: number;
  maxPdfs?: number;
  signal?: AbortSignal;
}

export interface CreateMonitorOptions {
  cadenceHours?: number;
  crawl?: boolean;
  maxPages?: number;
  maxPdfs?: number;
  signal?: AbortSignal;
}

export interface RunDueMonitorsOptions {
  webhookUrl?: string;
  signal?: AbortSignal;
}

export interface PatchFindingReviewPayload {
  status: Exclude<ReviewStatus, "PENDING">;
  rejection_reason?: string | null;
  edited_after_snippet?: string | null;
}

export interface BulkReviewFindingsOptions {
  findingIds?: string[];
  rejectionReason?: string | null;
}

export interface ExportAuditResponse {
  audit_id: string;
  evidence_digest: string;
  html_report: string;
  github_issues_markdown: string;
}

/**
 * Error thrown when the ServiceCore API returns a non-2xx response.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly detail: string;

  constructor(status: number, detail: string) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

/**
 * Resolve the configured ServiceCore FastAPI base URL without trailing slash.
 */
export function getApiBaseUrl(): string {
  const raw =
    process.env.NEXT_PUBLIC_SERVICECORE_API_URL ?? "http://localhost:8000";
  return raw.replace(/\/+$/, "");
}

async function parseErrorDetail(res: Response): Promise<string> {
  try {
    const data: unknown = await res.json();
    if (
      typeof data === "object" &&
      data !== null &&
      "detail" in data &&
      typeof (data as { detail: unknown }).detail === "string"
    ) {
      return (data as { detail: string }).detail;
    }
  } catch {
    // Ignore non-JSON error bodies and fall back to status text.
  }
  return res.statusText || `HTTP ${res.status}`;
}

async function requestJson<T>(
  path: string,
  init: RequestInit & { token?: string } = {},
): Promise<T> {
  const { token, headers, ...rest } = init;
  const mergedHeaders = new Headers(headers);
  if (!mergedHeaders.has("Content-Type") && rest.body !== undefined) {
    mergedHeaders.set("Content-Type", "application/json");
  }
  if (token) {
    mergedHeaders.set("Authorization", `Bearer ${token}`);
  }

  const res = await fetch(`${getApiBaseUrl()}${path}`, {
    ...rest,
    headers: mergedHeaders,
  });

  if (!res.ok) {
    const detail = await parseErrorDetail(res);
    throw new ApiError(res.status, detail);
  }

  return (await res.json()) as T;
}

/**
 * Mint a local development bearer token when SERVICECORE_DEV_MODE=1 is enabled.
 */
export async function bootstrapDevToken(
  signal?: AbortSignal,
): Promise<DevTokenResponse> {
  return requestJson<DevTokenResponse>("/dev/token", {
    method: "POST",
    signal,
  });
}

/**
 * Fetch all AuditBundles belonging to the authenticated tenant.
 */
export async function fetchAudits(
  token: string,
  signal?: AbortSignal,
): Promise<AuditBundle[]> {
  return requestJson<AuditBundle[]>("/audits", {
    method: "GET",
    token,
    signal,
  });
}

/**
 * Trigger a new accessibility/compliance scan and persist the resulting AuditBundle.
 */
export async function createAudit(
  targetUrl: string,
  token: string,
  options?: CreateAuditOptions,
): Promise<AuditBundle> {
  const payload: Record<string, unknown> = { target_url: targetUrl };
  if (options?.crawl !== undefined) {
    payload.crawl = options.crawl;
  }
  if (options?.maxPages !== undefined) {
    payload.max_pages = options.maxPages;
  }
  if (options?.maxPdfs !== undefined) {
    payload.max_pdfs = options.maxPdfs;
  }
  return requestJson<AuditBundle>("/audits", {
    method: "POST",
    token,
    body: JSON.stringify(payload),
    signal: options?.signal,
  });
}

/**
 * Persist a human-in-the-loop review decision (and optional edited snippet) for a finding.
 */
export async function patchFindingReview(
  token: string,
  auditId: string,
  findingId: string,
  payload: PatchFindingReviewPayload,
): Promise<AuditBundle> {
  return requestJson<AuditBundle>(
    `/audits/${encodeURIComponent(auditId)}/findings/${encodeURIComponent(findingId)}`,
    {
      method: "PATCH",
      token,
      body: JSON.stringify(payload),
    },
  );
}

/**
 * Bulk-review multiple findings (or all pending bound findings) in a single request.
 */
export async function bulkReviewFindings(
  auditId: string,
  status: "APPROVED" | "REJECTED",
  token: string,
  options?: BulkReviewFindingsOptions,
): Promise<AuditBundle> {
  const payload: Record<string, unknown> = { status };
  if (options?.findingIds !== undefined) {
    payload.finding_ids = options.findingIds;
  }
  if (options?.rejectionReason !== undefined) {
    payload.rejection_reason = options.rejectionReason;
  }
  return requestJson<AuditBundle>(
    `/audits/${encodeURIComponent(auditId)}/findings/bulk-review`,
    {
      method: "POST",
      token,
      body: JSON.stringify(payload),
    },
  );
}

/**
 * Sign and export a certified AuditBundle, returning its SHA-256 digest and artifacts.
 */
export async function exportAudit(
  token: string,
  auditId: string,
): Promise<ExportAuditResponse> {
  return requestJson<ExportAuditResponse>(
    `/audits/${encodeURIComponent(auditId)}/export`,
    {
      method: "POST",
      token,
    },
  );
}

/**
 * Export and download a certified AuditBundle PDF, returning the PDF Blob and X-Evidence-Digest header.
 */
export async function exportAuditPdf(
  auditId: string,
  token: string,
): Promise<{ blob: Blob; digest: string | null }> {
  const res = await fetch(
    `${getApiBaseUrl()}/audits/${encodeURIComponent(auditId)}/export/pdf`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    },
  );

  if (!res.ok) {
    const detail = await parseErrorDetail(res);
    throw new ApiError(res.status, detail);
  }

  const blob = await res.blob();
  const digest = res.headers.get("X-Evidence-Digest");
  return { blob, digest };
}

/**
 * Fetch a component-level regression diff comparing the current audit against a baseline audit.
 */
export async function fetchAuditDiff(
  auditId: string,
  baselineId: string,
  token: string,
  signal?: AbortSignal,
): Promise<DiffReport> {
  return requestJson<DiffReport>(
    `/audits/${encodeURIComponent(auditId)}/diff?baseline_id=${encodeURIComponent(baselineId)}`,
    {
      method: "GET",
      token,
      signal,
    },
  );
}

/**
 * Publish certified audit findings as GitHub issues via the ServiceCore API.
 */
export async function publishAuditToGitHub(
  auditId: string,
  repo: string,
  githubToken: string,
  token: string,
): Promise<PublishGitHubResponse> {
  return requestJson<PublishGitHubResponse>(
    `/audits/${encodeURIComponent(auditId)}/publish/github`,
    {
      method: "POST",
      token,
      body: JSON.stringify({ repo, github_token: githubToken }),
    },
  );
}

/**
 * Fetch all recurring MonitorSchedules belonging to the authenticated tenant.
 */
export async function fetchMonitors(
  token: string,
  signal?: AbortSignal,
): Promise<MonitorSchedule[]> {
  return requestJson<MonitorSchedule[]>("/monitors", {
    method: "GET",
    token,
    signal,
  });
}

/**
 * Create a new recurring MonitorSchedule for a target URL.
 */
export async function createMonitor(
  targetUrl: string,
  token: string,
  options?: CreateMonitorOptions,
): Promise<MonitorSchedule> {
  const payload: Record<string, unknown> = { target_url: targetUrl };
  if (options?.cadenceHours !== undefined) {
    payload.cadence_hours = options.cadenceHours;
  }
  if (options?.crawl !== undefined) {
    payload.crawl = options.crawl;
  }
  if (options?.maxPages !== undefined) {
    payload.max_pages = options.maxPages;
  }
  if (options?.maxPdfs !== undefined) {
    payload.max_pdfs = options.maxPdfs;
  }
  return requestJson<MonitorSchedule>("/monitors", {
    method: "POST",
    token,
    body: JSON.stringify(payload),
    signal: options?.signal,
  });
}

/**
 * Execute a recurring MonitorSchedule immediately, returning the updated monitor,
 * new AuditBundle, and optional regression DiffReport against the prior baseline.
 */
export async function runMonitor(
  monitorId: string,
  token: string,
  signal?: AbortSignal,
): Promise<MonitorRunResult> {
  return requestJson<MonitorRunResult>(
    `/monitors/${encodeURIComponent(monitorId)}/run`,
    {
      method: "POST",
      token,
      signal,
    },
  );
}

/**
 * Trigger all due MonitorSchedules for the authenticated tenant, optionally
 * delivering a webhook notification, and return their MonitorRunResults.
 */
export async function runDueMonitors(
  token: string,
  options?: RunDueMonitorsOptions,
): Promise<MonitorRunResult[]> {
  return requestJson<MonitorRunResult[]>("/monitors/run-due", {
    method: "POST",
    token,
    body: JSON.stringify({ webhook_url: options?.webhookUrl || null }),
    signal: options?.signal,
  });
}

/**
 * Export a SARIF 2.1.0 report for an audit from the ServiceCore API.
 */
export async function exportAuditSarif(
  auditId: string,
  token: string,
): Promise<Record<string, unknown>> {
  return requestJson<Record<string, unknown>>(
    `/audits/${encodeURIComponent(auditId)}/export/sarif`,
    {
      method: "GET",
      token,
    },
  );
}

/**
 * Export an audit's findings and review decisions as CSV text.
 */
export async function exportAuditCsv(
  auditId: string,
  token: string,
): Promise<string> {
  const res = await fetch(
    `${getApiBaseUrl()}/audits/${encodeURIComponent(auditId)}/export/csv`,
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    },
  );

  if (!res.ok) {
    const detail = await parseErrorDetail(res);
    throw new ApiError(res.status, detail);
  }

  return res.text();
}

/**
 * Update a recurring MonitorSchedule (e.g. pause/resume or adjust cadence).
 */
export async function updateMonitor(
  monitorId: string,
  updates: { enabled?: boolean; cadence_hours?: number; crawl?: boolean },
  token: string,
): Promise<MonitorSchedule> {
  return requestJson<MonitorSchedule>(
    `/monitors/${encodeURIComponent(monitorId)}`,
    {
      method: "PATCH",
      token,
      body: JSON.stringify(updates),
    },
  );
}

/**
 * Delete a recurring MonitorSchedule by ID.
 */
export async function deleteMonitor(
  monitorId: string,
  token: string,
): Promise<{ deleted: boolean }> {
  return requestJson<{ deleted: boolean }>(
    `/monitors/${encodeURIComponent(monitorId)}`,
    {
      method: "DELETE",
      token,
    },
  );
}

/**
 * Delete an AuditBundle by ID.
 */
export async function deleteAudit(
  auditId: string,
  token: string,
): Promise<{ deleted: boolean }> {
  return requestJson<{ deleted: boolean }>(
    `/audits/${encodeURIComponent(auditId)}`,
    {
      method: "DELETE",
      token,
    },
  );
}
