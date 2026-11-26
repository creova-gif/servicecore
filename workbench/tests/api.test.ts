import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it } from "node:test";
import {
  ApiError,
  bootstrapDevToken,
  createAudit,
  createMonitor,
  deleteAudit,
  deleteMonitor,
  exportAudit,
  exportAuditCsv,
  exportAuditPdf,
  exportAuditSarif,
  fetchAuditDiff,
  fetchAudits,
  fetchMonitors,
  getApiBaseUrl,
  patchFindingReview,
  publishAuditToGitHub,
  runDueMonitors,
  runMonitor,
  updateMonitor,
} from "../src/lib/api";
import type {
  AuditBundle,
  DiffReport,
  MonitorRunResult,
  MonitorSchedule,
  PublishGitHubResponse,
} from "../src/types/audit";

interface CapturedCall {
  url: string;
  init: RequestInit | undefined;
}

const originalFetch = globalThis.fetch;
const originalApiUrl = process.env.NEXT_PUBLIC_SERVICECORE_API_URL;

function makeAuditBundle(overrides: Partial<AuditBundle> = {}): AuditBundle {
  return {
    audit_id: "aud_123",
    org_id: "org_abc",
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

function mockFetch(
  handler: (url: string, init?: RequestInit) => Response | Promise<Response>,
): CapturedCall[] {
  const calls: CapturedCall[] = [];
  globalThis.fetch = (async (
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push({ url, init });
    return handler(url, init);
  }) as typeof fetch;
  return calls;
}

beforeEach(() => {
  delete process.env.NEXT_PUBLIC_SERVICECORE_API_URL;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalApiUrl === undefined) {
    delete process.env.NEXT_PUBLIC_SERVICECORE_API_URL;
  } else {
    process.env.NEXT_PUBLIC_SERVICECORE_API_URL = originalApiUrl;
  }
});

describe("getApiBaseUrl", () => {
  it("returns default localhost URL when env var is unset", () => {
    assert.equal(getApiBaseUrl(), "http://localhost:8000");
  });

  it("uses NEXT_PUBLIC_SERVICECORE_API_URL and strips trailing slashes", () => {
    process.env.NEXT_PUBLIC_SERVICECORE_API_URL = "https://api.servicecore.dev///";
    assert.equal(getApiBaseUrl(), "https://api.servicecore.dev");
  });
});

describe("bootstrapDevToken", () => {
  it("returns token and org_id on 200", async () => {
    const calls = mockFetch(() =>
      Response.json({ token: "dev-jwt-123", org_id: "org_dev" }, { status: 200 }),
    );

    const res = await bootstrapDevToken();
    assert.deepEqual(res, { token: "dev-jwt-123", org_id: "org_dev" });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "http://localhost:8000/dev/token");
    assert.equal(calls[0].init?.method, "POST");
  });

  it("throws ApiError with status 404 when dev token endpoint is disabled", async () => {
    mockFetch(() =>
      Response.json({ detail: "Not Found" }, { status: 404, statusText: "Not Found" }),
    );

    await assert.rejects(
      () => bootstrapDevToken(),
      (err: unknown) => {
        assert.ok(err instanceof ApiError);
        assert.equal(err.status, 404);
        assert.equal(err.detail, "Not Found");
        return true;
      },
    );
  });
});

describe("audit API client functions", () => {
  it("fetchAudits sends GET /audits with bearer token", async () => {
    const bundle = makeAuditBundle();
    const calls = mockFetch(() => Response.json([bundle], { status: 200 }));

    const res = await fetchAudits("tok_1");
    assert.deepEqual(res, [bundle]);
    assert.equal(calls[0].url, "http://localhost:8000/audits");
    assert.equal(calls[0].init?.method, "GET");
    const headers = new Headers(calls[0].init?.headers);
    assert.equal(headers.get("Authorization"), "Bearer tok_1");
  });

  it("createAudit sends POST /audits with JSON body and bearer token", async () => {
    const bundle = makeAuditBundle({ target_url: "https://acme.ca" });
    const calls = mockFetch(() => Response.json(bundle, { status: 201 }));

    const res = await createAudit("https://acme.ca", "tok_2");
    assert.deepEqual(res, bundle);
    assert.equal(calls[0].url, "http://localhost:8000/audits");
    assert.equal(calls[0].init?.method, "POST");
    assert.equal(
      calls[0].init?.body,
      JSON.stringify({ target_url: "https://acme.ca" }),
    );
    const headers = new Headers(calls[0].init?.headers);
    assert.equal(headers.get("Authorization"), "Bearer tok_2");
    assert.equal(headers.get("Content-Type"), "application/json");
  });

  it("createAudit includes crawl, max_pages, and max_pdfs when provided", async () => {
    const bundle = makeAuditBundle({ target_url: "https://acme.ca" });
    const calls = mockFetch(() => Response.json(bundle, { status: 201 }));

    const res = await createAudit("https://acme.ca", "tok_crawl", {
      crawl: true,
      maxPages: 10,
      maxPdfs: 3,
    });
    assert.deepEqual(res, bundle);
    assert.equal(calls[0].url, "http://localhost:8000/audits");
    assert.equal(calls[0].init?.method, "POST");
    assert.equal(
      calls[0].init?.body,
      JSON.stringify({
        target_url: "https://acme.ca",
        crawl: true,
        max_pages: 10,
        max_pdfs: 3,
      }),
    );
    const headers = new Headers(calls[0].init?.headers);
    assert.equal(headers.get("Authorization"), "Bearer tok_crawl");
  });

  it("patchFindingReview sends PATCH with encoded IDs and payload", async () => {
    const bundle = makeAuditBundle();
    const calls = mockFetch(() => Response.json(bundle, { status: 200 }));

    const res = await patchFindingReview("tok_3", "aud/1", "find#2", {
      status: "EDITED",
      rejection_reason: null,
      edited_after_snippet: "<img alt='Logo' />",
    });
    assert.deepEqual(res, bundle);
    assert.equal(
      calls[0].url,
      "http://localhost:8000/audits/aud%2F1/findings/find%232",
    );
    assert.equal(calls[0].init?.method, "PATCH");
    assert.equal(
      calls[0].init?.body,
      JSON.stringify({
        status: "EDITED",
        rejection_reason: null,
        edited_after_snippet: "<img alt='Logo' />",
      }),
    );
  });

  it("exportAudit sends POST /audits/:id/export and returns export artifacts", async () => {
    const payload = {
      audit_id: "aud_123",
      evidence_digest: "sha256:deadbeef",
      html_report: "<html></html>",
      github_issues_markdown: "# Issues",
    };
    const calls = mockFetch(() => Response.json(payload, { status: 200 }));

    const res = await exportAudit("tok_4", "aud_123");
    assert.deepEqual(res, payload);
    assert.equal(calls[0].url, "http://localhost:8000/audits/aud_123/export");
    assert.equal(calls[0].init?.method, "POST");
  });

  it("exportAuditPdf returns blob and X-Evidence-Digest header", async () => {
    const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
    const calls = mockFetch(
      () =>
        new Response(pdfBytes, {
          status: 200,
          headers: {
            "Content-Type": "application/pdf",
            "X-Evidence-Digest": "sha256:cafebabe",
          },
        }),
    );

    const { blob, digest } = await exportAuditPdf("aud_123", "tok_5");
    assert.equal(digest, "sha256:cafebabe");
    assert.equal(blob.size, 4);
    assert.deepEqual(new Uint8Array(await blob.arrayBuffer()), pdfBytes);
    assert.equal(calls[0].url, "http://localhost:8000/audits/aud_123/export/pdf");
    assert.equal(calls[0].init?.method, "POST");
    const headers = new Headers(calls[0].init?.headers);
    assert.equal(headers.get("Authorization"), "Bearer tok_5");
  });

  it("exportAuditSarif sends GET /audits/:id/export/sarif with bearer token", async () => {
    const sarifPayload = {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [{ tool: { driver: { name: "servicecore" } }, results: [] }],
    };
    const calls = mockFetch(() => Response.json(sarifPayload, { status: 200 }));

    const res = await exportAuditSarif("aud/1", "tok_sarif");
    assert.deepEqual(res, sarifPayload);
    assert.equal(
      calls[0].url,
      "http://localhost:8000/audits/aud%2F1/export/sarif",
    );
    assert.equal(calls[0].init?.method, "GET");
    const headers = new Headers(calls[0].init?.headers);
    assert.equal(headers.get("Authorization"), "Bearer tok_sarif");
  });

  it("exportAuditCsv sends GET /audits/:id/export/csv and returns CSV text", async () => {
    const csvBody = "finding_id,rule_id,status\nf_1,image-alt,APPROVED\n";
    const calls = mockFetch(
      () =>
        new Response(csvBody, {
          status: 200,
          headers: { "Content-Type": "text/csv" },
        }),
    );

    const res = await exportAuditCsv("aud/1", "tok_csv");
    assert.equal(res, csvBody);
    assert.equal(
      calls[0].url,
      "http://localhost:8000/audits/aud%2F1/export/csv",
    );
    assert.equal(calls[0].init?.method, "GET");
    const headers = new Headers(calls[0].init?.headers);
    assert.equal(headers.get("Authorization"), "Bearer tok_csv");
  });

  it("exportAuditCsv throws ApiError on non-2xx response", async () => {
    mockFetch(() =>
      Response.json(
        { detail: "Audit not found" },
        { status: 404, statusText: "Not Found" },
      ),
    );

    await assert.rejects(
      () => exportAuditCsv("aud_missing", "tok_csv"),
      (err: unknown) => {
        assert.ok(err instanceof ApiError);
        assert.equal(err.status, 404);
        assert.equal(err.detail, "Audit not found");
        return true;
      },
    );
  });

  it("deleteAudit sends DELETE /audits/:id with bearer token", async () => {
    const calls = mockFetch(() =>
      Response.json({ deleted: true }, { status: 200 }),
    );

    const res = await deleteAudit("aud/1", "tok_aud_del");
    assert.deepEqual(res, { deleted: true });
    assert.equal(calls[0].url, "http://localhost:8000/audits/aud%2F1");
    assert.equal(calls[0].init?.method, "DELETE");
    const headers = new Headers(calls[0].init?.headers);
    assert.equal(headers.get("Authorization"), "Bearer tok_aud_del");
  });

  it("fetchAuditDiff sends GET /audits/:id/diff?baseline_id=... with bearer token", async () => {
    const report: DiffReport = {
      baseline_audit_id: "aud/base",
      current_audit_id: "aud/curr",
      new_regressions: [
        {
          component_fingerprint: "fp_new",
          rule_id: "image-alt",
          status: "NEW_REGRESSION",
          target_selector: "img.hero",
          target_url: "https://example.com",
        },
      ],
      fixed: [],
      persistent: [],
    };
    const calls = mockFetch(() => Response.json(report, { status: 200 }));

    const res = await fetchAuditDiff("aud/curr", "aud/base", "tok_diff");
    assert.deepEqual(res, report);
    assert.equal(
      calls[0].url,
      "http://localhost:8000/audits/aud%2Fcurr/diff?baseline_id=aud%2Fbase",
    );
    assert.equal(calls[0].init?.method, "GET");
    const headers = new Headers(calls[0].init?.headers);
    assert.equal(headers.get("Authorization"), "Bearer tok_diff");
  });

  it("publishAuditToGitHub sends POST /audits/:id/publish/github with repo and github_token", async () => {
    const payload: PublishGitHubResponse = {
      audit_id: "aud/1",
      issues_created: 1,
      issues: [
        {
          finding_id: "f_1",
          issue_number: 42,
          html_url: "https://github.com/acme/web/issues/42",
          title: "[AODA] Fix image-alt on img.hero",
        },
      ],
    };
    const calls = mockFetch(() => Response.json(payload, { status: 200 }));

    const res = await publishAuditToGitHub(
      "aud/1",
      "acme/web",
      "ghp_secret123",
      "tok_pub",
    );
    assert.deepEqual(res, payload);
    assert.equal(
      calls[0].url,
      "http://localhost:8000/audits/aud%2F1/publish/github",
    );
    assert.equal(calls[0].init?.method, "POST");
    assert.equal(
      calls[0].init?.body,
      JSON.stringify({ repo: "acme/web", github_token: "ghp_secret123" }),
    );
    const headers = new Headers(calls[0].init?.headers);
    assert.equal(headers.get("Authorization"), "Bearer tok_pub");
    assert.equal(headers.get("Content-Type"), "application/json");
  });
});

describe("monitor API client functions", () => {
  function makeMonitor(overrides: Partial<MonitorSchedule> = {}): MonitorSchedule {
    return {
      monitor_id: "mon-abc123",
      org_id: "org_abc",
      target_url: "https://example.com",
      cadence_hours: 24,
      crawl: false,
      max_pages: 5,
      max_pdfs: 5,
      baseline_audit_id: null,
      last_run_at_utc: null,
      enabled: true,
      ...overrides,
    };
  }

  it("fetchMonitors sends GET /monitors with bearer token", async () => {
    const monitor = makeMonitor();
    const calls = mockFetch(() => Response.json([monitor], { status: 200 }));

    const res = await fetchMonitors("tok_mon_1");
    assert.deepEqual(res, [monitor]);
    assert.equal(calls[0].url, "http://localhost:8000/monitors");
    assert.equal(calls[0].init?.method, "GET");
    const headers = new Headers(calls[0].init?.headers);
    assert.equal(headers.get("Authorization"), "Bearer tok_mon_1");
  });

  it("createMonitor sends POST /monitors with target_url and optional fields", async () => {
    const monitor = makeMonitor({
      target_url: "https://acme.ca",
      cadence_hours: 12,
      crawl: true,
      max_pages: 8,
      max_pdfs: 2,
    });
    const calls = mockFetch(() => Response.json(monitor, { status: 201 }));

    const res = await createMonitor("https://acme.ca", "tok_mon_2", {
      cadenceHours: 12,
      crawl: true,
      maxPages: 8,
      maxPdfs: 2,
    });
    assert.deepEqual(res, monitor);
    assert.equal(calls[0].url, "http://localhost:8000/monitors");
    assert.equal(calls[0].init?.method, "POST");
    assert.equal(
      calls[0].init?.body,
      JSON.stringify({
        target_url: "https://acme.ca",
        cadence_hours: 12,
        crawl: true,
        max_pages: 8,
        max_pdfs: 2,
      }),
    );
    const headers = new Headers(calls[0].init?.headers);
    assert.equal(headers.get("Authorization"), "Bearer tok_mon_2");
    assert.equal(headers.get("Content-Type"), "application/json");
  });

  it("runMonitor sends POST /monitors/:id/run and returns MonitorRunResult", async () => {
    const bundle = makeAuditBundle({ audit_id: "aud_mon_2" });
    const diff: DiffReport = {
      baseline_audit_id: "aud_mon_1",
      current_audit_id: "aud_mon_2",
      new_regressions: [],
      fixed: [],
      persistent: [],
    };
    const payload: MonitorRunResult = {
      monitor: makeMonitor({
        monitor_id: "mon/1",
        baseline_audit_id: "aud_mon_2",
        last_run_at_utc: "2026-11-26T08:00:00Z",
      }),
      audit: bundle,
      diff,
    };
    const calls = mockFetch(() => Response.json(payload, { status: 200 }));

    const res = await runMonitor("mon/1", "tok_mon_3");
    assert.deepEqual(res, payload);
    assert.equal(calls[0].url, "http://localhost:8000/monitors/mon%2F1/run");
    assert.equal(calls[0].init?.method, "POST");
    const headers = new Headers(calls[0].init?.headers);
    assert.equal(headers.get("Authorization"), "Bearer tok_mon_3");
  });

  it("runDueMonitors sends POST /monitors/run-due with bearer token and optional webhook_url", async () => {
    const bundle = makeAuditBundle({ audit_id: "aud_due_1" });
    const payload: MonitorRunResult[] = [
      {
        monitor: makeMonitor({
          monitor_id: "mon_due_1",
          baseline_audit_id: "aud_due_1",
          last_run_at_utc: "2026-11-26T08:30:00Z",
        }),
        audit: bundle,
        diff: null,
      },
    ];
    const calls = mockFetch(() => Response.json(payload, { status: 200 }));

    const resWithoutWebhook = await runDueMonitors("tok_due_1");
    assert.deepEqual(resWithoutWebhook, payload);
    assert.equal(calls[0].url, "http://localhost:8000/monitors/run-due");
    assert.equal(calls[0].init?.method, "POST");
    assert.equal(calls[0].init?.body, JSON.stringify({ webhook_url: null }));
    const headers0 = new Headers(calls[0].init?.headers);
    assert.equal(headers0.get("Authorization"), "Bearer tok_due_1");
    assert.equal(headers0.get("Content-Type"), "application/json");

    const resWithWebhook = await runDueMonitors("tok_due_2", {
      webhookUrl: "https://hooks.example.com/servicecore",
    });
    assert.deepEqual(resWithWebhook, payload);
    assert.equal(calls[1].url, "http://localhost:8000/monitors/run-due");
    assert.equal(calls[1].init?.method, "POST");
    assert.equal(
      calls[1].init?.body,
      JSON.stringify({ webhook_url: "https://hooks.example.com/servicecore" }),
    );
    const headers1 = new Headers(calls[1].init?.headers);
    assert.equal(headers1.get("Authorization"), "Bearer tok_due_2");
  });

  it("updateMonitor sends PATCH /monitors/:id with JSON updates and bearer token", async () => {
    const updated = makeMonitor({
      monitor_id: "mon/1",
      enabled: false,
      cadence_hours: 48,
      crawl: true,
    });
    const calls = mockFetch(() => Response.json(updated, { status: 200 }));

    const res = await updateMonitor(
      "mon/1",
      { enabled: false, cadence_hours: 48, crawl: true },
      "tok_mon_upd",
    );
    assert.deepEqual(res, updated);
    assert.equal(calls[0].url, "http://localhost:8000/monitors/mon%2F1");
    assert.equal(calls[0].init?.method, "PATCH");
    assert.equal(
      calls[0].init?.body,
      JSON.stringify({ enabled: false, cadence_hours: 48, crawl: true }),
    );
    const headers = new Headers(calls[0].init?.headers);
    assert.equal(headers.get("Authorization"), "Bearer tok_mon_upd");
    assert.equal(headers.get("Content-Type"), "application/json");
  });

  it("deleteMonitor sends DELETE /monitors/:id with bearer token", async () => {
    const calls = mockFetch(() =>
      Response.json({ deleted: true }, { status: 200 }),
    );

    const res = await deleteMonitor("mon/1", "tok_mon_del");
    assert.deepEqual(res, { deleted: true });
    assert.equal(calls[0].url, "http://localhost:8000/monitors/mon%2F1");
    assert.equal(calls[0].init?.method, "DELETE");
    const headers = new Headers(calls[0].init?.headers);
    assert.equal(headers.get("Authorization"), "Bearer tok_mon_del");
  });
});

describe("ApiError handling", () => {
  it("throws ApiError with status 409 and detail on conflict", async () => {
    mockFetch(() =>
      Response.json(
        { detail: "Audit has pending findings that must be reviewed" },
        { status: 409, statusText: "Conflict" },
      ),
    );

    await assert.rejects(
      () => exportAudit("tok_err", "aud_123"),
      (err: unknown) => {
        assert.ok(err instanceof ApiError);
        assert.equal(err.name, "ApiError");
        assert.equal(err.status, 409);
        assert.equal(err.detail, "Audit has pending findings that must be reviewed");
        assert.equal(err.message, "Audit has pending findings that must be reviewed");
        return true;
      },
    );
  });

  it("throws ApiError with status 422 and detail on validation error", async () => {
    mockFetch(() =>
      Response.json(
        { detail: "rejection_reason is required when status is REJECTED" },
        { status: 422, statusText: "Unprocessable Entity" },
      ),
    );

    await assert.rejects(
      () =>
        patchFindingReview("tok_err", "aud_123", "f_1", {
          status: "REJECTED",
        }),
      (err: unknown) => {
        assert.ok(err instanceof ApiError);
        assert.equal(err.status, 422);
        assert.equal(
          err.detail,
          "rejection_reason is required when status is REJECTED",
        );
        return true;
      },
    );
  });

  it("falls back to statusText when error body is not JSON", async () => {
    mockFetch(
      () =>
        new Response("Bad Gateway", {
          status: 502,
          statusText: "Bad Gateway",
        }),
    );

    await assert.rejects(
      () => exportAuditPdf("aud_123", "tok_err"),
      (err: unknown) => {
        assert.ok(err instanceof ApiError);
        assert.equal(err.status, 502);
        assert.equal(err.detail, "Bad Gateway");
        return true;
      },
    );
  });
});
