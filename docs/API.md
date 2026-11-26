# ServiceCore Compliance API Reference

Base URL (local development): `http://localhost:8000`  
OpenAPI / Swagger UI (when enabled): `/docs` and `/redoc` (controlled by `SERVICECORE_ENABLE_DOCS`)

All non-`GET`/`HEAD`/`OPTIONS` requests enforce a **1 MiB** (`1,048,576` bytes) request body limit, and every response includes security headers (`X-Request-ID`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`). Tenant-scoped routes (`/audits`, `/monitors`, `/dev/token`) also set `Cache-Control: no-store`.

---

## Authentication

Tenant-scoped endpoints require an HMAC-SHA256 signed bearer token in the `Authorization` header:

```http
Authorization: Bearer <token>
```

### Token Format & Claims

Tokens use a compact two-segment format: `<base64url_payload>.<base64url_hmac_sha256_signature>`, signed with `SERVICECORE_AUTH_SECRET`.

| Claim | Type | Required | Description |
| --- | --- | --- | --- |
| `org_id` | `string` | Yes | Tenant organization identifier; all audits, monitors, and events are strictly scoped to this `org_id`. |
| `sub` | `string` | Yes | Reviewer or actor subject identifier (recorded as `reviewer_id` and `actor_sub` in audit events). |
| `iat` | `integer` | No | Issued-at Unix timestamp (seconds). Set automatically by `mint_auth_token`. |
| `exp` | `integer` | No | Expiration Unix timestamp (seconds). Default TTL in `mint_auth_token` is `86400` seconds (24 hours). |

### Local Development Token (`POST /dev/token`)

When `SERVICECORE_DEV_MODE=1`, you can mint a local development token without configuring `SERVICECORE_AUTH_SECRET`:

```bash
curl -s -X POST http://localhost:8000/dev/token
```

Response (`200 OK`):

```json
{
  "token": "<base64url_payload>.<base64url_sig>",
  "org_id": "org_dev"
}
```

> **Note:** `POST /dev/token` returns `404 Not Found` whenever `SERVICECORE_DEV_MODE` is not `1`.

---

## Endpoints

### Operations

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/healthz` | None | Liveness probe returning `{"status": "ok"}`. |
| `GET` | `/healthcheck` | None | Alias for `/healthz` returning `{"status": "ok"}`. |
| `GET` | `/readyz` | None | Readiness probe; verifies SQLite connectivity (`SELECT 1;`) when `SQLiteAuditStore` is active (returns `503` on failure). |
| `GET` | `/metrics` | None | Operational metrics snapshot (`total_audits`, `total_monitors`, `processed_stripe_events`, `uptime_seconds`). |
| `POST` | `/dev/token` | None | Mints a dev bearer token for `org_dev` when `SERVICECORE_DEV_MODE=1` (otherwise `404`). |

### Audits & Chain of Custody

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/audits` | Bearer | List `AuditBundle` records for the authenticated `org_id`. Supports `limit` (`1..200`, default `50`) and `offset` (`>= 0`, default `0`). |
| `POST` | `/audits` | Bearer | Run a new web/PDF accessibility audit (`201 Created`). Body: `target_url`, `audit_price_usd` (`1500.0`), `crawl` (`false`), `max_pages` (`5`), `max_pdfs` (`5`). Rate-limited. |
| `GET` | `/audits/{audit_id}` | Bearer | Fetch a single `AuditBundle` scoped to the authenticated `org_id`. |
| `GET` | `/audits/{audit_id}/summary` | Bearer | Return lightweight `AuditSummary` executive counts (`total_findings`, review status counts, `critical_count`, `serious_count`, `signed`, `evidence_digest`, telemetry) without full findings payloads. |
| `DELETE` | `/audits/{audit_id}` | Bearer | Delete an audit scoped to the authenticated `org_id`, returning `{"deleted": true}`. |
| `GET` | `/audits/{audit_id}/events` | Bearer | Return chronological immutable `AuditEvent` chain-of-custody entries (`finding.reviewed`, `finding.bulk_reviewed`, `audit.exported`, `audit.exported_pdf`, `audit.published_github`). Supports `limit` (`1..200`, default `50`) and `offset` (`>= 0`, default `0`). |
| `GET` | `/audits/{audit_id}/diff` | Bearer | Compare `audit_id` against query parameter `baseline_id` (`?baseline_id=...`), returning a `DiffReport` (`new_regressions`, `resolved`, `persisting`, `reopened`). |

### Triage

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `PATCH` | `/audits/{audit_id}/findings/{finding_id}` | Bearer | Review a single finding (`status`: `APPROVED`, `REJECTED`, or `EDITED`; optional `rejection_reason`, `edited_after_snippet`). Sanitizes HTML, validates patch binding, clears prior bundle signature, and records a `finding.reviewed` event. |
| `POST` | `/audits/{audit_id}/findings/bulk-review` | Bearer | Bulk approve or reject findings (`status`: `APPROVED` or `REJECTED`; optional `finding_ids` list, optional `rejection_reason`). Validates patch binding on all approved items, clears prior bundle signature, and records a `finding.bulk_reviewed` event. |

### Certified Exports & Publishing

All export and publish endpoints execute `sign_bundle` and `verify_bundle` first. Every non-rejected finding must be `APPROVED` or `EDITED` or the request fails with `409 Conflict`.

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/audits/{audit_id}/export` | Bearer | Sign, verify, and return `ExportResponse` (`audit_id`, `evidence_digest`, `html_report`, `github_issues_markdown`). Records `audit.exported`. |
| `POST` | `/audits/{audit_id}/export/pdf` | Bearer | Sign, verify, and render a Certified PDF (`application/pdf`) with `Content-Disposition` and `X-Evidence-Digest` headers. Records `audit.exported_pdf`. |
| `GET` | `/audits/{audit_id}/export/sarif` | Bearer | Sign, verify, and export findings as SARIF `2.1.0` JSON for GitHub Code Scanning / CI ingestion. |
| `GET` | `/audits/{audit_id}/export/csv` | Bearer | Sign, verify, and export findings as formula-safe CSV (`text/csv; charset=utf-8`) with `Content-Disposition` and `X-Evidence-Digest` headers. |
| `POST` | `/audits/{audit_id}/publish/github` | Bearer | Sign, verify, and publish approved/edited findings to GitHub Issues. Body: `repo` (`owner/repo`), `github_token`. Records `audit.published_github`. |

### Monitors

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/monitors` | Bearer | Create a recurring `MonitorSchedule` (`201 Created`). Body: `target_url` (SSRF-validated on write), `cadence_hours` (`1..720`, default `24`), `crawl`, `max_pages`, `max_pdfs`. |
| `GET` | `/monitors` | Bearer | List `MonitorSchedule` records for the authenticated `org_id`. Supports `limit` (`1..200`, default `50`) and `offset` (`>= 0`, default `0`). |
| `PATCH` | `/monitors/{monitor_id}` | Bearer | Update a monitor's `enabled`, `cadence_hours`, or `crawl` settings. |
| `DELETE` | `/monitors/{monitor_id}` | Bearer | Delete a monitor scoped to the authenticated `org_id`, returning `{"deleted": true}`. |
| `POST` | `/monitors/{monitor_id}/run` | Bearer | Execute an immediate scan for `monitor_id`, diff against its `baseline_audit_id`, and return `MonitorRunResult`. |
| `POST` | `/monitors/run-due` | Bearer | Execute all due monitors for the authenticated `org_id`. Optional body: `{"webhook_url": "https://..."}` (SSRF-validated). Rate-limited. |

### Billing

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/webhooks/stripe` | `Stripe-Signature` | Verify Stripe webhook signature against `STRIPE_WEBHOOK_SECRET`, deduplicate by `event.id`, and return `{"status": "processed" | "duplicate"}`. |

---

## Webhook Security

When `run-due` dispatches regression alerts (`new_regressions > 0`), ServiceCore validates `webhook_url` against SSRF (`validate_public_url`) and sends a `POST` request with canonical JSON (`sort_keys=True`, compact separators) and the following headers:

| Header | Description |
| --- | --- |
| `X-ServiceCore-Event` | Event type identifier (`monitor.regression`). |
| `X-ServiceCore-Signature-256` | HMAC-SHA256 signature formatted as `sha256=<hex_digest>` over the raw UTF-8 request body, computed with `SERVICECORE_WEBHOOK_SECRET` (omitted if no secret is configured). |

### Verifying Signatures

Consumers can verify incoming webhook deliveries in constant time using `verify_webhook_signature` from `servicecore.alerts`:

```python
from servicecore.alerts import verify_webhook_signature

is_valid = verify_webhook_signature(
    raw_body=request_body_bytes,
    signature_header=headers.get("X-ServiceCore-Signature-256"),
    secret=os.environ["SERVICECORE_WEBHOOK_SECRET"],
)
if not is_valid:
    raise ValueError("Invalid ServiceCore webhook signature")
```

---

## Standard Error Codes

| Status Code | Meaning | Common Causes |
| --- | --- | --- |
| `400` | Bad Request | Scanner execution failure (`ScannerError`), invalid Stripe signature, malformed webhook JSON, or missing Stripe event `id`. |
| `401` | Unauthorized | Missing `Authorization: Bearer` header, invalid token format, bad HMAC signature, or expired `exp` claim. |
| `404` | Not Found | Audit, finding, monitor, or baseline audit does not exist (or belongs to another `org_id`), or `POST /dev/token` called when `SERVICECORE_DEV_MODE != 1`. |
| `409` | Conflict | Export or publish attempted while findings remain `PENDING`, or bundle digest verification failed. |
| `413` | Payload Too Large | Request body exceeds the 1 MiB (`1,048,576` bytes) limit. |
| `422` | Unprocessable Content | Request schema validation failure, SSRF-blocked target/webhook URL, unsafe HTML in `edited_after_snippet`, or patch-binding mismatch. |
| `429` | Too Many Requests | Sliding-window rate limit exceeded on `POST /audits` or `POST /monitors/run-due`. Includes a `Retry-After` header (seconds). |
