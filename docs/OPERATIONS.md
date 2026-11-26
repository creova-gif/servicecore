# ServiceCore Operations, Backup/DR & Incident Response Runbook

This runbook covers production observability, online SQLite WAL backup and disaster recovery, secret rotation, and incident response procedures for the ServiceCore Compliance API and CLI.

For endpoint contracts and authentication details, see [docs/API.md](API.md) and [SECURITY.md](../SECURITY.md).

---

## 1. Probes & Observability

### Health, Readiness & Metrics Endpoints

All operational probes are unauthenticated so container orchestrators, load balancers, and Prometheus scrapers can query them directly:

| Endpoint | Content-Type | Purpose | Failure Behavior |
| --- | --- | --- | --- |
| `GET /healthz` (alias `GET /healthcheck`) | `application/json` | Liveness probe returning `{"status": "ok"}`. | Non-200 only if the ASGI process is unresponsive. |
| `GET /readyz` | `application/json` | Readiness probe returning `{"status": "ready"}`. When `SQLiteAuditStore` is active, executes `SELECT 1;` under `active_store._lock`. | Returns `503 Service Unavailable` (`"Database readiness check failed"`) if SQLite cannot be queried. |
| `GET /metrics` | `application/json` | JSON operational snapshot (`total_audits`, `total_monitors`, `processed_stripe_events`, `uptime_seconds`). | Returns `500` if store stats fail. |
| `GET /metrics/prometheus` | `text/plain; version=0.0.4; charset=utf-8` | Prometheus text exposition endpoint. | Returns `500` if store stats fail. |

#### Prometheus Metric Families

`GET /metrics/prometheus` emits the following metrics:

```text
# HELP servicecore_audits_total Total number of stored accessibility audits.
# TYPE servicecore_audits_total gauge
servicecore_audits_total 12
# HELP servicecore_monitors_total Total number of configured compliance monitors.
# TYPE servicecore_monitors_total gauge
servicecore_monitors_total 3
# HELP servicecore_stripe_events_total Total number of processed Stripe webhook events.
# TYPE servicecore_stripe_events_total counter
servicecore_stripe_events_total 4
# HELP servicecore_uptime_seconds Application uptime in seconds.
# TYPE servicecore_uptime_seconds gauge
servicecore_uptime_seconds 842.195
```

### Structured JSON Logging

Every HTTP request handled by `security_headers_middleware` in `src/servicecore/api.py` emits a single-line JSON log record via the `servicecore.api` logger (`_api_logger`) and propagates `X-Request-ID` on the response:

```json
{"request_id":"req-log-42","method":"GET","path":"/readyz","status_code":200,"duration_ms":1.247}
```

- `request_id`: Taken from the incoming `X-Request-ID` header if present, otherwise generated as a UUIDv4.
- `method`: HTTP method (`GET`, `POST`, `PATCH`, `DELETE`, etc.).
- `path`: Request URL path (e.g., `/audits`, `/readyz`).
- `status_code`: HTTP response status code.
- `duration_ms`: End-to-end request duration in milliseconds, rounded to 3 decimal places.

---

## 2. Online SQLite WAL Backup & Disaster Recovery

`SQLiteAuditStore` runs with `PRAGMA journal_mode=WAL;`, `PRAGMA busy_timeout=5000;`, and `PRAGMA synchronous=NORMAL;`. Because active writes live in the `-wal` file before checkpointing, **never** copy a live `.sqlite` file with `cp` while the API or scheduler is running.

### Online Backup (`servicecore backup`)

Use the `servicecore backup` CLI command, which invokes `SQLiteAuditStore.backup` (using SQLite's online backup API) and validates the resulting snapshot with `PRAGMA integrity_check`:

```bash
.venv/bin/servicecore backup \
  --db-path /data/servicecore.sqlite \
  --out /backups/servicecore-$(date -u +%Y%m%dT%H%M%SZ).sqlite
```

Verify the backup artifact independently if needed:

```bash
sqlite3 /backups/servicecore-20261126T180000Z.sqlite "PRAGMA integrity_check;"
# Expected output: ok
```

### Disaster Recovery / Restore Procedure

1. **Quiesce writers:** Stop the FastAPI service (`uvicorn` / container) and pause any cron or Cloud Scheduler triggers calling `servicecore monitors-run-due`.
2. **Verify backup integrity** before replacing production state:
   ```bash
   sqlite3 /backups/servicecore-latest.sqlite "PRAGMA integrity_check;"
   ```
3. **Preserve damaged files** for post-mortem analysis, then remove stale `-wal` and `-shm` sidecars before restoring:
   ```bash
   mv /data/servicecore.sqlite /data/servicecore.sqlite.corrupt.$(date -u +%s)
   rm -f /data/servicecore.sqlite-wal /data/servicecore.sqlite-shm
   cp /backups/servicecore-latest.sqlite /data/servicecore.sqlite
   ```
4. **Restart the API and verify readiness:**
   ```bash
   curl -fsS http://127.0.0.1:8000/readyz
   # Expected: {"status":"ready"}
   ```
5. **Re-verify signed bundles** exported prior to the incident if needed using `servicecore verify <bundle.json>`.

### Recurring Monitor Scheduling (`servicecore monitors-run-due`)

Run due `MonitorSchedule` jobs for an organization from cron, systemd timers, or Cloud Scheduler using `servicecore monitors-run-due`:

```bash
SERVICECORE_WEBHOOK_SECRET="$SERVICECORE_WEBHOOK_SECRET" \
.venv/bin/servicecore monitors-run-due \
  --db-path /data/servicecore.sqlite \
  --org-id org_prod \
  --webhook-url https://hooks.example.com/servicecore
```

- `--webhook-url` is optional; when provided, it is validated against SSRF (`validate_public_url`) and receives `monitor.regression` alerts when `new_regressions` are detected.
- `--webhook-secret` can be passed explicitly or read from `SERVICECORE_WEBHOOK_SECRET`.
- Output is a single JSON summary line: `{"monitors_run": <int>, "audit_ids": [...], "regressions_detected": <int>}`.

---

## 3. Secret & Key Rotation

Always rotate secrets via your secret manager (or `.env` in single-host deployments) and avoid committing secrets to source control.

| Environment Variable | Purpose | Rotation Impact & Procedure |
| --- | --- | --- |
| `SERVICECORE_AUTH_SECRET` | HMAC-SHA256 signing secret for tenant-scoped bearer tokens (`src/servicecore/auth.py`). Required when `SERVICECORE_DEV_MODE` is not `1`. | **Impact:** Rotating immediately invalidates all previously minted bearer tokens (`401 Unauthorized`).<br>**Procedure:** Generate a new >=32-byte random secret, update the service environment, restart the API, and re-mint client/Workbench tokens (default token TTL is `86400` seconds). |
| `SERVICECORE_WEBHOOK_SECRET` | HMAC-SHA256 signing secret for outbound `X-ServiceCore-Signature-256` headers (`src/servicecore/alerts.py`). | **Impact:** Consumers using `verify_webhook_signature` will reject deliveries until updated.<br>**Procedure:** Update the consumer's verification secret (or support dual-secret fallback during cutover), update `SERVICECORE_WEBHOOK_SECRET` on both the API and `monitors-run-due` scheduler, and restart. |
| `STRIPE_WEBHOOK_SECRET` | Signing secret (`whsec_...`) for `POST /webhooks/stripe` (`Stripe-Signature` verification in `src/servicecore/api.py`). | **Impact:** Stripe webhook deliveries fail with `400` if the secret does not match Stripe's active signing secret.<br>**Procedure:** Roll the endpoint secret in the Stripe Dashboard (Stripe retains the old secret briefly during rollover), update `STRIPE_WEBHOOK_SECRET` in the API environment, restart, and verify `POST /webhooks/stripe` returns `200`. |
| `ANTHROPIC_API_KEY` | API key used by `ClaudeSynthesizer` (`src/servicecore/synthesizer.py`). | **Impact:** Zero downtime if unset—`ClaudeSynthesizer` falls back to deterministic template synthesis.<br>**Procedure:** Create a new key in the Anthropic Console, update `ANTHROPIC_API_KEY`, restart the API, and revoke the old key after confirming synthesis requests succeed. |

---

## 4. Incident Response

### `429 Retry-After` Rate-Limit Mitigation

**Symptom:** `POST /audits` or `POST /monitors/run-due` returns `429 Too Many Requests` (`{"detail": "Rate limit exceeded"}`) with a `Retry-After: <seconds>` response header.

1. **Check client behavior:** Verify callers honor the `Retry-After` header before retrying and are not stuck in a tight retry loop.
2. **Inspect logs by `request_id`:** Filter structured JSON logs for `"status_code":429` and `"path":"/audits"` or `"/monitors/run-due"` to identify whether a single tenant (`org_id`) or automated job is exhausting the per-minute sliding window.
3. **Tune limit if legitimate:** Increase `SERVICECORE_RATE_LIMIT_PER_MINUTE` (must be a positive integer; unset disables the limiter) and restart the API if legitimate burst traffic exceeds the current threshold.

### `SSRFBlockedError` Triage

**Symptom:** Audit creation (`POST /audits`), monitor creation (`POST /monitors`), monitor execution (`POST /monitors/run-due`, `servicecore monitors-run-due`), or webhook delivery fails with `422 Unprocessable Content` or CLI `ERROR:` referencing `SSRFBlockedError`.

`validate_public_url` (`src/servicecore/scanners.py`) blocks:
- Non-`http`/`https` schemes (`file://`, `ftp://`, `javascript:`, etc.)
- Missing hostnames or internal hostnames (`localhost`, `*.local`, `*.internal`)
- Loopback, private, link-local, multicast, and reserved IP ranges (e.g., `127.0.0.0/8`, `10.0.0.0/8`, `169.254.169.254`)
- Hostnames that fail DNS resolution or resolve to any non-global IP

**Triage steps:**
1. Inspect the rejected `target_url` or `webhook_url` and the `X-Request-ID` in structured logs.
2. Confirm whether a user submitted an internal/staging URL or a DNS record pointing to a private IP, or whether an external attacker attempted SSRF probing.
3. Do **not** disable `validate_public_url`. For legitimate internal targets in isolated environments, expose the target via an authenticated public/routable endpoint or run offline CLI audits against local PDF files (`servicecore audit path/to/doc.pdf`).

### `EvidenceMismatchError` Investigation

**Symptom:** Patch review (`PATCH /audits/{audit_id}/findings/{finding_id}`), bulk review (`POST /audits/{audit_id}/findings/bulk-review`), or synthesis raises `EvidenceMismatchError` (HTTP `422` in the API).

`validate_patch_binding` (`src/servicecore/synthesizer.py`) raises `EvidenceMismatchError` when:
- A patch references an unknown `finding_id`, or alters `rule_id`, `target_selector`, `wcag_criterion`, or `aoda_section` away from the deterministic scanner `FindingEvidence`.
- An `edited_after_snippet` or synthesized HTML snippet contains disallowed unsafe markup (`<script>`, inline event handlers `on*=`, or `javascript:` URIs).

**Investigation steps:**
1. Capture the `audit_id`, `finding_id`, and `X-Request-ID` from the failing request.
2. Inspect the finding's `evidence` (`rule_id`, `target_selector`, `wcag_criterion`, `aoda_section`) via `GET /audits/{audit_id}`.
3. If triggered during human triage (`PATCH` or `POST .../bulk-review`), check the submitted `edited_after_snippet` for `<script>`, `on*=`, or `javascript:` payloads, and verify the reviewer is not attempting to approve a finding whose patch drifted from scanner evidence.
4. If triggered by `ClaudeSynthesizer`, inspect raw model output/fallback behavior and ensure `validate_patch_binding` remains enforced.

### `GET /audits/{audit_id}/events` Chain-of-Custody Audit

When investigating unexpected finding approvals, signature invalidation, certified exports, or GitHub issue publications, query the immutable chronological chain-of-custody log for the affected audit:

```bash
curl -s \
  -H "Authorization: Bearer $SERVICECORE_TOKEN" \
  "http://127.0.0.1:8000/audits/${AUDIT_ID}/events?limit=200&offset=0"
```

Each `AuditEvent` records:
- `event_id` and `timestamp_utc`
- `event_type`: `finding.reviewed`, `finding.bulk_reviewed`, `audit.exported`, `audit.exported_pdf`, or `audit.published_github`
- `actor_sub`: The authenticated `sub` claim from the bearer token that performed the action
- `details`: Structured metadata (e.g., `finding_id`, `status`, `evidence_digest`, `repo`, or `created_issues`)

Cross-reference `actor_sub` and `timestamp_utc` with structured API logs (`request_id`, `path`, `status_code`) and verify the current bundle's `evidence_digest` using `servicecore verify <bundle.json>`.
