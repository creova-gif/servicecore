# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-26

### Added

- **Wave 1 — Core Compliance Engine & Evals:**
  - Pydantic v2 domain schemas (`src/servicecore/schemas.py`) for evidence, patches, reviews, telemetry, and bundle diffs.
  - Deterministic Playwright/axe-core web scanner and `pypdf` PDF/UA inspector (`src/servicecore/scanners.py`) with SSRF protection.
  - Evidence-bound Claude remediation synthesizer with deterministic template fallback and XSS sanitization (`src/servicecore/synthesizer.py`).
  - SHA-256 canonical evidence signing, verification, bundle diffing, HTML/WeasyPrint PDF report rendering, and GitHub issue markdown export (`src/servicecore/exporter.py`).
  - CLI entrypoint (`src/servicecore/cli.py`) and 5-fixture SMB benchmark evaluation suite (`evals/corpus.py`, `evals/runner.py`).
- **Wave 2 — Architecture, API, Workbench & Deployment:**
  - Architecture Decision Record (`docs/adr/001-dual-engine-evidence-architecture.md`) and design system specification (`DESIGN.md`).
  - FastAPI service (`src/servicecore/api.py`) with bearer token auth, audit execution, review sign-off, and verification endpoints.
  - Next.js Reviewer Workbench (`workbench/`) for inspecting findings, approving/editing patches, and viewing evidence digests.
  - Container and CI/CD packaging (`Dockerfile`, `docker-compose.yml`, `cloudrun.yaml`, `.github/workflows/ci.yml`).
- **Wave 3 — Persistence, Live Workbench, Certified PDF & Partner Packaging:**
  - SQLite persistence store (`SQLiteAuditStore`) alongside live Workbench API integration.
  - Certified PDF export endpoint with unsigned-bundle gating.
  - Offline design-partner demo script (`scripts/demo_partner_audit.py`), deterministic test coverage (`tests/test_demo_partner.py`), `LICENSE`, and `CHANGELOG.md`.
- **Wave 4 — Multi-Page Crawl, Regression Diff & GitHub Publisher:**
  - Same-origin bounded BFS web/PDF crawler (`src/servicecore/crawler.py`).
  - Regression diff API (`GET /audits/{audit_id}/diff?baseline_id=...`) and Workbench regression comparison UI (`+N new`, `-N resolved`, `N persisting`, `N reopened`).
  - GitHub issue publisher (`src/servicecore/github_publisher.py`) for exporting approved/edited findings to repository issues.
- **Wave 5 — Crawl Integration, Monitor Persistence & Workbench GitHub Publish UI:**
  - CLI and `POST /audits` integration for `crawl`, `max_pages`, and `max_pdfs` options.
  - `MonitorSchedule` persistence and `/monitors` API endpoints (`GET`, `POST`, `POST /monitors/{id}/run`).
  - Workbench inline GitHub issue publishing workflow with ephemeral token handling and created issue links.
- **Wave 6 — CLI Verify/Diff, SARIF 2.1.0 Export & Monitors UI:**
  - Exposed `servicecore verify` and `servicecore diff` CLI subcommands for offline SHA-256 verification and baseline diffing.
  - Added SARIF `2.1.0` exporter (`src/servicecore/sarif.py`) and `GET /audits/{audit_id}/export/sarif` endpoint.
  - Added Workbench Recurring Monitors UI panel with schedule creation and `"Run Now"` baseline diff integration.
- **Wave 7 — Due-Monitor Scheduler, Webhook Alerts, CLI SARIF & CI Templates:**
  - Added due-monitor background scheduler loop and SSRF-safe signed webhook regression alerts (`src/servicecore/alerts.py`).
  - Added `servicecore sarif` CLI subcommand for exporting signed `AuditBundle` files to SARIF `2.1.0`.
  - Added Workbench SARIF download action and repository CI/contribution templates (`.github/workflows/ci.yml`, `CONTRIBUTING.md`).
- **Wave 8–9 — Enterprise Hardening, Pagination, Metrics & Modularity:**
  - Enabled SQLite WAL mode with busy timeout and foreign-key enforcement for concurrent persistence safety.
  - Added token `exp` TTL validation, security response headers, `X-Request-ID` propagation, structured JSON logging, and sliding-window rate limiting.
  - Added `/readyz` readiness and `/metrics` observability probes alongside paginated `/audits` and `/monitors` list endpoints.
  - Hardened the multi-page crawler with URL canonicalization and crawl budget guards.
  - Switched Workbench typography to offline-safe system font stacks and decomposed the UI into modular `HeaderBar`, `QueuePanel`, `MonitorsPanel`, and `DecisionCanvas` components.
  - Added `container-build-validation` CI job validating `docker compose config --quiet` and building both `servicecore-api:ci` and `servicecore-workbench:ci` images.
- **Wave 10 — Monitor Lifecycle CRUD, Formula-Safe CSV Export & Keyboard Hook Extraction:**
  - Added `PATCH /monitors/{monitor_id}` and `DELETE /monitors/{monitor_id}` endpoints with org-scoped persistence and Workbench monitor lifecycle controls.
  - Added formula-safe CSV export (`GET /audits/{audit_id}/export/csv`) and Workbench `"Download Bundle JSON"` / `"Download CSV"` export actions.
  - Extracted Workbench keyboard triage shortcuts into a dedicated hook with expanded unit test coverage.
- **Wave 11 — Outbound Webhook HMAC Signing, Audit Deletion & Concurrent SQLite Stress Verification:**
  - Added outbound webhook HMAC-SHA256 signing for monitor alert deliveries.
  - Added `DELETE /audits/{audit_id}` endpoint with org-scoped persistence, Workbench `"Delete"` audit switcher control, and `deleteAudit` API client coverage.
  - Added concurrent SQLite WAL stress verification tests for multi-writer audit and monitor operations.
- **Wave 12 — Monitor SSRF-on-Write, 1 MiB Body-Size DoS Guard, CLI `monitors-run-due` & Inline Delete Confirmation:**
  - Added SSRF target validation on monitor creation to reject private/loopback/metadata URLs on write.
  - Enforced a 1 MiB request body-size DoS guard in the API service.
  - Added `monitors-run-due` CLI subcommand for executing due monitors and dispatching webhook alerts.
  - Added two-click inline delete confirmation for selected audits in `HeaderBar` and recurring monitors in `MonitorsPanel`.
- **Wave 13 — Executive Audit Summary Endpoint, Webhook Signature Verifier, Queue Search & Shortcuts Help:**
  - Added `GET /audits/{audit_id}/summary` returning lightweight executive counts without full findings payloads.
  - Added `verify_webhook_signature` helper (`src/servicecore/alerts.py`) for validating `X-ServiceCore-Signature-256` and `X-ServiceCore-Event` webhook deliveries.
  - Added Workbench Queue search filtering and `?` keyboard shortcuts help dialog.
- **Wave 14 — Bulk Evidence-Bound Triage, Thread-Safe InMemory Store & Shortcuts Dialog Focus Restoration:**
  - Added `POST /audits/{audit_id}/findings/bulk-review` for evidence-bound bulk finding approval.
  - Added thread-safe locking to `InMemoryAuditStore` for concurrent access.
  - Added `"Approve All Bound"` bulk triage action and keyboard shortcuts dialog focus restoration in the Workbench.
- **Wave 15–16 — Chain-of-Custody Audit Events & Enterprise API Reference:**
  - Added immutable compliance audit event logging (`GET /audits/{audit_id}/events`) covering finding reviews, bulk reviews, certified exports, and GitHub issue publishing.
  - Published enterprise API reference documentation in `docs/API.md` covering bearer authentication, all grouped endpoints, webhook signature verification, and standard error codes.
  - Documented `SERVICECORE_RATE_LIMIT_PER_MINUTE` and `SERVICECORE_ENABLE_DOCS` in `.env.example` and `README.md`.
