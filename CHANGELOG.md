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
