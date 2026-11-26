# servicecore — Execution Checklist

## Wave 1: Day 1–5 Setup
- [x] Set up `src/servicecore/` (`schemas.py`, `scanners.py`, `synthesizer.py`, `exporter.py`, `cli.py`) and `evals/` (`corpus.py`, `runner.py`)
- [x] Lock initial wedge (AODA/WCAG Web & Doc Accessibility Audit — `ROW-01` Option B)
- [x] Build CLI taking a target URL/PDF, running Playwright/axe-core + `pypdf` PDF/UA inspector + Claude synthesis + SHA-256 verify/diff, and exporting PDF/GitHub issues
- [x] Run on 5 deterministic SMB site/PDF benchmark fixtures (`evals/runner.py`: precision 1.0, recall 1.0, 0 unverified claims)

## Wave 2: MVP & Eval Gate
- [x] Write ADR-001 in `docs/adr/001-dual-engine-evidence-architecture.md`
- [x] Implement core pipeline + deterministic unit/eval tests (`pytest`, `mypy --strict`, `ruff check`)
- [x] Implement Wave 2–3 FastAPI (`src/servicecore/api.py`), Next.js Workbench (`workbench/`), `DESIGN.md`, `Dockerfile`, `cloudrun.yaml`, and CI (`.github/workflows/ci.yml`) (`T6`, `D1`–`D2`)

## Wave 3: Launch & Design Partner Validation
- [x] Publish clean README with reproducible benchmark numbers and E2E pipeline verification (`tests/test_e2e_pipeline.py`)
- [x] Package `0.1.0` release (`LICENSE`, `CHANGELOG.md`) and offline design-partner demo script (`scripts/demo_partner_audit.py`, `tests/test_demo_partner.py`)

## Wave 4: Full Product Engineering & Scope Expansion
- [x] Multi-page & PDF crawler for site-wide WCAG 2.2 AA / AODA discovery with bounded page/PDF traversal
- [x] Regression diff API (`GET /audits/{audit_id}/diff?baseline_id=...`) + Workbench regression comparison UI (`+N new`, `-N resolved`, `N persisting`, `N reopened`)
- [x] GitHub issue publisher for exporting approved/edited remediation findings directly to repository issues

## Wave 5: Recurring Monitoring, Crawl Integration & GitHub Publishing
- [ ] Integrate `crawl`, `max_pages`, and `max_pdfs` options into Live API audit creation and Workbench scan form
- [ ] Add Workbench inline GitHub issue publishing workflow with ephemeral token handling and created issue links
- [ ] Add recurring scheduled audit monitoring and webhook/notification triggers for regression alerts

## Wave 6: Recurring Monitors UI, SARIF 2.1.0 Export & CLI Verify/Diff
- [x] Add Workbench Recurring Monitors UI (`MonitorSchedule`/`MonitorRunResult` types, `fetchMonitors`/`createMonitor`/`runMonitor` API client + unit tests, collapsible Monitors panel with create form and `"Run Now"` baseline diff integration)
- [ ] Add SARIF 2.1.0 export formatter (`src/servicecore/exporter.py`, `POST /audits/{audit_id}/export/sarif`) for GitHub Code Scanning / CI ingestion
- [ ] Expose `servicecore verify` and `servicecore diff` CLI subcommands for offline SHA-256 evidence digest verification and baseline regression diffing

## Wave 7: Autonomous Monitor Scheduler, Webhook Alerts & SARIF CI Parity
- [ ] Add background monitor scheduler loop (`asyncio` / Cloud Scheduler trigger) to automatically execute due `MonitorSchedule` jobs on cadence
- [ ] Add signed webhook / Slack / email regression alert delivery when a scheduled monitor run detects `new_regressions`
- [ ] Add GitHub Actions SARIF upload workflow (`github/codeql-action/upload-sarif`) consuming `servicecore` SARIF 2.1.0 output for PR Code Scanning annotations

## Wave 8–9: Enterprise Hardening, Pagination, Metrics & Modularity
- [x] Enable SQLite WAL mode with busy timeout and foreign-key enforcement for concurrent persistence safety
- [x] Add token `exp` TTL validation, security response headers, `X-Request-ID` propagation, structured JSON logging, and sliding-window rate limiting
- [x] Add `/readyz` readiness and `GET /metrics` observability probes alongside paginated `/audits` and `/monitors` list endpoints
- [x] Harden multi-page crawler with URL canonicalization and crawl budget guards, decompose Workbench UI into modular components, and add `container-build-validation` CI job

## Wave 10: Monitor Lifecycle CRUD, CSV Export & Keyboard Hook Extraction
- [x] Add `PATCH /monitors/{monitor_id}` and `DELETE /monitors/{monitor_id}` lifecycle CRUD endpoints and Workbench monitor controls
- [x] Add formula-safe CSV export (`GET /audits/{audit_id}/export/csv`) and Workbench `"Download Bundle JSON"` / `"Download CSV"` export actions
- [x] Extract Workbench keyboard triage shortcuts into a dedicated hook with expanded unit test coverage
