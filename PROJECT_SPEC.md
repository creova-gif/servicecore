# ServiceCore: AI-Native Services Delivery Platform

- **Model:** AI-Native Services Startup ($1,000-$2,500/audit + $299/mo monitoring)
- **Thesis Alignment:** #04 AI-Native Service Companies, #03 AI-Native Agencies
- **Full Google Doc Spec:** [ServiceCore: AI-Native Services Delivery Platform](https://docs.google.com/document/d/1iE5qMqXfkxI8aMr6VyiM-TLtwQfysLqPN9ovKjKBcUc/edit?usp=drivesdk&ouid=110227624285917376281)
- **Portfolio Strategy:** [00 - Startup & Open-Source Cross-Project Strategy](https://docs.google.com/document/d/12Wpg5mMGnjnl2uhMBTOR0QqRzQj8kwfzTLpvLoRuB5Q/edit?usp=drivesdk&ouid=110227624285917376281)

## 1. Goal & Problem
Deliver outcome-priced B2B compliance/accessibility/QA audits in <= 24 hours at >= 75% gross margin by pairing automated scanners with a human sign-off workbench.

## 2. Target Customer (ICP) & Monetization
North American SMBs, SaaS vendors, and nonprofits facing accessibility (AODA/WCAG/ADA) or security-readiness deadlines.

## 3. Tech Stack
Python FastAPI, Playwright/axe-core deterministic scanners, Anthropic Claude, Next.js Review Workbench, Stripe, Cloud Run.

## 4. Evaluation & Acceptance Thresholds
>= 70% reduction in manual delivery hours; 0 unverified claims in final client PDFs; < 2% client revision rate.

## 5. Key Architectural Decision (ADR-001)
Sell guaranteed business outcomes powered by private AI tooling + mandatory human sign-off rather than raw AI seats.

## 6. Day 1–5 Quickstart
- [ ] Set up pipeline/, workbench/, exporter/, and evals/ directories
- [ ] Lock initial wedge (e.g., AODA/WCAG Web & Doc Accessibility Audit)
- [ ] Build CLI taking a target URL/PDF, routing HTML URLs to Playwright/axe-core and PDF inputs/links to a pure-Python `pypdf` PDF/UA structure-tree inspector behind a unified Pydantic `FindingEvidence` schema, running Claude remediation synthesis, and exporting a draft PDF after human sign-off (`ROW-01` Option B)
- [ ] Run on 5 public SMB sites to measure turnaround time and defect precision

---

## Step 0: CEO Plan Review (Pre-Review Audit, Reality Check & Ledger)

### Pre-Review System Audit & Taste Calibration
- **System state:** Greenfield repository on `main` (no commits yet, no remote configured). Contains `PROJECT_SPEC.md:1-27`, `TASKS.md:1-16`, `AGENTS.md:1-8`, `docs/THREAT_MODEL.md:1-4`, `docs/adr/000-template.md:1-8`, `pyproject.toml:1-12` (`python >=3.12`, `pydantic>=2.9`, `mypy strict = true`), `src/servicecore/__init__.py:1-2` (`healthcheck() -> str`), and `tests/test_smoke.py:1-4`.
- **Frontend/UI Scope Detection:** `DESIGN_SCOPE` applies (`PROJECT_SPEC.md:15` names the Next.js Review Workbench and exported client PDF report).
- **Taste Calibration (Good patterns to emulate):**
  1. `pyproject.toml:11-12` + `AGENTS.md:3`: Strict type-checking (`mypy --strict`) and Pydantic v2 schema validation at trust boundaries (`docs/THREAT_MODEL.md:4`).
  2. `PROJECT_SPEC.md:18`: Hard invariant that final client PDFs contain `"0 unverified claims in final client PDFs"`, tying every finding to a deterministic scanner rule ID, DOM selector/PDF object reference, and human reviewer sign-off.
- **Taste Calibration (Anti-patterns to avoid):**
  1. Running `axe-core` against a `.pdf` URL/file (`PROJECT_SPEC.md:26`), which scans Chromium's `<embed>` wrapper DOM and falsely reports 0 violations on untagged PDFs.
  2. Shipping raw LLM prose into compliance reports without deterministic evidence binding and mandatory human sign-off (`PROJECT_SPEC.md:21`).
- **Landscape Synthesis (Layers 1–3):**
  - **[Layer 1 — Tried and true]:** Automated HTML scanners (`axe-core`, Pa11y, WAVE) catch ~30–60% of WCAG 2.1/2.2 AA violations (programmatic rules, contrast, missing labels) while PDF/UA tools (PAC, VeraPDF, `pypdf` tag-tree checks) inspect PDF structure trees; manual keyboard and screen-reader testing plus human sign-off is required by W3C and courts (`PROJECT_SPEC.md:9`).
  - **[Layer 2 — Current market]:** Overlay widgets face FTC penalties and plaintiff targeting because they leave source code broken; buyers demand verifiable audit trails, code-level remediation diffs, and human-verified sign-off under ADA Title II, EAA, and Ontario AODA deadlines (`PROJECT_SPEC.md:12`).
  - **[Layer 3 — First principles / Eureka]:** `PROJECT_SPEC.md:26` proposes `"Build CLI taking a target URL/PDF, running axe-core + Claude synthesis, and exporting draft PDF"`. First-principles reality: `axe-core` only executes in an HTML DOM. Pointing Playwright + `axe-core` at a PDF inspects the browser's PDF viewer wrapper and produces a silent false negative. To uphold `"0 unverified claims in final client PDFs"` (`PROJECT_SPEC.md:18`), Web DOM scanning (`axe-core`) and PDF structure-tree inspection (`pypdf`/`pdfminer.six` tag tree + `/StructTreeRoot`, `/Lang`, `/Alt`, reading order checks) must be distinct deterministic engines behind a unified `FindingEvidence` schema.

### 0A. Premise Challenge
- **Real problem:** SMBs, SaaS vendors, and nonprofits facing AODA/WCAG/ADA deadlines (`PROJECT_SPEC.md:12`) cannot trust automated overlay widgets (which fail lawsuits) and cannot afford slow, manual-only agency audits.
- **Target outcome:** `"Deliver outcome-priced B2B compliance/accessibility/QA audits in <= 24 hours at >= 75% gross margin by pairing automated scanners with a human sign-off workbench."` (`PROJECT_SPEC.md:9`).
- **Do-nothing cost:** Either manual delivery hours eat the margin below `"75% gross margin"` (`PROJECT_SPEC.md:9`), or unverified scanner/LLM claims leak into client PDFs and create legal/reputational liability (`PROJECT_SPEC.md:18`).
- **Direct vs. proxy:** The core model (deterministic scanner evidence + Claude remediation synthesis + mandatory human sign-off workbench) solves the pain directly, except for the PDF scanner premise in `PROJECT_SPEC.md:26` (`axe-core` cannot audit PDFs).

### 0B. Existing Code Leverage & Reality Rows
- **Existing code map:**
  - Package & test scaffold: `pyproject.toml:1-12`, `src/servicecore/__init__.py:1-2`, `tests/test_smoke.py:1-4`.
  - Architecture & security templates: `AGENTS.md:1-8`, `docs/adr/000-template.md:1-8`, `docs/THREAT_MODEL.md:1-4`.
  - Unbuilt directories named in spec: `pipeline/`, `workbench/`, `exporter/`, `evals/` (`PROJECT_SPEC.md:24`, `TASKS.md:4`).

#### Premise Table (`unverified=0`)
| Premise | Claim | File:Line Receipt | Verdict |
|---|---|---|---|
| Outcome-priced SLA & margin target | `"Deliver outcome-priced B2B compliance/accessibility/QA audits in <= 24 hours at >= 75% gross margin"` | `PROJECT_SPEC.md:9` | verified (spec target, `[estimated]`) |
| Zero unverified claims invariant | `"0 unverified claims in final client PDFs; < 2% client revision rate"` | `PROJECT_SPEC.md:18` | verified (acceptance threshold) |
| CLI URL/PDF + axe-core scope | `"Build CLI taking a target URL/PDF, running axe-core + Claude synthesis, and exporting draft PDF"` | `PROJECT_SPEC.md:26` | finding (`axe-core` is HTML-only; PDF input requires a PDF tag-tree inspector) |
| Current codebase implementation state | Repo currently has only `healthcheck() -> str` and `test_healthcheck()`; `pipeline/`, `workbench/`, `exporter/`, `evals/` do not exist yet | `src/servicecore/__init__.py:1-2` | verified |
| Tenant & secret boundary rules | `"Strict schema validation, org_id tenant scoping, GCP Secret Manager + OIDC, gitleaks in CI"` | `docs/THREAT_MODEL.md:4` | verified |

REALITY: premise-table finding Premise table audited across 5 claims with unverified=0; flagged axe-core PDF limitation PROJECT_SPEC.md:26
REALITY: already-done pass Repo has no prior commits and only healthcheck() stub in src/servicecore/__init__.py; pipeline/workbench/exporter/evals are not yet built src/servicecore/__init__.py:1-2
REALITY: surface-check finding CLI and FastAPI routes named in PROJECT_SPEC.md are not yet implemented in src/servicecore/__init__.py PROJECT_SPEC.md:24-26
REALITY: binding-decisions pass Checked gstack-decision-search and AGENTS.md standards; no overruled project decisions reintroduced AGENTS.md:1-8
REALITY: numbers pass Spec targets ("$1,000-$2,500/audit", "$299/mo", "<= 24 hours", ">= 75% gross margin", ">= 70% reduction", "0 unverified claims", "< 2% client revision rate", "5 public SMB sites") tagged as [estimated] spec targets [re-measure before gate] PROJECT_SPEC.md:3-27
REALITY: deferred-asks pass No linked issue requests left out; Wave 1-3 checklist items in TASKS.md match PROJECT_SPEC.md TASKS.md:3-16
REALITY: pr-count pass Default single-wave PR structure preserved for initial greenfield implementation TASKS.md:3-16

### 0C. Dream State Mapping
```
  CURRENT STATE                        THIS PLAN (WAVE 1-3 MVP)                     12-MONTH IDEAL
  Greenfield repo stub                 Deterministic Web (axe-core) +               Continuous multi-tenant compliance
  (healthcheck() only in     --->      PDF/UA tag-tree scanner CLI,       --->      platform: automated PR remediation
  src/servicecore/__init__.py:1-2;     Pydantic evidence ledger, Claude             bots, live ARIA/keyboard flow agents,
  spec in PROJECT_SPEC.md:1-27)        remediation synthesizer, human               cryptographically signed audit vaults,
                                       sign-off gate, and draft PDF exporter        and $299/mo drift monitoring
```

### Decision Ledger
| ID and owner | Contract and evidence | Current | Proposed | Status | Exact approval and scope |
|---|---|---|---|---|---|
| ROW-01 (Owner: Justin Mafie / ServiceCore Pipeline) | `PROJECT_SPEC.md:18` requires `"0 unverified claims in final client PDFs"`, while `PROJECT_SPEC.md:26` and `TASKS.md:6` specify `"Build CLI taking a target URL/PDF"`. Unit & fixture tests must verify both HTML DOM violations and untagged PDF detection. | Approved Option B: Dual-engine deterministic scanner (`Playwright/axe-core` for HTML URLs + pure-Python `pypdf` PDF/UA tag-tree inspector for PDF inputs/links, normalized into one Pydantic `FindingEvidence` schema) + mandatory human sign-off gate. | **A)** HTML URLs only in Wave 1. **B)** Dual-engine Python scanner: `axe-core` (Web) + `pypdf` tag-tree inspector (PDF) (approved). **C)** External VeraPDF subprocess orchestration. | approved | User answered D2 (ROW-01) → Option B (`2026-11-25`): Route HTML URLs to Playwright/axe-core and PDF inputs/links to pure-Python `pypdf` PDF/UA structure-tree checker (`/StructTreeRoot`, `/Lang`, `/Title`, figure `/Alt`, table headers) behind one Pydantic `FindingEvidence` model (~10 planned files `[estimated]`). |
| EXP-01 (Owner: Justin Mafie / ServiceCore Synthesizer) | `PROJECT_SPEC.md:9,18,26` specifies `"running axe-core + Claude synthesis, and exporting draft PDF"` with `"< 2% client revision rate"`. Standard audits hand clients vague prose; generating deterministic before/after HTML/ARIA patch diffs + exact WCAG 2.1/2.2 AA & Ontario AODA IASR legal clause citations validated against the captured DOM/PDF snippet turns the report into an actionable developer patchbook. | Approved Option A: Structured Pydantic `RemediationPatch` (`before_snippet`, `after_snippet`, `wcag_criterion`, `aoda_section`, `component_fingerprint`), deterministic evidence-binding validator, component deduplication, and GitHub-issue markdown export (`+~120 lines` + unit tests). | **A)** Add to this plan's scope (approved). **B)** Defer to `TODOS.md`. **C)** Skip. | approved | User answered D4 (EXP-01) → Option A (`2026-11-25`): Add structured `RemediationPatch` schema, deterministic evidence-binding guard, component deduplication, and GitHub-issue markdown export to Wave 1 scope. |
| EXP-02 (Owner: Justin Mafie / ServiceCore Exporter & Workbench) | `PROJECT_SPEC.md:18,21` requires `"0 unverified claims in final client PDFs"` and `"mandatory human sign-off"`. Buyers use accessibility audits as legal/procurement evidence; an unsigned PDF cannot prove which scanner payload or human reviewer certified the report. | Approved Option A: Deterministic SHA-256 `evidence_digest` over canonical `FindingEvidence` + `reviewer_id` + `signed_at_utc` embedded in PDF/JSON + `servicecore verify` CLI + hard export gate blocking unsigned findings (`+~80 lines` + unit tests). | **A)** Add to this plan's scope (approved). **B)** Defer to `TODOS.md`. **C)** Skip. | approved | User answered D5 (EXP-02) → Option A (`2026-11-25`): Add SHA-256 `evidence_digest` receipt, `servicecore verify` CLI, and unsigned-claim export block to Wave 1 scope. |
| EXP-03 (Owner: Justin Mafie / ServiceCore Pipeline & Monitoring) | `PROJECT_SPEC.md:3` prices ServiceCore at `"$1,000-$2,500/audit + $299/mo monitoring"`. Without a deterministic snapshot diff engine comparing a new scan against the prior signed baseline, the `"$299/mo monitoring"` recurring revenue stream has no technical foundation in the CLI/pipeline. | Approved Option A: `servicecore diff <baseline.json> <current.json>` (`NEW_REGRESSION`, `FIXED`, `PERSISTENT`) + `<a href="*.pdf">` auto-discovery during HTML crawl (`+~90 lines` + unit tests). | **A)** Add to this plan's scope (approved). **B)** Defer to `TODOS.md`. **C)** Skip. | approved | User answered D6 (EXP-03) → Option A (`2026-11-25`): Add `servicecore diff` snapshot diff engine and linked-PDF auto-discovery to Wave 1 scope. |
| EXP-04 (Owner: Justin Mafie / ServiceCore Workbench) | Step 0G Delight #3 & #4 proposed keyboard-first workbench hotkeys (`j`/`k`/`a`/`r`/`e`, `Space`/`n` next pending, `u` undo toast) and a live per-run Cost & Margin Telemetry Footer (`$LLM`, scan runtime, `% gross margin` vs `$1,000-$2,500` price), which the 0H Spec Reviewer flagged as needing explicit Decision Ledger approval before entering Wave 2–3 scope. | Approved Option A: Keyboard-first triage hotkeys (`j`/`k`/`a`/`r`/`e`, auto-disabled inside inputs, 5s undo toast) + live Cost & Margin Telemetry Footer in Wave 2–3 Workbench & CLI (`+~80 lines` + unit/E2E tests). | **A)** Add to Wave 2–3 Workbench scope (approved). **B)** Defer to `TODOS.md`. **C)** Skip. | approved | User answered D7 (EXP-04) → Option A (`2026-11-25`): Add keyboard-first triage hotkeys and per-run Cost & Margin Telemetry Footer to Wave 2–3 scope. |

### 0E. Mode Selection & Provenance
- **Selected Mode:** `SCOPE EXPANSION`
- **Provenance:** Actual question answer (`D3`, user selected Option A `SCOPE EXPANSION`, `auto_decided: false`).
- **Governing Approved Decisions at Mode Handoff:** `ROW-01` (D2 → Option B: Dual-engine Python scanner pairing `Playwright/axe-core` for HTML URLs and `pypdf` tag-tree inspector for PDF inputs/links behind a unified Pydantic `FindingEvidence` schema).

### 0F & 0G. Scope Expansion Analysis (10x Check, Platonic Ideal & Delight Scan)

#### 1. 10x Check (10x Value for 2x Effort)
A commodity scanner dumps 200 raw `axe-core` JSON warnings that SMB developers ignore. For ~2x the effort of a naive CLI wrapper (Wave 1 `~15 Python files` `[estimated]` instead of `~10 files` `[estimated]`), ServiceCore becomes an **outcome-grade compliance & remediation engine**:
1. **Zero-Hallucination Evidence + Ready-to-Merge Code Patches (`EXP-01`):** Every finding includes the exact offending HTML DOM node or PDF object ID, the exact WCAG 2.1/2.2 AA + Ontario AODA IASR clause, and a copy-pasteable `before -> after` HTML/ARIA diff.
2. **Cryptographically Verifiable Sign-Off Certificate (`EXP-02`):** Every client PDF and JSON bundle carries a tamper-evident SHA-256 `evidence_digest` binding the raw scanner output, the human reviewer's sign-off identity, and UTC timestamp—blocking any unverified LLM claim from ever reaching a client PDF (`PROJECT_SPEC.md:18`).
3. **Built-In `$299/mo` Drift & Regression Engine (`EXP-03`):** Every audit snapshot can be diffed against the next month's scan (`NEW_REGRESSION`, `FIXED`, `PERSISTENT`), immediately powering the `$299/mo` recurring revenue tier (`PROJECT_SPEC.md:3`).

#### 2. Platonic Ideal
An SMB CTO or compliance lead receives a ServiceCore audit package within 24 hours (`PROJECT_SPEC.md:9`). Page 1 is an executive AODA/WCAG conformance certificate signed by a human specialist with a verifiable SHA-256 audit hash (`EXP-02`). Pages 2+ group findings by root component (so 40 pages sharing one broken navbar count as 1 component fix, not 40 noisy rows), with side-by-side `before/after` HTML/ARIA patches (`EXP-01`) their developer can paste into a PR in 10 minutes. Thirty days later, ServiceCore's `$299/mo` monitor (`EXP-03`) runs automatically, confirms their fixes resolved 100% of critical blockers, and alerts if a new deploy introduced a regression. Inside ServiceCore, the human reviewer uses a keyboard-first Review Workbench where approving, editing, or rejecting each AI-synthesized patch takes `< 5 seconds` (`[estimated]`), easily sustaining `>= 75% gross margin` (`PROJECT_SPEC.md:9`).

#### 3. Delight Scan (5 Adjacent ~30-Minute Improvements)
1. **Component Deduplication Fingerprinting (`rule_id + normalized_dom_signature`):** Collapse identical header/footer/nav violations across pages into a single review item so reviewers sign off once instead of 50 times (`~25 min CC` `[estimated]`).
2. **Auto-Discovery of Linked PDFs During HTML Crawl:** When scanning a web URL, automatically extract `<a href="*.pdf">` links on the page and queue them for the `pypdf` PDF/UA tag-tree inspector (`~20 min CC` `[estimated]`).
3. **One-Keystroke Workbench Hotkeys (`j`/`k` navigate, `a` approve, `r` reject, `e` edit):** Let the human reviewer clear 30 findings in 3 minutes without touching the mouse (`~25 min CC` `[estimated]`).
4. **Deterministic Cost & Margin Telemetry Footer per Run:** Print token usage, scanner runtime, and estimated gross margin % against the `$1,000-$2,500` audit price in the workbench and CLI summary (`~15 min CC` `[estimated]`).
5. **Copy-as-GitHub-Issue / Markdown Export per Finding:** One click (or `--format github-issues` flag) exports approved findings into developer-ready GitHub issue markdown blocks with checkboxes (`~20 min CC` `[estimated]`).

### Accepted Scope, Phasing & Architecture Contracts (Post-Step 0G / 0H)

#### Phasing & Footprint
- **Wave 1 (Day 1–5 CLI, Pipeline, Exporter & Evals — `~15 Python files` `[estimated]`):**
  1. `ROW-01` (D2 → Option B): Dual-engine Python scanner (`Playwright/axe-core` for HTML URLs + pure-Python `pypdf` PDF/UA structure-tree inspector) behind unified Pydantic v2 `FindingEvidence`.
     - **Reconciled `pypdf` PDF/UA checks (Wave 1 deterministic scope):** `/StructTreeRoot` present, `/Lang` present, `/Title` present, `/Figure` nodes have `/Alt`, `/Table` nodes have `/TH`, and page `/Tabs /S` flag. Deep reading-order simulation is out of Wave 1 scope (`"0 unverified claims"`).
     - **Crawler & SSRF bounds:** `https://`/`http://` only; block `file://`/`data:`/`javascript:` and non-global IPs (`127.0.0.0/8`, `10.0.0.0/8`, `169.254.169.254`, `100.64.0.0/10`, `::1`, `fc00::/7`) on DNS resolution and every manual redirect hop (max 5 hops) + Playwright `page.route("**/*")`. Crawl caps: same-origin default, max `25` pages, max depth `2`, `30_000 ms` page timeout, max `10` auto-discovered `<a href="*.pdf">` links, `25 MB` PDF stream cap, iterative BFS/DFS tag-tree traversal with `visited` indirect-object cycle guard.
  2. `EXP-01` (D4 → Option A): Structured Pydantic `RemediationPatch` + deterministic `rule_id -> (wcag_criterion, aoda_section)` lookup table (never LLM-invented) + evidence-binding validator (`patch.rule_id` and `patch.target_selector` must exist in `FindingEvidence`) + component deduplication (`sha256(rule_id + normalized_dom_signature)` stripping dynamic IDs/`nth-child` or `sha256(rule_id + pdf_object_type)` for PDFs) + `--format github-issues` markdown export.
  3. `EXP-02` (D5 → Option A): Canonical SHA-256 `evidence_digest` (`json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)`) computed over `(findings, reviewer_id, signed_at_utc)` with `raw_scanner_sha256` recorded inside `FindingEvidence`; `servicecore verify <bundle.json>` CLI (exit `0` valid, exit `1` tampered/unsigned); hard export gate blocking certified PDF export (`WeasyPrint`) if any non-rejected finding lacks `APPROVED`/`EDITED` sign-off (`--draft` flag allowed only for watermarked internal preview without conformance certificate).
  4. `EXP-03` (D6 → Option A): `servicecore diff <baseline.json> <current.json>` classifying findings by `component_fingerprint` into `NEW_REGRESSION`, `FIXED`, `PERSISTENT` (exit `0` if 0 regressions, exit `2` if `NEW_REGRESSION` > 0) + `<a href="*.pdf">` auto-discovery.
  5. `evals/` & 5-site SMB benchmark: Ground-truth fixture corpus (HTML + tagged/untagged/encrypted/corrupt PDFs) verifying `100%` precision on deterministic rules, `0` unbacked LLM claims, and `mypy --strict` + `ruff check` + `pytest` in CI.
- **Wave 2–3 (Platform, Workbench, Billing & Cloud Run — `~25+ files` `[estimated]`):**
  - FastAPI backend (`org_id` extracted exclusively from verified auth JWT/session, `WHERE org_id = :auth_org_id`, GCS `orgs/{org_id}/...`), PostgreSQL + GCS artifact storage, Stripe Checkout + idempotent webhook (`Stripe-Signature` + `event.id` dedup), Next.js Review Workbench (`PENDING` / `APPROVED` / `REJECTED` / `EDITED` finding states; `REJECTED` logged as suppressed with reason and excluded from client PDF; `EDITED` re-runs evidence-binding & HTML-sanitization checks), and Cloud Run (lightweight API `512 MiB` + isolated Playwright/pypdf worker `2–4 GiB`, `concurrency=2`, `--disable-dev-shm-usage`).

#### Core Pydantic v2 Data Contracts
```python
# FindingEvidence: finding_id, source ("axe-core" | "pypdf"), rule_id, wcag_criterion, aoda_section,
# target_selector (CSS selector or "page:N/obj:M"), raw_snippet, component_fingerprint, raw_scanner_sha256
# RemediationPatch: finding_id, rule_id, target_selector, patch_kind ("html_diff" | "pdf_tag_action"),
# before_snippet (str | None), after_snippet (str | None), pdf_remediation_steps (list[str]),
# wcag_criterion, aoda_section, component_fingerprint
# FindingReview: finding_id, status ("PENDING" | "APPROVED" | "REJECTED" | "EDITED"),
# rejection_reason (str | None), reviewer_id (str | None), signed_at_utc (datetime | None)
# AuditBundle: audit_id, org_id, target_url, findings (list[FindingEvidence]), patches (list[RemediationPatch]),
# reviews (list[FindingReview]), reviewer_id, signed_at_utc, evidence_digest (sha256 hex)
```

#### NOT in Scope (Explicitly Excluded)
- External Java VeraPDF / PAC subprocess orchestration (`ROW-01` Option C — rejected in favor of pure-Python `pypdf` PDF/UA tag-tree inspector in Wave 1).
- Automated accessibility overlay widgets (explicitly excluded; non-compliant under WCAG/AODA/ADA).
- Raw AI seat SaaS billing (`PROJECT_SPEC.md:21` / ADR-001).

### Answered Decisions (Chronological)

1. **ROW-01 (D2) — Approved Option B:** Dual-engine Python scanner (`Playwright/axe-core` for HTML URLs + pure-Python `pypdf` PDF/UA structure-tree inspector for `/StructTreeRoot`, `/Lang`, `/Title`, `/Figure` `/Alt`, `/Table` `/TH`, page `/Tabs /S`) behind unified Pydantic `FindingEvidence`.
2. **EXP-01 (D4) — Approved Option A:** Structured Pydantic `RemediationPatch`, deterministic `rule_id -> (wcag_criterion, aoda_section)` lookup, evidence-binding validator, component deduplication, and `--format github-issues` markdown export.
3. **EXP-02 (D5) — Approved Option A:** Canonical SHA-256 `evidence_digest`, `servicecore verify <bundle.json>` CLI, and hard export gate blocking certified PDF export on unsigned findings.
4. **EXP-03 (D6) — Approved Option A:** `servicecore diff <baseline.json> <current.json>` (`NEW_REGRESSION`, `FIXED`, `PERSISTENT`) and `<a href="*.pdf">` auto-discovery.
5. **EXP-04 (D7) — Approved Option A:** Wave 2–3 Next.js Workbench keyboard-first triage hotkeys (`j`/`k`/`a`/`r`/`e`, `Space`/`n`, 5s undo toast) and live per-run Cost & Margin Telemetry Footer.

---

## Step 0I: Temporal Interrogation
- **HOUR 1 (Foundations):** Implement `pyproject.toml` dependencies (`playwright`, `axe-playwright-python`/`axe-core`, `pypdf`, `anthropic`, `weasyprint`, `httpx`), SSRF URL/IP validator, and canonical Pydantic v2 models (`FindingEvidence`, `RemediationPatch`, `FindingReview`, `AuditBundle`) (`human: ~1 day / CC: ~20 min`).
- **HOUR 2–3 (Core Logic):** Implement dual-engine scanner (`web_axe.py` + `pdf_ua.py` iterative tag-tree inspector with `visited` cycle guard), deterministic `rule_id -> (wcag_criterion, aoda_section)` lookup, `component_fingerprint` deduplication, Claude structured patch synthesizer + evidence-binding validator, and `servicecore diff` (`human: ~3 days / CC: ~35 min`).
- **HOUR 4–5 (Integration & Export):** Implement canonical SHA-256 `evidence_digest`, `servicecore verify`, `WeasyPrint` certified PDF exporter (with hard unsigned-finding export gate and `--draft` watermark mode), `--format github-issues` export, and `<a href="*.pdf">` crawler auto-discovery (`human: ~2 days / CC: ~25 min`).
- **HOUR 6+ (Polish, Evals & Wave 2–3):** Build `evals/` ground-truth HTML/PDF fixture suite, run 5-site SMB benchmark, and implement Wave 2–3 FastAPI (`org_id` JWT), PostgreSQL/GCS, Next.js Review Workbench (`EXP-04`), Stripe, and split Cloud Run deployment (`human: ~1.5 weeks / CC: ~1.5 hours`).
- **Feasibility Blockers:** None remaining after `ROW-01` Option B and `pypdf` deterministic bounds. **Pending Implementation Choices (Non-blocking):** Exact `WeasyPrint` HTML/CSS report template styling and PostgreSQL schema migration tool (`alembic` vs raw SQL) owned by `/gstack-plan-eng-review`.

---

## Current Scope Summary
- **Mode:** `SCOPE EXPANSION` (`D3` → Option A, `auto_decided: false`).
- **Accepted Decisions:** `ROW-01` (D2 → B), `EXP-01` (D4 → A), `EXP-02` (D5 → A), `EXP-03` (D6 → A), `EXP-04` (D7 → A), `0H Doc Approval` (D8 → A).
- **Deferred:** None. **Rejected/Excluded:** Java VeraPDF subprocess, overlay widgets, raw AI seat SaaS billing.

---

## Section 1: Architecture Review

### System Architecture & Dependency Graph
```text
[CLI / Next.js Workbench] ──▶ [FastAPI Gateway (org_id JWT, Stripe Webhook)]
                                     │
                                     ▼
                           [pipeline/router.py]
                    (SSRF Guard + Scheme/MIME Router)
                       ┌─────────────┴─────────────┐
                       ▼ (HTML URL)                ▼ (PDF URL/File / <a href="*.pdf">)
             [web_axe.py]                    [pdf_ua.py]
      (Playwright + axe-core JS)       (pypdf iterative tag-tree)
                       └─────────────┬─────────────┘
                                     ▼
                     [schemas/evidence.py: FindingEvidence]
                                     │
                                     ▼
                   [synthesizer/claude.py: RemediationPatch]
           (Component Dedup + WCAG/AODA Lookup + Evidence Guard)
                                     │
                                     ▼
                [workbench/: FindingReview (j/k/a/r/e)]
                                     │
                                     ▼
            [exporter/: WeasyPrint PDF + JSON + GH Issues]
         (Unsigned-Claim Gate + SHA-256 evidence_digest + verify/diff)
```

### `AuditRun` State Machine
```text
  [QUEUED] ──(worker pickup)──▶ [SCANNING] ──(FindingEvidence[] ready)──▶ [SYNTHESIZING]
     │                              │                                          │
     ▼ (validation/SSRF fail)       ▼ (scanner timeout/WAF/corrupt PDF)        ▼ (Claude 429/5xx exhausted)
  [FAILED] ◀──────────────────── [FAILED] ◀──────────────────────────────── [FAILED]

  [SYNTHESIZING] ──(validated patches)──▶ [PENDING_REVIEW] ──(all non-rejected signed)──▶ [SIGNED_OFF] ──(digest + gate pass)──▶ [EXPORTED]
```
- **Impossible Transitions Prevented:** `PENDING_REVIEW -> EXPORTED` and `SIGNED_OFF -> EXPORTED` with any `PENDING` finding raise `UnsignedFindingError` (`EXP-02`).
- **4-Path Data Flow:** Happy (scans → dedups → synthesizes → signs → exports certified PDF/JSON); Nil (missing URL/scheme fails fast with `pydantic.ValidationError`; missing PDF `/StructTreeRoot` emits deterministic `PDF_UNTAGGED_DOCUMENT` finding); Empty (`0` violations skips Claude completely, `0` LLM cost, exports signed zero-defect certificate); Error (typed failure on `AuditRun(status=FAILED)`, Chromium closed in `finally`).
- **Scaling & SPOFs:** Headless Chromium OOMs at `10x` in `512 MiB` containers → split lightweight API (`512 MiB`) from isolated Playwright/pypdf worker (`2–4 GiB`, `concurrency=2`, `--disable-dev-shm-usage`). At `100x`, component dedup cuts Anthropic calls `5–10x`, paired with Cloud Tasks rate-limiting.
- **Rollback Posture:** Feature-flag Wave 2–3 Cloud Run revisions via traffic splitting (`gcloud run services update-traffic`, `< 2 min` rollback); Wave 1 CLI is stateless local/CI execution.

---

## Section 2: Error & Rescue Map

| METHOD / CODEPATH | WHAT CAN GO WRONG | EXCEPTION CLASS | RESCUED? | RESCUE ACTION | USER SEES |
|---|---|---|---|---|---|
| `web_axe.scan_url` | Page/hydration timeout | `playwright.async_api.TimeoutError` | Y | `domcontentloaded` + bounded `10s` hydration wait; hard `30s` cap; close context in `finally` | Typed `ScannerTimeoutError` |
| `web_axe.scan_url` | WAF / Cloudflare `403`/`429` | `ScannerBlockedError` | Y | Inspect `response.status` before `axe-core`; fail fast without scanning challenge DOM | `"Target blocked automated scan (HTTP 403/429)"` |
| `web_axe.scan_url` | URL serves PDF MIME | `ContentTypeMismatch` | Y | Check `Content-Type` + `%PDF-` magic bytes; route to `pdf_ua.py` | Seamless PDF/UA scan |
| `pdf_ua.inspect_pdf` | Password-encrypted PDF | `pypdf.errors.FileNotDecryptedError` | Y | Try `decrypt("")`; if locked, emit `EncryptedPdfError` | `"Encrypted PDF requires unlocked copy"` |
| `pdf_ua.inspect_pdf` | Corrupt/truncated PDF | `pypdf.errors.PdfReadError` | Y | Check `%PDF-` header; catch `PdfReadError`/`PdfStreamError` | `"Corrupt PDF at byte offset..."` |
| `pdf_ua.inspect_pdf` | Missing `/StructTreeRoot` | `KeyError` (nil catalog) | Y | Use `.get()` + `isinstance` guards; emit `PDF_UNTAGGED_DOCUMENT` finding | Deterministic PDF/UA violation |
| `claude.synthesize` | API `429` / `5xx` / timeout | `anthropic.RateLimitError`, `APITimeoutError` | Y | Exponential backoff + jitter (max 3–5 retries) honoring `Retry-After` | Transparent retry or `"Synthesis deferred"` |
| `claude.synthesize` | Malformed JSON / Hallucinated `rule_id` | `pydantic.ValidationError`, `EvidenceMismatchError` | Y | Structured tool-use + 1 repair retry; strip unbacked patch & flag `MANUAL_SYNTHESIS_REQUIRED` | Raw `FindingEvidence` + empty manual patch box |
| `exporter.export_pdf` | Any finding `PENDING` | `UnsignedFindingError` | Y | Hard block on certified export; allow `--draft` watermark only | `"Export blocked: N findings unsigned"` |

**0 CRITICAL GAPS remaining** (all 9 error paths mapped with explicit exceptions and rescue actions).

---

## Section 3: Security & Threat Model

| # | Threat | Likelihood | Impact | Mitigation in Plan |
|---|---|---|---|---|
| 1 | **SSRF via Target URL / `<a href="*.pdf">` & DNS Rebinding** (`169.254.169.254`, `127.0.0.1`, RFC 1918, `file://`) | High | Critical | Scheme allowlist (`https://`/`http://`), DNS IP check (`not ip.is_global`), manual redirect hop validation (max 5) with socket IP pinning, Playwright `page.route("**/*")` interception, Cloud Run VPC egress firewall + zero-priv SA. |
| 2 | **Indirect Prompt Injection via Untrusted DOM / PDF** (`aria-label`, `/Alt`, HTML comments) | High | High | `<untrusted_evidence>` delimiters, `EXP-01` deterministic evidence-binding guard, HTML/SVG sanitization rejecting `<script>`/`on*=`/`javascript:` in `after_snippet`, strict escaping in Workbench & WeasyPrint. |
| 3 | **Multi-Tenant `org_id` IDOR / BOLA** | Medium | High | Extract `org_id` solely from verified JWT/session; enforce `WHERE org_id = :auth_org_id` + PostgreSQL RLS; GCS keys prefixed `orgs/{org_id}/...`. |
| 4 | **Stripe Webhook Forgery / Replay** | Low–Med | High | Verify `Stripe-Signature` on raw bytes (`STRIPE_WEBHOOK_SECRET` in GCP Secret Manager); deduplicate processed `event.id`. |
| 5 | **PDF Parser DoS (`pypdf` Zip Bomb / Cycle)** | Medium | High | `25 MB` streaming byte cap, `%PDF-` magic check, isolated worker `RLIMIT_AS` + `15s` timeout, iterative BFS/DFS with `visited` indirect-object cycle guard. |

---

## Section 4: Data Flow & Interaction Edge Cases

```text
INPUT (URL/.pdf) ─▶ VALIDATION (Scheme+SSRF+25MB) ─▶ TRANSFORM (axe-core/pypdf -> FindingEvidence -> Claude Patch) ─▶ PERSIST (PG/GCS/JSON) ─▶ OUTPUT (PDF/JSON/GH)
   └─ nil/empty: ValidationError    └─ private IP: SSRFBlockedError    └─ 0 findings: skip Claude    └─ unsigned: UnsignedFindingError    └─ tamper: verify exit 1
```
- **Async Ordering:** Concurrent Workbench triage actions (`approve`/`reject`) on the same `finding_id` or concurrent `export` while a finding is edited are serialized via optimistic locking (`version` / `updated_at` check on `FindingReview`) and atomic DB transaction before computing `evidence_digest`.
- **Interaction Edge Cases:** Double-click on `Approve` (idempotent state transition + `5s` undo toast); navigate away during edit (dirty-state `beforeunload` warning); `0` findings (green clean certificate flow); partial failure when HTML succeeds and linked PDF fails (yellow warning card, HTML triage unblocked).

---

## Section 5: Code Quality Review
- Strict `mypy --strict`, `ruff check`, Pydantic v2 (`pyproject.toml:11-12`, `AGENTS.md:3`).
- No bare `except Exception: pass` (`AGENTS.md:5`).
- Keep `pipeline/scanners/`, `pipeline/synthesizer/`, `exporter/`, and `evals/` modular with shallow nesting (`<= 5` branches per function; extract DOM normalization and PDF dictionary traversal helpers).

---

## Section 6: Test Review

```text
  [web_axe.py] ──▶ Unit: mocked Playwright + HTML fixtures (no_claim=live browser; unit only)
  [pdf_ua.py]  ──▶ Unit: tagged, untagged, missing-/Alt, missing-/TH, encrypted, corrupt, cyclic PDF fixtures
  [claude.py]  ──▶ Unit: mocked Anthropic client + hallucinated rule_id rejection + 429 retry
  [exporter/]  ──▶ Unit: canonical SHA-256 stability, tamper detection, unsigned export block, diff NEW_REGRESSION
  [evals/]     ──▶ E2E/Eval: 5 public SMB sites benchmark (turnaround <= 24h, 0 unverified claims)
```
- **2am Friday Confidence Test:** Run `servicecore verify` on a tampered `bundle.json` (1 flipped character in `raw_snippet`) and confirm exit code `1`; run `servicecore export` with 1 `PENDING` finding and confirm `UnsignedFindingError`.
- **Hostile QA / Chaos Test:** Feed a redirect chain `https://public.example -> http://169.254.169.254/latest/meta-data/`, a cyclic `/StructTreeRoot` PDF, and a Claude response injecting `<script>alert(1)</script>` in `after_snippet`—all must be blocked/sanitized cleanly.
- **Test Pyramid:** Heavy deterministic unit tests (`pytest` with HTML/PDF fixtures, 0 network flakiness) + targeted E2E integration tests on the 5 SMB sites.

---

## Section 7: Performance Review
- **Slowest Paths (p99 `[estimated]`):** (1) Multi-page Playwright crawl (`25` pages × `~2–4s` = `~50–100s`); (2) Anthropic Claude synthesis (`~1–3s` per deduplicated component); (3) `WeasyPrint` PDF rendering (`~1–2s`).
- **Optimizations:** Component deduplication (`EXP-01`) cuts LLM calls `5–10x`; Playwright shares 1 `Browser` across `BrowserContext`s; PDF streaming caps memory at `25 MB`; PostgreSQL indexes on `(org_id, audit_id)` and `(audit_id, component_fingerprint)`.

---

## Section 8: Observability & Debuggability Review
- Structured JSON logs (`audit_id`, `org_id`, `stage`, `duration_ms`, `token_cost_usd`, `error_code` — never logging raw secrets or client PII).
- Metrics & Alerts: Scan duration p95, `ScannerBlockedError` rate, Claude `429` / `EvidenceMismatchError` rate, and per-audit gross margin (`EXP-04`).
- Runbooks: `EvidenceMismatchError` spike → inspect prompt/axe-core version drift; Chromium OOM → verify `--disable-dev-shm-usage` and worker `concurrency=2`.

---

## Section 9: Deployment & Rollout Review
- Wave 1 ships as a versioned Python CLI package (`pyproject.toml`).
- Wave 2–3 ships via backward-compatible PostgreSQL migrations (expand-contract), Cloud Run traffic-split canary (`10% -> 100%`), post-deploy `/healthcheck` smoke test, and `< 2 min` revision rollback.

---

## Section 10: Long-Term Trajectory Review
- **Reversibility:** `4 / 5` (Clean Pydantic `FindingEvidence` boundary lets us swap `pypdf` for `VeraPDF` or add SOC2/HIPAA compliance scanners in Phase 2 without changing the Workbench, `evidence_digest`, or `diff` engine).
- **Platform Potential:** `FindingEvidence` + `RemediationPatch` + `evidence_digest` generalizes directly from AODA/WCAG to Security-Readiness / SOC2 / QA audits (`PROJECT_SPEC.md:9,12`).

---

## Section 11: Design & UX Review (`DESIGN_SCOPE` Active)
- **Information Architecture:** 2-column split-pane Next.js Workbench (Left `320px`: component-deduped queue; Right `1fr`: Verdict/Blast-Radius header → Side-by-side `FindingEvidence` & `RemediationPatch` diff → Sticky `j`/`k`/`a`/`r`/`e` action & margin footer).
- **Interaction State Coverage Map:**

| FEATURE | LOADING | EMPTY | ERROR | SUCCESS | PARTIAL |
|---|---|---|---|---|---|
| Workbench Queue | Skeleton cards + stage stepper | Green WCAG/AODA clean state | Failed engine banner + retry | `100% Signed`, export unlocked | Filter pills (`Pending`/`Approved`/`Rejected`) |
| Patch Diff & Guard | Shimmer on `after_snippet` | Raw `FindingEvidence` + manual box | Red `"Blocked: rule_id mismatch"` | Green `"Evidence Bound"` pill | Inline `[e]` editor + `Cmd+Enter` |
| Export Flow | `"Computing SHA-256 -> Rendering PDF"` | Disabled CTA (`N unsigned`) | `UnsignedFindingError` + `[g]` jump | Copyable `evidence_digest` + PDF/JSON/GH | Drift counts if baseline linked |

- **Workbench Accessibility:** Dogfoods WCAG 2.2 AA (`2px` focus rings, `>= 24x24px` targets, `aria-live="polite"` triage announcements, `Esc` exits code editor, color-independent `+`/`-` diff markers).
- **User Flow Diagram:**
```text
[URL / .pdf] ─▶ [Playwright+axe / pypdf] ─▶ [Dedup + Claude Patch] ─▶ [Workbench: j/k/a/r/e] ─▶ {Pending==0?} ─▶ [SHA-256 + PDF/JSON/GH]
```
- **Recommendation:** Run `/gstack-plan-design-review` before implementing the Wave 2–3 Next.js Review Workbench.

---

## Approval Readiness & Completion Summary
- **Approval readiness:** `PASS` — All 5 Decision Ledger rows (`ROW-01`, `EXP-01`, `EXP-02`, `EXP-03`, `EXP-04`) are `approved` with recorded answers (`D2`, `D4`, `D5`, `D6`, `D7`), `D3` (`SCOPE EXPANSION`), and `D8` (0H Document Approval). `0` unresolved decisions, `0` critical gaps.
- **Lake Score:** `1/1` (`D2` chose 10/10 complete option `B`; `D1`, `D3–D8` differed in kind).
- **Diagrams Produced:** 4 ASCII diagrams (Dream State Map, System Architecture & Dependency Graph, `AuditRun` State Machine, Data Flow & User Flow).
- **Stale Diagrams Found:** 0.

```text
  +====================================================================+
  |            MEGA PLAN REVIEW — COMPLETION SUMMARY                   |
  +====================================================================+
  | Mode selected        | SCOPE EXPANSION                             |
  | System Audit         | Greenfield scaffold (healthcheck() only);   |
  |                      | flagged axe-core PDF limitation (ROW-01)    |
  | Step 0               | SCOPE EXPANSION; approved ROW-01(B),        |
  |                      | EXP-01(A), EXP-02(A), EXP-03(A), EXP-04(A)  |
  | Section 1  (Arch)    | 0 open issues (split API/worker + state map)|
  | Section 2  (Errors)  | 9 error paths mapped, 0 GAPS                |
  | Section 3  (Security)| 5 threats mitigated, 1 Critical (SSRF)      |
  | Section 4  (Data/UX) | 4 shadow paths + 4 UX edge cases mapped, 0  |
  | Section 5  (Quality) | 0 issues (mypy --strict + ruff + <=5 branch)|
  | Section 6  (Tests)   | Diagram produced, 0 gaps                    |
  | Section 7  (Perf)    | 0 open issues (dedup + 25MB cap + indexes)  |
  | Section 8  (Observ)  | 0 gaps (JSON logs, metrics, margin, runbook)|
  | Section 9  (Deploy)  | 0 open risks (Cloud Run canary + rollback)  |
  | Section 10 (Future)  | Reversibility: 4/5, debt items: 0           |
  | Section 11 (Design)  | 0 issues (Next.js split-pane + WCAG 2.2 AA) |
  +--------------------------------------------------------------------+
  | NOT in scope         | written (3 items: VeraPDF, overlays, seats) |
  | What already exists  | written                                     |
  | Dream state delta    | written                                     |
  | Error/rescue registry| 9 rows, 0 CRITICAL GAPS                     |
  | Failure modes        | 9 total, 0 CRITICAL GAPS                    |
  | TODOS.md updates     | 0 items deferred (all 4 EXP accepted)       |
  | Scope proposals      | 5 proposed (ROW-01 + EXP-01..04), 5 accepted|
  | CEO plan             | written (~/.gstack/projects/.../ceo-plans/) |
  | Outside voice        | codex unavailable (MODEL_UNUSABLE)          |
  | Lake Score           | 1/1 recommendations chose complete option   |
  | Diagrams produced    | 4 (Dream State, Arch, State Machine, Flow)  |
  | Stale diagrams found | 0                                           |
  | Unresolved decisions | 0                                           |
  | Reality rows         | 7/7 rows (PLAN_REALITY), 0 unverified       |
  +====================================================================+
```

---

## Engineering Review (`/gstack-plan-eng-review`)

### Step 0: Scope Challenge & Complexity Resolution
- **Target:** [PROJECT_SPEC.md](file:///Users/justinmafie/Documents/antigravity/servicecore/PROJECT_SPEC.md) & [docs/designs/servicecore-platform.md](file:///Users/justinmafie/Documents/antigravity/servicecore/docs/designs/servicecore-platform.md).
- **Scope Challenge Result:** `scope accepted as-is` (`feature answers: ROW-01(B), EXP-01(A), EXP-02(A), EXP-03(A), EXP-04(A) all kept; structure: B + D1; accepted scope: Wave 1 Smaller Arrangement [8 core Python modules + 4 test files = 12 files, 5 domain classes] + Wave 2-3 Workbench/Stripe/Cloud Run; pending remedies: none`).
- **Wave 1 File Map (`Smaller Arrangement`, `D1 -> B`):**
  - `src/servicecore/schemas.py` (`FindingEvidence`, `RemediationPatch`, `FindingReview`, `AuditBundle`, `DiffReport`)
  - `src/servicecore/scanners.py` (`validate_public_url` SSRF guard, `WebAxeScanner`, `PdfUaInspector`, `<a href="*.pdf">` discovery)
  - `src/servicecore/synthesizer.py` (deterministic `WCAG_AODA_MAP`, `component_fingerprint` dedup, `ClaudeSynthesizer`, evidence-binding & XSS guard)
  - `src/servicecore/exporter.py` (canonical SHA-256 `evidence_digest`, `verify_bundle`, `diff_bundles`, `WeasyPrint` certified PDF & `--format github-issues`)
  - `src/servicecore/cli.py` (`audit`, `verify`, `diff` CLI entrypoints)
  - `evals/runner.py`, `evals/corpus.py`, `src/servicecore/__init__.py`
  - `tests/test_scanners.py`, `tests/test_synthesizer.py`, `tests/test_exporter.py`, `tests/test_cli.py` (plus `tests/test_smoke.py`)

### 1. Architecture Review (Design-Twice & 8 Red Flags)
- **Two Shapes Evaluated:**
  - **Shape 1 (Chosen): Immutable Value-Object Pipeline (`ScannerBackend` Protocol → `AuditBundle` → `Exporter`).** `scanners.py` hides Playwright, `pypdf`, and SSRF/redirect-pinning behind `scan(target) -> list[FindingEvidence]`. `synthesizer.py` enriches into `list[RemediationPatch]`. `exporter.py` enforces the `UnsignedFindingError` gate and computes `evidence_digest` over canonical JSON.
  - **Shape 2 (Rejected): Shared Mutable `AuditContext` State Bag** passed through `load()`, `validate()`, `transform()`, `save()` stages.
  - **Depth Argument:** Shape 1 hides SSRF DNS-pinning, Playwright context cleanup, and `pypdf` iterative cycle-guard traversal behind a single `scan()` boundary with zero shared mutable state.
- **8 Red Flags Screen:**
  1. Shallow module: Mitigated by consolidating into 5 deep domain modules (`D1 -> B`).
  2. Information leakage: External `axe-core` JSON and `pypdf` dicts are parsed into Pydantic v2 `FindingEvidence` immediately at `scanners.py` boundary.
  3. Temporal decomposition: Avoided by grouping by domain knowledge (`scanners`, `synthesizer`, `exporter`) rather than execution steps.
  4. Pass-through method: `cli.py` calls `scanners`/`synthesizer`/`exporter` directly without intermediate wrapper services.
  5. Split ownership: `FindingReview` status (`PENDING`/`APPROVED`/`REJECTED`/`EDITED`) has one owner (`AuditBundle` / DB transaction in Wave 2–3).
  6. Two ways to do one task: Single `validate_public_url()` SSRF guard shared by both `WebAxeScanner` and `PdfUaInspector` PDF fetcher.
  7. Importable internals: Prefix internal helpers (`_normalize_dom_signature`, `_pin_dns_ip`) with `_` and export public contracts in `__all__`.
  8. Hand-synced list: Single `WCAG_AODA_MAP` dict in `synthesizer.py` drives both patch synthesis and PDF legal citations.
- **Dispositions:** 0 open issues (`Shape 1` adopted via `D1 -> B`).

### 2. Code Quality Review
- **Shared-Code Evaluation:** `validate_public_url()` + `_safe_http_get()` in `scanners.py` serves both HTML pre-flight/linked-PDF fetching and direct `.pdf` URL fetching (2 verified planned callers, saves ~45 duplicated SSRF/redirect lines, tested once in `test_scanners.py`).
- **Quality Rules:** `mypy --strict`, `ruff check`, Pydantic v2, zero bare `except Exception: pass` (`AGENTS.md:3-5`), max 5 branches per function.
- **Dispositions:** 0 issues found.

### 3. Test Review
- **Detected Framework:** `pytest` + `mypy --strict` (`pyproject.toml:7-12`).
- **Coverage Diagram:**
```text
CODE PATHS                                            USER FLOWS
[+] src/servicecore/scanners.py                       [+] CLI Audit & Export Flow
  ├── validate_public_url() [SSRF/DNS/redirect]       ├── [GAP] [→E2E] servicecore audit <url> (5 SMB sites)
  │   └── [GAP] Unit: private IP / 169.254 / 302      ├── [GAP]        Export blocked while PENDING
  ├── WebAxeScanner.scan()                            ├── [GAP]        Export certified PDF + SHA-256
  │   └── [GAP] Unit: HTML DOM + 403 WAF + PDF MIME   ├── [GAP]        servicecore verify (exit 0 / exit 1)
  └── PdfUaInspector.scan()                           └── [GAP]        servicecore diff (exit 0 / exit 2)
      └── [GAP] Unit: tagged/untagged/encrypted/cycle [+] Wave 2-3 Workbench Flow
[+] src/servicecore/synthesizer.py                    └── [GAP] [→E2E] j/k/a/r/e triage + 5s undo
  ├── [GAP] [→EVAL] Claude structured RemediationPatch
  └── [GAP] Unit: hallucinated rule_id + XSS guard
[+] src/servicecore/exporter.py
  └── [GAP] Unit: canonical SHA-256 + verify + diff

COVERAGE: 1/11 paths tested (smoke only)  |  Code paths: 1/6  |  User flows: 0/5
QUALITY: ★★★:0 ★★:0 ★:1 (test_smoke.py)  |  GAPS: 10 (2 E2E, 1 eval) — greenfield Wave 1
```
- **Test Plan Artifact:** Written to `~/.gstack/projects/justinmafie/justinmafie-main-eng-review-test-plan-*.md`.
- **Dispositions:** 10 greenfield test gaps mapped to `T1`–`T6` implementation tasks below; 0 unresolved test decisions.

### 4. Performance Review
- **Scale & Latency Bounds:** `25` max pages × `30s` timeout (`~750s` worst-case sequential; bounded via `4` concurrent `BrowserContext`s on single shared Chromium `Browser`), `25 MB` max PDF stream buffer, `EXP-01` component deduplication reduces Claude API calls `5–10x`.
- **Dispositions:** 0 open issues.

### Worktree Parallelization Strategy
| Step | Modules touched | Depends on |
|---|---|---|
| Lane A: Schemas & SSRF/PDF | `src/servicecore/schemas.py`, `src/servicecore/scanners.py` | — |
| Lane B: Synthesizer & Exporter | `src/servicecore/synthesizer.py`, `src/servicecore/exporter.py` | `schemas.py` |
| Lane C: CLI, Evals & Tests | `src/servicecore/cli.py`, `evals/`, `tests/` | Lane A + Lane B |
- **Parallel Lanes:** `Lane A` (after `schemas.py` lands) and `Lane B` run in parallel; merge both, then run `Lane C`.

## Implementation Tasks
- [ ] **T1 (P1, human: ~3h / CC: ~20min)** — `schemas` — Implement Pydantic v2 contracts (`FindingEvidence`, `RemediationPatch`, `FindingReview`, `AuditBundle`, `DiffReport`)
  - Surfaced by: Eng Review Section 1 — `schemas.py` boundary
  - Files: `src/servicecore/schemas.py`, `tests/test_scanners.py`
  - Verify: `mypy --strict src/ tests/ && pytest`
- [ ] **T2 (P1, human: ~6h / CC: ~35min)** — `scanners` — Implement SSRF-hardened `validate_public_url()`, `WebAxeScanner` (Playwright/axe-core + `<a href="*.pdf">` discovery), and iterative `PdfUaInspector` (`pypdf`)
  - Surfaced by: Eng Review Section 1 & 2 — `ROW-01`, `EXP-03`, SSRF & PDF cycle guards
  - Files: `src/servicecore/scanners.py`, `tests/test_scanners.py`
  - Verify: `pytest tests/test_scanners.py -v`
- [ ] **T3 (P1, human: ~4h / CC: ~25min)** — `synthesizer` — Implement `WCAG_AODA_MAP`, `component_fingerprint` dedup, Claude structured `RemediationPatch` synthesizer, and evidence-binding + XSS sanitization guard
  - Surfaced by: Eng Review Section 1 & 3 — `EXP-01`
  - Files: `src/servicecore/synthesizer.py`, `tests/test_synthesizer.py`
  - Verify: `pytest tests/test_synthesizer.py -v`
- [ ] **T4 (P1, human: ~4h / CC: ~25min)** — `exporter` — Implement canonical SHA-256 `evidence_digest`, `verify_bundle`, `diff_bundles`, `WeasyPrint` certified PDF export gate (`--draft` watermark), and `--format github-issues`
  - Surfaced by: Eng Review Section 1 & 3 — `EXP-02`, `EXP-03`
  - Files: `src/servicecore/exporter.py`, `tests/test_exporter.py`
  - Verify: `pytest tests/test_exporter.py -v`
- [ ] **T5 (P1, human: ~3h / CC: ~20min)** — `cli` — Wire `servicecore audit`, `servicecore verify`, and `servicecore diff` CLI commands and run 5-site SMB benchmark in `evals/`
  - Surfaced by: Eng Review Section 3 — `PROJECT_SPEC.md:26-27`
  - Files: `src/servicecore/cli.py`, `evals/runner.py`, `evals/corpus.py`, `tests/test_cli.py`
  - Verify: `mypy --strict src/ tests/ && ruff check src/ tests/ && pytest`
- [ ] **T6 (P2, human: ~2w / CC: ~2h)** — `workbench-platform` — Implement Wave 2–3 FastAPI (`org_id` JWT), PostgreSQL/GCS, Next.js Review Workbench (`EXP-04` hotkeys + margin footer), Stripe webhook, and split Cloud Run deploy
  - Surfaced by: Eng Review Section 1 & 4 — Wave 2–3 deliverables
  - Files: `workbench/`, `docs/adr/001-outcome-pricing-workbench.md`
  - Verify: `pytest && npm test` (after `/gstack-plan-design-review`)

---

## Design Plan Review (`/gstack-plan-design-review`)

### Pre-Review Audit & Step 0
- **UI Scope:** Wave 2–3 Next.js Review Workbench (`OPERATE` App UI) and Wave 1–3 Exported Client PDF Report (`READ` document).
- **`DESIGN.md` Status:** Absent (`NO_DESIGN_MD`). Addressed in Pass 5 (`D3 -> A`).
- **Mockups (Step 0.5):** `DESIGN_READY` binary detected, but image generation exited `2` (`No image API key found`). Continued text-only per Step 0.5 fallback.
- **Initial Overall Design Score:** `4/10` (lowest of Passes 1–6 before fixes: Pass 5 `4/10`, Pass 3 `5/10`, Pass 6 `6/10`, Passes 1/2/4 `9/10`).

### Passes 1–7 Summary
- **Pass 1 (Information Architecture): `9/10 → 9/10`** — 3-tier Workbench hierarchy (Verdict/Blast-Radius → Side-by-side `FindingEvidence`/`RemediationPatch` diff → Sticky hotkey & margin footer) and 3-stage Client PDF (Page 1 SHA-256 Certificate, Page 2 Component Summary, Pages 3+ Developer Patchbook).
- **Pass 2 (Interaction State Coverage): `9/10 → 9/10`** — Complete `LOADING / EMPTY / ERROR / SUCCESS / PARTIAL` table across Queue, Patch Diff & Guard, and Export Flow (`PROJECT_SPEC.md` Section 11).
- **Pass 3 (User Journey & Emotional Arc): `5/10 → 9/10`** — Added required Storyboard & Time-Horizon framing:
  - *5-sec visceral:* Calm editorial slate-and-ink cockpit; green `Evidence Bound` badge immediately reassures reviewer that AI didn't hallucinate.
  - *5-min behavioral:* `j`/`k`/`a`/`r`/`e` hotkeys + `5s` undo toast clear 28 component-deduped findings at `< 5s/finding`.
  - *5-year reflective:* Client receives tamper-evident SHA-256 certificate + copy-pasteable PR diffs (`< 2%` revision rate).

| STEP | USER DOES | USER FEELS | PLAN SPECIFIES? |
|---|---|---|---|
| 1 | Opens `/audits/[id]` in Review Workbench | Oriented, zero clutter | `320px` component-deduped queue + `1fr` Decision Canvas |
| 2 | Scans top finding (`WCAG 1.4.3 · 42 pages`) | Confident in scope & evidence | Sticky header + `FindingEvidence` receipt + `Evidence Bound` pill |
| 3 | Presses `a` (Approve) or `e` (Edit) | Fast, in-flow, safe from mistakes | Auto-advances to next `PENDING`, `5s` undo toast (`u`), live margin footer |
| 4 | Clears last pending item | Accomplished, ready to certify | Progress bar turns emerald; `Export Certified PDF` unlocks |
| 5 | Downloads PDF / runs `servicecore verify` | Legally defensible & proud | Page 1 SHA-256 `evidence_digest` certificate + Pages 3+ PR diffs |

- **Pass 4 (AI Slop Risk): `9/10 → 9/10`** — Classifier: `OPERATE` (Workbench) + `READ` (PDF). Zero hard-rejection hits (no SaaS card grid, no stacked cards, no decorative shadows/blobs, utility copy).
- **Pass 5 (Design System Alignment): `4/10 → 9/10` (`D3 -> Option A`)** — Approved explicit editorial slate-and-ink tokens & `DESIGN.md` creation in Wave 2–3:
  - **Scene & Mode:** Light-mode default (`--bg-canvas: #F8F9FA`, `--bg-surface: #FFFFFF`, `--ink-primary: #0F172A`, `--ink-muted: #475569`) for bright-office compliance review and seamless parity with printed/PDF client reports.
  - **Accents & Status:** `--accent-verify: #059669` (emerald), `--accent-critical: #DC2626`, `--accent-warn: #D97706`; `4.5:1` minimum text contrast; `4px` base spacing grid.
  - **Typography:** `IBM Plex Sans` (`>= 16px` body) + `JetBrains Mono` (selectors, code diffs, SHA-256 hashes, `font-variant-numeric: tabular-nums` on telemetry/counts).
  - **Browser Surfaces:** Custom `--accent-verify` selection highlight, `2px` high-contrast focus ring (`outline-offset: 2px`), styled thin scrollbars.
- **Pass 6 (Responsive & Accessibility): `6/10 → 9/10` (`D4 -> Option A`)** — Approved `< 1024px` intentional layout & `44px` touch targets:
  - **Desktop (`>= 1024px`):** Fixed `320px` Queue + `1fr` Decision Canvas + sticky bottom hotkey/telemetry bar.
  - **Tablet/Mobile (`< 1024px`):** Collapsible slide-over Queue drawer (opened via top finding-counter chip) + full-width Decision Canvas + sticky bottom `Approve` / `Reject` / `Edit` action bar.
  - **Accessibility:** `>= 44x44px` touch targets on touch viewports, `<a href="#main-content">Skip to main content</a>` + `<main id="main-content">`, `aria-live="polite"` triage announcements, `Esc` exits code editor, color-independent `+`/`-` diff markers.
- **Pass 7 (Unresolved Design Decisions): `2 resolved, 0 deferred`** — `D3` (Pass 5) and `D4` (Pass 6) resolved; 0 unresolved design decisions.

### Design Implementation Tasks
- [ ] **D1 (P2, human: ~2h / CC: ~10min)** — `design-system` — Create `DESIGN.md` and CSS custom properties (`#F8F9FA` canvas, `#0F172A` ink, `#059669` verify, `IBM Plex Sans` + `JetBrains Mono`, `tabular-nums`, themed focus/selection)
  - Surfaced by: Design Review Pass 5 (`D3 -> Option A`)
  - Files: `DESIGN.md`, `workbench/src/app/globals.css`
  - Verify: Contrast check (`>= 4.5:1`) and token parity across Workbench & `WeasyPrint` PDF
- [ ] **D2 (P2, human: ~1h / CC: ~8min)** — `responsive-a11y` — Implement `< 1024px` collapsible Queue drawer + sticky bottom action bar, `>= 44x44px` touch targets, and skip-to-main link (`<main id="main-content">`)
  - Surfaced by: Design Review Pass 6 (`D4 -> Option A`)
  - Files: `workbench/src/components/WorkbenchLayout.tsx`, `workbench/src/app/layout.tsx`
  - Verify: Playwright viewport tests at `375px`, `768px`, and `1440px` + keyboard/axe-core self-audit

## Design Review Completion Summary
```text
  +====================================================================+
  |         DESIGN PLAN REVIEW — COMPLETION SUMMARY (RE-RATING PASS)   |
  +====================================================================+
  | System Audit         | Tokens + <1024px/44px specs in PROJECT_SPEC |
  | Step 0               | Re-rating pass: all 6 passes at 9/10 (>=8)  |
  | Pass 1  (Info Arch)  | 9/10 → 9/10 (quick pass — no issues)        |
  | Pass 2  (States)     | 9/10 → 9/10 (quick pass — no issues)        |
  | Pass 3  (Journey)    | 9/10 → 9/10 (quick pass — storyboard intact) |
  | Pass 4  (AI Slop)    | 9/10 → 9/10 (quick pass — OPERATE + READ)   |
  | Pass 5  (Design Sys) | 9/10 → 9/10 (quick pass — tokens + D1)      |
  | Pass 6  (Responsive) | 9/10 → 9/10 (quick pass — <1024px/44px D2)  |
  | Pass 7  (Decisions)  | 0 new, 0 unresolved, 0 deferred             |
  +--------------------------------------------------------------------+
  | NOT in scope         | 0 new deferrals (VeraPDF/overlays/seats)    |
  | What already exists  | Section 11 split-pane + EXP-04 + D1/D2      |
  | TODOS.md updates     | 0 items proposed                            |
  | Approved Mockups     | 0 generated, 0 approved (no image API key)  |
  | Decisions made       | 0 new in re-rating pass (2 prior: D3, D4)   |
  | Decisions deferred   | 0                                           |
  | Overall design score | 9/10 → 9/10                                 |
  +====================================================================+
```

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/gstack-plan-ceo-review` | Scope & strategy | 2 | CLEAR | 5 proposals, 5 accepted, 0 deferred |
| Outside Review | `codex` (auto) | Independent 2nd opinion | 1 | UNAVAILABLE | codex MODEL_UNUSABLE (gpt-6.2-astra); no completed external review |
| Eng Review | `/gstack-plan-eng-review` | Architecture & tests (required) | 2 | CLEAR | 0 issues, 0 critical gaps |
| Design Review | `/gstack-plan-design-review` | UI/UX gaps | 2 | CLEAR | score: 9/10 → 9/10, 0 new decisions |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

- **OUTSIDE COVERAGE:** `codex` (`plan-review`) unavailable (`MODEL_UNUSABLE: gpt-6.2-astra`; native `Plan` subagent and `TaskStop` not offered in host). No completed external review.
- **VERDICT:** CEO + ENG + DESIGN CLEARED — ready to implement

NO UNRESOLVED DECISIONS
