# ADR-001: Outcome-Priced Accessibility Audits via Dual-Engine Scanner & Mandatory Human Sign-Off
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
ServiceCore targets North American SMBs, SaaS vendors, and nonprofits facing AODA, WCAG 2.1/2.2 AA, and ADA compliance deadlines (`PROJECT_SPEC.md:9-12`). Automated overlay widgets fail legally and technically, while manual-only audits erode gross margin below the `>= 75%` target. Furthermore, `axe-core` only audits HTML DOMs and silently reports 0 violations on untagged PDFs.

## Decision
1. **Outcome Pricing + Mandatory Human Sign-Off:** Sell guaranteed business outcomes (`$1,000-$2,500/audit + $299/mo monitoring`) powered by private AI tooling and mandatory human sign-off rather than raw AI seats.
2. **Dual-Engine Deterministic Scanner (`ROW-01` Option B):** Route HTML URLs to `Playwright/axe-core` and PDF inputs/auto-discovered `<a href="*.pdf">` links to a pure-Python `pypdf` PDF/UA structure-tree inspector (`/StructTreeRoot`, `/Lang`, `/Title`, `/Figure` `/Alt`, `/Table` `/TH`, `/Tabs /S`) behind a unified Pydantic v2 `FindingEvidence` schema.
3. **Zero Unverified Claims (`EXP-01` & `EXP-02`):** Bind every Claude `RemediationPatch` to a verified `FindingEvidence` record + deterministic `WCAG_AODA_MAP` legal lookup, block certified PDF export (`UnsignedFindingError`) until all non-rejected findings have human sign-off, and embed a canonical SHA-256 `evidence_digest` verifiable via `servicecore verify`.
4. **Monitoring Diff Engine (`EXP-03`):** Classify `NEW_REGRESSION`, `FIXED`, and `PERSISTENT` findings across snapshots via `servicecore diff` using `component_fingerprint`.

## Alternatives Considered
- **HTML-only Wave 1 (`ROW-01` A):** Rejected because Ontario AODA requires compliant public PDFs alongside web pages.
- **External Java VeraPDF Subprocess (`ROW-01` C):** Rejected for Wave 1 due to JRE container/CI weight; `ScannerBackend` protocol preserves clean swap-in later.

## Consequences & Failure Modes
- `pypdf` checks are scoped to deterministic structural tags; deep reading-order simulation is explicitly out of Wave 1 scope.
- SSRF protections (`validate_public_url` + manual redirect IP pinning + Playwright `page.route`) and `25 MB` / cycle-guarded PDF parsing are required on all untrusted targets.
