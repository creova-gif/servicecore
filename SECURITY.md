# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| `0.1.x` | Yes |
| `< 0.1.0` | No |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities privately through GitHub Security Advisories for `creova-gif/servicecore`:

- **Private Advisory:** [https://github.com/creova-gif/servicecore/security/advisories/new](https://github.com/creova-gif/servicecore/security/advisories/new)

Include as much detail as possible to reproduce the issue (affected endpoint/module, request payload or input fixture, expected vs. actual behavior, and potential impact). We will acknowledge receipt, triage the report, and coordinate a fix and advisory disclosure.

## Implemented Security Controls

ServiceCore enforces defense-in-depth controls across scanning, authentication, API transport, and audit exports:

- **SSRF Validation (`src/servicecore/scanners.py`, `src/servicecore/crawler.py`, `src/servicecore/alerts.py`):** `validate_public_url` restricts target URLs and webhook destinations to `http`/`https` and blocks loopback, private, link-local, multicast, and reserved IP ranges.
- **HMAC-SHA256 Bearer & Webhook Authentication (`src/servicecore/auth.py`, `src/servicecore/alerts.py`):**
  - Bearer tokens are signed and verified using HMAC-SHA256 (`SERVICECORE_AUTH_SECRET`) with constant-time `hmac.compare_digest` checks and `org_id` tenant scoping. Outside `SERVICECORE_DEV_MODE=1`, `SERVICECORE_AUTH_SECRET` is required.
  - Outbound webhook alerts are signed with `X-ServiceCore-Signature-256` (`sha256=<hex>`) using `SERVICECORE_WEBHOOK_SECRET` and verified via `verify_webhook_signature`.
  - Inbound Stripe webhooks (`POST /webhooks/stripe`) verify `Stripe-Signature` timestamps and HMAC-SHA256 signatures against `STRIPE_WEBHOOK_SECRET`.
- **Request Body Size Limit (`src/servicecore/api.py`):** Non-`GET`/`HEAD`/`OPTIONS` requests exceeding `1 MiB` (`1,048,576` bytes) are rejected with HTTP `413` before route execution.
- **Response Security & Cache Headers (`src/servicecore/api.py`):**
  - Sensitive API routes (`/audits`, `/monitors`, `/dev/token`) emit `Cache-Control: no-store`.
  - All API responses include `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and `X-Request-ID`.
- **Formula-Safe CSV Escaping (`src/servicecore/exporter.py`):** `export_csv` passes cells through `_sanitize_csv_cell`, prefixing values starting with `=`, `+`, `-`, `@`, `\t`, or `\r` (including after leading whitespace) with `'` to prevent spreadsheet formula injection.
- **Cryptographic `evidence_digest` Sign-Off Gate (`src/servicecore/exporter.py`, `src/servicecore/synthesizer.py`):**
  - `sign_bundle` and `verify_bundle` enforce that every non-rejected finding has a human review status of `APPROVED` or `EDITED` before computing or validating the canonical SHA-256 `evidence_digest`.
  - `validate_patch_binding` rejects any synthesized `RemediationPatch` that drifts from the scanner's `rule_id`, `target_selector`, `wcag_criterion`, or `aoda_section`, or introduces unsafe HTML (`<script>`, `on*=`, `javascript:` URIs).
