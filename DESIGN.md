# ServiceCore Design System (`DESIGN.md`)

## 1. Visual Direction & Scene Rationale
- **Mode:** Light-mode default (`--bg-canvas: #F8F9FA`, `--bg-surface: #FFFFFF`) designed for bright-office compliance review and visual parity with exported WeasyPrint client PDF reports.
- **Tone:** Crisp editorial slate-and-ink (`OPERATE` App UI for the Next.js Review Workbench; `READ` document for the Client PDF Report). Zero decorative card grids, zero purple gradients, zero glassmorphism.

## 2. Color Tokens
```css
:root {
  --bg-canvas: #F8F9FA;
  --bg-surface: #FFFFFF;
  --bg-subtle: #F1F5F9;
  --border-hairline: #E2E8F0;
  --ink-primary: #0F172A;
  --ink-muted: #475569;
  --accent-verify: #059669;
  --accent-critical: #DC2626;
  --accent-warn: #D97706;
  --focus-ring: #059669;
}
```
- Minimum text contrast ratio: `>= 4.5:1` across all body and status badges.
- Color independence: diff lines and severity badges always pair color with `+`/`-` prefixes and text labels.

## 3. Typography & Spacing
- **UI & Report Body:** `IBM Plex Sans` (`>= 16px` body, `1.5` line-height).
- **Selectors, Code Diffs & SHA-256 Digests:** `JetBrains Mono` (`font-variant-numeric: tabular-nums` for counts, scan duration, and gross-margin telemetry).
- **Spacing Grid:** `4px` base unit (`4 / 8 / 12 / 16 / 24 / 32`).

## 4. Browser Surfaces & Accessibility
- Selection highlight tinted from `--accent-verify`; `2px` solid `--focus-ring` with `2px` offset (`:focus-visible`).
- Skip-to-main link (`<a href="#main-content">Skip to main content</a>`) + `<main id="main-content">`.
- Minimum interactive target size: `>= 44x44px` on `< 1024px` touch viewports (`>= 24x24px` dense desktop controls).
- `< 1024px` layout: collapsible slide-over Queue drawer + full-width Decision Canvas + sticky bottom Approve/Reject/Edit action bar.
