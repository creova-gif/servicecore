# Contributing to ServiceCore

Thank you for your interest in contributing to ServiceCore! Please follow the setup, coding standards, architecture documentation, and pull request guidelines below.

## Development Setup

### Prerequisites
- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/)
- Node.js 22+ and `npm`

### Backend (Python)
Create and activate a virtual environment, then install the package with development dependencies:

```bash
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Workbench (Next.js / TypeScript)
Install frontend dependencies inside `workbench/`:

```bash
cd workbench
npm install
```

## Coding Standards & Verification

All contributions must adhere to the repository's shared engineering standards in [`AGENTS.md`](AGENTS.md).

### Python Checks
- **Type checking:** `mypy --strict src tests`
- **Linting:** `ruff check src tests`
- **Tests:** `pytest`
- **Standards:** Python 3.12+, Pydantic v2, and explicit error handling (never use bare `except Exception: pass`).

### Workbench Checks (`workbench/`)
- **Type checking:** `npx tsc --noEmit` (or `npm run typecheck`)
- **Tests:** `npm test`
- **Build:** `npm run build`
- **Linting:** `npm run lint`

## Architecture Decision Records (ADRs)

Every non-trivial design or architectural choice must be recorded in `docs/adr/` using [`docs/adr/000-template.md`](docs/adr/000-template.md).

1. Copy `docs/adr/000-template.md` to `docs/adr/NNN-short-title.md` (incrementing the number).
2. Fill in the Context, Decision, and Consequences sections.
3. Include the new ADR in your pull request.

## Pull Request Guidelines

1. **Branching:** Create a focused branch from `main` for your change.
2. **Tests:** Every PR must include deterministic unit tests covering new behavior or bug fixes.
3. **Verification:** Run all relevant backend (`mypy --strict`, `ruff check`, `pytest`) and frontend (`npx tsc --noEmit`, `npm test`, `npm run build`) checks locally before opening a PR.
4. **Security:** Never commit `.env` files, API keys, credentials, or PII/PHI fixtures.
5. **PR Template:** Complete all sections of the [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md).
