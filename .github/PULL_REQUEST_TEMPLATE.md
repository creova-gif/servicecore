## Summary
Briefly describe the changes introduced by this PR and link any related issues.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Refactoring / maintenance
- [ ] Documentation / ADR

## Verification Checklist
- [ ] `mypy --strict` passes
- [ ] `ruff check` passes
- [ ] `pytest` passes with deterministic unit tests for new/changed behavior
- [ ] Workbench checks pass (`npx tsc --noEmit`, `npm test`, `npm run build`) if applicable
- [ ] Non-trivial design choices recorded in `docs/adr/` using `docs/adr/000-template.md`
- [ ] No `.env` files, API keys, or PII/PHI fixtures committed
