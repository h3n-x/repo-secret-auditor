# Release Candidate Checklist

Date: 2026-03-24
Target version: 0.1.0
Release type: Initial MVP candidate

## 1) Quality gates

- [x] Lint clean (Ruff)
- [x] Type check clean (mypy)
- [x] Tests passing (unit + integration + smoke)
- [x] Coverage gate maintained (>= 80%)
- [x] Strict warning mode validated (`pytest -W error`)

## 2) Security and compliance artifacts

- [x] OWASP evidence checklist available in `docs/security/security-owasp-checklist.md`
- [x] SARIF output path documented and validated
- [x] Severity gate behavior documented for CI usage

## 3) Product and documentation readiness

- [x] Technical README complete and aligned with executable commands
- [x] API reference and OpenAPI snapshot published
- [x] Demo script prepared for 10-15 minute walkthrough
- [x] Interview dry-run package preparado para uso local
- [x] Initial changelog created (`CHANGELOG.md`)

## 4) Git/release operations

- [ ] Create annotated tag `v0.1.0`
- [ ] Push tag to remote

Recommended commands once final commit is created:

```bash
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

Note: tag creation is intentionally left as a final explicit step after commit grouping/approval.

## 5) Final go/no-go

- [x] GO for release candidate handoff

Rationale:
1. Core MVP scope (scan, findings, SARIF, CI gate) is implemented and validated.
2. Security, testing, and documentation evidence are present and reviewable.
3. Remaining release operation is a controlled repository action (tag push).
