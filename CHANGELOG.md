# Changelog

All notable changes to this project are documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic Versioning.

## [0.1.0] - 2026-03-24

Initial MVP release candidate for Repo Secret and Dependency Auditor.

### Added
- FastAPI endpoints to create scans and query status/findings.
- Secret detection engine with baseline rules and scoring support.
- Dependency auditing for Python and Node lockfiles.
- SARIF 2.1.0 exporter for GitHub Code Scanning integration.
- Reusable GitHub Actions security workflow with severity gate.
- Dedicated quality workflow with lint, type checking, tests, and coverage enforcement.

### Security
- Rate limiting on scan creation endpoints.
- Strict validation for repository URL and ref inputs.
- Safer logging behavior to avoid leaking sensitive values.
- OWASP-oriented checklist with implementation evidence and residual risk notes.

### Performance
- Scan path pruning and file-type filtering for faster local/CI execution.
- Limits to keep scan scope aligned with MVP targets.

### Documentation
- Technical README with architecture, setup, runbook, CI usage, and troubleshooting.
- API reference and versioned OpenAPI snapshot.
- Interview/demo assets: issue grooming, demo script, and interview dry run package.

### Validation
- Local quality baseline verified: Ruff, mypy, and pytest suites (unit, integration, smoke).
- Strict warning mode (`pytest -W error`) validated on Python 3.14.
