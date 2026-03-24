# Demo Script - 10 to 15 Minutes

Tipo de documento: How-to (Diataxis)

Objetivo: demostrar el flujo completo del MVP en entrevista técnica.

Flujo obligatorio cubierto:
1. scan
2. findings
3. SARIF
4. policy gate

## Audience and outcomes

Audience:
1. Recruiters técnicos
2. Engineering managers
3. Reviewers de seguridad

Expected outcomes:
1. El sistema crea y consulta scans por API.
2. El scanner produce artefactos de seguridad utilizables (`summary.json`, `findings.sarif`).
3. Se evidencia un gate de severidad en CI.
4. Se comunica claramente qué está implementado y qué queda en backlog.

## Pre-demo checklist (2 to 3 minutes)

Run from repository root.

```bash
source .venv/bin/activate
python -m pytest -q
python -m ruff check src tests
```

Prepare a clean artifacts folder:

```bash
rm -rf artifacts && mkdir -p artifacts
```

## Timeline

1. Minute 0-1: Problem and architecture snapshot.
2. Minute 1-4: API flow (create scan and query status/findings).
3. Minute 4-7: Local CLI scan and generated artifacts.
4. Minute 7-10: SARIF evidence and CI policy gate.
5. Minute 10-12: Security posture and OWASP summary.
6. Minute 12-15: Q&A and roadmap.

## Step-by-step live demo

## 1) Open API service

Terminal A:

```bash
source .venv/bin/activate
python -m uvicorn app.main:app --reload --app-dir src
```

Narrative:
1. Explain this is the FastAPI surface for scan orchestration.
2. Mention docs are available at `http://127.0.0.1:8000/docs`.

## 2) Create a scan request

Terminal B:

```bash
curl -s -X POST "http://127.0.0.1:8000/scans" \
  -H "Content-Type: application/json" \
  -d '{"repo_url":"https://github.com/h3n-x/repo-secret-auditor","ref":"main"}'
```

Expected response shape:

```json
{
  "scan_id": 1,
  "status": "queued",
  "job_id": "scan-1"
}
```

Narrative:
1. Point out idempotent-style tracking via `scan_id` and `job_id`.
2. Mention input validation and rate limiting are active.

## 3) Query scan details and findings

```bash
curl -s "http://127.0.0.1:8000/scans/1"
curl -s "http://127.0.0.1:8000/scans/1/findings?limit=50&offset=0"
```

Narrative:
1. Explain schema stability and pagination.
2. Show that filters exist (`severity`, `type`) and are validated.

## 4) Run local security scan (CLI path)

```bash
source .venv/bin/activate
python scripts/run_security_scan.py \
  --project-root . \
  --summary artifacts/summary.json \
  --sarif artifacts/findings.sarif
```

Confirm outputs:

```bash
ls -lh artifacts/summary.json artifacts/findings.sarif
```

Narrative:
1. This is the same path consumed by reusable CI workflow.
2. Artifacts are portable and reviewable.

## 5) Show summary and SARIF snippets

```bash
python - <<'PY'
import json
from pathlib import Path

summary = json.loads(Path('artifacts/summary.json').read_text(encoding='utf-8'))
print({
    'total_findings': summary.get('total_findings'),
    'critical_count': summary.get('critical_count'),
    'high_count': summary.get('high_count'),
    'medium_count': summary.get('medium_count'),
    'low_count': summary.get('low_count'),
})
PY
```

```bash
python - <<'PY'
import json
from pathlib import Path

sarif = json.loads(Path('artifacts/findings.sarif').read_text(encoding='utf-8'))
run = sarif['runs'][0]
print('tool:', run['tool']['driver']['name'])
print('results:', len(run.get('results', [])))
if run.get('results'):
    first = run['results'][0]
    print('first_rule_id:', first.get('ruleId'))
PY
```

Narrative:
1. Explain SARIF compatibility with GitHub Code Scanning.
2. Point to reusable workflow that uploads SARIF and applies severity gate.

## 6) Explain CI policy gate

Reference workflow files:
1. `.github/workflows/reusable-security-scan.yml`
2. `.github/workflows/security.yml`

Key message:
1. Pipeline fails if `critical_count > 0` or `high_count > 0` when `fail-on-severity: true`.

Optional local gate simulation:

```bash
python - <<'PY'
import json
from pathlib import Path

summary = json.loads(Path('artifacts/summary.json').read_text(encoding='utf-8'))
critical = int(summary.get('critical_count', 0))
high = int(summary.get('high_count', 0))
print('critical_count=', critical)
print('high_count=', high)
if critical > 0 or high > 0:
    raise SystemExit('Security gate failed: HIGH/CRITICAL findings detected')
print('Security gate passed')
PY
```

## 7) Close with security posture and roadmap

Use these references:
1. `docs/security/security-owasp-checklist.md`
2. `docs/backlog/issue-grooming.md`

Closing points:
1. Current MVP includes validation, rate limiting, secure logging, SARIF, and CI gate.
2. Next priorities are authentication/authorization and extended SAST coverage.

## Interview speaking notes

Use this short script:
1. "This project focuses on practical AppSec automation for repository scanning."
2. "The API orchestrates scan lifecycle, and the scanner emits JSON summary plus SARIF."
3. "The reusable workflow turns findings into enforceable CI policy via severity gate."
4. "Security controls are documented against OWASP with explicit residual risks."
5. "The backlog is already groomed with priorities, estimations, and acceptance criteria."

## Demo fallback options

If network or environment fails:
1. Use `docs/reference/openapi.json` and `docs/reference/api-reference.md` to validate contract.
2. Use existing `artifacts/summary.json` and `artifacts/findings.sarif` from a prior successful run.
3. Run only unit and security tests to show quality baseline:

```bash
python -m pytest -q tests/unit tests/smoke
```
