# API Reference - Repo Secret & Dependency Auditor

Document type: Reference (Diataxis)

This document describes the current HTTP API contract and provides concrete request/response examples.

## OpenAPI sources

1. Live Swagger UI: `http://127.0.0.1:8000/docs`
2. OpenAPI snapshot (versioned): `docs/reference/openapi.json`

OpenAPI version: `3.1.0`

## Base URL

```text
http://127.0.0.1:8000
```

## Authentication

Current API version does not require authentication headers.

## Rate limiting

1. `POST /scans`: `10/minute` per client IP.
2. `GET /scans/{scan_id}` and `GET /scans/{scan_id}/findings`: `30/minute` per client IP.

When exceeded:

```json
{
  "detail": "Rate limit exceeded. Please try again later."
}
```

## Endpoints

## `POST /scans`

Create a security scan request.

### Request body

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `repo_url` | string (URI) | yes | Must match allowed Git hosts and supported schemes. |
| `ref` | string \| null | no | Git reference (branch/tag/sha). If omitted, backend defaults to `HEAD`. |

Example:

```json
{
  "repo_url": "https://github.com/h3n-x/repo-secret-auditor",
  "ref": "main"
}
```

### Responses

`202 Accepted`

```json
{
  "scan_id": 1,
  "status": "queued",
  "job_id": "scan-1"
}
```

`422 Unprocessable Content` (input validation)

```json
{
  "detail": "repo_url must point to a whitelisted Git host: github.com, gitlab.com, bitbucket.org, gitea.io, localhost"
}
```

## `GET /scans/{scan_id}`

Retrieve scan summary and current status.

### Path params

| Name | Type | Required |
| --- | --- | --- |
| `scan_id` | integer | yes |

### Responses

`200 OK`

```json
{
  "scan_id": 1,
  "repo_url": "https://github.com/h3n-x/repo-secret-auditor",
  "commit_sha": "main",
  "status": "queued",
  "started_at": "2026-03-24T20:15:00.000000Z",
  "finished_at": null,
  "total_findings": 0,
  "critical_count": 0,
  "high_count": 0,
  "medium_count": 0,
  "low_count": 0
}
```

`404 Not Found`

```json
{
  "detail": "Scan not found"
}
```

## `GET /scans/{scan_id}/findings`

Retrieve findings with pagination and optional filters.

### Path params

| Name | Type | Required |
| --- | --- | --- |
| `scan_id` | integer | yes |

### Query params

| Name | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `severity` | string \| null | no | null | Allowed runtime values: `low`, `medium`, `high`, `critical`. |
| `type` | string \| null | no | null | Allowed runtime values: `secret`, `dependency`. |
| `limit` | integer | no | 50 | Min 1, max 200 |
| `offset` | integer | no | 0 | Min 0 |

Example request:

```text
GET /scans/1/findings?severity=high&type=secret&limit=50&offset=0
```

### Responses

`200 OK`

```json
{
  "version": "v1",
  "scan_id": 1,
  "total": 1,
  "limit": 50,
  "offset": 0,
  "items": [
    {
      "id": 10,
      "type": "secret",
      "rule_id": "secret.github_pat",
      "file_path": "src/high.py",
      "line_start": 3,
      "line_end": 3,
      "severity": "high",
      "confidence": 0.9,
      "recommendation": "Rotate credential"
    }
  ]
}
```

`404 Not Found`

```json
{
  "detail": "Scan not found"
}
```

`422 Unprocessable Content` (invalid filters)

```json
{
  "detail": "Invalid severity filter"
}
```

or:

```json
{
  "detail": "Invalid type filter"
}
```

## Response models

Canonical models are defined in `src/app/api/schemas.py`:
1. `CreateScanRequest`
2. `CreateScanResponse`
3. `ScanDetailResponse`
4. `FindingItemResponse`
5. `FindingListResponse`

## Runbook: refresh OpenAPI snapshot

Whenever endpoint contracts change, regenerate `docs/reference/openapi.json`:

```bash
/home/h3n/Desktop/Security/.venv/bin/python - <<'PY'
import json
import sys
from pathlib import Path

sys.path.insert(0, 'src')
from app.main import app

Path('docs/reference/openapi.json').write_text(
    json.dumps(app.openapi(), indent=2, sort_keys=True),
    encoding='utf-8',
)
PY
```
