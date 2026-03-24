# Repo Secret & Dependency Auditor

Backend para escaneo de secretos y dependencias vulnerables, con salida SARIF e integración con GitHub Code Scanning.

## Estado del MVP

Versión actual: `0.1.0`

Capacidades implementadas:
1. API para crear scans y consultar estado/findings.
2. Detección de secretos en archivos del repositorio.
3. Auditoría de dependencias (Python y Node lockfiles).
4. Exportación SARIF 2.1.0.
5. Workflow reusable de GitHub Actions con policy gate por severidad.
6. Suite de calidad (unit + integration + smoke) con cobertura mínima.

## Arquitectura

Componentes principales:
1. API FastAPI en `src/app/main.py`.
2. Endpoints de escaneo en `src/app/api/scans.py`.
3. Persistencia con SQLAlchemy en `src/app/db/`.
4. Motor de escaneo CI en `src/app/ci/scan_runner.py`.
5. Exportador SARIF en `src/app/reporting/sarif.py`.
6. Seguridad de entrada y rate limiting en `src/app/security/`.

Flujo de alto nivel:
1. `POST /scans` crea un scan con estado `queued`.
2. El runner procesa secretos y dependencias.
3. Se genera resumen JSON y SARIF.
4. `GET /scans/{scan_id}` y `GET /scans/{scan_id}/findings` exponen resultados.
5. En CI, el workflow sube SARIF a GitHub Code Scanning y aplica el gate HIGH/CRITICAL.

## Requisitos

1. Linux/macOS/WSL (probado en Linux).
2. Python `3.12+`.
3. `pip` actualizado.

## Setup local

1. Crear entorno virtual e instalar dependencias:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

2. Configurar base de datos (opcional). Por defecto usa SQLite local:

```bash
export DATABASE_URL="sqlite+pysqlite:///./repo_secret_auditor.db"
```

3. Levantar API:

```bash
python -m uvicorn app.main:app --reload --app-dir src
```

4. Abrir documentación interactiva:

```text
http://127.0.0.1:8000/docs
```

## Uso de API

Referencia completa de API:
1. `docs/reference/api-reference.md`
2. `docs/reference/openapi.json`

Evidencia de seguridad:
1. `docs/security/security-owasp-checklist.md`

Guion de demo (10-15 min):
1. `docs/demo/demo-script.md`

Paquete de dry run de entrevista:
1. Disponible solo en entorno local (no versionado en GitHub).

Cierre release candidate:
1. `docs/release/release-candidate.md`
2. `CHANGELOG.md`

Crear scan:

```bash
curl -X POST "http://127.0.0.1:8000/scans" \
  -H "Content-Type: application/json" \
  -d '{"repo_url":"https://github.com/octocat/Hello-World.git","ref":"main"}'
```

Consultar estado:

```bash
curl "http://127.0.0.1:8000/scans/1"
```

Consultar findings (paginado y filtros):

```bash
curl "http://127.0.0.1:8000/scans/1/findings?severity=HIGH&type=secret&limit=50&offset=0"
```

## Ejecutar escaneo desde CLI

Comando local equivalente al workflow reusable:

```bash
python scripts/run_security_scan.py \
  --project-root . \
  --summary artifacts/summary.json \
  --sarif artifacts/findings.sarif
```

Salidas esperadas:
1. `artifacts/summary.json`
2. `artifacts/findings.sarif`

## Calidad y validación

Lint:

```bash
python -m ruff check src tests
```

Tipos:

```bash
python -m mypy src tests
```

Tests + cobertura:

```bash
python -m pytest tests/unit tests/integration tests/smoke \
  --cov=src \
  --cov-report=term-missing \
  --cov-fail-under=80
```

Modo estricto de warnings:

```bash
python -m pytest -W error
```

## CI/CD

Workflows incluidos:
1. Reusable security scan: [.github/workflows/reusable-security-scan.yml](.github/workflows/reusable-security-scan.yml)
2. Caller de seguridad para `pull_request`/`push` a `main`: [.github/workflows/security.yml](.github/workflows/security.yml)
3. Pipeline de calidad: [.github/workflows/quality.yml](.github/workflows/quality.yml)

Invocación del reusable en otro workflow:

```yaml
name: Custom Security Scan

on:
  workflow_dispatch:

jobs:
  security:
    uses: ./.github/workflows/reusable-security-scan.yml
    permissions:
      contents: read
      security-events: write
    with:
      python-version: "3.12"
      fail-on-severity: true
      summary-json-path: artifacts/summary.json
      sarif-path: artifacts/findings.sarif
    secrets:
      github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Configuración

Variables relevantes:
1. `DATABASE_URL`: URL de base de datos. Default: `sqlite+pysqlite:///./repo_secret_auditor.db`.

Controles de seguridad relevantes:
1. Rate limiting en endpoints de scans.
2. Validación estricta de URL/ref de repositorio.
3. Logging seguro para evitar exponer secretos.
4. Actions pinneadas por SHA en workflows críticos.

## Troubleshooting

### Error de importación al ejecutar API

Síntoma: `ModuleNotFoundError: No module named 'app'`.

Solución:

```bash
python -m uvicorn app.main:app --reload --app-dir src
```

### `pytest -W error` falla por warning externo de SlowAPI

Síntoma: deprecación interna en Python 3.14 sobre `asyncio.iscoroutinefunction`.

Estado actual: mitigado con shim de compatibilidad en `src/app/security/rate_limiting.py` y validado en modo estricto.

### El workflow de seguridad falla por severidad

Síntoma: job falla con findings `HIGH` o `CRITICAL`.

Solución:
1. Revisar `artifacts/summary.json` y `artifacts/findings.sarif`.
2. Corregir findings o bajar el gate con `fail-on-severity: false` solo para pruebas controladas.

### No se generan artefactos en local

Síntoma: faltan `artifacts/summary.json` o `artifacts/findings.sarif`.

Solución:
1. Verificar que el comando CLI use rutas válidas.
2. Ejecutar desde la raíz del repo.
3. Confirmar que existe `scripts/run_security_scan.py`.

## Estructura del repositorio

```text
src/app/
  api/         # Endpoints y esquemas de respuesta
  ci/          # Runner de escaneo para CI/local
  db/          # Engine, sesión y modelos SQLAlchemy
  reporting/   # Exportación SARIF
  scanner/     # Detectores y scoring
  security/    # Validación, logging seguro, rate limiting
.github/workflows/
  reusable-security-scan.yml
  security.yml
  quality.yml
scripts/
  run_security_scan.py
tests/
  unit/
  integration/
  smoke/
```
