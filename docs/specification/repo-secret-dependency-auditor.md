# Especificación Técnica Formal

## 1. Resumen
- **Proyecto**: Repo Secret & Dependency Auditor
- **Objetivo**: detectar secretos expuestos y vulnerabilidades en dependencias, priorizarlas por riesgo y generar resultados consumibles por GitHub Code Scanning (SARIF) y PR checks.
- **Tipo**: backend API + worker asíncrono + integración CI reusable.

## 2. Problema
Los repositorios pequeños y medianos suelen carecer de un control continuo y contextual de:
- secretos hardcodeados (tokens, claves, credenciales)
- dependencias vulnerables (directas y transitivas)
- priorización accionable para PRs

Esto produce deuda de seguridad, riesgo operacional y fricción al momento de demostrar buenas prácticas en entrevistas técnicas.

## 3. Alcance
### 3.1 Incluye
- API backend para crear escaneos y consultar resultados.
- Motor de detección de secretos (regex + entropía + allowlist).
- Motor de auditoría de dependencias (lockfiles + fuentes OSV/NVD según disponibilidad).
- Cola de trabajos asíncronos para escaneos.
- Exportación SARIF 2.1.0.
- Reusable workflow de GitHub Actions con acciones pinneadas por SHA.
- Política de fallo de pipeline para findings HIGH/CRITICAL.

### 3.2 No incluye (MVP)
- Dashboard frontend completo.
- Auto-remediación de código.
- Integración multi-VCS fuera de GitHub.

## 4. Requisitos Funcionales
1. Crear un escaneo de repositorio vía endpoint API.
2. Procesar escaneo en background y persistir resultados.
3. Detectar al menos:
   - GitHub PAT
   - AWS Access Key ID
   - Generic API key patterns
4. Calcular severidad y score de riesgo por finding.
5. Parsear lockfiles al menos para `requirements.txt` y `package-lock.json` (MVP mínimo).
6. Consultar base de vulnerabilidades y mapear CVEs a dependencias.
7. Exponer resultados vía API con filtros por severidad y tipo.
8. Generar SARIF válido y subirlo en CI.
9. Publicar artefactos de escaneo (`summary.json`, `findings.sarif`).

## 5. Requisitos No Funcionales
- **Seguridad**: OWASP Top 10 como baseline; deny-by-default.
- **Rendimiento**: escaneo inicial < 5 min en repo mediano (~50k LOC) en runner estándar.
- **Confiabilidad**: trabajos idempotentes por scan_id.
- **Observabilidad**: logs estructurados JSON + trazabilidad por request_id/scan_id.
- **Portabilidad**: ejecución local por Docker Compose y CI en GitHub Actions.

## 6. Arquitectura
### 6.1 Componentes
- **API (FastAPI)**: autenticación, orquestación, exposición de resultados.
- **Worker (RQ/Celery Lite)**: ejecución de escaneos de secretos/dependencias.
- **PostgreSQL**: persistencia de scans/findings/vulnerabilities.
- **Redis**: cola y estado transitorio.
- **Scanner Core**:
  - secret detector
  - dependency auditor
  - risk scorer
  - SARIF formatter

### 6.2 Flujo principal
1. Cliente llama `POST /scans`.
2. API crea registro `scan` (estado `queued`) y encola job.
3. Worker ejecuta detectores y enriquece findings.
4. Worker persiste findings + summary y marca estado `completed` o `failed`.
5. CI consume salida SARIF y publica resultados.

## 7. Modelo de Datos (mínimo)
- **scan**: id, repo_url, commit_sha, status, started_at, finished_at, metadata_json
- **finding**: id, scan_id, type(secret|dependency), rule_id, file_path, line_start, line_end, evidence_hash, severity, confidence, recommendation
- **vulnerability**: id, finding_id, cve_id, package_name, installed_version, fixed_version, cvss_score, cvss_vector, advisory_url
- **scan_summary**: scan_id, total_findings, critical_count, high_count, medium_count, low_count

## 8. API Contract (MVP)
### POST /scans
- Input:
  - repo_url (string, https)
  - ref (string, opcional)
- Output:
  - scan_id
  - status=queued

### GET /scans/{scan_id}
- Output:
  - estado del escaneo
  - timestamps
  - resumen agregado

### GET /scans/{scan_id}/findings
- Query params:
  - severity
  - type
  - limit/offset
- Output:
  - lista de findings

### GET /scans/{scan_id}/sarif
- Output:
  - SARIF 2.1.0

## 9. Reglas de Riesgo y Priorización
- Severidad base por tipo/regla.
- Ajustes por:
  - exposición (rama default/PR)
  - exploitabilidad conocida
  - fix disponible
  - dependencia directa vs transitive
- Umbral CI por defecto: fallar en HIGH/CRITICAL.

## 10. Seguridad (controles obligatorios)
- Validación estricta de input (Pydantic).
- Autenticación por token de servicio (entorno local: simple bearer).
- Rate limit por IP/token en endpoints de creación.
- Sin secretos en logs; masking y hashing de evidencia.
- Parametrización SQL (sin concatenación).
- Dependencias fijadas y escaneo de supply chain en CI.

## 11. Integración CI/CD
- Workflow reusable invocable por `workflow_call`.
- Acciones pinneadas por SHA.
- Permisos mínimos:
  - contents: read
  - security-events: write
  - pull-requests: write (solo si se comenta PR)
- Publicación SARIF + artefactos.

## 12. Criterios de Aceptación (MVP)
1. Se puede lanzar escaneo y obtener estado por API.
2. Se detectan secretos de prueba en fixtures y se evitan falsos positivos básicos.
3. Se detecta al menos una dependencia vulnerable conocida en fixture controlado.
4. CI reusable genera SARIF válido y lo sube a Code Scanning.
5. CI falla si `critical_count > 0` o `high_count > 0` cuando `fail_on_severity=true`.
6. Existe suite mínima de tests (unit + integración API).

## 13. Riesgos y Mitigaciones
- **Falsos positivos**: allowlists + baseline + confidence score.
- **Falsos negativos**: ampliar reglas y tests de regresión.
- **Límites API externas**: caché local y reintentos exponenciales.
- **Tiempo de escaneo**: paralelismo por archivo y exclusiones.

## 14. Entregables
- Código backend + worker.
- Esquema DB y migraciones.
- Workflow reusable de seguridad.
- README técnico y guía de ejecución local.
- 10 issues de implementación priorizados.
