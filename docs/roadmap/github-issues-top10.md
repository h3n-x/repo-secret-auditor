# Texto Exacto de 10 Issues (GitHub)

## Issue 1
**Title:** feat(api): crear endpoint POST /scans para orquestar escaneos

**Body:**
### Contexto
Necesitamos un endpoint inicial para crear solicitudes de escaneo y encolarlas para procesamiento asíncrono.

### Objetivo
Implementar `POST /scans` con validación de entrada y creación de registro en estado `queued`.

### Alcance
- DTO de entrada (`repo_url`, `ref` opcional).
- Validación estricta de URL HTTPS.
- Persistencia de scan inicial.
- Encolado de job en Redis/RQ.

### Acceptance Criteria
- `POST /scans` retorna `202` con `scan_id` y `status=queued`.
- Si input inválido, retorna `422`.
- Se registra `scan_id` y `job_id` en logs estructurados.
- Test de integración para caso exitoso e inválido.

### Labels
`type:feature`, `area:api`, `priority:high`, `estimate:1d`

---

## Issue 2
**Title:** feat(db): definir esquema inicial y migraciones para scans y findings

**Body:**
### Contexto
La persistencia es base para trazabilidad, API y reporting.

### Objetivo
Crear modelo relacional inicial y migraciones versionadas.

### Alcance
- Tablas: `scan`, `finding`, `vulnerability`, `scan_summary`.
- Índices por `scan_id`, `severity`, `type`.
- Constraints de integridad referencial.

### Acceptance Criteria
- Migraciones `upgrade/downgrade` funcionales.
- Tests básicos de repositorio.
- Documentado diagrama de relaciones en `/spec`.

### Labels
`type:feature`, `area:database`, `priority:high`, `estimate:1d`

---

## Issue 3
**Title:** feat(scanner): implementar detector de secretos v1 (regex + entropía)

**Body:**
### Contexto
Secret scanning es el primer pilar del producto.

### Objetivo
Detectar secretos comunes con señal robusta y bajo ruido.

### Alcance
- Reglas iniciales: GitHub PAT, AWS key, generic API key.
- Shannon entropy para elevar/reducir confianza.
- Hash de evidencia para no guardar secretos en claro.
- Allowlist básica por rutas/patrones.

### Acceptance Criteria
- Detecta secretos en fixtures de prueba.
- Evita falsos positivos básicos conocidos.
- Exposición de `severity` + `confidence` por finding.
- Cobertura de tests del módulo >= 90%.

### Labels
`type:feature`, `area:scanner`, `priority:high`, `estimate:2d`

---

## Issue 4
**Title:** feat(scanner): implementar auditor de dependencias v1 (requirements + package-lock)

**Body:**
### Contexto
El segundo pilar es detectar CVEs en dependencias.

### Objetivo
Parsear lockfiles y consultar vulnerabilidades para generar findings de dependencia.

### Alcance
- Parser `requirements.txt`.
- Parser `package-lock.json`.
- Cliente OSV con retries y timeout.
- Mapeo package/version -> advisory.

### Acceptance Criteria
- Identifica al menos un CVE en fixture controlado.
- Maneja fallos de red sin romper worker.
- Persiste findings de tipo `dependency`.

### Labels
`type:feature`, `area:scanner`, `priority:high`, `estimate:2d`

---

## Issue 5
**Title:** feat(worker): pipeline de escaneo asíncrono e idempotente por scan_id

**Body:**
### Contexto
El escaneo debe ejecutarse fuera del request cycle para escalabilidad.

### Objetivo
Implementar worker que procese escaneos completos con estado consistente.

### Alcance
- Consumidor de cola RQ.
- Transiciones de estado: `queued -> running -> completed|failed`.
- Idempotencia por `scan_id`.
- Logging estructurado por job.

### Acceptance Criteria
- Worker procesa scan real end-to-end.
- Reintento no duplica findings.
- Fallos actualizan estado a `failed` con razón.

### Labels
`type:feature`, `area:worker`, `priority:high`, `estimate:2d`

---

## Issue 6
**Title:** feat(api): endpoint GET /scans/{scan_id}/findings con filtros y paginación

**Body:**
### Contexto
Necesitamos consultar resultados de forma usable para API y CI.

### Objetivo
Exponer findings por scan con filtros de severidad/tipo.

### Alcance
- Endpoint `GET /scans/{scan_id}/findings`.
- Query params: `severity`, `type`, `limit`, `offset`.
- Contrato de respuesta estable.

### Acceptance Criteria
- Filtrado correcto por severidad y tipo.
- Paginación determinística.
- Test de integración con fixtures.

### Labels
`type:feature`, `area:api`, `priority:medium`, `estimate:1d`

---

## Issue 7
**Title:** feat(reporting): generar salida SARIF 2.1.0 para findings

**Body:**
### Contexto
SARIF es obligatorio para integración con GitHub Code Scanning.

### Objetivo
Implementar serializador SARIF compatible y validable.

### Alcance
- Mapper findings -> `runs[].results[]`.
- Definición de rules por detector.
- Metadatos mínimos del tool driver.

### Acceptance Criteria
- Archivo SARIF válido contra schema 2.1.0.
- Incluye location, ruleId, level y mensaje por finding.
- Test de contrato de output.

### Labels
`type:feature`, `area:reporting`, `priority:high`, `estimate:1d`

---

## Issue 8
**Title:** ci(security): crear workflow reusable con acciones pinneadas por SHA

**Body:**
### Contexto
Necesitamos CI portable para ejecutar escaneo en múltiples repos.

### Objetivo
Crear workflow reusable invocable por `workflow_call`.

### Alcance
- Archivo `.github/workflows/reusable-security-scan.yml`.
- Acciones pinneadas por SHA (checkout, cache, upload-artifact, upload-sarif).
- Publicación de SARIF + artefactos.
- Gate configurable para HIGH/CRITICAL.

### Acceptance Criteria
- Workflow invocable desde otro workflow.
- Publica SARIF en Code Scanning.
- Falla correctamente cuando supera umbral.

### Labels
`type:feature`, `area:ci-cd`, `priority:high`, `estimate:1d`

---

## Issue 9
**Title:** sec(api): hardening OWASP (rate limit, validación estricta, logging seguro)

**Body:**
### Contexto
El proyecto debe demostrar seguridad aplicada, no solo detección.

### Objetivo
Incorporar controles de seguridad backend para abuso y filtración de datos sensibles.

### Alcance
- Rate limit por IP/token en creación de scans.
- Sanitización y validación reforzada de entradas.
- Prohibir secretos en logs (mask/hash).
- Manejo de errores sin exposición de internals.

### Acceptance Criteria
- Test de rate limiting exitoso.
- Logs no contienen secretos en claro.
- Respuestas de error consistentes y seguras.

### Labels
`type:security`, `area:api`, `priority:high`, `estimate:1d`

---

## Issue 10
**Title:** docs(release): README técnico, guía de demo y checklist de entrevista

**Body:**
### Contexto
El valor portfolio depende tanto de ejecución técnica como de comunicación.

### Objetivo
Documentar instalación, arquitectura, uso, demo y decisiones de diseño.

### Alcance
- README completo con setup local y CI.
- Guion de demo 10-15 minutos.
- FAQ técnica para entrevistas.
- Sección de limitaciones y roadmap.

### Acceptance Criteria
- Cualquier persona puede correr el proyecto siguiendo README.
- Demo script ejecutable extremo a extremo.
- Documentación revisada y consistente con código.

### Labels
`type:docs`, `area:project`, `priority:medium`, `estimate:1d`
