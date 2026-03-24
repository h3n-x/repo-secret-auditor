# Evidencia de Seguridad - OWASP Top 10

Tipo de documento: Reference (Diataxis)

Este documento registra el estado de controles de seguridad del proyecto en 2026, usando OWASP Top 10 (edicion 2021, vigente a la fecha) como marco de referencia, con evidencia verificable en codigo, tests y workflows.

## Alcance de la evaluación

Incluye:
1. API HTTP en FastAPI (`/scans`, `/scans/{scan_id}`, `/scans/{scan_id}/findings`).
2. Validación de inputs y controles de abuso.
3. Logging seguro.
4. Workflows CI de seguridad y calidad.

No incluye:
1. Frontend (no existe en este repositorio).
2. Autenticación de usuarios final (no implementada en esta versión MVP).
3. Hardening de infraestructura en runtime productivo fuera de CI.

## Resumen ejecutivo

Estado general del MVP:
1. Controles fuertes en validación de entrada, rate limiting, redacción de secretos y gate de severidad en CI.
2. Cobertura de pruebas de seguridad específica activa.
3. Persisten controles pendientes de fase posterior para autenticación/autorización y cabeceras de seguridad HTTP en producción.

Evidencia de ejecución local:
1. `pytest tests/unit/test_api_security.py` -> `18 passed`.
2. Workflows con acciones pinneadas por SHA y permisos mínimos declarados.

## Matriz OWASP Top 10 (edicion 2021, evaluacion 2026)

| ID | Riesgo | Estado | Evidencia implementada |
| --- | --- | --- | --- |
| A01 | Broken Access Control | Parcial | No hay modelo de usuarios/roles aún; endpoints limitados a operación técnica y validación estricta de parámetros. |
| A02 | Cryptographic Failures | Parcial | No se persisten secretos en claro en findings (hash de evidencia), pero aún no hay cifrado de datos en reposo configurable por entorno. |
| A03 | Injection | Cumple (MVP scope) | Uso de SQLAlchemy ORM y validación estricta de `repo_url`/`ref` para reducir vectores de inyección/abuso. |
| A04 | Insecure Design | Parcial | Reglas de validación y límites de paginación/rate limit presentes; falta threat model formal versionado. |
| A05 | Security Misconfiguration | Cumple (MVP scope) | Workflows con `permissions` mínimos, acciones pinneadas por SHA y policy gate HIGH/CRITICAL. |
| A06 | Vulnerable Components | Cumple (MVP scope) | Scanner de dependencias + integración SARIF con Code Scanning y gate configurable por severidad. |
| A07 | Identification and Authentication Failures | No aplicable en MVP actual | No existe login/sesiones en esta versión; riesgo a cubrir al introducir auth. |
| A08 | Software and Data Integrity Failures | Parcial | Artefactos de seguridad y calidad versionados; falta firma/verificación criptográfica de artefactos de build. |
| A09 | Security Logging and Monitoring Failures | Cumple (MVP scope) | `SecureLogger` con redacción de secretos y trazas de eventos clave de scans/errores de input. |
| A10 | SSRF | Cumple (MVP scope) | Validación de host/scheme con allowlist para `repo_url`, bloqueando destinos no permitidos. |

## Evidencia técnica por control

## A03 Injection

Controles:
1. Validación estricta de `repo_url` por esquema y host allowlist.
2. Validación de `ref` bloqueando patrones peligrosos (`..`, `//`, prefijo/sufijo `/`).
3. Capa ORM SQLAlchemy en lugar de SQL dinámico por concatenación.

Evidencia:
1. `src/app/security/validation.py`
2. `src/app/api/scans.py`
3. `tests/unit/test_api_security.py`

## A05 Security Misconfiguration

Controles:
1. Permisos mínimos de `GITHUB_TOKEN` en workflows.
2. Acciones pinneadas por SHA en pipeline de seguridad y calidad.
3. Gate de severidad configurable para bloquear findings HIGH/CRITICAL.

Evidencia:
1. `.github/workflows/reusable-security-scan.yml`
2. `.github/workflows/security.yml`
3. `.github/workflows/quality.yml`

## A06 Vulnerable Components

Controles:
1. Escaneo de dependencias y salida SARIF.
2. Publicación de SARIF a GitHub Code Scanning.
3. Umbral de fallo por severidad en CI.

Evidencia:
1. `src/app/ci/scan_runner.py`
2. `scripts/run_security_scan.py`
3. `.github/workflows/reusable-security-scan.yml`

## A09 Security Logging and Monitoring Failures

Controles:
1. Redacción automática de PATs, API keys, Authorization Bearer, passwords y tokens.
2. Logging de eventos de negocio y errores de validación sin exponer datos sensibles.

Evidencia:
1. `src/app/security/logging.py`
2. `src/app/api/scans.py`
3. `tests/unit/test_api_security.py`

## A10 SSRF

Controles:
1. Allowlist de hosts de Git (`github.com`, `gitlab.com`, `bitbucket.org`, `gitea.io`, `localhost`).
2. Esquemas permitidos y rechazo explícito de hosts no permitidos.

Evidencia:
1. `src/app/security/validation.py`
2. `tests/unit/test_api_security.py`

## Resultados de pruebas de seguridad

Comando ejecutado:

```bash
python -m pytest -q tests/unit/test_api_security.py
```

Resultado:

```text
18 passed
```

## Riesgos residuales y backlog recomendado

Prioridad alta:
1. Implementar autenticación/autorización antes de exponer la API fuera de entornos controlados.
2. Definir cabeceras de seguridad HTTP para despliegue productivo (`CSP`, `HSTS`, `X-Content-Type-Options`).

Prioridad media:
1. Definir threat model formal y abuso por actor.
2. Añadir escaneo SAST dedicado en CI (por ejemplo, CodeQL) para ampliar cobertura de A03/A04/A08.

Prioridad baja:
1. Firma de artefactos de build.
2. Telemetría de seguridad con alertas operativas.
