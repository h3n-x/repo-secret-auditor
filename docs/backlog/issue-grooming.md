# Issue Grooming Backlog

Tipo de documento: How-to / backlog operativo

Objetivo: dejar una lista refinada de 10 issues accionables para ejecución y seguimiento, con prioridad, estimación y criterios de aceptación.

## Convenciones de priorización

1. `P0`: bloqueante de demo/seguridad.
2. `P1`: alto impacto para release candidato.
3. `P2`: mejora relevante, no bloqueante.

## Convenciones de estimación

Escala relativa en puntos:
1. `1`: cambio pequeño.
2. `2`: cambio acotado con validación.
3. `3`: cambio mediano multiarchivo.
4. `5`: cambio amplio o con riesgo técnico.

## Resumen de issues (10)

| ID | Titulo | Tipo | Prioridad | Estimacion | Labels |
| --- | --- | --- | --- | --- | --- |
| I-01 | Add service authentication for scan endpoints | Feature | P0 | 5 | `security`, `api`, `feature`, `priority:P0` |
| I-02 | Add production security headers middleware | Task | P0 | 3 | `security`, `api`, `chore`, `priority:P0` |
| I-03 | Add CodeQL SAST workflow and baseline policies | Task | P1 | 3 | `security`, `ci`, `chore`, `priority:P1` |
| I-04 | Implement threat model document for API and scanner | Task | P1 | 2 | `security`, `documentation`, `chore`, `priority:P1` |
| I-05 | Add retry/backoff and timeout metrics for OSV calls | Feature | P1 | 3 | `scanner`, `reliability`, `feature`, `priority:P1` |
| I-06 | Add baseline/allowlist workflow for secret findings | Feature | P1 | 5 | `scanner`, `security`, `feature`, `priority:P1` |
| I-07 | Add paginated findings contract tests for edge cases | Task | P2 | 2 | `testing`, `api`, `chore`, `priority:P2` |
| I-08 | Improve SARIF rule metadata and remediation guidance | Feature | P2 | 2 | `reporting`, `security`, `feature`, `priority:P2` |
| I-09 | Add release checklist and versioning automation | Task | P2 | 2 | `release`, `documentation`, `chore`, `priority:P2` |
| I-10 | Prepare interview Q&A package from architecture decisions | Task | P2 | 1 | `portfolio`, `documentation`, `chore`, `priority:P2` |

## Issues detalladas

## I-01 Add service authentication for scan endpoints

- Tipo: Feature
- Prioridad: P0
- Estimacion: 5
- Labels: `security`, `api`, `feature`, `priority:P0`
- Dependencias: ninguna

Descripcion:
Implementar autenticación por token de servicio para proteger endpoints de scans en entornos no locales.

Acceptance criteria:
1. `POST /scans`, `GET /scans/{scan_id}`, `GET /scans/{scan_id}/findings` requieren credencial válida fuera de modo dev.
2. Tokens leídos desde variables de entorno seguras, sin hardcodeo.
3. Tests unitarios e integración cubren casos autorizado/no autorizado.
4. Documentación actualizada en `README.md` y `docs/reference/api-reference.md`.

## I-02 Add production security headers middleware

- Tipo: Task
- Prioridad: P0
- Estimacion: 3
- Labels: `security`, `api`, `chore`, `priority:P0`
- Dependencias: I-01 (recomendado, no bloqueante)

Descripcion:
Agregar middleware configurable para cabeceras HTTP de seguridad en despliegue productivo.

Acceptance criteria:
1. Se configuran al menos `Strict-Transport-Security`, `X-Content-Type-Options`, `Content-Security-Policy`.
2. Las cabeceras son verificables vía tests.
3. Existe toggle por entorno para evitar romper desarrollo local.

## I-03 Add CodeQL SAST workflow and baseline policies

- Tipo: Task
- Prioridad: P1
- Estimacion: 3
- Labels: `security`, `ci`, `chore`, `priority:P1`
- Dependencias: ninguna

Descripcion:
Incorporar SAST en CI con CodeQL y política mínima de revisión de hallazgos.

Acceptance criteria:
1. Nuevo workflow de CodeQL para Python.
2. Permisos del workflow por principio de mínimo privilegio.
3. Acciones pinneadas por SHA.
4. Documentación de operación y resultados en `docs/security/security-owasp-checklist.md`.

## I-04 Implement threat model document for API and scanner

- Tipo: Task
- Prioridad: P1
- Estimacion: 2
- Labels: `security`, `documentation`, `chore`, `priority:P1`
- Dependencias: ninguna

Descripcion:
Crear threat model versionado para API, scanner y pipelines.

Acceptance criteria:
1. Documento incluye activos, amenazas, mitigaciones y riesgos residuales.
2. Cobertura mínima para A01, A03, A05, A08, A10.
3. Referenciado desde README y checklist OWASP.

## I-05 Add retry/backoff and timeout metrics for OSV calls

- Tipo: Feature
- Prioridad: P1
- Estimacion: 3
- Labels: `scanner`, `reliability`, `feature`, `priority:P1`
- Dependencias: ninguna

Descripcion:
Fortalecer auditoría de dependencias con métricas y manejo resiliente de fallos de red.

Acceptance criteria:
1. Reintentos exponenciales con límite y timeout por request.
2. Métricas básicas de éxito/fallo/latencia disponibles en logs.
3. Tests para timeouts y respuestas transitorias.

## I-06 Add baseline/allowlist workflow for secret findings

- Tipo: Feature
- Prioridad: P1
- Estimacion: 5
- Labels: `scanner`, `security`, `feature`, `priority:P1`
- Dependencias: I-05 (recomendado)

Descripcion:
Reducir falso positivo operativo usando baseline y allowlist mantenible.

Acceptance criteria:
1. Soporte de baseline versionado para findings conocidos.
2. Allowlist por reglas/rutas validada en pipeline.
3. Documentación de uso y gobernanza para evitar abuso.

## I-07 Add paginated findings contract tests for edge cases

- Tipo: Task
- Prioridad: P2
- Estimacion: 2
- Labels: `testing`, `api`, `chore`, `priority:P2`
- Dependencias: ninguna

Descripcion:
Ampliar pruebas de contrato para paginación y filtros combinados en findings.

Acceptance criteria:
1. Cobertura de bordes: `limit=1`, `limit=200`, offsets grandes, filtros vacíos.
2. Verificación de orden y consistencia de `total`.
3. Sin regresión en suite actual.

## I-08 Improve SARIF rule metadata and remediation guidance

- Tipo: Feature
- Prioridad: P2
- Estimacion: 2
- Labels: `reporting`, `security`, `feature`, `priority:P2`
- Dependencias: ninguna

Descripcion:
Mejorar calidad de reporte SARIF para lectura de reclutadores y equipos de seguridad.

Acceptance criteria:
1. Reglas incluyen mensajes y recomendaciones más específicas.
2. Mapeo de severidad consistente entre findings y SARIF.
3. Fixture de validación SARIF actualizado.

## I-09 Add release checklist and versioning automation

- Tipo: Task
- Prioridad: P2
- Estimacion: 2
- Labels: `release`, `documentation`, `chore`, `priority:P2`
- Dependencias: ninguna

Descripcion:
Estandarizar salida de release candidato con checklist repetible.

Acceptance criteria:
1. Checklist de pre-release en archivo versionado.
2. Pasos para tag y validación final documentados.
3. Referencia cruzada con plan de 21 días.

## I-10 Prepare interview Q&A package from architecture decisions

- Tipo: Task
- Prioridad: P2
- Estimacion: 1
- Labels: `portfolio`, `documentation`, `chore`, `priority:P2`
- Dependencias: I-04 (recomendado)

Descripcion:
Preparar material de entrevista técnica para explicar decisiones de seguridad, arquitectura y trade-offs.

Acceptance criteria:
1. Documento Q&A con al menos 20 preguntas esperables.
2. Respuestas basadas en decisiones reales del repositorio.
3. Incluye preguntas de follow-up y riesgos residuales.

## Orden sugerido de ejecución

1. I-01
2. I-02
3. I-03
4. I-04
5. I-05
6. I-06
7. I-07
8. I-08
9. I-09
10. I-10

## Nota operativa

Este backlog está listo para copiarse a GitHub Issues usando la plantilla de feature/chore.
