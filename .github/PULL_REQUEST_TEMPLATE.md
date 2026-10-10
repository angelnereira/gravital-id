## Qué cambia y por qué

<!-- Resumen breve. Un issue por PR. -->

- Issue: Closes #… / Fixes #…
- Tarea: F<n>.T<nn>
- Requisitos: REQ-…
- ADR relacionado (si aplica): ADR-NNNN

## Tipo de cambio

- [ ] feat · [ ] fix · [ ] docs · [ ] test · [ ] refactor · [ ] perf · [ ] build/ci · [ ] security

## Documentación (spec-first)

- [ ] La documentación afectada se actualizó en este PR o antes: <enlaces>
- [ ] No cambia comportamiento observable (justificar):

## Verificación

- [ ] Pruebas positivas y negativas añadidas o actualizadas
- [ ] REQ trazados (`// Verifies: REQ-…`); `cargo xtask trace` en verde
- [ ] Parsers nuevos/modificados con objetivo de fuzzing
- [ ] Prueba de regresión con `// Regression: #…` (si es un fix)
- [ ] `fmt`, `clippy -D warnings`, `nextest`, `doc`, `check-layers`, `deny`, `audit` en verde

## Invariantes (AGENTS.md §4) — confirma explícitamente

- [ ] Sin I/O de red en la ruta de verificación
- [ ] Sin datos personales en ledger, logs, métricas o errores
- [ ] Resultado de verificación de 4 estados intacto; fail-closed preservado
- [ ] Sin `unsafe` fuera de `bindings/`; sin `unwrap`/`expect`/`panic` en bibliotecas
- [ ] Sin vectores de conformidad publicados modificados
- [ ] Sin pruebas desactivadas, ignoradas o relajadas

## Dependencias nuevas

- [ ] Ninguna
- [ ] Sí — justificación según AGENTS.md §13:

## API pública

- [ ] Sin cambios
- [ ] Cambios compatibles (SemVer menor/parche)
- [ ] Cambios incompatibles (requiere ADR y versión mayor)

## Bugs encontrados durante el trabajo

<!-- Enlaza los issues creados (o archivos en .issues/pending/). -->

## CHANGELOG y STATUS

- [ ] `CHANGELOG.md` actualizado (si aplica)
- [ ] `docs/STATUS.md` actualizado
