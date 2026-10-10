# STATUS.md — Estado vivo del proyecto

> Fuente única del **avance**. Se actualiza al final de cada sesión de trabajo (`AGENTS.md §5.3`) y al cerrar cada gate. Mantén solo el estado actual y las últimas notas; el histórico queda en los issues y en git.

## Resumen

| Campo | Valor |
|---|---|
| Fase actual | **F0 — Fundación, gobierno y especificación** |
| Último gate cerrado | — |
| Próximo gate | G0 |
| Hito siguiente | M1 · Núcleo offline (al cerrar G5) |
| Última actualización | 2026-10-10 |

## Gates

| Gate | Estado | Fecha | Evidencia |
|---|---|---|---|
| G0 | Abierto | — | — |
| G1 … G17 | Pendiente | — | — |

## Tareas en curso

| Tarea | Issue | Responsable | Estado | Siguiente paso |
|---|---|---|---|---|
| F0.T01 | — | Angel Nereira | En curso | Paquete documental en su estructura y commit inicial hechos en local. Falta: push, proteger `main`, labels y tablero en GitHub |
| Revisión de arquitectura v0.2 | `.issues/pending/20261010-decision-revision-arquitectura.md` | Claude (agente) | Lista para revisión | El mantenedor acepta, rechaza o difiere ADR-0016 a ADR-0020 y fusiona la rama `docs/pending-architecture-review` |

## Bloqueos

- Los ADR-0016 a ADR-0020 están **Propuestos**: las especificaciones de F0 que dependen de ellos (F0.T13, F0.T14, F0.T16, F0.T18) esperan su aceptación.
- Proceso con un único mantenedor humano sin decidir (`.issues/pending/20261010-decision-mantenedor-unico.md`, riesgo R-14).

## Decisiones pendientes que bloquean la fase actual

ADR-0001 a ADR-0012, ADR-0016 a ADR-0018 y ADR-0020 (ver `docs/adr/README.md`). ADR-0003 incluye ahora la alineación con HAIP 1.0. ADR-0019 debe decidirse en F1.

## Métricas base (se rellenan desde F2)

| Métrica | x86_64 | aarch64 | wasm32 | Android | iOS |
|---|---|---|---|---|---|
| Verificación de presentación (tiempo) | — | — | — | — | — |
| Tamaño de presentación de referencia | — | — | — | — | — |
| Tamaño binario del SDK | — | — | — | — | — |

## Última nota de traspaso

### Traspaso — 2026-10-10 — Claude (agente)
- Tarea: F0.T01 y revisión de arquitectura v0.2 — `.issues/pending/20261010-decision-revision-arquitectura.md` — rama `docs/pending-architecture-review`
- Estado: lista para revisión
- Hecho en esta sesión:
  - Paquete documental colocado en la estructura de `PROJECT_STRUCTURE.md §2`; commit inicial en `main` (local).
  - Revisión completa de la documentación; correcciones aplicadas a `ARCHITECTURE.md`, `REQUIREMENTS.md`, `PROJECT_STRUCTURE.md`, `ROADMAP.md` y `AGENTS.md` (v0.2).
  - ADR-0016 a ADR-0020 redactados en estado Propuesto; índice de ADRs actualizado.
- Pendiente (siguiente paso concreto):
  - El mantenedor revisa la rama y decide cada ADR; después, push y creación de los issues en GitHub.
  - Completar F0.T01 en GitHub (protección de `main`, labels, tablero).
  - Primera especificación a redactar tras la decisión: `TRUST_BUNDLE.md` (F0.T13).
- Bugs/issues abiertos durante la sesión: cinco archivos en `.issues/pending/` (dos `type:decision`, tres `type:spec-gap`).
- Decisiones tomadas (con enlace a ADR/issue): ninguna aceptada; todas quedan propuestas en ADR-0016 a ADR-0020.
- Riesgos o dudas: el estado de los estándares citados se verificó en línea el 2026-10-10 (tabla en el issue de decisión) y debe volver a comprobarse en F0.T06; la rama no sigue el patrón `<tipo>/<issue>-<slug>` porque aún no existen issues en GitHub; nada se ha subido al remoto.
- Comprobaciones locales: fmt, clippy, tests, layers y trace no aplican (aún no hay código ni `xtask`).
