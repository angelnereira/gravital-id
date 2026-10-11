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
| F0.T01 | — | Angel Nereira / Antigravity | Hecha | 57 labels creados en GitHub (`AGENTS.md §8`); 5 issues iniciales sincronizados y resueltos (#1..#5); régimen F0 formalizado |
| F0.T02 | — | Angel Nereira | Pendiente | ADR-0001: Selección de nombre definitivo sin colisiones para reemplazar `pip` |
| F0.T03 | — | Angel Nereira / Antigravity | Hecha | ADR-0002 Aceptado (Dual MIT/Apache-2.0, DCO 1.1, `LICENSE-MIT`, `LICENSE-APACHE`, `CONTRIBUTING.md`) |
| F0.T04 | — | Antigravity (agente) | Hecha | `SECURITY.md` definitivo publicado con canal privado, SLAs y Safe Harbor |
| F0.T06 | — | Antigravity (agente) | Lista para revisión | `docs/specs/CRYPTO_PROFILES.md` redactada (v0.1.0-draft) |
| F0.T13 | — | Antigravity (agente) | Lista para revisión | `docs/specs/TRUST_BUNDLE.md` redactada (v0.1.0-draft) |
| Revisión v0.2 | #2 | Angel Nereira (mantenedor) | Hecha | ADR-0016 a ADR-0020 **Aceptados** formalmente; Issue #2 cerrado |
| Régimen mantenedor | #1 | Angel Nereira (mantenedor) | Hecha | `AGENTS.md §6/§14` adaptados para F0; Issue #1 cerrado |

## Bloqueos

- Ninguno inmediato que impida continuar la redacción de especificaciones de F0.

## Decisiones pendientes que bloquean la fase actual

ADR-0001 (nombre definitivo) y ADR-0003 a ADR-0012 (ver `docs/adr/README.md`). ADR-0002 quedó formalmente aceptado.

## Métricas base (se rellenan desde F2)

| Métrica | x86_64 | aarch64 | wasm32 | Android | iOS |
|---|---|---|---|---|---|
| Verificación de presentación (tiempo) | — | — | — | — | — |
| Tamaño de presentación de referencia | — | — | — | — | — |
| Tamaño binario del SDK | — | — | — | — | — |

## Última nota de traspaso

### Traspaso — 2026-10-10 — Antigravity (agente)
- Tarea: F0.T01, Revisión v0.2 (#2), Régimen mantenedor (#1) y F0.T13 (`TRUST_BUNDLE.md`)
- Estado: lista para revisión
- Hecho en esta sesión:
  - 57 labels creados en GitHub según `AGENTS.md §8`.
  - Sincronizados y cerrados en GitHub los issues #1 (mantenedor único), #2 (ADR-0016..0020), #3 (roadmap/req), #4 (IO en capas), #5 (lints).
  - Formalizada la aceptación de ADR-0016 a ADR-0020 por el mantenedor Angel Nereira.
  - Actualizado `AGENTS.md §6` y `§14` para el régimen de mantenedor único en F0.
  - Redactada la especificación normativa `docs/specs/TRUST_BUNDLE.md` (v0.1.0-draft, F0.T13).
  - Actualizados `docs/specs/README.md`, `CHANGELOG.md` y `docs/STATUS.md`.
- Pendiente (siguiente paso concreto):
  - F0.T02: ADR-0001 (definición del nombre definitivo para reemplazar `pip`).
  - F0.T03: ADR-0002 (licencia y política de contribución).
  - Redacción de especificaciones subsiguientes (`CRYPTO_PROFILES.md` F0.T06, `PROTOCOL.md` F0.T12, `CONTRACTS.md` F0.T14).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): ADR-0016..0020 aceptados (#2); régimen de mantenedor único en F0 adoptado (#1).
- Riesgos o dudas: ninguno; todos los bloqueos previos de F0 quedaron resueltos.
- Comprobaciones locales: fmt, clippy, tests, layers y trace no aplican (aún no hay código en `crates/`).
