# STATUS.md — Estado vivo del proyecto

> Fuente única del **avance**. Se actualiza al final de cada sesión de trabajo (`AGENTS.md §5.3`) y al cerrar cada gate. Mantén solo el estado actual y las últimas notas; el histórico queda en los issues y en git.

## Resumen

| Campo | Valor |
|---|---|
| Fase actual | **F1 — Infraestructura de ingeniería** |
| Último gate cerrado | **G0** (2026-10-11) |
| Próximo gate | G1 |
| Hito siguiente | M1 · Núcleo offline (al cerrar G5) |
| Última actualización | 2026-10-12 |

## Gates

| Gate | Estado | Fecha | Evidencia |
|---|---|---|---|
| G0 | **Cerrado** | 2026-10-11 | Especificaciones v0.1 completadas, ADRs 0001-0012 y 0016-0020 aceptados, 4 spikes concluidos viables, revisión cruzada F0.T21 aprobada |
| G1 | En curso | — | Workspace, xtask, CI y gobierno del repositorio implementados en `feat/6-workspace-cargo` (#6); pendiente verificación de CI en GitHub |
| G2 … G17 | Pendiente | — | — |

## Tareas en curso

| Tarea | Issue | Responsable | Estado | Siguiente paso |
|---|---|---|---|---|
| F1.T01 Workspace Cargo | #6 | OpenCode (agente) | Hecha | 20 crates `gravital-id-*` con lints estrictos y perfiles; PR contra `main` |
| F1.T02 Toolchain/MSRV (ADR-0014) | #6 | OpenCode (agente) | Hecha | Rust 1.85.0 fijado en `rust-toolchain.toml`; ADR-0014 Aceptado |
| F1.T03 `xtask check-layers` | #6 | OpenCode (agente) | Hecha | Capas, `no_std`, aislamiento del verificador y bindings; casos negativos probados |
| F1.T04 `xtask trace` | #6 | OpenCode (agente) | Hecha | Matriz REQ→pruebas regenerada y commiteada; CI falla si queda obsoleta |
| F1.T05 Workflows de CI | #6 | OpenCode (agente) | Hecha | `ci.yml`, `security.yml`, `docs.yml`, `wasm.yml`, `fuzz.yml`, `mutation.yml`, `bench.yml` |
| F1.T06 `deny.toml` | #6 | OpenCode (agente) | Hecha | Allowlist ADR-0002; excepción `unicode-ident` pendiente de confirmación del mantenedor |
| F1.T07 `gravital-id-testkit` base | #6 | OpenCode (agente) | Hecha | `FixedClock` + `SeededRng`; aserciones de `VerificationResult` diferidas a F4.T06 |
| F1.T08 Esqueleto de errores | #6 | OpenCode (agente) | Hecha | 48 códigos únicos y documentados; `check-error-codes` corregido |
| F1.T09 `clippy.toml` restrictivo | #6 | OpenCode (agente) | Hecha | `SystemTime::now`, `std::net`, `std::fs` prohibidos |
| F1.T10 Compilación cruzada | #6 | OpenCode (agente) | Hecha | wasm32/android/ios + bare-metal L1–L3 verificados en local y en CI |
| F1.T11 Fuzzing y benchmarks | #6 | OpenCode (agente) | Hecha | Objetivo de ejemplo + criterion + `fuzz.yml` nocturno |
| F1.T12 Gobierno del repo | #6 | OpenCode (agente) | Hecha | `CODEOWNERS` + labels como código con sync idempotente |
| F1.T13 ADR-0019 + esqueleto vertical | #6 | OpenCode (agente) | Hecha | Fachada mínima del SDK + `bindings/wasm` con pruebas de humo en Node |
| F1.T14 Mutación y Kani | #6 | OpenCode (agente) | Hecha | `cargo-mutants` + pruebas Kani de invariantes; job nocturno |

## Bloqueos

- **Bloqueo de facturación de la cuenta de GitHub:** los workflows de PR #22 se crean correctamente pero los jobs no arrancan ("The job was not started because your account is locked due to a billing issue"). No es un defecto de los workflows: se validaron por sintaxis y todas sus comprobaciones se ejecutaron en local con éxito. El mantenedor debe resolver la facturación para que CI verifique G1.

## Decisiones pendientes que bloquean la fase actual

1. Excepción de licencia `Unicode-3.0` para `unicode-ident` (dependencia de compilación de `proc-macro2`): registrada como excepción acotada en `deny.toml`; falta confirmar si se incorpora a la allowlist de ADR-0002 (issue abierto por el agente).
2. `PROJECT_STRUCTURE.md §7` contradice a `ERROR_CODES.md` en los rangos de códigos y sitúa `GidError` en `gravital-id-sdk` (L6) cuando el catálogo canónico vive en `gravital-id-types` (L1) y el SDK lo re-exporta: registrado como `type:spec-gap`.

## Métricas base (se rellenan desde F2)

| Métrica | x86_64 | aarch64 | wasm32 | Android | iOS |
|---|---|---|---|---|---|
| Verificación de presentación (tiempo) | — | — | — | — | — |
| Tamaño de presentación de referencia | — | — | — | — | — |
| Tamaño binario del SDK | — | — | — | — | — |

## Última nota de traspaso

### Traspaso — 2026-10-12 — OpenCode (agente)
- Tarea: F1.T01–F1.T14 — #6 — rama `feat/6-workspace-cargo`
- Estado: lista para revisión (PR contra `main` pendiente de aprobación del mantenedor)
- Hecho en esta sesión:
  - Verificado y commiteado el WIP previo de F1.T01 (workspace `gravital-id-*`, lints, perfiles) y F1.T02 (ADR-0014, toolchain 1.85.0).
  - `xtask`: corregido `check-error-codes` (falsos duplicados por menciones en doc-comments; ahora valida también discriminantes del enum) y ampliado `check-layers` con la regla de bindings (solo `gravital-id-sdk`).
  - F1.T07: traits `Clock` (types) y `Rng` (crypto) + `FixedClock`/`SeededRng` en testkit con pruebas de determinismo.
  - F1.T05/T06/T10: workflows `ci`, `security`, `docs`, `wasm`, `fuzz`, `mutation`, `bench`; `deny.toml`; compilación cruzada (4 targets) verificada en local.
  - F1.T11/T14: objetivo de fuzzing de ejemplo (3.9M ejecuciones sin fallos), criterion, cargo-mutants y pruebas Kani.
  - F1.T12: `CODEOWNERS` y labels como código (56/56 sincronizadas).
  - F1.T13: fachada mínima del SDK y `bindings/wasm` con pruebas de humo en Node (`wasm-pack test`).
  - `CHANGELOG.md` y esta nota actualizados.
- Pendiente (siguiente paso concreto):
  - Mantenedor: revisar y mergear el PR de `feat/6-workspace-cargo`; confirmar las dos decisiones pendientes (excepción `Unicode-3.0` y el spec-gap de `PROJECT_STRUCTURE §7`).
  - Confirmar que GitHub Actions ejecuta los workflows (no se registran runs tras el push).
  - Cerrar G1 con evidencia (CI verde en todos los targets) y abrir los issues de F2 (`ROADMAP.md §7`, F2.T01…T12).
- Bugs/issues abiertos durante la sesión: bug corregido en `xtask check-error-codes` (nunca llegó a `main`); issues de decisión y spec-gap creados desde el agente (ver comentarios en #6).
- Decisiones tomadas (con enlace a ADR/issue): ADR-0014 y ADR-0019 (Aceptados, previos); excepción acotada `unicode-ident` en `deny.toml` (pendiente de confirmación en #6); catálogo de errores en `gravital-id-types` re-exportado por el SDK (spec-gap abierto).
- Riesgos o dudas: los workflows se ejecutan en GitHub pero los jobs no arrancan por el bloqueo de facturación de la cuenta (pendiente del mantenedor); Kani y los jobs nocturnos pendientes de primera ejecución real.
- Comprobaciones locales: fmt ✅ clippy ✅ tests ✅ (cargo test; nextest no instalado localmente) layers ✅ trace ✅ check-error-codes ✅ deny ✅ wasm-pack test ✅ cross-compile ✅
