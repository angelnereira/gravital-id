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
| G0 | **Cerrado** | 2026-10-11 | Especificaciones v0.1 completadas, ADRs 0001-0012 y 0016-0020 aceptados, 4 spikes concluidos viables, revisión cruzada F0.T21 aprobada |
| G1 … G17 | Pendiente | — | — |

## Tareas en curso

| Tarea | Issue | Responsable | Estado | Siguiente paso |
|---|---|---|---|---|
| F0.T01 | — | Angel Nereira / Antigravity | Hecha | 57 labels creados en GitHub (`AGENTS.md §8`); 5 issues iniciales sincronizados y resueltos (#1..#5); régimen F0 formalizado |
| F0.T02 | #7 | Angel Nereira / Antigravity | Hecha | ADR-0001 Aceptado: Gravital ID (`gravital-id` / `gid`) como nombre definitivo |
| F0.T03 | #6 | Angel Nereira / Antigravity | Hecha | ADR-0002 Aceptado (Dual MIT/Apache-2.0, DCO 1.1, `LICENSE-MIT`, `LICENSE-APACHE`, `CONTRIBUTING.md`) |
| F0.T04 | — | Antigravity (agente) | Hecha | `SECURITY.md` definitivo publicado con canal privado, SLAs y Safe Harbor |
| F0.T05 | — | Antigravity (agente) | Hecha | `docs/specs/THREAT_MODEL.md` redactada y revisada (STRIDE + LINDDUN) |
| F0.T06 | — | Antigravity (agente) | Hecha | `docs/specs/CRYPTO_PROFILES.md` redactada y revisada |
| F0.T07 | — | Antigravity (agente) | Hecha | `spikes/qr/REPORT.md`: Viabilidad de transcodificación CBOR+DEFLATE+Base45 (reducción ~51%, multi-QR) |
| F0.T08 | — | Antigravity (agente) | Hecha | `spikes/keystore/REPORT.md`: Viabilidad de Secure Enclave / StrongBox vía UniFFI, DER a IEEE P1363 s-low |
| F0.T09 | — | Antigravity (agente) | Hecha | `spikes/wasm/REPORT.md`: Compilación RustCrypto a wasm32 (174 KB / 62 KB brotli), pánico envenena GID-E9999 |
| F0.T10 | — | Antigravity (agente) | Hecha | `spikes/ledger/REPORT.md`: Evaluación EVM en Arbitrum/Base L2 (< $0.005 gas/anclaje), INV-02 auditado |
| F0.T11 | #8..#17 | Angel Nereira / Antigravity | Hecha | ADR-0003 a ADR-0012 Aceptados formalmente e indexados en `docs/adr/` |
| F0.T12 | — | Antigravity (agente) | Hecha | `docs/specs/PROTOCOL.md` redactada y revisada |
| F0.T13 | — | Antigravity (agente) | Hecha | `docs/specs/TRUST_BUNDLE.md` redactada y revisada |
| F0.T14 | — | Antigravity (agente) | Hecha | `docs/specs/CONTRACTS.md` redactada y revisada |
| F0.T15 | — | Antigravity (agente) | Hecha | Perfiles `personal-v1`, `financial-v1` y `enterprise-v1` redactados y revisados |
| F0.T16 | — | Antigravity (agente) | Hecha | `docs/specs/SDK_API.md` y `ERROR_CODES.md` redactadas y revisadas |
| F0.T17 | — | Antigravity (agente) | Hecha | `docs/specs/STORAGE_FORMAT.md` redactada y revisada (cifrado sobre, índices ciegos) |
| F0.T18 | — | Antigravity (agente) | Hecha | `docs/specs/TRUST_FRAMEWORK.md` redactada y revisada (técnica v0.1, legal F14) |
| F0.T19 | — | Antigravity (agente) | Hecha | `docs/specs/TEST_STRATEGY.md` redactada y revisada (pirámide, horas fuzzing por gate) |
| F0.T20 | — | Antigravity (agente) | Hecha | `docs/legal/2026-analisis-regulatorio-preliminar.md` redactada y revisada (Ley 81, KYC/AML) |
| F0.T21 | — | Angel Nereira / Antigravity | Hecha | `docs/specs/CROSS_REVIEW.md`: Auditoría cruzada exhaustiva aprobada (100% conforme con INV-01..16) |
| Revisión v0.2 | #2 | Angel Nereira (mantenedor) | Hecha | ADR-0016 a ADR-0020 **Aceptados** formalmente; Issue #2 cerrado |
| Régimen mantenedor | #1 | Angel Nereira (mantenedor) | Hecha | `AGENTS.md §6/§14` adaptados para F0; Issue #1 cerrado |

## Bloqueos

- Ninguno. La Fase F0 ha finalizado con éxito y el Gate G0 está cerrado. Se puede iniciar la Fase F1 (Estructura del workspace Cargo, esqueletos y CI base).

## Decisiones pendientes que bloquean la fase actual

Ninguna para F0. Todos los ADRs obligatorios de F0 (ADR-0001 a ADR-0012, ADR-0016 a ADR-0018 y ADR-0020) han sido formalmente aceptados. Los ADRs 0013, 0014, 0015 y 0019 están programados para sus respectivas fases (F7, F1, F3, F1).

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
