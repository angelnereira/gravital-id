# STATUS.md — Estado vivo del proyecto

> Fuente única del **avance**. Se actualiza al final de cada sesión de trabajo (`AGENTS.md §5.3`) y al cerrar cada gate. Mantén solo el estado actual y las últimas notas; el histórico queda en los issues y en git.

## Resumen

| Campo | Valor |
|---|---|
| Fase actual | **F2 — Núcleo: tipos, codificación, criptografía y claves** |
| Último gate cerrado | **G0** (2026-10-11) |
| Próximo gate | G1 |
| Hito siguiente | M1 · Núcleo offline (al cerrar G5) |
| Última actualización | 2026-10-13 (F2: T01–T08 hechas) |

## Gates

| Gate | Estado | Fecha | Evidencia |
|---|---|---|---|
| G0 | **Cerrado** | 2026-10-11 | Especificaciones v0.1 completadas, ADRs 0001-0012 y 0016-0020 aceptados, 4 spikes concluidos viables, revisión cruzada F0.T21 aprobada |
| G1 | En curso | — | Workspace, xtask, CI y gobierno del repositorio implementados en `feat/6-workspace-cargo` (#6, PR #22); pendiente merge del mantenedor |
| G2 | En curso | — | F2 iniciada en `feat/24-types-newtypes`: F2.T01 a F2.T07 hechas (#24–#30) |
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
| F2.T01 Newtypes validados | #24 | OpenCode (agente) | Hecha | `IssuerId`, `Kid`, `Vct`, `ProfileId`, `UnixTime`, `BundleVersion` + propiedades; rama `feat/24-types-newtypes` |
| F2.T02 base64url estricto | #25 | OpenCode (agente) | Hecha | Sin relleno, canónica, acotada; fuzzing 6.9M ejecuciones; rama `feat/24-types-newtypes` |
| F2.T03 JSON acotado | #26 | OpenCode (agente) | Hecha | Límites, duplicados rechazados, UTF-8 estricto, números acotados; diferencial vs serde_json + fuzzing; rama `feat/24-types-newtypes` |
| F2.T04 CBOR acotado | #27 | OpenCode (agente) | Hecha | Límites, modo determinista RFC 8949 §4.2; desbordamiento de pila del fuzzing corregido; rama `feat/24-types-newtypes` |
| F2.T05 DEFLATE + Base45 | #28 | OpenCode (agente) | Hecha | zlib acotado (2 MiB / 10:1, adler32) con backend `no_std` miniz_oxide; Base45 RFC 9285 con vectores del RFC; rama `feat/24-types-newtypes` |
| F2.T06 CryptoBackend + RustCrypto | #29 | Antigravity (agente) | Hecha | ES256 P1363/DER, SHA-256, HMAC, HKDF, XChaCha20-Poly1305, ECDH P-256, HPKE (RFC 9180); rama `feat/24-types-newtypes` |
| F2.T07 JWK y thumbprints | #30 | Antigravity (agente) | Hecha | Parseo estricto JWK EC P-256, validación de curva, rechazo miembros privados (d), RFC 7638 thumbprint; rama `feat/24-types-newtypes` |
| F2.T08 Vectores externos | #31 | Antigravity (agente) | Hecha | RFC 7515 (ES256), RFC 7638, RFC 5869 (HKDF), RFC 9180 (HPKE), Wycheproof (ECDSA P-256 484/484 y AEAD 315/315); rama `feat/24-types-newtypes` |

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

### Traspaso — 2026-10-13 (cierre F2.T08) — Antigravity (agente)
- Tareas: F2.T08 (#31) — rama `feat/24-types-newtypes` (acumula F2.T01–T08)
- Estado: hecha y verificada
- Hecho en esta sesión:
  - Implementada suite integral de vectores externos en `crates/gravital-id-crypto/tests/external_vectors.rs`:
    - RFC 7515 (Apéndice A.3, ES256): verificación P1363, DER, firma determinista propia RFC 6979 con clave `d` oficial, pruebas negativas de alteración de mensaje y coordenadas `(r, s)`.
    - RFC 7638: cálculo de JWK Thumbprints para claves EC P-256 (vector oficial RFC 7638 y clave RFC 7515 A.3) en SHA-256 binario, base64url y formato URI RFC 9278, con pruebas negativas.
    - RFC 5869 (HKDF SHA-256): Casos 1, 2 y 3 (extract, expand, entradas largas de 80B, salt/info vacíos, límite de salida L > 255*32).
    - RFC 9180 (HPKE Modo Base, Apéndice A.5.1): DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + ChaCha20Poly1305. Verificación exacta de `shared_secret`, derivación del `key_schedule` (`key` y `base_nonce`), descifrado (`open`) y cifrado (`seal`) contra vectores de referencia oficiales.
    - Project Wycheproof ECDSA P-256 SHA-256 (`wycheproof_ecdsa_secp256r1_sha256.json`): 484/484 pruebas ejecutadas y pasando al 100% (174 casos válidos incluyendo High-S, 310 casos inválidos rechazados fail-closed).
    - Project Wycheproof XChaCha20-Poly1305 (`wycheproof_xchacha20_poly1305.json`): 315/315 pruebas ejecutadas y pasando al 100% (246 casos válidos con round-trip seal/open, 69 casos inválidos rechazados fail-closed).
  - Actualizado `crates/gravital-id-crypto/src/hpke.rs` para alineación estricta con RFC 9180 (suite IDs, DHKEM encap/decap, labeled extract/expand y AEAD ChaCha20Poly1305).
  - 48 pruebas en `gravital-id-crypto` pasando (42 unitarias + 6 de integración externa).
  - REQ-SEC-002 trazado en todas las pruebas de vectores externos.
  - Compilación cruzada validada para los 4 targets del toolchain (`thumbv7em-none-eabihf`, `wasm32-unknown-unknown`, `aarch64-linux-android`, `aarch64-apple-ios`).
- Pendiente (siguiente paso concreto):
  - F2.T09 Higiene de secretos (#32): Zeroize, Debug redactado, comparación subtle.
  - F2.T10 gravital-id-keys (#33): KeyPurpose, KeyHandle, KeyStore.
- Bugs/issues abiertos: #7, #8, #23 (decisiones/spec-gaps del mantenedor).
- Decisiones tomadas: Se incorporaron los archivos de vectores inmutables de Project Wycheproof en `crates/gravital-id-crypto/tests/vectors/` conforme a `PROJECT_STRUCTURE.md §8`.
- Riesgos o dudas: Ninguno en F2.T08; CI sigue a la espera de desbloqueo de facturación de GitHub.
- Comprobaciones locales: fmt ✅ clippy ✅ tests ✅ (154) layers ✅ trace ✅ doc ✅ no_std ✅ wasm32 ✅ android ✅ ios ✅
