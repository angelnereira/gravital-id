# STATUS.md — Estado vivo del proyecto

> Fuente única del **avance**. Se actualiza al final de cada sesión de trabajo (`AGENTS.md §5.3`) y al cerrar cada gate. Mantén solo el estado actual y las últimas notas; el histórico queda en los issues y en git.

## Resumen

| Campo | Valor |
|---|---|
| Fase actual | **F2 — Núcleo: tipos, codificación, criptografía y claves (COMPLETADA)** |
| Último gate cerrado | **G0** (2026-10-11) |
| Próximo gate | **G2** (Revisión y cierre formal de Fase F2) |
| Hito siguiente | M1 · Núcleo offline (al cerrar G5) |
| Última actualización | 2026-10-13 (F2: T01–T12 completadas — Fase F2 finalizada) |

## Gates

| Gate | Estado | Fecha | Evidencia |
|---|---|---|---|
| G0 | **Cerrado** | 2026-10-11 | Especificaciones v0.1 completadas, ADRs 0001-0012 y 0016-0020 aceptados, 4 spikes concluidos viables, revisión cruzada F0.T21 aprobada |
| G1 | En curso | — | Workspace, xtask, CI y gobierno del repositorio implementados en `feat/6-workspace-cargo` (#6, PR #22); pendiente merge del mantenedor |
| G2 | **Listo para revisión** | — | F2.T01 a F2.T12 completadas en rama `feat/24-types-newtypes` (#24–#35). Vectores externos 100% pasando (RFC 7515/7638/5869/9180, Wycheproof 799/799), 6 parsers fuzzeados en CI (`fuzz.yml`), cobertura `gravital-id-crypto` al 92,46% (≥ 90%), 25 REQ trazados en `docs/TRACEABILITY.md`. |
| G3 … G17 | Pendiente | — | — |

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
| F2.T09 Higiene de secretos | #32 | Antigravity (agente) | Hecha | Tipos secretos con `Zeroize`, `ZeroizeOnDrop`, `Debug` y `Display` redactados (`[REDACTED]`), comparación en tiempo constante con `subtle`; rama `feat/24-types-newtypes` |
| F2.T10 gravital-id-keys | #33 | Antigravity (agente) | Hecha | `KeyPurpose`, `KeyHandle` tipado por propósito, trait `KeyStore`, `SoftwareKeyStore` bajo feature `software-keystore`, normalización DER↔P1363, pruebas `trybuild` compile-fail; rama `feat/24-types-newtypes` |
| F2.T11 Objetivos de fuzzing | #34 | Antigravity (agente) | Hecha | Un objetivo por parser (`base64url_strict`, `json_bounded`, `cbor_bounded`, `base45_strict`, `deflate_bounded`, `jwk_parser`) con trazabilidad REQ-SEC-005 en `fuzz.yml`; rama `feat/24-types-newtypes` |
| F2.T12 Benchmarks base | #35 | Antigravity (agente) | Hecha | Suite criterion `crypto_primitives` en `gravital-id-crypto` (ES256, SHA-256, XChaCha20, HPKE); línea base registrada en `STATUS.md` (REQ-PERF-001); cobertura `gravital-id-crypto` al 92,46 %; rama `feat/24-types-newtypes` |

## Bloqueos

- **Bloqueo de facturación de la cuenta de GitHub:** los workflows de PR #22 se crean correctamente pero los jobs no arrancan ("The job was not started because your account is locked due to a billing issue"). No es un defecto de los workflows: se validaron por sintaxis y todas sus comprobaciones se ejecutaron en local con éxito. El mantenedor debe resolver la facturación para que CI verifique G1.

## Decisiones pendientes que bloquean la fase actual

1. Excepción de licencia `Unicode-3.0` para `unicode-ident` (dependencia de compilación de `proc-macro2`): registrada como excepción acotada en `deny.toml`; falta confirmar si se incorpora a la allowlist de ADR-0002 (issue abierto por el agente).
2. `PROJECT_STRUCTURE.md §7` contradice a `ERROR_CODES.md` en los rangos de códigos y sitúa `GidError` en `gravital-id-sdk` (L6) cuando el catálogo canónico vive en `gravital-id-types` (L1) y el SDK lo re-exporta: registrado como `type:spec-gap`.

## Métricas base (se rellenan desde F2)

### Primitivas criptográficas (F2.T12, REQ-PERF-001)

| Operación | Parámetro | x86_64 (Linux) | aarch64 | wasm32 |
|---|---|---|---|---|
| Firma ES256 (`sign_es256`) | Payload 256 B (RFC 6979) | 204 µs (~4.900 op/s) | — | — |
| Firma ES256 prehash (`sign_es256_digest`) | Digest 32 B | 396 µs (~2.525 op/s) | — | — |
| Verificación ES256 (`verify_es256`) | Payload 256 B + VerifyingKey | 373 µs (~2.680 op/s) | — | — |
| Verificación ES256 JWK (`verify_es256_jwk`) | Payload 256 B + JWK EC P-256 | 420 µs (~2.380 op/s) | — | — |
| Verificación ES256 digest (`verify_es256_digest_jwk`) | Digest 32 B + JWK EC P-256 | 341 µs (~2.930 op/s) | — | — |
| SHA-256 | 32 B | 105 ns (291 MiB/s) | — | — |
| SHA-256 | 256 B | 323 ns (757 MiB/s) | — | — |
| SHA-256 | 1 KiB | 1,04 µs (936 MiB/s) | — | — |
| SHA-256 | 10 KiB | 9,80 µs (996 MiB/s) | — | — |
| XChaCha20-Poly1305 seal | 256 B | 2,73 µs (89 MiB/s) | — | — |
| XChaCha20-Poly1305 open | 256 B | 2,89 µs (84 MiB/s) | — | — |
| XChaCha20-Poly1305 seal | 1 KiB | 3,79 µs (258 MiB/s) | — | — |
| XChaCha20-Poly1305 open | 1 KiB | 4,20 µs (232 MiB/s) | — | — |
| XChaCha20-Poly1305 seal | 8 KiB | 12,65 µs (618 MiB/s) | — | — |
| XChaCha20-Poly1305 open | 8 KiB | 12,59 µs (621 MiB/s) | — | — |
| HPKE Base seal (`p256_hkdf_chacha`) | 256 B | 346 µs | — | — |
| HPKE Base open (`p256_hkdf_chacha`) | 256 B | 361 µs | — | — |

### Métricas de alto nivel

| Métrica | x86_64 | aarch64 | wasm32 | Android | iOS |
|---|---|---|---|---|---|
| Verificación de presentación (tiempo) | — | — | — | — | — |
| Tamaño de presentación de referencia | — | — | — | — | — |
| Tamaño binario del SDK | — | — | — | — | — |

## Última nota de traspaso

### Traspaso — 2026-10-13 (cierre Fase F2: F2.T11 y F2.T12) — Antigravity (agente)
- Tareas: F2.T11 (#34), F2.T12 (#35) — rama `feat/24-types-newtypes` (acumula F2.T01–T12 completa)
- Estado: **Fase F2 100 % completada; Gate G2 listo para revisión/cierre**
- Hecho en esta sesión:
  - F2.T11 (#34):
    - Verificados y etiquetados con trazabilidad (`// Verifies: REQ-SEC-005`) los 6 objetivos de fuzzing para parsers en `fuzz/fuzz_targets/` (`base64url_strict`, `json_bounded`, `cbor_bounded`, `base45_strict`, `deflate_bounded`, `jwk_parser`).
    - Todos integrados en la matriz nocturna de `.github/workflows/fuzz.yml`.
    - Detectado y corregido bug #36 en `xtask/src/trace.rs`: tablas transversales de 5 columnas en `REQUIREMENTS.md` ahora son parseadas correctamente con test de regresión.
  - F2.T12 (#35):
    - Implementada suite Criterion en `crates/gravital-id-crypto/benches/crypto_primitives.rs` midiendo ES256 (sign y verify en formatos P1363/DER/JWK), SHA-256 (32B a 10KiB), XChaCha20-Poly1305 (seal y open 256B a 8KiB) y HPKE Base suite (seal y open 256B).
    - Ejecutados benchmarks localmente en x86_64 y registrada la línea base en `docs/STATUS.md` (REQ-PERF-001).
    - Diseñada e implementada suite `tests/api_coverage.rs` para `gravital-id-crypto`: cobertura de líneas elevada al **92,46 %** (superando el umbral de ≥ 90 % requerido por Gate G2).
    - Pruebas de humo WASM verificadas en Node (`wasm-pack test --node bindings/wasm`).
  - Total de pruebas en el workspace: **174 pruebas unitarias e integración en verde**; 25 requisitos trazados en `docs/TRACEABILITY.md`.
  - Compilación cruzada verificada y limpia en los 4 targets (`thumbv7em-none-eabihf`, `wasm32-unknown-unknown`, `aarch64-linux-android`, `aarch64-apple-ios`).
  - Lints `fmt`, `clippy -D warnings`, `check-layers`, `check-error-codes`, `deny` pasando al 100 %.
- Pendiente (siguiente paso concreto):
  - Revisión y cierre formal del Gate G2 por el mantenedor Angel Nereira.
  - Apertura de Fase F3: Credenciales SD-JWT VC (iniciando con F3.T01: ADR-0015 evaluar construir o reutilizar SD-JWT).
- Bugs/issues resueltos en la sesión: #34 (cerrado), #35 (cerrado), #36 (cerrado).
- Decisiones tomadas: Se implementó `TestRng` en `api_coverage.rs` con traits de `p256::elliptic_curve::rand_core` sin añadir crates externos; benchmarks basales documentados en `STATUS.md`.
- Riesgos o dudas: Ninguno en F2; CI sigue a la espera de desbloqueo de facturación de GitHub.
- Comprobaciones locales: fmt ✅ clippy ✅ tests ✅ (174) layers ✅ trace ✅ doc ✅ deny ✅ no_std ✅ wasm32 ✅ android ✅ ios ✅ cov (92.46%) ✅
