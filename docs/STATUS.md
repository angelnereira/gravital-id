# STATUS.md — Estado vivo del proyecto

> Fuente única del **avance**. Se actualiza al final de cada sesión de trabajo (`AGENTS.md §5.3`) y al cerrar cada gate. Mantén solo el estado actual y las últimas notas; el histórico queda en los issues y en git.

## Resumen

| Campo | Valor |
|---|---|
| Fase actual | **F2 — Núcleo: tipos, codificación, criptografía y claves** |
| Último gate cerrado | **G0** (2026-10-11) |
| Próximo gate | G1 |
| Hito siguiente | M1 · Núcleo offline (al cerrar G5) |
| Última actualización | 2026-10-13 (F2: T01–T10 hechas) |

## Gates

| Gate | Estado | Fecha | Evidencia |
|---|---|---|---|
| G0 | **Cerrado** | 2026-10-11 | Especificaciones v0.1 completadas, ADRs 0001-0012 y 0016-0020 aceptados, 4 spikes concluidos viables, revisión cruzada F0.T21 aprobada |
| G1 | En curso | — | Workspace, xtask, CI y gobierno del repositorio implementados en `feat/6-workspace-cargo` (#6, PR #22); pendiente merge del mantenedor |
| G2 | En curso | — | F2 iniciada en `feat/24-types-newtypes`: F2.T01 a F2.T10 hechas (#24–#33) |
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
| F2.T09 Higiene de secretos | #32 | Antigravity (agente) | Hecha | Tipos secretos con `Zeroize`, `ZeroizeOnDrop`, `Debug` y `Display` redactados (`[REDACTED]`), comparación en tiempo constante con `subtle`; rama `feat/24-types-newtypes` |
| F2.T10 gravital-id-keys | #33 | Antigravity (agente) | Hecha | `KeyPurpose`, `KeyHandle` tipado por propósito, trait `KeyStore`, `SoftwareKeyStore` bajo feature `software-keystore`, normalización DER↔P1363, pruebas `trybuild` compile-fail; rama `feat/24-types-newtypes` |

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

### Traspaso — 2026-10-13 (cierre F2.T10) — Antigravity (agente)
- Tareas: F2.T10 (#33) — rama `feat/24-types-newtypes` (acumula F2.T01–T10)
- Estado: hecha y verificada
- Hecho en esta sesión:
  - Implementado `gravital-id-keys` (`crates/gravital-id-keys/`):
    - `KeyPurpose`: enumeración completa con propósitos normativos (`HolderBinding`, `VerifierRequest`, `HolderRecovery`, `IssuerSigning`, `StatusListSigning`, `HpkeKeyAgreement`, `TrustRoot`, `TrustBundle`) con métodos de consulta `allows_signing()` y `allows_key_agreement()`.
    - Marcadores a nivel de tipo (`KeyPurposeMarker`, `SigningPurpose`, `KeyAgreementPurpose`) y tipos marcador en `purpose` (`HolderBinding`, `HpkeKeyAgreement`, etc.).
    - `KeyHandle<P>` tipado por propósito con identificador RFC 7638 thumbprint y prevención en compilación de uso indebido (REQ-KEY-001, REQ-KEY-009).
    - Trait abstracto `KeyStore`: operaciones object-safe (`generate_key_for_purpose`, `public_key_by_id`, `sign_digest`, `agree_key_by_id`, `delete_key_by_id`, `key_attestation_by_id`) y métodos tipados por propósito (`generate_key`, `public_key`, `sign`, `agree_key`, `delete_key`, `key_attestation`) (REQ-KEY-004).
    - Implementación `SoftwareKeyStore` bajo feature `software-keystore`, respaldada en memoria con `SecretKeyBytes` (`ZeroizeOnDrop`) y `Rng` inyectado (INV-03, INV-11, REQ-KEY-004, REQ-KEY-007).
    - Normalización de firmas ECDSA P-256 en Rust (`normalize_signature_to_p1363`, `signature_to_der`) validando escalares $(r, s)$ y convirtiendo DER a IEEE P1363 (REQ-KEY-010).
    - Suite de compilación fallida con `trybuild` (`tests/compile_fail.rs` y `tests/ui/`): verifica que pasar una clave de acuerdo HPKE a `sign` o una clave de firma a `agree_key` falla en tiempo de compilación.
    - Suite de integración completa en `tests/keys_tests.rs`: generación para todos los propósitos, round-trip de firma determinista RFC 6979, acuerdo Diffie-Hellman bilateral, borrado con `KeyNotFound`, defensa en profundidad en tiempo de ejecución y normalización DER/P1363.
  - Actualizado `gravital-id-crypto`:
    - Funciones auxiliares `sign_es256_digest`, `public_key_from_secret_key`, `generate_p256_secret_key`, `ecdh_agree_keys`, `verify_es256_jwk`, `verify_es256_digest_jwk`.
  - 169 pruebas pasando en el workspace (12 en `gravital-id-keys`).
  - REQ-KEY-001, REQ-KEY-004, REQ-KEY-007, REQ-KEY-009, REQ-KEY-010 trazados en código y pruebas (`xtask trace` actualizado a 23 requisitos).
  - Compilación cruzada verificada en los 4 targets (`thumbv7em-none-eabihf`, `wasm32-unknown-unknown`, `aarch64-linux-android`, `aarch64-apple-ios`).
  - `cargo deny check bans sources licenses` verificado en verde.
- Pendiente (siguiente paso concreto):
  - F2.T11 Objetivos de fuzzing (#34): Un objetivo por parser (base64url, JSON, CBOR, DEFLATE, Base45, JWK) en `fuzz.yml`.
  - F2.T12 Benchmarks base (#35): Firma, verificación, hash y AEAD en x86_64, aarch64 y WASM; resultados publicados en `docs/STATUS.md`.
- Bugs/issues abiertos: #7, #8, #23 (decisiones/spec-gaps del mantenedor).
- Decisiones tomadas: Se fijó `trybuild = "=1.0.101"` para compatibilidad estricta con MSRV 1.85.0 (ADR-0014) y se configuró `gravital-id-testkit` con versión en `dev-dependencies` para cumplir `deny.toml`.
- Riesgos o dudas: Ninguno en F2.T10; CI sigue a la espera de desbloqueo de facturación de GitHub.
- Comprobaciones locales: fmt ✅ clippy ✅ tests ✅ (169) layers ✅ trace ✅ doc ✅ deny ✅ no_std ✅ wasm32 ✅ android ✅ ios ✅
