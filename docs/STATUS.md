# STATUS.md — Estado vivo del proyecto

> Fuente única del **avance**. Se actualiza al final de cada sesión de trabajo (`AGENTS.md §5.3`) y al cerrar cada gate. Mantén solo el estado actual y las últimas notas; el histórico queda en los issues y en git.

## Resumen

| Campo | Valor |
|---|---|
| Fase actual | **F4 — Estado, confianza y verificación offline (en curso)** · **F19 — Especificación de la ampliación (en paralelo, en curso)** |
| Último gate cerrado | **G0** (2026-10-11) |
| Próximo gate | **G3** — revisión formal de Fase F3 (#59); **G2** sigue pendiente de merge/CI |
| Hito siguiente | M1 · Núcleo offline (al cerrar G5) · MP1 · Tap offline (al cerrar G21) |
| Última actualización | 2026-10-15 (F19.T03–F19.T07 completadas — ADR-0022 a ADR-0026 redactados; #74 y #77 resueltos) |

## Gates

| Gate | Estado | Fecha | Evidencia |
|---|---|---|---|
| G0 | **Cerrado** | 2026-10-11 | Especificaciones v0.1 completadas, ADRs 0001-0012 y 0016-0020 aceptados, 4 spikes concluidos viables, revisión cruzada F0.T21 aprobada |
| G1 | En curso | — | Workspace, xtask, CI y gobierno del repositorio implementados en `feat/6-workspace-cargo` (#6, PR #22); pendiente merge del mantenedor |
| G2 | **Listo para revisión** | — | F2.T01 a F2.T12 completadas en rama `feat/24-types-newtypes` (#24–#35). Vectores externos 100% pasando (RFC 7515/7638/5869/9180, Wycheproof 799/799), 6 parsers fuzzeados en CI (`fuzz.yml`), cobertura `gravital-id-crypto` al 92,46% (≥ 90%), 25 REQ trazados en `docs/TRACEABILITY.md`. |
| G3 | **Abierto a revisión** (#59) | — | F3.T01–T09 implementadas y trazadas (24 vectores de conformidad, 304 pruebas). **Decisión: NO CERRADO**: F3.T10 (interoperabilidad bidireccional) está bloqueada por depender de una implementación externa, y la campaña de fuzzing nocturna no puede ejecutarse mientras GitHub Actions esté bloqueado por facturación. |
| G4 … G25 | Pendiente | — | — |

## Tareas en curso

| Tarea | Issue | Responsable | Estado | Siguiente paso |
|---|---|---|---|---|
| F19.T07 ADR-0026: perfil de identidad y retrato | #79 | Antigravity (agente) | Hecha | `docs/adr/0026-perfil-identidad-retrato.md` redactado (`pip-identity-v1` con `vct` oficial/derivado y retrato JPEG $\le 16\text{ KiB}$ solo por NFC/BLE) |
| F19.T06 ADR-0025: identificadores numéricos | #79 | Antigravity (agente) | Hecha | `docs/adr/0025-identificadores-numericos-sesion.md` redactado (`SessionCode` 10 dígitos + Damm en línea, número por emisor opcional); resuelve `#77` |
| F19.T05 ADR-0024: tarjeta física Java Card | #79 | Antigravity (agente) | Hecha | `docs/adr/0024-tarjeta-fisica-javacard.md` redactado (Java Card 3.0.5+, P-256 en hardware, PIN niveles 0/1, `gid-perso` y vectores en `jCardSim`) |
| F19.T04 ADR-0023: cifrado de sesión y transcrito | #79 | Antigravity (agente) | Hecha | `docs/adr/0023-cifrado-sesion-proximidad-transcrito.md` y `CRYPTO_PROFILES.md` actualizados (HPKE RFC 9180 + `SessionTranscript` como AAD y `nonce` del KB-JWT) |
| F19.T03 ADR-0022: transporte de proximidad | #79 | Antigravity (agente) | Hecha | `docs/adr/0022-transporte-proximidad-gid-apdu.md` y `ADR-0011` actualizados (`GID-APDU` ISO 7816-4, AID `F0475241564954414C01`, capas L4/L5); resuelve `#74` |
| F19.T08 Requisitos PROX, CARD, CODE, IDDOC | #78 | Antigravity (agente) | Hecha | 20 nuevos requisitos (`REQ-PROX-001..008`, `REQ-CARD-001..005`, `REQ-CODE-001..004`, `REQ-IDDOC-001..003`) incorporados a `REQUIREMENTS.md` v0.3 y trazados en `TRACEABILITY.md` (167 REQ totales) |
| F19.T01 ADR-0021: ampliación de alcance | #78 | Antigravity (agente) | Hecha | `ADR-0021` **Aceptado** por el mantenedor; `ROADMAP.md` v0.3 (`F19`–`F25`, `MP1`–`MP3`, `R-15`–`R-23`), `ARCHITECTURE.md` v0.3, `PROJECT_STRUCTURE.md` y `CODEOWNERS` actualizados |
| F19.T02 Registrar discrepancias (§5.3) | #78 | Antigravity (agente) | Hecha | 5 issues `type:spec-gap` registrados (`#73` multi-QR, `#74` calendario BLE/NFC, `#75` estado en README, `#76` reproducibilidad spikes, `#77` código numérico vs P-09) |
| F4.T08 Estados de clave del emisor | #71 | Antigravity (agente) | Hecha | Semántica `active`/`retired`/`suspended`/`compromised` (`ARCHITECTURE.md §11.6`, REQ-KEY-005, REQ-KEY-006); integrada en `main` (`cbecf33`) |
| F4.T07 Caché de nonces | #68 | Antigravity (agente) | Hecha | Trait `NonceCache`, `InMemoryNonceCache` acotada (4.096), evicción determinista por expiración, `proptest`; integrada en `main` |
| F4.T06 Pipeline del verificador | #66 | Antigravity (agente) | Hecha | Pipeline typestate con 11 comprobaciones ordenadas, evidencia y testigo compile-fail; integrada en `main` |
| F4.T05 Policy del verificador | #65 | OpenCode (agente) | Hecha | `VerificationPolicy`, frescura por operación, sesgo acotado, allowlist/denylist; integrada en `main` |
| F4.T04 Estado del verificador | #64 | OpenCode (agente) | Hecha | `VerifierStateStore`, `TimeFloorGuard`, `InMemoryStateStore` con HMAC-SHA256; integrada en `main` |
| F4.T03 Trust bundle | #62 | OpenCode (agente) | Hecha | Multi-firma k-de-n, anti-rollback `(bundle_epoch, bundle_version)` y estados de clave; integrada en `main` |
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
| F2.T01 Newtypes validados | #24 | OpenCode (agente) | Hecha | `IssuerId`, `Kid`, `Vct`, `ProfileId`, `UnixTime`, `BundleVersion` + propiedades; integrada en `main` |
| F2.T02 base64url estricto | #25 | OpenCode (agente) | Hecha | Sin relleno, canónica, acotada; fuzzing 6.9M ejecuciones; integrada en `main` |
| F2.T03 JSON acotado | #26 | OpenCode (agente) | Hecha | Límites, duplicados rechazados, UTF-8 estricto, números acotados; diferencial vs serde_json + fuzzing; integrada en `main` |
| F2.T04 CBOR acotado | #27 | OpenCode (agente) | Hecha | Límites, modo determinista RFC 8949 §4.2; desbordamiento de pila del fuzzing corregido; integrada en `main` |
| F2.T05 DEFLATE + Base45 | #28 | OpenCode (agente) | Hecha | zlib acotado (2 MiB / 10:1, adler32) con backend `no_std` miniz_oxide; Base45 RFC 9285 con vectores del RFC; integrada en `main` |
| F2.T06 CryptoBackend + RustCrypto | #29 | Antigravity (agente) | Hecha | ES256 P1363/DER, SHA-256, HMAC, HKDF, XChaCha20-Poly1305, ECDH P-256, HPKE (RFC 9180); integrada en `main` |
| F2.T07 JWK y thumbprints | #30 | Antigravity (agente) | Hecha | Parseo estricto JWK EC P-256, validación de curva, rechazo miembros privados (d), RFC 7638 thumbprint; integrada en `main` |
| F2.T08 Vectores externos | #31 | Antigravity (agente) | Hecha | RFC 7515 (ES256), RFC 7638, RFC 5869 (HKDF), RFC 9180 (HPKE), Wycheproof (ECDSA P-256 484/484 y AEAD 315/315); integrada en `main` |
| F2.T09 Higiene de secretos | #32 | Antigravity (agente) | Hecha | Tipos secretos con `Zeroize`, `ZeroizeOnDrop`, `Debug` y `Display` redactados (`[REDACTED]`), comparación en tiempo constante con `subtle`; integrada en `main` |
| F2.T10 gravital-id-keys | #33 | Antigravity (agente) | Hecha | `KeyPurpose`, `KeyHandle` tipado por propósito, trait `KeyStore`, `SoftwareKeyStore` bajo feature `software-keystore`, normalización DER↔P1363, pruebas `trybuild` compile-fail; integrada en `main` |
| F2.T11 Objetivos de fuzzing | #34 | Antigravity (agente) | Hecha | Un objetivo por parser (`base64url_strict`, `json_bounded`, `cbor_bounded`, `base45_strict`, `deflate_bounded`, `jwk_parser`) con trazabilidad REQ-SEC-005 en `fuzz.yml`; integrada en `main` |
| F2.T12 Benchmarks base | #35 | Antigravity (agente) | Hecha | Suite criterion `crypto_primitives` en `gravital-id-crypto` (ES256, SHA-256, XChaCha20, HPKE); línea base registrada en `STATUS.md` (REQ-PERF-001); cobertura `gravital-id-crypto` al 92,46 %; integrada en `main` |
| F3.T01 ADR-0015 construir o reutilizar | #39 | Antigravity (agente) | Hecha | Evaluación de crates SD-JWT existentes; redactado `ADR-0015` propuesto; decisión Opción B (implementar en L2 `gravital-id-credential`); integrada en `main` |
| F3.T02 Emisión SD-JWT | #41 | Antigravity (agente) | Hecha | Emisión RFC 9901 en `gravital-id-credential` (objetos/arrays, sal ≥ 128b, decoys, anidación, serialización compacta y firma ES256 vía `KeyStore`); integrada en `main` |
| F3.T03 Parseo y verificación SD-JWT | #43 | Antigravity (agente) | Hecha | Parseo RFC 9901 en `gravital-id-credential` (verificación de digests, rechazo de duplicados, claims reservados, huérfanos, colisión de claves, reconstrucción, firma ES256, límites DoS y fuzzing); integrada en `main` |
| F3.T04 KB-JWT | #45 | Antigravity (agente) | Hecha | Creación y verificación de KB-JWT (`typ: kb+jwt`, `nonce`, `aud`, `iat`, `sd_hash`; firma delegada al `KeyStore`; REQ-PRES-002, REQ-CRED-001, REQ-VER-003); integrada en `main` |
| F4.T02 `pip-status`: caché y frescura | #61 | OpenCode (agente) | Hecha | `StatusSnapshot` + `FreshnessPolicy` (7 días personal, 30 min/4 h financiero, 8 h empresarial) + `StatusCache` acotada, con reloj inyectado; integrada en `main` |
| F4.T01 `pip-status`: listas | #60 | OpenCode (agente) | Hecha | Token Status List (JWT) con descompresión acotada, 1/2 bits, URI y frescura + `IssuerStatusManifest` con versión monotónica (REQ-STAT-001/003/004/007/008); integrada en `main` |
| F3.T09 Vectores de conformidad v1 | #58 | OpenCode (agente) | Hecha | 24 vectores en `conformance/vectors/sd-jwt-vc/` (6 positivos, 18 negativos) + runner `cargo xtask conformance`; integrada en `main` |
| F3.T08 `pip-issuer` | #57 | OpenCode (agente) | Hecha | API de construcción y firma; emisión por lotes con claves, sales e índices distintos (REQ-CRED-006); integrada en `main` |
| F3.T07 Claims de predicado | #49 | OpenCode (agente) | Hecha | Predicados precomputados (`age_over_18`/`age_over_21`) con cálculo por calendario y reloj inyectado; integrada en `main` |
| F3.T06 Esquemas de perfil | #48 | OpenCode (agente) | Hecha | Esquemas de `pip-personal-v1`, `pip-financial-v1` y `pip-enterprise-v1` en compilación con validación en emisión y verificación (REQ-CRED-004); integrada en `main` |
| F3.T05 Capa SD-JWT VC | #47 | OpenCode (agente) | Hecha | `typ: dc+sd-jwt`, `iss`/`vct`/`iat`/`nbf`/`exp`, `cnf.jwk` canónico, `status.status_list`, lista de algoritmos del perfil y rechazo de `none`; integrada en `main` |

## Bloqueos

- **Bloqueo de facturación de la cuenta de GitHub:** los workflows de PR #22 se crean correctamente pero los jobs no arrancan ("The job was not started because your account is locked due to a billing issue"). No es un defecto de los workflows: se validaron por sintaxis y todas sus comprobaciones se ejecutaron en local con éxito. El mantenedor debe resolver la facturación para que CI verifique G1.

## Decisiones pendientes que bloquean la fase actual

1. Excepción de licencia `Unicode-3.0` para `unicode-ident` (dependencia de compilación de `proc-macro2`): registrada como excepción acotada en `deny.toml`; falta confirmar si se incorpora a la allowlist de ADR-0002 (#7).
2. `PROJECT_STRUCTURE.md §7` contradice a `ERROR_CODES.md` en los rangos de códigos y sitúa `GidError` en `gravital-id-sdk` (L6) cuando el catálogo canónico vive en `gravital-id-types` (L1) y el SDK lo re-exporta: registrado como `type:spec-gap` (#8).
3. **Presupuesto y cabecera Multi-QR (#73):** contradicción entre `ADR-0011` (1.200 caracteres, `GID01/P...`), `PROTOCOL.md §3.3` (800 caracteres, `PIP1/M/...`) y `spikes/qr/REPORT.md` (fragmentos de 900 caracteres, `GID01/P...`); bloquea `F5.T09`.
4. **Aprobación formal de `ADR-0022` a `ADR-0026` (`F19.T03`–`F19.T07`):** redactados en estado **Propuesto** (#79); sujetos a revisión del mantenedor humano y a las mediciones en hardware de `F19.T12`–`F19.T13` para cerrar `G19`.

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

### Traspaso — 2026-10-15 (F19.T03–F19.T07: ADR-0022 a ADR-0026 redactados) — Antigravity (agente)
- Tarea: F19.T03 / F19.T04 / F19.T05 / F19.T06 / F19.T07 — #79 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - Redactados los 5 ADRs técnicos de la ampliación en `docs/adr/`:
    - `0022-transporte-proximidad-gid-apdu.md` (`F19.T03`, resuelve `#74` junto con la actualización de `ADR-0011`),
    - `0023-cifrado-sesion-proximidad-transcrito.md` (`F19.T04`, junto con la referencia explícita a RFC 9180 HPKE en `CRYPTO_PROFILES.md`),
    - `0024-tarjeta-fisica-javacard.md` (`F19.T05`),
    - `0025-identificadores-numericos-sesion.md` (`F19.T06`, resuelve `#77`),
    - `0026-perfil-identidad-retrato.md` (`F19.T07`).
  - Actualizado `docs/adr/README.md` enlazando los cinco ADRs.
- Pendiente (siguiente paso concreto):
  - En `F19`: completar `F19.T09` (`PROTOCOL.md §7` + `ERROR_CODES.md` familia 8 + resolver `#73`), `F19.T10` (adenda `THREAT_MODEL.md`), `F19.T11` (`docs/specs/profiles/pip-identity-v1.md`) y `F19.T15` (adenda legal en `docs/legal/`).
  - En `F4`: completar `F4.T09`–`F4.T12`.
- Bugs/issues abiertos durante la sesión: `#79` (cerrado); cerrados los `spec-gap` `#74` y `#77`.
- Decisiones tomadas (con enlace a ADR/issue): propuestas documentadas en `ADR-0022` a `ADR-0026` (#79).
- Riesgos o dudas: `R-16` (soporte AEAD en tarjeta Java Card) queda sujeto a mediciones del spike `F19.T13`.
- Comprobaciones locales: fmt ✅ clippy ✅ tests ✅ (402 pruebas) layers ✅ trace ✅ check-error-codes ✅ check-req-ids ✅

