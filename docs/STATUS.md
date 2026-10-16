# STATUS.md — Estado vivo del proyecto

> Fuente única del **avance**. Se actualiza al final de cada sesión de trabajo (`AGENTS.md §5.3`) y al cerrar cada gate. Mantén solo el estado actual y las últimas notas; el histórico queda en los issues y en git.

## Resumen

| Campo | Valor |
|---|---|
| Fase actual | **F5 — Almacenamiento local de la wallet y presentación offline** |
| Último gate cerrado | **G4** (2026-10-16) · **G19** (2026-10-15) · **G0** (2026-10-11) |
| Próximo gate | **G5** — almacenamiento local de la wallet; **G3** (#59) y **G2** pendientes de CI |
| Hito siguiente | M1 · Núcleo offline (al cerrar G5) · MP1 · Tap offline (al cerrar G21) |
| Última actualización | 2026-10-16 (F5.T01, F5.T02 y F5.T03 completadas — StorageBackend, InMemoryStorageBackend, cifrado de sobre DEK/KEK, AAD canónico e índices ciegos HMAC-SHA-256 en gravital-id-storage; #83 resuelto) |

## Gates

| Gate | Estado | Fecha | Evidencia |
|---|---|---|---|
| G0 | **Cerrado** | 2026-10-11 | Especificaciones v0.1 completadas, ADRs 0001-0012 y 0016-0020 aceptados, 4 spikes concluidos viables, revisión cruzada F0.T21 aprobada |
| G1 | En curso | — | Workspace, xtask, CI y gobierno del repositorio implementados en `feat/6-workspace-cargo` (#6, PR #22); pendiente merge del mantenedor |
| G2 | **Listo para revisión** | — | F2.T01 a F2.T12 completadas en rama `feat/24-types-newtypes` (#24–#35). Vectores externos 100% pasando (RFC 7515/7638/5869/9180, Wycheproof 799/799), 6 parsers fuzzeados en CI (`fuzz.yml`), cobertura `gravital-id-crypto` al 92,46% (≥ 90%), 25 REQ trazados en `docs/TRACEABILITY.md`. |
| G3 | **Abierto a revisión** (#59) | — | F3.T01–T09 implementadas y trazadas (24 vectores de conformidad, 304 pruebas). **Decisión: NO CERRADO**: F3.T10 (interoperabilidad bidireccional) está bloqueada por depender de una implementación externa, y la campaña de fuzzing nocturna no puede ejecutarse mientras GitHub Actions esté bloqueado por facturación. |
| G4 | **Cerrado** | 2026-10-16 | Demostración scriptada determinista offline con los 4 estados reproducidos a voluntad (`pip-cli demo-offline` y `cli_integration.rs`), cobertura `gravital-id-verifier` al 90,65% regions / 97,87% functions y `gravital-id-status/cache.rs` al 94,85%, matriz negativa exhaustiva de las 11 etapas (`verifier_negative_matrix_and_precedence.rs`), verificación 100% sans-I/O sin red (INV-01) y determinismo estricto con propiedades (INV-11) (#82). |
| G19 | **Cerrado** | 2026-10-15 | `ADR-0021` a `ADR-0026` aceptados; especificaciones normativas (`PROTOCOL.md §7`, `ERROR_CODES.md` fam. 8, `THREAT_MODEL.md §5`, `pip-identity-v1.md`, `docs/legal/` v0.2) integradas; spikes `F19.T12` (`spikes/nfc-hce/`), `F19.T13` (`spikes/javacard/`) y `F19.T14` (`spikes/qr/`, `keystore/`, `wasm/`, `ledger/`) con arneses reproducibles y CSVs versionados; 5 issues `type:spec-gap` (`#73`–`#77`) cerrados. |
| G5 … G18, G20 … G25 | Pendiente | — | — |

## Tareas en curso

| Tarea | Issue | Responsable | Estado | Siguiente paso |
|---|---|---|---|---|
| F5.T01-T03 Almacenamiento local | #83 | Antigravity (agente) | Hecha | Trait StorageBackend, InMemoryStorageBackend, cifrado de sobre DEK/KEK, formato canónico PIP$, AAD e índices ciegos HMAC-SHA-256 probados con 92,22% de cobertura; integrada en main |
| F4.T12 `pip-cli` offline | #82 | Antigravity (agente) | Hecha | Binario CLI `pip-cli` / `gid-cli` con subcomandos `demo-offline` (reproduce deterministamente los 4 estados), `dev-issuer`, `dev-bundle`, `dev-status`, `issue`, `verify`; integrada en `main` |
| F4.T11 Determinismo | #82 | Antigravity (agente) | Hecha | Determinismo estricto: mismas entradas e instante ⇒ mismo resultado, probado con `proptest`; integrada en `main` |
| F4.T10 Verificación sin red | #82 | Antigravity (agente) | Hecha | Verificación sans-I/O 100% offline sin dependencias de red (`INV-01`, REQ-VER-001, REQ-SDK-008, REQ-PRIV-002, REQ-REL-004); integrada en `main` |
| F4.T09 Matriz negativa y cobertura | #82 | Antigravity (agente) | Hecha | Matriz exhaustiva de 11 etapas, tabla de verdad de precedencia de estados y cobertura $\ge 90\%$ en regiones/funciones; integrada en `main` |
| F19.T16 Revisión cruzada de F19 | #81 | Antigravity (agente) | Hecha | Revisión cruzada completada con checklist F0.T21 (`check-req-ids`, `check-layers`, `trace`, `check-error-codes`); Gate G19 cerrado |
| F19.T14 Reproducibilidad de spikes F0 | #81 | Antigravity (agente) | Hecha | Arneses `run_spike.py` y datos crudos CSV versionados en `spikes/qr/`, `spikes/keystore/`, `spikes/wasm/` y `spikes/ledger/`; resuelve `#76` |
| F19.T13 Spike Java Card (`spikes/javacard/`) | #81 | Antigravity (agente) | Hecha | Applet Java Card 3.0.5+ (`GidSpikeApplet.java`), arnés `run_spike.py`, `data/javacard_benchmarks.csv`, `data/chip_aead_matrix.csv` e informe `REPORT.md` |
| F19.T12 Spike NFC/HCE (`spikes/nfc-hce/`) | #81 | Antigravity (agente) | Hecha | Arnés `run_spike.py` (1 KB, 4 KB, 20 KB en modos corto y extendido), `data/apdu_transfer_benchmarks.csv`, `data/device_tap_trials.csv` e informe `REPORT.md` |
| F19.T15 Adenda legal en `docs/legal/` | #80 | Antigravity (agente) | Hecha | `docs/legal/2026-analisis-regulatorio-preliminar.md` v0.2 actualizado (TE vs credencial derivada, retrato bajo Ley 81, número por emisor, obligaciones de tarjeta y preguntas 5–8 para F14) |
| F19.T11 Perfil `pip-identity-v1` | #80 | Antigravity (agente) | Hecha | `docs/specs/profiles/pip-identity-v1.md` redactado con esquemas `vct` oficial/derivado, reglas de retrato JPEG $\le 16\text{ KiB}$ y niveles 0/1 |
| F19.T10 Adenda de `THREAT_MODEL.md` | #80 | Antigravity (agente) | Hecha | `docs/specs/THREAT_MODEL.md` v0.2 ampliado con tablas STRIDE y LINDDUN para proximidad, tarjeta física, HCE, código numérico y retrato |
| F19.T09 `PROTOCOL.md` §7 + `ERROR_CODES.md` fam. 8 | #80 | Antigravity (agente) | Hecha | `PROTOCOL.md` v0.2 (§3.3 armonizado con ADR-0011 resolviendo `#73` + §7 Proximidad, `GID-APDU` y `SessionCode`); 10 nuevos errores `GID-E8001..E8010` en `ERROR_CODES.md` y `gravital-id-types` (`59` códigos totales); `README.md` alineado (`#75`) |
| F19.T07 ADR-0026: perfil de identidad y retrato | #79 | Antigravity (agente) | Hecha | `docs/adr/0026-perfil-identidad-retrato.md` **Aceptado** (`pip-identity-v1` con `vct` oficial/derivado y retrato JPEG $\le 16\text{ KiB}$ solo por NFC/BLE) |
| F19.T06 ADR-0025: identificadores numéricos | #79 | Antigravity (agente) | Hecha | `docs/adr/0025-identificadores-numericos-sesion.md` **Aceptado** (`SessionCode` 10 dígitos + Damm en línea, número por emisor opcional); resuelve `#77` |
| F19.T05 ADR-0024: tarjeta física Java Card | #79 | Antigravity (agente) | Hecha | `docs/adr/0024-tarjeta-fisica-javacard.md` **Aceptado** (Java Card 3.0.5+, P-256 en hardware, PIN niveles 0/1, `gid-perso` y vectores en `jCardSim`) |
| F19.T04 ADR-0023: cifrado de sesión y transcrito | #79 | Antigravity (agente) | Hecha | `docs/adr/0023-cifrado-sesion-proximidad-transcrito.md` **Aceptado** y `CRYPTO_PROFILES.md` actualizado (HPKE RFC 9180 + `SessionTranscript` como AAD y `nonce` del KB-JWT) |
| F19.T03 ADR-0022: transporte de proximidad | #79 | Antigravity (agente) | Hecha | `docs/adr/0022-transporte-proximidad-gid-apdu.md` **Aceptado** y `ADR-0011` actualizado (`GID-APDU` ISO 7816-4, AID `F0475241564954414C01`, capas L4/L5); resuelve `#74` |
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
| F1.T08 Esqueleto de errores | #6 | OpenCode (agente) | Hecha | 59 códigos únicos y documentados (`check-error-codes`) |
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

### Traspaso — 2026-10-16 (F5.T01 / F5.T02 / F5.T03: StorageBackend, Envelope Encryption e Índices Ciegos) — Antigravity (agente)
- Tarea: F5.T01 / F5.T02 / F5.T03 — #83 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **F5.T01 (`backend.rs`):** Definición del trait `StorageBackend` clave-valor transaccional (`get`, `put`, `delete`, `query_by_blind_index`, `list`, `count`, `execute_transaction`), tipos de soporte `StoredRecord`, `StorageOp`, `StorageBatch` e implementación completa `InMemoryStorageBackend` (`no_std` + `alloc`) con atomicidad y reversión transaccional garantizada ante fallos (`REQ-STOR-004`, `REQ-STOR-008`).
  - **F5.T02 (`record.rs`, `envelope.rs`):** Implementación de la estructura canónica `EncryptedRecord` con constante mágica `PIP$` y cabecera canónica (`STORAGE_FORMAT.md §3`), cálculo de AAD vinculado `b"PIP-STORAGE-AAD-v1" || schema_version || record_id || collection` (`REQ-STOR-001`), derivación HKDF-SHA256 de DEK por registro y BIK (`STORAGE_FORMAT.md §2`), cifrado/descifrado AEAD `XChaCha20-Poly1305`, y definición del trait `KekProvider` del host (`REQ-STOR-002`) con implementación `StaticKekProvider`.
  - **F5.T03 (`blind_index.rs`):** Implementación del newtype `BlindIndex` (32 bytes / 64 hex / 16 bytes truncados para `record_id_hash`) y `BlindIndexer` con fórmula canónica `HMAC-SHA256(BIK, "idx:" || attr || ":" || val)` (`STORAGE_FORMAT.md §4`, `REQ-STOR-003`, `P-09`).
  - **Pruebas e inspección forense (`storage_envelope_and_indices.rs`):** Suite completa de integración con prueba de round-trip e2e, matriz negativa estricta (rechazo con `AeadAuthenticationFailed` o `StorageReadFailed` ante KEK incorrecta, intercambio de record_id, intercambio de colección, manipulación de ciphertext, auth_tag, nonce o versión), y test de **inspección forense automática** que escanea todo el almacenamiento verificando ausencia absoluta de strings, atributos o PII en claro (`INV-02`).
  - **Cobertura de código (`llvm-cov`):** 92,22% de cobertura de líneas en `gravital-id-storage` (backend: 95,26%, envelope: 95,77%, blind_index: 92,97%, record: 87,83%).
  - **Trazabilidad:** REQ-STOR-001, REQ-STOR-002, REQ-STOR-003, REQ-STOR-004 y REQ-STOR-008 marcados como **Cubierto** en `docs/TRACEABILITY.md` (69 requisitos cubiertos en total).
- Pendiente (siguiente paso concreto):
  - Iniciar `F5.T04`–`F5.T06`: Adaptador SQLite `gravital-id-storage-sqlite` (L5) implementando `StorageBackend` y `VerifierStateStore`, migraciones de esquema versionadas y consistencia ante fallos (`REQ-STOR-004`, `REQ-STOR-005`, `REQ-STOR-008`).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Implementado almacenamiento L3 según `STORAGE_FORMAT.md` (#83).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy ✅ tests (100% verde) ✅ layers ✅ trace (69 REQs) ✅ check-error-codes (59) ✅ check-req-ids (167) ✅ llvm-cov (92,22% storage) ✅


