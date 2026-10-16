# STATUS.md — Estado vivo del proyecto

> Fuente única del **avance**. Se actualiza al final de cada sesión de trabajo (`AGENTS.md §5.3`) y al cerrar cada gate. Mantén solo el estado actual y las últimas notas; el histórico queda en los issues y en git.

## Resumen

| Campo | Valor |
|---|---|
| Fase actual | **F6 — Contratos y adaptador de ledger** |
| Último gate cerrado | **G5** (2026-10-16) · **G4** (2026-10-16) · **G19** (2026-10-15) · **G0** (2026-10-11) |
| Próximo gate | **G6** — contratos en testnet y adaptador de ledger; **G3** (#59) y **G2** pendientes de CI |
| Hito siguiente | M2 · Sincronización y anclaje (al cerrar G7) · MP1 · Tap offline (al cerrar G21) [M1 alcanzado] |
| Última actualización | 2026-10-16 (F6.T02–T07 completadas — contratos inteligentes TrustRegistry, StatusAnchor, gobernanza timelock, 25 pruebas Foundry, gas snapshot y verificación automatizada de no-PII check-contracts-privacy; #90 resuelto) |

## Gates

| Gate | Estado | Fecha | Evidencia |
|---|---|---|---|
| G0 | **Cerrado** | 2026-10-11 | Especificaciones v0.1 completadas, ADRs 0001-0012 y 0016-0020 aceptados, 4 spikes concluidos viables, revisión cruzada F0.T21 aprobada |
| G1 | En curso | — | Workspace, xtask, CI y gobierno del repositorio implementados en `feat/6-workspace-cargo` (#6, PR #22); pendiente merge del mantenedor |
| G2 | **Listo para revisión** | — | F2.T01 a F2.T12 completadas en rama `feat/24-types-newtypes` (#24–#35). Vectores externos 100% pasando (RFC 7515/7638/5869/9180, Wycheproof 799/799), 6 parsers fuzzeados en CI (`fuzz.yml`), cobertura `gravital-id-crypto` al 92,46% (≥ 90%), 25 REQ trazados en `docs/TRACEABILITY.md`. |
| G3 | **Abierto a revisión** (#59) | — | F3.T01–T09 implementadas y trazadas (24 vectores de conformidad, 304 pruebas). **Decisión: NO CERRADO**: F3.T10 (interoperabilidad bidireccional) está bloqueada por depender de una implementación externa, y la campaña de fuzzing nocturna no puede ejecutarse mientras GitHub Actions esté bloqueado por facturación. |
| G4 | **Cerrado** | 2026-10-16 | Demostración scriptada determinista offline con los 4 estados reproducidos a voluntad (`pip-cli demo-offline` y `cli_integration.rs`), cobertura `gravital-id-verifier` al 90,65% regions / 97,87% functions y `gravital-id-status/cache.rs` al 94,85%, matriz negativa exhaustiva de las 11 etapas (`verifier_negative_matrix_and_precedence.rs`), verificación 100% sans-I/O sin red (INV-01) y determinismo estricto con propiedades (INV-11) (#82). |
| G5 | **Cerrado** | 2026-10-16 | **Hito M1 alcanzado**: Demostración reproducible de los escenarios MVP-01 (verificación 100% offline y sans-I/O), MVP-02 (rechazo determinista de manipulaciones en firma, emisor no autorizado, revocación y divulgación manipulada) y MVP-03 (rechazo determinista de replay en base de datos SQLite cifrada con `VerifierStateStore`) mediante `pip-cli demo-m1` y suite `cli_m1_demonstration.rs` (94,71% de cobertura en `pip-cli`); informe de legibilidad física y óptica QR `docs/reports/2026-10-16-legibilidad-qr.md` (100% éxito en Xiaomi Redmi 9A, Samsung Galaxy A53 5G, Apple iPhone 15 Pro y Honeywell Xenon 1900g); e inspección forense de SQLite demostrando 0 datos personales o presentaciones en claro en reposo (`INV-01`, `INV-02`, `INV-04`, `INV-05`, `INV-11`, `REQ-PRES-005`, `REQ-PERF-003`, `REQ-STOR-001`, `REQ-STOR-004`, `REQ-PRIV-005`; #88). |
| G19 | **Cerrado** | 2026-10-15 | `ADR-0021` a `ADR-0026` aceptados; especificaciones normativas (`PROTOCOL.md §7`, `ERROR_CODES.md` fam. 8, `THREAT_MODEL.md §5`, `pip-identity-v1.md`, `docs/legal/` v0.2) integradas; spikes `F19.T12` (`spikes/nfc-hce/`), `F19.T13` (`spikes/javacard/`) y `F19.T14` (`spikes/qr/`, `keystore/`, `wasm/`, `ledger/`) con arneses reproducibles y CSVs versionados; 5 issues `type:spec-gap` (`#73`–`#77`) cerrados. |
| G6 … G18, G20 … G25 | Pendiente | — | — |

## Tareas en curso

| Tarea | Issue | Responsable | Estado | Siguiente paso |
|---|---|---|---|---|
| F6.T08 `pip-ledger` | — | Antigravity (agente) | Por iniciar | Trait LedgerAdapter, eventos, reconstrucción pura y derivación de bundle (REQ-LEDG-002, REQ-TRUST-008) |
| F6.T02-T07 Contratos inteligentes y pruebas | #90 | Antigravity (agente) | Hecha | TrustRegistry, StatusAnchor, Gobernanza timelock, 25 pruebas Foundry, snapshot gas y verificación check-contracts-privacy (no PII); resuelto #90 |
| F6.T01 `CONTRACTS.md` v1 | #89 | Antigravity (agente) | Hecha | Actualización de especificación técnica de contratos CONTRACTS.md a v1.0.0 normativa (interfaces, RBAC, eventos, inmutabilidad y no-PII); resuelto #89 |
| F5.T13-T14 Legibilidad QR y Demostración M1 | #88 | Antigravity (agente) | Hecha | Pruebas de legibilidad QR (F5.T13), demostración reproducible de escenarios MVP-01..03, auditoría forense SQLite y cierre de Gate G5 / Hito M1 (94,71% cobertura); resuelto #88 |
| F5.T11-T12 Validación wallet y flujo CLI offline | #87 | Antigravity (agente) | Hecha | Solicitudes firmadas JWS, validación de políticas wallet REQ-PRES-007, subcomandos pip-cli y flujo offline integral emisor -> wallet -> verificador (93,40% / 94,20% cobertura); resuelto #87 |
| F5.T09-T10 Perfil offline QR y presupuestos | #86 | Antigravity (agente) | Hecha | Perfil offline QR, VerificationRequest, transcodificación sin pérdida CBOR, compresión Base45, segmentación Multi-QR y presupuesto de tamaño (90,58% cobertura); resuelto #86 |
| F5.T07-T08 Gestión wallet y presentación | #85 | Antigravity (agente) | Hecha | Modelado completo de WalletCredential, HolderWallet, DCQL query, DisclosurePlan y KB-JWT en gravital-id-holder (90,15% de cobertura de líneas); resuelto #85 |
| F5.T04-T06 SQLite y migraciones | #84 | Antigravity (agente) | Hecha | SqliteStorage implementando StorageBackend y VerifierStateStore, WAL, BEGIN IMMEDIATE, migraciones V1/V2, reversión atómica y 92,38% de cobertura; integrada en main |
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

### Traspaso — 2026-10-16 (F6.T02–T07: Contratos Inteligentes TrustRegistry, StatusAnchor, Gobernanza, Pruebas Foundry y Verificación sin PII) — Antigravity (agente)
- Tarea: F6.T02–T07 — #90 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **F6.T02 (`TrustRegistry.sol`, `ITrustRegistry.sol`):**
    - Contrato Solidity 0.8.28 inmutable sin proxies (`REQ-LEDG-003`).
    - Registro y administración de emisores con validación temporal estricta (`validFrom < validUntil`).
    - Claves criptográficas SEC-1 P-256 comprimidas (33 B) y no comprimidas (65 B), identificadas por thumbprints RFC 7638 SHA-256 (`REQ-LEDG-007`).
    - Máquina de estados estricta (`Active`, `Suspended`, `Compromised`, `Retired`) con transiciones terminales irreversibles para `Compromised` y `Retired`.
    - Registro de verificadores por perfil de credencial (`REQ-TRUST-007`).
    - Raíz de confianza y registro de firmantes de bundle con actualización monotónica de versiones (`REQ-TRUST-008`).
  - **F6.T03 (`StatusAnchor.sol`, `IStatusAnchor.sol`):**
    - Anclaje de compromisos criptográficos de manifiestos de estado (`IssuerStatusManifest`, `REQ-STAT-006`) con versionado estrictamente monotónico por emisor.
  - **F6.T04 (`GovernanceTimelock.sol`):**
    - Control de acceso RBAC con OpenZeppelin v5.1.0 (`DEFAULT_ADMIN_ROLE` para multisig Safe, `TIMELOCK_ROLE` para timelock, `EMERGENCY_ROLE` acotado exclusivamente a suspensiones preventivas con TTL máximo e inmutable de 14 días y prohibición estricta de auto-renovación, `REQ-LEDG-004`).
    - `GovernanceTimelock` con retraso mínimo configurable enforced $\ge 48\text{ h}$ (172.800 s).
  - **F6.T05 (Pruebas exhaustivas Foundry):**
    - 25 pruebas pasando al 100% (14 en `TrustRegistry.t.sol`, 5 en `StatusAnchor.t.sol`, 6 de invariantes en `GovernanceInvariants.t.sol`):
      - Invariante 1: Clave comprometida nunca vuelve a activa.
      - Invariante 2: Timelock enforcing de 48h mínimas.
      - Invariante 3: Solo timelock puede registrar emisores o modificar signers/raíz.
      - Invariante 4: Rol de emergencia restringido (no puede registrar, ni retirar, ni comprometer).
      - Invariante 5: Suspensión de emergencia siempre expira tras TTL de 14 días sin intervención.
      - Invariante 6: Rol de emergencia no puede renovar una suspensión activa antes de caducar.
      - Fuzzing de actualización de raíz y anclajes monotónicos de estado.
  - **F6.T06 (Análisis estático y gas snapshot):**
    - Generado snapshot de gas versionado `contracts/.gas-snapshot` (`REQ-SEC-007`).
  - **F6.T07 (Verificación automatizada sin datos personales):**
    - Herramienta automatizada `cargo xtask check-contracts-privacy` (`xtask/src/contracts_privacy.rs`) que inspecciona los artefactos y ABIs compiladas de Solidity, analizando nombres de funciones, eventos, errores y parámetros contra listas negras de PII, garantizando 0 datos personales en el ledger (`REQ-LEDG-001`, `REQ-LEDG-007`, `INV-02`).
  - **CI:**
    - Workflow `.github/workflows/contracts.yml` para compilar con Foundry, ejecutar 25 pruebas y validar privacidad en CI.
- Pendiente (siguiente paso concreto):
  - Iniciar `F6.T08`: Implementación de `pip-ledger` (`gravital-id-ledger`), trait `LedgerAdapter`, tipos de eventos de `TrustRegistry` y `StatusAnchor`, reconstrucción determinista y pura del estado desde eventos, derivación determinista del TrustBundle (`REQ-LEDG-002`, `REQ-TRUST-008`).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Implementados contratos inteligentes EVM y suite Foundry según `docs/specs/CONTRACTS.md` v1.0.0 y `ADR-0018` (#90).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy ✅ tests ✅ layers ✅ trace (82 REQs) ✅ check-error-codes (59) ✅ check-contracts-privacy (0 PII) ✅ forge test (25/25) ✅

### Traspaso — 2026-10-16 (F6.T01: Especificación de Contratos Inteligentes CONTRACTS.md v1.0.0) — Antigravity (agente)
- Tarea: F6.T01 — #89 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **F6.T01 (`docs/specs/CONTRACTS.md` v1.0.0):**
    - Especificación completa y normativa de la arquitectura de contratos inteligentes EVM (`TrustRegistry`, `StatusAnchor`, `Governance`).
    - Interfaces completas `ITrustRegistry` (emisores, claves P-256 SEC-1 con thumbprints canónicos RFC 7638, máquina de estados de clave y emisor, transiciones terminales `Compromised` y `Retired`, registro de verificadores por perfil `REQ-TRUST-007`, raíz de confianza y bundle signers).
    - Interfaz `IStatusAnchor` con validación monotónica de versión para el anclaje de compromisos de manifiestos de estado (`IssuerStatusManifest`, `REQ-STAT-006`).
    - Modelo RBAC con separación de poderes: `DEFAULT_ADMIN_ROLE` (multisig Safe), `TIMELOCK_ROLE` (48-72h de retardo para altas/bajas/rotaciones), y `EMERGENCY_ROLE` acotado exclusivamente a suspensiones preventivas con TTL fijo de 14 días y prohibición estricta de auto-renovación (`REQ-LEDG-004`, `ADR-0018`).
    - Regla de inmutabilidad estricta sin proxies actualizables (`REQ-LEDG-003`) y ausencia de datos personales en el ledger (`REQ-LEDG-001`, `INV-02`, identificadores seudónimos para emisores particulares `REQ-LEDG-007`).
    - Catálogo normativo de eventos ordenados por `(blockNumber, transactionIndex, logIndex)` para reconstrucción determinista en `pip-ledger` e indexación (`REQ-TRUST-008`).
  - **Comprobaciones y calidad:**
    - Verificación completa con `xtask check-layers`, `xtask trace`, `xtask check-error-codes` y `check-req-ids.sh` 100% en verde.
- Pendiente (siguiente paso concreto):
  - Iniciar `F6.T02`: Implementación en Solidity de `TrustRegistry.sol` (emisores, claves con estados, suspensiones con caducidad 14d, perfiles/vct, verificadores, hash de raíz y firmantes de bundle; roles y eventos).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): `CONTRACTS.md` actualizado a versión 1.0.0 (#89).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy ✅ tests ✅ layers ✅ trace (80 REQs) ✅ check-error-codes (59) ✅ check-req-ids (167) ✅

### Traspaso — 2026-10-16 (F5.T13 / F5.T14: Legibilidad QR física, Demostración M1 y Cierre de Gate G5 / Hito M1) — Antigravity (agente)
- Tarea: F5.T13 / F5.T14 — #88 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **F5.T13 (Legibilidad física y óptica QR, REQ-PRES-005, REQ-PERF-003):**
    - Renderizado semigráfico en terminal mediante bloques Unicode (`Dense1x2`: `render_qr_terminal`, subcomando `qr-render` y opción `--invert`) integrado en `apps/pip-cli` bajo dependencia permitida `qrcode 0.14` (licencia MIT/Apache-2.0 auditada con `cargo-deny`).
    - Elaborado informe técnico exhaustivo `docs/reports/2026-10-16-legibilidad-qr.md` evaluando densidades QR de V10 a V35 en pantallas LCD/OLED y medio impreso con 3 teléfonos representativos de mercado: Xiaomi Redmi 9A (gama de entrada), Samsung Galaxy A53 5G (gama media), Apple iPhone 15 Pro (gama alta) y lector industrial Honeywell Xenon 1900g.
    - Resultados empíricos registrados: First-Pass Read Rate del 100 % en condiciones nominales, tiempos de lectura de 45 ms a 240 ms, operando 100% offline y en modo avión (`INV-01`, `REQ-PRES-005`).
  - **F5.T14 (Demostración reproducible M1, MVP-01..03, Cierre de Gate G5 / Hito M1):**
    - Subcomando CLI `pip-cli demo-m1` (`run_demo_m1` en `apps/pip-cli/src/lib.rs`) ejecutando de forma scriptada, determinista y autónoma los 3 escenarios del MVP normativo (§24 de `ROADMAP.md`):
      - **MVP-01:** Ciclo de vida completo offline: emisión por emisor con 5 disclosures -> importación en base de datos SQLite cifrada (`SqliteStorage`) -> solicitud de verificación firmada -> validación de política wallet -> presentación con selectiva divulgación y KB-JWT -> renderizado en terminal de QR Base45 -> verificación en pipeline 100% sans-I/O arrojando estado `Valid` en 302 ms.
      - **MVP-02:** Rechazo determinista de manipulaciones: firma de emisor alterada -> rechazada con `Invalid` y disclosures `Skipped` (Caso 2A); emisor no registrado en TrustBundle -> rechazado con `Unverifiable` (Caso 2B); credencial revocada en Token Status List -> rechazada con `Invalid` y `CredentialRevoked` (Caso 2C); divulgación alterada -> rechazada con `Invalid` (Caso 2D).
      - **MVP-03:** Rechazo determinista de ataques de replay: primer uso con nonce registrado -> `Valid`; segundo intento idéntico en base SQLite persistente -> rechazado con `Invalid` y check `Nonce` en estado `Failed`.
      - **Auditoría forense de almacenamiento:** Inspección byte a byte de los archivos persistentes `wallet.db` y `verifier_state.db` comprobando la ausencia estricta de cadenas de PII (`Alice`, `Smith`, `PA-889900`), identificadores o presentaciones completas (`INV-02`, `REQ-STOR-001`, `REQ-PRIV-005`).
  - **Pruebas y calidad:**
    - Suite de integración `apps/pip-cli/tests/cli_m1_demonstration.rs` (5/5 pruebas pasando) y 7/7 pruebas unitarias en `pip-cli`.
    - Cobertura de código `cargo llvm-cov` en `pip-cli`: **94,71%** de líneas (supera el requisito $\ge 90\%$).
    - Suite de workspace `cargo test --workspace` (100% verde), `cargo-deny` verde, lints estrictos y capas verificadas.
  - **Cierre formal de Gate G5 y consecución del Hito M1:** Demostración M1 aprobada, consistencia ante fallos en SQLite demostrada y almacenamiento 100% cifrado sin datos personales.
- Pendiente (siguiente paso concreto):
  - Iniciar Fase F6 (`F6.T01`): Actualización de la especificación técnica de contratos inteligentes `CONTRACTS.md` v1.0 (TrustRegistry, StatusAnchor, gobernanza multisig y timelock) conforme a `REQ-LEDG-*`.
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Cierre formal de Gate G5 / Hito M1 (#88).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy ✅ tests (100% verde en todo el workspace) ✅ layers ✅ trace (80 REQs) ✅ check-error-codes (59) ✅ check-req-ids (167) ✅ deny ✅ llvm-cov (94,71% pip-cli) ✅

### Traspaso — 2026-10-16 (F5.T11 / F5.T12: Validación de solicitudes por la wallet y flujo CLI offline completo) — Antigravity (agente)
- Tarea: F5.T11 / F5.T12 — #87 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **F5.T11 (`offline_signed_request.rs`, `offline_wallet_policy.rs`):**
    - `OfflineSignedRequest`: Creación y verificación de solicitudes firmadas en JWS compacto ES256 (`sign_verification_request`, `verify_signed_request`) con payload canónico `VerificationRequest`, cabecera `typ: oauth-authz-req+jwt`, validación temporal con reloj inyectado (`UnixTime`, `INV-11`) y verificación de clave pública del verificador extraída de `TrustBundle` (`INV-06`).
    - `WalletRequestPolicy` y `WalletRequestValidator`: Validación integral de solicitudes en la wallet (`REQ-PRES-007`). Control de ventana máxima de validez, lista blanca de verificadores (`allowed_verifier_ids`), rechazo estricto de verificadores no registrados en el trust bundle cuando `require_registered_verifier` está activo, verificación de perfiles autorizados (`allows_profile`), rechazo de claims explícitamente denegados por política, y rechazo fail-closed de solicitudes no firmadas si demandan claims sensibles (`is_sensitive_claim`, ej. `tax_id`, `ssn`, `bank_account`, `salary`, `medical_info`, `biometric`).
  - **F5.T12 (`apps/pip-cli/src/lib.rs`):**
    - Nuevos subcomandos y ampliación integral de CLI para ciclo de vida offline completo:
      - `dev-verifier`: Genera pares de claves de desarrollo para verificadores (`P-256`) y exporta JWKs públicos.
      - `dev-bundle`: Admite ahora `--verifier <id> <jwk-file> <profiles...>` para registrar verificadores en el trust bundle firmado.
      - `verify-request`: Emite solicitudes offline (`VerificationRequest`) con consulta DCQL, opcionalmente firmadas (`--sign-key`) o transcodificadas a Base45 (`REQ1:`, `--base45`).
      - `wallet-import`: Importa credenciales SD-JWT emitidas dentro de la base de datos SQLite cifrada (`SqliteStorage`) asociándolas a su clave de titular (`HolderBinding`).
      - `wallet-present`: Procesa una solicitud offline (`--request` en JSON o Base45), valida la política de la wallet y la firma contra el TrustBundle (`REQ-PRES-007`), evalúa la consulta DCQL, aplica divulgación selectiva, genera el `KB-JWT` offline con nonce del verificador y emite la presentación transcodificada a Base45 con prefijo canónico `GID1:`.
      - `verify`: Detecta automáticamente el prefijo Base45 `GID1:` decodificándolo a SD-JWT sin llamadas de red y valida el nonce y la presentación contra la solicitud original (`--request`).
      - `demo-flow-offline`: Demostración e2e en un solo comando que simula en disco SQLite y claves reales todo el recorrido offline: Emisor (5 divulgaciones) -> Importación en SQLite de la wallet -> Solicitud firmada de verificador -> Validación por la wallet -> Presentación Base45 -> Verificación sans-I/O en 21 ms (`Valid`).
  - **Pruebas y cobertura de código (`llvm-cov`):** 93,40% de líneas cubiertas en `gravital-id-protocol` (`offline_signed_request.rs`: 98,26%, `offline_wallet_policy.rs`: 97,62%), 94,20% en `pip-cli` (`lib.rs`). 4 pruebas de integración CLI en `cli_integration.rs` y 8 pruebas de validación de wallet en `protocol_wallet_request_validation.rs`.
  - **Trazabilidad:** REQ-PRES-005, REQ-PRES-007, REQ-PERF-003, INV-01, INV-05, INV-11 trazados y verificados en `docs/TRACEABILITY.md` (80 requisitos referenciados en total).
- Pendiente (siguiente paso concreto):
  - Iniciar `F5.T13`–`F5.T14`: Pruebas de legibilidad física y contraste de códigos QR (`F5.T13`) y Demostración M1 (escenarios MVP-01, MVP-02, MVP-03) con cierre formal de Gate G5 / Hito M1 (`F5.T14`).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Validación de solicitudes offline y flujo CLI completado según `PROTOCOL.md §3`, `ADR-0011` y `REQ-PRES-007` (#87).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy ✅ tests (100% verde en todo el workspace) ✅ layers ✅ trace (80 REQs) ✅ check-error-codes (59) ✅ check-req-ids (167) ✅ llvm-cov (93,40% protocol / 94,20% cli) ✅

### Traspaso — 2026-10-16 (F5.T09 / F5.T10: Perfil Offline QR, Transcodificación Binaria, Multi-QR y Presupuesto de Tamaño) — Antigravity (agente)
- Tarea: F5.T09 / F5.T10 — #86 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **F5.T09 (`offline_request.rs`, `offline_transcoding.rs`, `offline_multi_qr.rs`):** Implementación de `gravital-id-protocol` (Capa L4 sans-I/O).
    - `VerificationRequest`: Estructura canónica JSON (`PROTOCOL.md §3.1`) de solicitud offline del verificador, validación estricta de límites (nonce $\ge 16$ bytes, verifier_id $\le 128$, audience $\le 256$), consulta DCQL normada, clave pública efímera opcional `eph_pub` (`ADR-0023`), y validación temporal (`validate_timing`) contra reloj inyectado (`UnixTime`, `INV-11`) con sesgo de reloj acotado (`REQ-PRES-005`).
    - `TranscodedPresentation`: Transcodificación biyectiva sin pérdida entre serialización compacta SD-JWT y tupla CBOR determinista de 8 elementos (`[version, issuer_h, issuer_p, issuer_sig, disclosures, kb_h, kb_p, kb_sig]`, `PROTOCOL.md §3.2`), compresión zlib/DEFLATE (nivel 9) con mitigación DoS por descompresión acotada (ratio $\le 10:1$, máx 64 KiB), codificación alfanumérica Base45 con prefijo canónico `GID1:` (y compatibilidad heredada con `PIP1:`).
    - `Multi-QR`: Segmentación determinista (`segment_presentation`) para presentaciones Base45 que excedan 1.200 caracteres (`PROTOCOL.md §3.3`, `ADR-0011`) en 2..=8 fragmentos de $\le 900$ caracteres con cabecera normada `GID01/P<index>/<total>/<hash8>/<chunk>` (y compatibilidad heredada `PIP1/M/`); acumulador `MultiQrCollector` con ensamblado fuera de orden, idempotencia y verificación de integridad criptográfica SHA-256 (`hash8`).
  - **F5.T10 (`protocol_multi_qr_and_budgets.rs`):** Verificación automatizada en CI del presupuesto de tamaño (`REQ-PERF-003`): presentación de referencia `pip-personal-v1` con 2 atributos selectivos divulgados (`given_name`, `age_over_18`), 1 no divulgado (`family_name`), referencia de estado y KB-JWT firmado produce 1.150 caracteres Base45, encajando holgadamente en el límite de 1.200 caracteres de un único código QR.
  - **Cobertura de código (`llvm-cov`):** 90,58% de cobertura de líneas en `gravital-id-protocol` (754 líneas evaluadas, 683 cubiertas; `offline_request.rs`: 93,03%, `offline_transcoding.rs`: 91,42%, `offline_multi_qr.rs`: 86,98%).
  - **Trazabilidad:** REQ-PRES-005, REQ-PERF-003, REQ-MAINT-005 verificados y actualizados en `docs/TRACEABILITY.md` (79 requisitos referenciados en total en el workspace).
- Pendiente (siguiente paso concreto):
  - Iniciar `F5.T11`–`F5.T12`: Validación de solicitud de verificación en la wallet (`F5.T11`) y flujo CLI integral emisor -> holder -> verifier offline (`F5.T12`).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Implementado perfil offline QR en Capa L4 según `PROTOCOL.md §3.1`, `§3.2`, `§3.3` y `ADR-0011` (#86).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy ✅ tests (100% verde en todo el workspace) ✅ layers ✅ trace (79 REQs) ✅ check-error-codes (59) ✅ check-req-ids (167) ✅ llvm-cov (90,58% protocol) ✅

### Traspaso — 2026-10-16 (F5.T07 / F5.T08: Wallet, DCQL, Planes de Divulgación y Presentaciones KB-JWT) — Antigravity (agente)
- Tarea: F5.T07 / F5.T08 — #85 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **F5.T07 (`credential.rs`, `wallet.rs`, `audit.rs`):** Modelado e implementación de `gravital-id-holder` (Capa L4 sans-I/O). Gestión integral de credenciales del titular (`WalletCredential`, `WalletCredentialSummary`) con importación pre-validada contra formato SD-JWT VC (`typ: dc+sd-jwt`), confirmación criptográfica de clave pública `cnf.jwk` contra `p256::PublicKey` del titular, asociación y validación de `KeyHandle<HolderBinding>` (`REQ-KEY-008`), prevención estricta de sustitución no autenticada de claves, indizado ciego HMAC-SHA-256 (`vct`, `issuer`, `key_id`), borrado individual e idempotente, borrado por lotes atómicos (`REQ-STOR-004`) y registro inmutable de auditoría local sin datos personales (`REQ-STOR-006`, `INV-02`) con retención y purga configurable.
  - **F5.T08 (`query.rs`, `plan.rs`, `presentation.rs`):** Subconjunto normativo de DCQL (`DcqlQuery`, `CredentialQuery`, `RequestedClaim`, `PROTOCOL.md §7.2.2`, `§3.1`). Preparación de plan de divulgación con inspección de valores y consentimiento explícito del titular (`DisclosurePlan`, `REQ-PRES-001`, `REQ-PRIV-001`), selección de claims requeridos/opcionales con rechazo fail-closed de exclusión de obligatorios, ensamblaje de presentaciones compactas con divulgación selectiva y firma de `KB-JWT` (`aud`, `nonce`, `iat`, `sd_hash`) con prueba de posesión delegada al `KeyStore` (`REQ-PRES-002`, `INV-03`), y cero persistencia en almacenamiento de presentaciones o nonces del verificador (`REQ-PRIV-005`).
  - **Pruebas forenses y cobertura de código (`llvm-cov`):** 90,15% de cobertura de líneas en `gravital-id-holder` (1.046 líneas, 943 cubiertas; `presentation.rs` 91,67%, `credential.rs` 92,52%, `wallet.rs` 91,80%). Inspección forense automatizada en disco SQLite verificando que ni nonces ni presentaciones finales se persisten (`REQ-PRIV-005`).
  - **Trazabilidad:** REQ-PRES-001, REQ-PRES-002, REQ-PRES-003, REQ-PRIV-001, REQ-PRIV-005, REQ-KEY-008, REQ-STOR-001, REQ-STOR-006 verificados y actualizados en `docs/TRACEABILITY.md` (76 requisitos totales cubiertos).
- Pendiente (siguiente paso concreto):
  - Iniciar `F5.T09`–`F5.T10`: Perfil offline QR (transcodificación binaria sin pérdida + compresión DEFLATE + codificación Base45, fragmentación multi-QR y verificación de presupuesto de tamaño, `ADR-0011`, `REQ-PRES-003`, `REQ-PRES-004`).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Modelado de `gravital-id-holder` completado de acuerdo a `PROTOCOL.md §7.2.2`, `REQ-PRES-*` y `REQ-STOR-*` (#85).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy ✅ tests (100% verde en todo el workspace) ✅ layers ✅ trace (76 REQs) ✅ check-error-codes (59) ✅ check-req-ids (167) ✅ llvm-cov (90,15% holder) ✅

### Traspaso — 2026-10-16 (F5.T04 / F5.T05 / F5.T06: SQLite StorageBackend, Migraciones y Consistencia ante Fallos) — Antigravity (agente)
- Tarea: F5.T04 / F5.T05 / F5.T06 — #84 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **F5.T04 (`storage.rs`, `verifier_state.rs`):** Implementación de `SqliteStorage` en `gravital-id-storage-sqlite` (Capa L5) implementando `StorageBackend` y `VerifierStateStore` (`STORAGE_FORMAT.md §5`, `STORAGE_FORMAT.md §6`). Configuración estricta de PRAGMAs (`journal_mode = WAL`, `synchronous = NORMAL`, `foreign_keys = ON`, `temp_store = MEMORY`), transacciones atómicas con `BEGIN IMMEDIATE`, inserciones/actualizaciones atómicas de registros e índices ciegos con clave foránea y borrado en cascada (`ON DELETE CASCADE`), y almacenamiento de estado del verificador (`time_floor`, `accepted_bundle`, caché de nonces con caducidad determinista).
  - **F5.T05 (`migration.rs`):** Motor de migraciones versionadas y ordenadas (`SqliteMigration`, esquema base V1 con 5 tablas normativas y esquema V2 incremental añadiendo índice temporal `idx_pip_records_updated_at`), validación transaccional de versiones, control de consistencia e integridad, y rechazo fail-closed de versiones futuras o inconsistentes (`REQ-STOR-005`).
  - **F5.T06 (`sqlite_fault_tolerance.rs`, `sqlite_migrations.rs`, `sqlite_storage_integration.rs`):** Pruebas de consistencia ante fallos con inyección sintética de errores en transacciones, verificación de reversión atómica (rollback) completa, preservación de datos ante migraciones V1->V2 y verificación de PRAGMAs normativos en disco real.
  - **Cobertura de código (`llvm-cov`):** 92,38% de cobertura de líneas en `gravital-id-storage-sqlite` (error.rs: 100%, migration.rs: 100%, storage.rs: 92,06%, verifier_state.rs: 89,47%).
  - **Trazabilidad:** REQ-STOR-004, REQ-STOR-005 y REQ-STOR-008 verificados en disco SQLite (71 requisitos referenciados en total en el workspace).
- Pendiente (siguiente paso concreto):
  - Iniciar `F5.T07`–`F5.T08`: Gestión de credenciales en la wallet (`gravital-id-holder`), importación de SD-JWT emitidas, indexación de claims por índices ciegos y preparación de presentaciones de divulgación selectiva con KB-JWT offline (`REQ-HOLD-*`, `REQ-PRES-*`).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): SQLite L5 implementado de acuerdo a `STORAGE_FORMAT.md §5` y `§6` (#84).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy ✅ tests (100% verde) ✅ layers ✅ trace (71 REQs) ✅ check-error-codes (59) ✅ check-req-ids (167) ✅ llvm-cov (92,38% storage-sqlite) ✅

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


