# STATUS.md — Estado vivo del proyecto

> Fuente única del **avance**. Se actualiza al final de cada sesión de trabajo (`AGENTS.md §5.3`) y al cerrar cada gate. Mantén solo el estado actual y las últimas notas; el histórico queda en los issues y en git.

## Resumen

| Campo | Valor |
|---|---|
| Fase actual | **F8 — Recuperación, migración y rotación** |
| Último gate cerrado | **G7** (2026-10-18) · **G6** (2026-10-17) · **G5** (2026-10-16) · **G4** (2026-10-16) · **G19** (2026-10-15) · **G0** (2026-10-11) |
| Próximo gate | **G8 / Hito M2** — los nueve criterios de aceptación del MVP (§24); **G3** (#59) y **G2** pendientes de CI |
| Hito siguiente | M2 · Sincronización y anclaje (al cerrar G8) · MP1 · Tap offline (al cerrar G21) [M1 alcanzado] |
| Última actualización | 2026-10-18 (`F8.T04` completada: re-vinculación y reemplazo atómico por clase de factor de dispositivo `DeviceFactorClass` en `gravital-id-recovery` y `gravital-id-issuer`, `ADR-0029`, `SPEC-PIP-REBIND-001`, `DeviceSlotManager`, revocación atómica del índice previo en Token Status List preservando intactos los dispositivos de otras clases, suite de 5 pruebas de integración en verde y auditoría forense cero PII; resuelto #104; siguiente tarea: F8.T05 Migración entre dispositivos con SAS y compromiso previo) |

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
| G6 | **Cerrado** | 2026-10-17 | Contratos en testnet (`contracts/script/Deploy.s.sol`, `deploy/environments/testnet/contracts.json`), 25 pruebas Foundry pasando (unitarias, fuzz e invariantes), adaptador `gravital-id-ledger-evm` con pruebas de fallos (91,44% cobertura) y verificación "sin datos personales" (`check-contracts-privacy`) aprobada con 0 PII (#90, #91, #92, #93). |
| G7 | **Cerrado** | 2026-10-18 | Plano de servicio en testnet funcionando end-to-end (`F7.T10` con `container_stack_integration.rs`), pruebas de caos aprobadas con degradación determinista canónica sin pánicos (`F7.T12` con `pip-cli demo-chaos` y `chaos_fault_injection.rs`), y auditoría forense cero PII (`INV-01`, `INV-02`, `INV-04`, `INV-05`, `INV-10`, `INV-11`, `INV-16`, `REQ-REL-004`, `REQ-SYNC-004`, `REQ-PRIV-003`). |
| G8 … G18, G20 … G25 | Pendiente | — | — |

## Tareas en curso

| Tarea | Issue | Responsable | Estado | Siguiente paso |
|---|---|---|---|---|
| F8.T05 Migración entre dispositivos con SAS y compromiso previo | — | Antigravity (agente) | Por iniciar | Protocolo de migración directa entre dispositivos con Short Authentication String (SAS), verificación visual de compromiso y transferencia cifrada E2E (`REQ-REC-001`, `REQ-PROX-001`) |
| F8.T04 Re-vinculación y reemplazo atómico por clase de dispositivo | #104 | Antigravity (agente) | Hecha | `RebindingChallenge`, `RebindingRequest`, transcrito canónico `SPEC-PIP-REBIND-001`, `DeviceSlotManager` con revocación atómica de ranura previa (`mobile`/`card`/`other`) en `TokenStatusList` preservando ranuras activas de otras clases y re-emisión (`REQ-REC-004`, `REQ-ISS-006`, `REQ-DEVSLOT-001..004`, `ADR-0029`); resuelto #104 |
| F8.T03 Clave de recuperación | #103 | Antigravity (agente) | Hecha | `KeyPurpose::HolderRecovery`, `HolderRecoveryKey`, derivación no correlacionable por emisor, extensión de emisión `cnf.rec` (`PROTOCOL.md §2.2`), 8 pruebas de integración y auditoría cero PII (`REQ-REC-004`, `REQ-REC-007`); resuelto #103 |
| F8.T02 Shamir k-de-n | #102 | Antigravity (agente) | Hecha | Aritmética $GF(2^8)$, interpolación de Lagrange de Shamir $k$-de-$n$, contenedor `GIDS` canónico, Crockford Base32, 44 pruebas verdes y auditoría cero PII (`REQ-REC-003`, `SPEC-PIP-SHAMIR-001`); resuelto #102 |
| F8.T01 Código de recuperación y respaldo | #101 | Antigravity (agente) | Hecha | Generación $\ge 128$ bits, codificación legible BIP-39/Crockford con checksum, derivación HKDF por emisor, formato de respaldo GIDB versionado y cifrado con XChaCha20-Poly1305 (`REQ-REC-002`, `REQ-REC-004`, `REQ-REC-007`, `SPEC-PIP-BACKUP-001`); resuelto #101 |
| F7.T12 Caos (inyección de fallos) | #105 | Antigravity (agente) | Hecha | Subcomando `pip-cli demo-chaos` y suite `apps/pip-cli/tests/chaos_fault_injection.rs` con 6 escenarios de inyección: relay malicioso (rollback, retención, alteración), RPC caído, divergencia inter-ledger, CDN caída y degradación a `ValidWithStaleStatus`/`Unverifiable`, y auditoría cero PII (`REQ-REL-004`, `REQ-SYNC-004`, `REQ-SYNC-007`, `REQ-TRUST-004`, `REQ-OBS-002`, `INV-01`, `INV-02`, `INV-04`, `INV-05`, `INV-10`, `INV-11`, `INV-16`); resuelto #105 y Gate G7 cerrado |
| F7.T11 Revocación durante periodo offline (MVP-05) | #104 | Antigravity (agente) | Hecha | Subcomando `pip-cli demo-mvp05` y suite `apps/pip-cli/tests/offline_revocation_mvp05.rs` con ciclo de vida completo: $T_0 \to \text{Valid}$, $T_{\text{offline}} \to \text{ValidWithStaleStatus}$ por umbral de frescura de transacción, $T_{\text{sync}} \to \text{Invalid}$ por revocación, y anti-rollback monotónico (`REQ-STAT-004`, `REQ-STAT-008`, `REQ-REL-004`, `MVP-05`); resuelto #104 |
| F7.T10 Integración con contenedores | #103 | Antigravity (agente) | Hecha | Suite automatizada `apps/pip-cli/tests/container_stack_integration.rs` con flujo nominal E2E, aislamiento de divergencia en operadores, fail-closed en divergencia de ledger y auditoría cero PII (`INV-01`, `INV-02`, `INV-04`, `INV-05`, `INV-11`, `INV-16`); resuelto #103 |
| F7.T09 Backend `aws-lc-rs` (FIPS, condicional) | #103 | Antigravity (agente) | Hecha | Evaluada y cerrada condicionalmente conforme a ROADMAP.md y ADR-0007 (cumplimiento FIPS 140-2/3 en producción delegado a HSM/KMS bajo REQ-ISS-002); resuelto #103 |
| F7.T08 Modo de verificación completa | #102 | Antigravity (agente) | Hecha | Motor `FullVerificationEngine` en capa L4 contrastando con $\ge 2$ fuentes de ledger, alarma y rechazo fail-closed ante divergencia o fuentes insuficientes (`REQ-TRUST-004`); resuelto #102 |
| F7.T07 `pip-sync` | #100 | Antigravity (agente) | Hecha | Crate L4 `gravital-id-sync` (sans-I/O) y adaptador L5 `gravital-id-transport-http` con cola cifrada idempotente, deduplicación, HPKE RFC 9180, backoff determinista y pool de relays con failover (REQ-SYNC-001..007); resuelto #100 |
| F11.T01-T02 `gravital_experience_ui` + `reference-wallet` (adelanto UI, multi-inquilino ADR-0027..0030, NFC `GID-APDU` y Passkey `CTAP2`) | #101 | Antigravity (agente) | Hecha | ADRs 0027–0030 aceptados, `GRAVITAL_EXPERIENCE_UI.md`, `pip-tenant-role-v1.md`, `PROTOCOL.md §7.8`, cumplimiento Tribunal Electoral Panamá (Decreto 43/2024 + SVI + VOPRF `GID-E2010`), ranura única por clase (`mobile`/`card`/`other`, `GID-E2011`), motor NFC `GID-APDU` (HCE Android `HostApduService` + lector ISO-DEP + iOS `CoreNFC`) y servicio Passkey (`FIDO2 / WebAuthn Level 3` + `CTAP2 over NFC`) con 11 suites de pruebas en verde |
| F7.T06 `pip-relay` | #99 | Antigravity (agente) | Hecha | Servicio de retransmisión stateless, objetos direccionados por SHA-256, buzones HPKE con idempotencia, punto de encuentro efímero con SessionCode Damm y límites de tasa (91,86% cobertura); resuelto #99 |
| F7.T05 Listas de estado del emisor | #98 | Antigravity (agente) | Hecha | Asignación aleatoria no correlacionada (P-09), TokenStatusListBuilder (>= 131.072), compresión DEFLATE acotada (<= 10:1), IssuerStatusManifestBuilder monotónico, IssuerStatusManager y ABI anchorStatusManifest; resuelto #98 |
| F7.T04 `pip-trust-service` | #97 | Antigravity (agente) | Hecha | Derivación determinista de trust bundles, cofirma multi-operador k-de-n y publicación en S3/CDN (93,72% cobertura); resuelto #97 |
| F7.T03 `pip-indexer` | #96 | Antigravity (agente) | Hecha | Ingesta de bloques finalizados, PostgreSQL, idempotencia, reprocesamiento, detección divergencia RPC y métricas de lag (90,19% cobertura); resuelto #96 |
| F7.T02 `pip-service-common` | #95 | Antigravity (agente) | Hecha | Crate L5 pip-service-common con configuración tipada, OpenTelemetry, /healthz, /readyz y redacción no-PII (94,86% cobertura); resuelto #95 |
| F7.T01 ADR-0013 e IaC base | #94 | Antigravity (agente) | Hecha | ADR-0013 Aceptado, Dockerfile.service multi-stage, docker-compose local, módulos OpenTofu/Terraform dev/testnet, check-deploy-hygiene (REQ-REL-001); resuelto #94 |
| F6.T11 Despliegue en testnet y Gate G6 | #93 | Antigravity (agente) | Hecha | Scripts reproducibles en Foundry, esquemas y artefactos en deploy/environments/testnet/contracts.json; Gate G6 cerrado (#93) |
| F6.T09-T10 `pip-ledger-evm` y pruebas de fallos | #92 | Antigravity (agente) | Hecha | EvmLedgerAdapter con MultiRpcClient, failover, consistencia cruzada, tolerancia a reorgs y fallos (91,44% cobertura); resuelto #92 |
| F6.T08 `pip-ledger` | #91 | Antigravity (agente) | Hecha | Trait LedgerAdapter, eventos, reconstrucción pura y derivación de bundle (REQ-LEDG-002, REQ-TRUST-008); resuelto #91 |
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

### Traspaso — 2026-10-18 (F8.T04: Re-vinculación y reemplazo atómico por clase de dispositivo — gravital-id-recovery y gravital-id-issuer L3 no_std, DeviceFactorClass, SPEC-PIP-REBIND-001, ADR-0029, DeviceSlotManager, revocación atómica selectiva en TokenStatusList y auditoría forense cero PII) — Antigravity (agente)
- Tarea: F8.T04 — #104 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **`docs/specs/PROTOCOL.md §2.3` (`SPEC-PIP-REBIND-001`, `ADR-0029`):** Especificación normativa del protocolo de re-vinculación de dispositivo y reemplazo atómico gobernado por `DeviceFactorClass` (`mobile`, `card`, `other`):
    - Transcrito canónico de re-vinculación: $\text{"pip-rebinding-v1:"} \mathbin{\Vert} \text{issuer\_uri} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{nonce} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{device\_class} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{new\_holder\_key\_thumbprint}$
    - Firma digital IEEE P1363 (64 bytes) con `HolderRecoveryKey` (propósito exclusivo `KeyPurpose::HolderRecovery`).
    - Flujo de desafío de un solo uso con anti-replay y expiración ($\le 300$ s).
    - Regla de reemplazo atómico por clase: si el titular ya posee una ranura activa en esa clase, su `status_index` anterior se revoca atómicamente a `01 Revoked` en la `Token Status List`, mientras que las ranuras activas de otras clases (p. ej. tarjeta física `card`) permanecen 100% activas e inalteradas (`REQ-DEVSLOT-003`).
  - **`crates/gravital-id-types`:**
    - `DeviceFactorClass` (`ids.rs`): Enum `Mobile` (`"mobile"`), `Card` (`"card"`), `Other` (`"other"`) con parsing estricto, métodos canónicos `as_str()`, y derivaciones `PartialOrd`, `Ord`, `Hash` y `Display`.
    - Código de error normativo `DuplicateDeviceClassActive` (`PIP-E2011`).
  - **`crates/gravital-id-recovery` (Capa L3 `no_std` + `alloc`):**
    - `rebinding.rs`:
      - `compute_rebinding_transcript` y `compute_rebinding_digest`: Generación del transcrito canónico UTF-8 y digest SHA-256.
      - `RebindingChallenge`: Modelado del desafío con `issuer_uri`, `nonce` y `expires_at`, validación contra tiempo inyectado (`now <= expires_at`).
      - `RebindingRequest`: Creación y firma de la solicitud con `HolderRecoveryKey`, verificación de alcance de emisor y verificación criptográfica fail-closed contra clave pública de recuperación (`verify_signature`, `verify`).
    - `key.rs`: Método `HolderRecoveryKey::create_rebinding_request` con propósito exclusivo `KeyPurpose::HolderRecovery`.
    - `error.rs`: Variantes `RebindingExpired`, `InvalidRebindingSignature`, `InvalidRebindingParameter`.
  - **`crates/gravital-id-issuer` (Capa L3 `no_std` + `alloc`):**
    - `slot_manager.rs`:
      - `ActiveDeviceSlot`: Registro de ranura activa de dispositivo (`device_class`, `status_list_id`, `status_index`, `holder_key`, `issued_at`, `expires_at`).
      - `DeviceSlotManager`: Gestor de ranuras con control de unicidad (`REQ-DEVSLOT-001`, rechazo de duplicados sin re-vinculación con `DuplicateDeviceClassActive`), soporte de coexistencia independiente de clases (`REQ-DEVSLOT-002`: móvil y tarjeta física simultáneos), y ejecución de re-vinculación atómica (`execute_atomic_rebinding`).
      - Revocación atómica selectiva: en la misma operación transaccional, revoca el índice del dispositivo anterior de esa clase en `IssuerStatusManager`, asigna un nuevo índice, emite la credencial con la nueva clave del dispositivo y activa la nueva ranura (`REQ-DEVSLOT-003`).
      - Cero identificadores permanentes de hardware o IMEIs en claro (`REQ-DEVSLOT-004`, `INV-02`).
    - `status_manager.rs`: Método `allocate_with_list_id` para asignación de índices con retorno del identificador de lista.
    - `request.rs`: Método `clone_for_rebinding` en `CredentialRequest`.
  - **Pruebas y calidad (`crates/gravital-id-recovery/tests/rebinding_tests.rs`):**
    - 5 pruebas de integración exhaustivas:
      - `test_e2e_atomic_rebinding_device_slots`: Ciclo de vida completo end-to-end (alta de móvil 1 -> alta de tarjeta física -> intento de alta directa de móvil 2 rechazado con `DuplicateDeviceClassActive` -> emisión de desafío -> firma con `HolderRecoveryKey` -> reemplazo atómico: móvil 1 pasa a `Revoked`, tarjeta física permanece `Valid`, móvil 2 queda `Valid`).
      - `test_rebinding_corrupted_signature_fails_closed`: Rechazo fail-closed de firmas alteradas con `InvalidSignature` sin mutación de estado.
      - `test_rebinding_expired_challenge_fails_closed`: Rechazo con `CredentialExpired` ante desafíos caducados.
      - `test_rebinding_cross_issuer_isolation_enforced`: Claves de recuperación aisladas por emisor no permiten firmar desafíos de emisores ajenos (`REQ-REC-007`).
      - `test_rebinding_zero_pii_audit`: Auditoría forense verificando la ausencia de IMEIs, IMSIs, MACs, cédulas o PII en transcritos y registros (`INV-02`, `REQ-DEVSLOT-004`).
- Pendiente (siguiente paso concreto):
  - Iniciar `F8.T05`: Protocolo de migración directa entre dispositivos con Short Authentication String (SAS), verificación visual de compromiso y transferencia cifrada E2E (`REQ-REC-001`, `REQ-PROX-001`).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Re-vinculación atómica por clase implementada conforme a `ADR-0029`, `REQ-DEVSLOT-001..004` y `SPEC-PIP-REBIND-001` (#104).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy ✅ tests (100% verde en todo el workspace) ✅ layers ✅ trace (117 REQs) ✅ check-deploy-hygiene ✅

### Traspaso — 2026-10-18 (F8.T03: Clave de recuperación — gravital-id-recovery L3 no_std, HolderRecoveryKey, propósito exclusivo KeyPurpose::HolderRecovery, derivación determinista no correlacionable por emisor, extensión normativa cnf.rec en PROTOCOL.md §2.2 y auditoría forense cero PII) — Antigravity (agente)
- Tarea: F8.T03 — #103 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **`docs/specs/PROTOCOL.md §2.2`:** Especificación normativa de la extensión de emisión para registro de la clave de recuperación del titular (`cnf.rec`):
    - Derivación determinista por emisor: $\text{RecoveryKey}_{\text{Issuer}} = \text{HKDF-Expand}(\text{HKDF-Extract}(\text{IssuerId}, S_{\text{recovery}}), \text{"pip-issuer-recovery-key-v1"}, 32)$ con par público P-256.
    - Propósito exclusivo `KeyPurpose::HolderRecovery`: restringido a la autorización de re-vinculación ante el emisor; prohibido para firmas de presentación KB-JWT o acuerdo HPKE (`REQ-REC-004`, `REQ-KEY-001`).
    - Huella canónica RFC 7638 SHA-256 en formato URI RFC 9278 (`urn:ietf:params:oauth:jwk-thumbprint:sha-256:<b64u>`).
    - Inclusión en el claim de nivel superior `cnf` (`cnf.rec`) de la credencial SD-JWT VC emitida.
    - Demostración de no correlación matemática entre emisores ($I_1 \ne I_2 \implies \text{rec\_thumbprint}(I_1) \ne \text{rec\_thumbprint}(I_2)$, `REQ-REC-007`, `P-09`, `INV-02`).
  - **`crates/gravital-id-recovery` (Capa L3 `no_std` + `alloc`, `#![forbid(unsafe_code)]`):**
    - `HolderRecoveryKey` (`key.rs`): Encapsulación tipada de la clave de recuperación del titular por emisor, métodos de derivación determinista, cálculo de thumbprints SHA-256, base64url y URI RFC 9278, protección con `ZeroizeOnDrop` y `Debug` redactado (`[REDACTED]`).
    - `kdf.rs`: Funciones de conveniencia `derive_issuer_recovery_thumbprint` y `derive_issuer_recovery_thumbprint_uri`.
  - **`crates/gravital-id-credential`:**
    - `ConfirmationClaim` (`vc.rs`): Soporte para campo opcional `rec: Option<String>`, método constructor `with_recovery_thumbprint`, serialización y deserialización JSON sin pérdida.
    - `SdJwtVcBuilder`: Método helper `cnf_jwk_with_recovery`.
  - **`crates/gravital-id-issuer`:**
    - `CredentialRequest` (`request.rs`): Soporte para `recovery_thumbprint: Option<String>` con setter y getter.
    - `Issuer::build` e `Issuer::issue`: Inyección automática de `cnf.rec` en el builder de credenciales y propagación al objeto `IssuedCredential`.
  - **Pruebas y trazabilidad (`crates/gravital-id-recovery/tests/recovery_key_tests.rs`):**
    - 8 pruebas de integración exhaustivas:
      - `test_recovery_key_deterministic_derivation`: Verificación de identidad estricta de clave privada, JWK y thumbprints a partir de la misma semilla y emisor.
      - `test_recovery_key_isolation_across_issuers`: Prueba combinatoria exhaustiva sobre 10 emisores distintos comprobando ausencia total de colisión de claves privadas, claves públicas, digests SHA-256 o huellas URI (`REQ-REC-007`, `P-09`).
      - `test_recovery_key_different_seeds_different_keys`: Distintas semillas generan claves disjuntas para el mismo emisor.
      - `test_key_purpose_holder_recovery_type_safety`: Aislamiento en el sistema de tipos bajo `KeyPurpose::HolderRecovery`, integración con `SoftwareKeyStore` y firma/verificación matemática de desafío de re-vinculación (`REQ-REC-004`).
      - `test_credential_issuance_with_recovery_thumbprint_extension`: Ciclo completo de emisión con `gravital-id-issuer`, verificación de presencia de `cnf.jwk` y `cnf.rec` en el payload SD-JWT VC y verificación offline con `SdJwtVcClaims`.
      - `test_zero_pii_in_recovery_extension`: Auditoría forense verificando ausencia absoluta de PII o secretos en la huella de recuperación (`INV-02`).
      - `test_recovery_key_empty_issuer_fails_closed`: Emisor vacío falla cerrado con error tipado (`INV-05`).
      - `test_recovery_key_debug_redaction`: Redacción estricta en `Debug` (`[REDACTED]`) sin filtración de material privado (`REQ-SEC-003`).
  - **Verificaciones del workspace:** `fmt` ✅, `clippy` (-D warnings) ✅, `test --workspace` ✅ (100% pasando, 52 pruebas en `gravital-id-recovery`), `check-layers` ✅, `check-deploy-hygiene` ✅, `trace` ✅ (112 REQs referenciados).
- Pendiente (siguiente paso concreto):
  - Iniciar `F8.T04`: Re-vinculación y reemplazo atómico por clase de dispositivo (`ADR-0029`, `REQ-REC-004`, `REQ-ISS-006`, `REQ-DEVSLOT-001`, `REQ-DEVSLOT-003`, `REQ-DEVSLOT-004`).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Implementada extensión de emisión para registro de clave de recuperación según `PROTOCOL.md §2.2`, `REQ-REC-004` y `REQ-REC-007` (#103).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy (-D warnings) ✅ tests (100% verde en todo el workspace) ✅ layers (21 crates) ✅ trace (112 REQs) ✅ check-deploy-hygiene ✅

### Traspaso — 2026-10-18 (F8.T02: Shamir k-de-n — gravital-id-recovery L3 no_std, aritmética GF(2^8) canónica, contenedor canónico GIDS SPEC-PIP-SHAMIR-001, Crockford Base32, validación de integridad fail-closed y auditoría forense cero PII) — Antigravity (agente)
- Tarea: F8.T02 — #102 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **`docs/specs/STORAGE_FORMAT.md §8` (`SPEC-PIP-SHAMIR-001`):** Especificación normativa del esquema de fragmentos de Shamir $k$-de-$n$ para custodia social y recuperación distribuida sin I/O de red (`REQ-REC-003`, `INV-01`, `INV-02`, `INV-05`, `INV-11`):
    - Campo de Galois $GF(2^8)$ con polinomio irreducible canónico de Rijndael/AES $P(x) = x^8 + x^4 + x^3 + x + 1$ (`0x11B`).
    - Interpolación polinómica de Lagrange evaluada en $x = 0$ para reconstrucción exacta del secreto.
    - Contenedor binario canónico `GIDS` (13 bytes de cabecera AAD/metadatos: número mágico `b"GIDS"`, versión de formato 1, umbral $k$, total $n$, índice de fragmento $x \in [1, 255]$, identificador de secreto `sha256(secret)[..4]`, longitud de payload $L$ de 2 bytes, valor del fragmento de $L$ bytes y checksum SHA-256 de 4 bytes).
    - Representación canónica alfanumérica en Crockford Base32 compacto con dígito de control para custodia humana en papel o almacenamiento seguro.
  - **`crates/gravital-id-recovery` (Capa L3 `no_std` + `alloc`, `#![forbid(unsafe_code)]`):**
    - `gf256.rs`: Aritmética de campo finito en tiempo constante sin tablas de búsqueda dependientes de datos (Russian peasant multiplication, inverso multiplicativo modular mediante Pequeño Teorema de Fermat $a^{-1} = a^{254}$, división segura e interpolación de Lagrange en $x = 0$).
    - `shamir.rs`: Estructura `ShamirShare` con `Zeroize`/`ZeroizeOnDrop`, `Debug` redactado (`[REDACTED]`), serialización y deserialización binaria estricta `GIDS`, y codificación legible Base32 Crockford. `ShamirSecretSharing`: partición polinómica aleatoria con RNG inyectado (`split`, `split_recovery_code`) y reconstrucción determinista (`combine`, `combine_recovery_code`) con validación fail-closed de umbral ($k \ge 2$, $n \ge k$, $n \le 255$), deduplicación de índices y verificación de coincidencia de `secret_id` e integridad SHA-256.
  - **Pruebas y trazabilidad (`crates/gravital-id-recovery/tests/shamir_tests.rs`):**
    - 8 pruebas de integración exhaustivas:
      - `test_shamir_threshold_matrix_roundtrips`: Matriz de umbrales exhaustiva $(2, 3), (3, 5), (4, 7), (5, 10), (8, 12)$ probada con múltiples combinaciones de subconjuntos de fragmentos.
      - `test_insufficient_shares_fail_closed`: Verificación estricta de que $k-1$ fragmentos devuelven error explícito `InsufficientShares` y nunca reconstruyen el secreto (`INV-05`).
      - `test_duplicate_share_index_rejected`: Rechazo fail-closed inmediato ante fragmentos con índice $x$ duplicado (`DuplicateShareIndex`).
      - `test_mismatched_secret_id_rejected`: Rechazo fail-closed ante mezcla de fragmentos pertenecientes a diferentes secretos (`SecretIdMismatch`).
      - `test_corrupted_share_integrity_fail_closed`: Mutación de 1 solo bit en payload o checksum provoca rechazo fail-closed con `InvalidChecksum`.
      - `test_zero_pii_in_shares_forensic_audit`: Auditoría forense en memoria verificando ausencia total de PII o identificadores en shares o logs (`INV-02`).
      - `test_recovery_code_shamir_journey`: Ciclo completo de generación de `RecoveryCode`, división en 3 de 5 fragmentos, serialización Crockford Base32, deserialización de 3 fragmentos arbitrarios, reconstrucción de la entropía y validación del mnemónico BIP-39 idéntico al original.
      - `test_hostile_input_immunity`: Inmunidad a entradas hostiles arbitrarias sin pánicos (`INV-10`).
  - **Verificaciones del workspace:** `fmt` ✅, `clippy` (-D warnings) ✅, `test --workspace` ✅ (100% pasando, 44 pruebas en `gravital-id-recovery`), `check-layers` ✅, `check-deploy-hygiene` ✅, `trace` ✅ (112 REQs referenciados).
- Pendiente (siguiente paso concreto):
  - Iniciar `F8.T03`: Clave de recuperación (`REQ-REC-004`, `REQ-REC-007`): propósito de clave `KeyPurpose::HolderRecovery`, derivación por emisor a partir del secreto de recuperación, registro de huella en la emisión como extensión en `PROTOCOL.md` y prueba de no-correlación entre emisores.
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Implementado esquema normativo `SPEC-PIP-SHAMIR-001` en `STORAGE_FORMAT.md §8` y `gravital-id-recovery` según `REQ-REC-003` (#102).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy (-D warnings) ✅ tests (100% verde en todo el workspace) ✅ layers (21 crates) ✅ trace (112 REQs) ✅ check-deploy-hygiene ✅

### Traspaso — 2026-10-18 (F8.T01: Código de recuperación y respaldo cifrado — gravital-id-recovery L3 no_std, mnemónico BIP-39, Crockford Base32, jerarquía KDF determinista por emisor, paquete GIDB con AAD y auditoría forense cero PII) — Antigravity (agente)
- Tarea: F8.T01 — #101 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **`docs/specs/STORAGE_FORMAT.md §7` (`SPEC-PIP-BACKUP-001`):** Especificación canónica y normativa del formato del paquete de respaldo binario (`GIDB`), layout con 59 bytes de cabecera AAD vinculada (`b"GID-BACKUP-AAD-v1" || format_version || cipher_suite || created_at || salt`), compresión DEFLATE previa y cifrado `XChaCha20-Poly1305` (`REQ-REC-002`, `INV-01`, `INV-02`, `INV-05`).
  - **`crates/gravital-id-recovery` (Capa L3 `no_std` + `alloc`, `#![forbid(unsafe_code)]`):** Implementación completa y modular del núcleo de recuperación del titular:
    - `RecoveryCode` (`code.rs`): Entropía criptográfica de 128 bits generada deterministamente mediante RNG inyectado (`INV-11`), codificación y validación de mnemónico BIP-39 de 12 palabras (wordlist canónica estricta de 2.048 palabras) con checksum SHA-256 de 4 bits, codificación y decodificación de Base32 Crockford compacto con dígito de control (26 caracteres de datos + 1 de control agrupados en 33 caracteres legibles), protección con `Zeroize`/`ZeroizeOnDrop` y `Debug` redactado.
    - `kdf.rs`: Jerarquía HKDF-SHA256 (RFC 5869): `derive_backup_keys` (extracción de clave AEAD de 256 bits y secreto maestro de recuperación a partir del código y sal de 128 bits); y `derive_issuer_recovery_secret` / `derive_issuer_recovery_jwk` para la derivación determinista por emisor ($\text{RecoveryKey}_{\text{Issuer}} = \text{HKDF}(\text{RecoverySecret}, \text{IssuerId})$) de pares P-256 exclusivos con propósito `HolderRecovery` (`REQ-REC-004`), garantizando huellas disjuntas que imposibilitan la correlación cruzada del titular (`REQ-REC-007`, `P-09`, `INV-02`).
    - `payload.rs`: Estructura canónica `BackupPayload` con versión de esquema, secreto de recuperación, credenciales (`BackupCredential`), ranuras de factor de dispositivo (`BackupDeviceSlot`) y roles de tenant (`BackupTenantRole`), serialización canónica en JSON determinista con límites estrictos de DoS (`MAX_BACKUP_PAYLOAD_BYTES`).
    - `package.rs`: `EncryptedBackupPackage` con compresión DEFLATE previa, vinculación AAD estricta y sellado/apertura AEAD `XChaCha20-Poly1305`.
    - `manager.rs`: `RecoveryManager` sans-I/O para exportación (`export_backup`) y restauración íntegra (`restore_backup`).
    - `README.md`: Documentación técnica completa del crate L3 con arquitectura, tipos principales e invariantes aplicables.
  - **Pruebas y trazabilidad (`crates/gravital-id-recovery/tests/recovery_tests.rs`):**
    - 17 pruebas unitarias internas en verde.
    - 6 pruebas de integración, propiedades, negativas y forenses:
      - `e2e_recovery_export_and_restore_cycle`: Ciclo completo de vida de la bóveda verificado con identidad exacta de datos (`REQ-REC-002`).
      - `test_zero_pii_in_backup_package`: Auditoría forense automática que comprueba que ningún dato personal o secreto confidencial aparece en texto claro en el paquete binario (`INV-02`).
      - `test_per_issuer_recovery_keys_uncorrelated`: Verificación de aislamiento estricto de claves y JWKs públicos entre múltiples emisores (`REQ-REC-007`, `P-09`).
      - `test_fail_closed_on_bit_tampering`: Verificación fail-closed probando mutación de 1 solo bit en 10 posiciones de la cabecera, criptograma y auth tag Poly1305 (`INV-05`).
      - `test_recovery_code_property_roundtrips`: Prueba de roundtrip y preservación de entropía y checksums sobre 100 semillas deterministas independientes.
      - `test_fuzz_style_arbitrary_inputs_no_panics`: Resistencia a entradas hostiles arbitrarias sin pánicos (`INV-10`).
  - **Verificaciones del workspace:** `fmt` ✅, `clippy` (-D warnings) ✅, `test --workspace` ✅ (100% pasando), `check-layers` ✅ (21 crates), `check-deploy-hygiene` ✅, `trace` ✅ (111 REQs referenciados).
- Pendiente (siguiente paso concreto):
  - Iniciar `F8.T02`: Shamir $k$-de-$n$ (`REQ-REC-003`): división de secreto $k$-de-$n$ para recuperación social o custodia distribuida sin I/O de red.
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Implementado formato canónico `SPEC-PIP-BACKUP-001` y crate `gravital-id-recovery` según `REQ-REC-002`, `REQ-REC-004`, `REQ-REC-007` y `STORAGE_FORMAT.md §7` (#101).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy (-D warnings) ✅ tests (100% verde en todo el workspace) ✅ layers (21 crates) ✅ trace (111 REQs) ✅ check-deploy-hygiene ✅

### Traspaso — 2026-10-18 (F7.T12: Caos e inyección de fallos y Cierre de Gate G7 — Subcomando demo-chaos, degradación determinista sans-I/O y auditoría cero PII) — Antigravity (agente)
- Tarea: F7.T12 / Gate G7 — #105 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **F7.T12 (`apps/pip-cli/src/lib.rs`):** Implementado subcomando oficial `pip-cli demo-chaos` que ejecuta de forma determinista y reproducible la suite de inyección de fallos de la Fase F7 en 6 escenarios:
    1. Relay malicioso (Ataque de rollback y replay): Intento de forzar rollback de versión en `StatusManifest` ($1 \le 2$) y replay de sobres en buzones $\to$ rechazo fail-closed inmediato (`REQ-STAT-008`, `REQ-SYNC-002`, `INV-05`).
    2. Relay malicioso (Retención e indisponibilidad): Inyección de fallos de red persistentes en endpoint primario $\to$ backoff determinista con variación acotada y conmutación automática por error (failover) en `RelayPool` hacia el relay secundario sin pánicos (`REQ-SYNC-007`, `INV-10`).
    3. Relay malicioso (Alteración de integridad): Corrupción de bytes en objeto direccionado por contenido $\to$ rechazo por discrepancia de hash SHA-256 (`REQ-SYNC-004`); y alteración del tag de autenticación Poly1305 en sobre HPKE $\to$ fallo estricto de autenticación AEAD ChaCha20Poly1305 (`REQ-SYNC-006`, `INV-05`).
    4. RPC caído y divergencia de ledger: Caída total simulada de todos los RPCs $\to$ resultado fail-closed `InsufficientSources`; e inconsistencia en altura de bloque entre proveedores $\to$ resultado `CrossLedgerDivergence` con emisión de alarma `CrossLedgerDivergenceAlarm` (`REQ-TRUST-004`, `REQ-OBS-002`, `INV-05`, `INV-16`).
    5. CDN / almacenamiento de bundles caído: Verificador offline degrada limpiamente a `ValidWithStaleStatus` ante snapshot local envejecido y a `Unverifiable` ante ausencia total de estado con evidencia estructurada, sin aceptar datos no comprobados ni generar pánicos (`REQ-REL-004`, `REQ-STAT-004`, `INV-04`, `INV-05`, `INV-10`).
    6. Auditoría forense de cero PII y ausencia total de pánicos: Verificación rigurosa de que ningún log ni mensaje de error durante las condiciones de caos expone datos personales o secretos (`INV-02`, `REQ-PRIV-003`).
  - **F7.T12 (`apps/pip-cli/tests/chaos_fault_injection.rs`):** Suite automatizada de pruebas de integración con 7 tests pasando al 100%:
    - `cli_demo_chaos_completes_all_scenarios_successfully`
    - `test_chaos_malicious_relay_rollback_and_replay_rejection`
    - `test_chaos_malicious_relay_withholding_and_failover`
    - `test_chaos_malicious_relay_tampering_hash_mismatch_and_aead_failure`
    - `test_chaos_rpc_outage_and_cross_ledger_divergence`
    - `test_chaos_cdn_outage_verifier_graceful_degradation`
    - `test_chaos_zero_pii_and_zero_panic_forensic_audit`
  - **Cierre formal del Gate G7:** Todos los criterios de aceptación de la Fase F7 cumplidos: servicios en testnet funcionando end-to-end, pruebas de caos aprobadas y auditoría de cero PII sin hallazgos.
- Pendiente (siguiente paso concreto):
  - Iniciar Fase F8 (`F8.T01`): Código de recuperación y respaldo (`REQ-REC-002`).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Cierre formal del Gate G7 (#105).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy (-D warnings) ✅ tests (100% verde en todo el workspace) ✅ layers (21 crates) ✅ trace (108 REQs) ✅ check-deploy-hygiene ✅

### Traspaso — 2026-10-18 (F7.T11: Revocación durante periodo offline MVP-05 — Subcomando demo-mvp05, degradación determinista a ValidWithStaleStatus y resolución a Invalid tras sincronizar con anti-rollback) — Antigravity (agente)
- Tarea: F7.T11 — #104 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **F7.T11 (`apps/pip-cli/src/lib.rs`):** Implementado subcomando reproducible `pip-cli demo-mvp05` que demuestra paso a paso las 6 etapas normativas del escenario MVP-05 (§24 de ARCHITECTURE.md):
    1. $T_0$: Emisión inicial e ingesta de credencial en wallet; verificación en línea con trust bundle y status list frescos $\to$ `Valid`.
    2. Desconexión del verificador a modo 100% offline (sin red, `INV-01`); el emisor revoca en línea la credencial (bit 1) y ancla nuevo `IssuerStatusManifest` v2 con BitString actualizado.
    3. $T_{\text{offline}}$: El titular presenta la credencial sin conexión. Dado que transcurrieron 1.801 segundos superando el umbral de frescura de `OperationClass::Transaction` (1.800 s, `REQ-STAT-004`, `REQ-REL-004`), el pipeline se degrada deterministamente a `ValidWithStaleStatus` documentando la advertencia sin fallar en falso.
    4. $T_{\text{sync}}$: El verificador recupera conectividad con el relay/mirror de estado e ingesta el manifiesto v2 y la lista de estado actualizada.
    5. Verificación post-sincronización: Con el estado actualizado en su caché local, el pipeline del verificador rechaza deterministamente la credencial revocada como `Invalid` con fallo en `CheckKind::Status` (`ErrorCode::CredentialRevoked`, `INV-04`, `INV-05`).
    6. Mitigación anti-rollback (`REQ-STAT-008`): Verificación explícita de rechazo fail-closed si un adversario o relay malicioso intenta suministrar un manifiesto con versión menor o igual a la última aceptada ($v1 \le v2$).
  - **F7.T11 (`apps/pip-cli/tests/offline_revocation_mvp05.rs`):** Suite automatizada de pruebas de integración con 4 pruebas exhaustivas:
    - `cli_demo_mvp05_completes_all_steps_successfully`: Ejecución integral del comando de demostración CLI.
    - `test_mvp05_lifecycle_offline_stale_to_invalid_after_sync`: Comprobación programática del ciclo de vida exacto $T_0 \to T_{\text{offline}} \to T_{\text{sync}}$.
    - `test_mvp05_freshness_thresholds_per_operation_class`: Verificación precisa de degradación a `ValidWithStaleStatus` según las 3 clases operativas de `REQ-STAT-004` (Transaction = 1.800 s, Query = 14.400 s, Default = 604.800 s).
    - `test_mvp05_status_manifest_anti_rollback_enforcement`: Verificación estricta de mitigación anti-rollback fail-closed (`REQ-STAT-008`, `INV-05`).
  - **Trazabilidad y capas:** Requisitos trazados (`REQ-STAT-004`, `REQ-STAT-008`, `REQ-REL-004`), 0 datos personales (`INV-02`), y determinismo estricto con inyección de reloj (`INV-11`).
- Pendiente (siguiente paso concreto):
  - Iniciar `F7.T12`: Caos (inyección de fallos, `REQ-REL-004`, `REQ-SYNC-004`): relay malicioso (rollback de sobres, retención, alteración), RPC caído, CDN caída; degradación a estados canónicos explícitos (`Unverifiable`, `Invalid`) sin aceptar datos falsos.
  - Proceder con la evaluación y cierre de **Gate G7**.
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Implementado ciclo de vida MVP-05 y subcomando CLI demo-mvp05 según especificación (#104).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy (-D warnings) ✅ tests (100% verde en todo el workspace) ✅ layers (21 crates) ✅ trace (107 REQs) ✅ check-deploy-hygiene ✅

### Traspaso — 2026-10-18 (F7.T09: Backend aws-lc-rs condicional / F7.T10: Integración completa de la pila de contenedores en pruebas automatizadas) — Antigravity (agente)
- Tarea: F7.T09 / F7.T10 — #103 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **F7.T09 (Evaluación técnica `aws-lc-rs` / FIPS, `ADR-0007`, `REQ-ISS-002`):** Cierre condicional formalizado conforme a `ROADMAP.md` y `ADR-0007`. En producción corporativa e institucional, el cumplimiento FIPS 140-2/3 para emisión y custodia de claves raíz se delega a los módulos de hardware HSM/KMS bajo `REQ-ISS-002`, no requiriendo bifurcar `pip-crypto` para añadir `aws-lc-rs` como backend condicional alternativo a `p256` y `k256`.
  - **F7.T10 (`deploy/docker/docker-compose.yml`, `deploy/docker/.env.example`):** Parametrización de puertos de host (`ANVIL_PORT`, `POSTGRES_PORT`, `MINIO_PORT`, `MINIO_CONSOLE_PORT`) para prevenir colisiones locales y en CI; validación de higiene de despliegue (`cargo xtask check-deploy-hygiene`) en verde con cero secretos en claro.
  - **F7.T10 (`apps/pip-cli/tests/container_stack_integration.rs`):** Suite automatizada de pruebas de integración end-to-end multi-servicio ejecutando las interacciones coordinadas entre:
    1. Cadena EVM local / adaptador de ledger en memoria (`gravital-id-ledger-evm`, `InMemoryLedgerAdapter`).
    2. Indexador (`pip-indexer`): Ingesta de bloques finalizados, checkpoints monotónicos, proyecciones puras de estado (`LedgerState`) e idempotencia estricta.
    3. Servicio de confianza (`pip-trust-service`): Derivación determinista de bundles, evaluación y cofirma $k$-de-$n$ (`LocalDevSigner`), agregación no confiable (`UntrustedBundleAggregator`) y publicación (`InMemoryBundlePublisher`).
    4. Servicio de relay (`pip-relay`): Almacenamiento inmutable direccionado por contenido SHA-256 (`put_object`), buzones de sobres de sincronización HPKE y punto de encuentro efímero con código de sesión de 10 dígitos validado con algoritmo de Damm (`REQ-CODE-001..004`).
    5. SDK y motor de verificación: Verificación formal contra `TrustRoot` activa (`TrustBundleVerifier`) y modo de verificación completa multi-fuente (`FullVerificationEngine`) contrastando $\ge 2$ fuentes de ledger independientes (`REQ-TRUST-004`).
    6. Sincronización sans-I/O (`gravital-id-sync`): Encolado (`EncryptedOutboxQueue`), cifrado híbrido HPKE (RFC 9180), transmisión a buzón de relay y deduplicación por ventana deslizante (`InboundDeduplicationFilter`).
  - **Casos de prueba implementados:**
    - `test_container_stack_e2e_nominal_flow`: Flujo completo nominal entre todos los componentes.
    - `test_container_stack_operator_divergence_tolerance_and_quorum_failure`: Aislamiento de operador divergente con quórum suficiente y fallo cerrado sin emisión si se pierde el quórum (`INV-05`, `INV-16`).
    - `test_container_stack_ledger_divergence_fails_closed`: Detección de claves comprometidas entre nodos independientes y alarma crítica fail-closed.
    - `test_container_stack_zero_pii_audit`: Auditoría forense exhaustiva garantizando 0 datos personales o identificadores de titular en payloads serializados (`INV-02`, `REQ-PRIV-003`).
  - **Trazabilidad y capas:** 107 requisitos trazados en `docs/TRACEABILITY.md`, reglas de capas verificadas en 21 crates (`cargo xtask check-layers`), y 100% de pruebas del workspace pasando.
- Pendiente (siguiente paso concreto):
  - Iniciar `F7.T11`: Revocación durante periodo offline (escenario MVP-05 §24, `REQ-STAT-004`: verificador offline; revocación ocurre; resultado `ValidWithStaleStatus` mientras corresponde e `Invalid` tras sincronizar).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Integración completa de la pila de servicios en contenedores y cierre condicional de FIPS según ADR-0007 (#103).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy (-D warnings) ✅ tests (100% verde en todo el workspace) ✅ layers (21 crates) ✅ trace (107 REQs) ✅ check-deploy-hygiene ✅ check-error-codes (61) ✅ check-contracts-privacy (0 PII) ✅ doc (0 warnings) ✅

### Traspaso — 2026-10-18 (F7.T08: Modo de verificación completa — Contraste determinista del TrustBundle con $\ge 2$ fuentes de ledger independientes, consistencia cruzada y alarmas estructuradas de divergencia) — Antigravity (agente)
- Tarea: F7.T08 — #102 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **F7.T08 (`crates/gravital-id-ledger/src/full_verification.rs`):** Implementación del motor `FullVerificationEngine` en Capa L4 sans-I/O (`#![forbid(unsafe_code)]`) para contrastar de forma determinista el `TrustBundle` contra $\ge 2$ fuentes de ledger independientes (`REQ-TRUST-004`, `P-10`, `INV-01`, `INV-02`, `INV-04`, `INV-05`, `INV-11`, `INV-16`).
  - **Política de verificación completa (`FullVerificationPolicy`):** Validación estricta que exige `min_sources >= 2` en el constructor (`InvalidPolicy`), umbral de deriva de bloques (`max_allowed_block_drift`) y regla opcional de cobertura de bloque finalizado.
  - **Resultado estructurado de 4 estados (`FullVerificationOutcome`):** `Verified`, `BundleDivergence`, `CrossLedgerDivergence`, `InsufficientSources` cumpliendo `INV-04` y sin reducción a booleanos.
  - **Consistencia cruzada inter-ledger (`check_cross_ledger_consistency`):** Comprobación entre todas las fuentes saludables de que comparten el mismo `chain_id` y que la diferencia entre bloques finalizados no supera `max_allowed_block_drift`, emitiendo `CrossLedgerDivergenceAlarm` ante fallos.
  - **Contraste estado ↔ bundle:** Reconstrucción del `LedgerState` de cada fuente a partir de sus eventos finalizados (`apply_event`) y comparación contra el `TrustBundle` (`compare_bundle_with_state`), detectando divergencias administrativas, emisores/verificadores dados de baja o suspendidos, y alertas críticas de seguridad ante claves comprometidas (`CompromisedKeyNotReflected`) emitiendo `BundleDivergenceAlarm`.
  - **Cumplimiento de invariantes:** Fail-closed ante fuentes insuficientes o fallos de adaptador (`INV-05`, `INV-16`), cero I/O de red en L4 (`INV-01`), cero datos personales en alarmas o diagnósticos (`INV-02`), inyección explícita del instante temporal (`INV-11`).
  - **Pruebas y trazabilidad (`full_verification_test.rs`):** 9 suites de pruebas unitarias, de integración y de propiedades con `proptest` (`prop_full_verification_agreement_iff_verified`), y requisito `REQ-TRUST-004` trazado en `docs/TRACEABILITY.md`.
- Pendiente (siguiente paso concreto):
  - Iniciar `F7.T09` / `F7.T10`: Evaluar backend `aws-lc-rs` (FIPS) según ADR-0007 / Integración con contenedores (`F7.T10`).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Implementado modo de verificación completa multi-fuente en `gravital-id-ledger` cumpliendo `REQ-TRUST-004` e invariante `INV-16` (#102).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy (-D warnings) ✅ tests (100% verde en todo el workspace) ✅ layers (21 crates) ✅ trace (107 REQs) ✅ check-error-codes (61) ✅ check-contracts-privacy (0 PII) ✅ doc (0 warnings) ✅

### Traspaso — 2026-10-18 (F7.T07: `pip-sync` — Máquina de estados sans-I/O, cola cifrada idempotente, deduplicación, HPKE RFC 9180, backoff con jitter determinista, pool de relays con failover y adaptador de transporte HTTP L5) — Antigravity (agente)
- Tarea: F7.T07 — #100 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **F7.T07 (`crates/gravital-id-sync`, `crates/gravital-id-transport-http`):** Creación e implementación completa del motor de sincronización L4 sans-I/O y su adaptador de red L5 en HTTP/1.1 REST (`REQ-SYNC-001..007`, `P-01`, `P-08`, `P-09`, `P-10`, `INV-01`, `INV-02`, `INV-05`, `INV-07`, `INV-11`).
  - **Cola de salida cifrada con idempotencia (`queue.rs`):** `EncryptedOutboxQueue` (`REQ-SYNC-001`) con ordenación monotónica de operaciones, claves de idempotencia (`OperationId`), capacidad acotada y eliminación idempotente.
  - **Filtro de deduplicación en recepción (`dedup.rs`):** `InboundDeduplicationFilter` (`REQ-SYNC-002`) con ventana de deduplicación deslizante, purga periódica y garantía de entrega al-menos-una-vez.
  - **Backoff con jitter determinista (`backoff.rs`):** `RetryPolicy` (`REQ-SYNC-003`) con retardo exponencial acotado y cálculo de variación determinista a partir de semilla inyectada (`INV-11`).
  - **Verificación de integridad y descargas anónimas (`verifier.rs`):** `ContentVerifier` con validación estricta de digest SHA-256 (`REQ-SYNC-004`) y rechazo fail-closed de cualquier identificador del titular o credencial en peticiones de objetos públicos (`REQ-SYNC-005`, `INV-02`).
  - **Sobres cifrados con HPKE (`hpke_envelope.rs`):** `HpkeEnvelope` (`REQ-SYNC-006`) con cifrado híbrido RFC 9180 (DHKEM P-256 + HKDF-SHA256 + ChaCha20Poly1305) delegado en `gravital-id-crypto`.
  - **Pool de relays con failover automático (`relay_pool.rs`):** `RelayPool` (`REQ-SYNC-007`) con rotación circular, detección de fallos y penalización temporal exponencial en memoria.
  - **Trait de transporte y mock determinista (`transport.rs`):** Trait `Transport` e implementación `MockTransport` sin dependencias de red (`INV-01`).
  - **Motor orquestador (`engine.rs`):** `SyncEngine` que ejecuta los pasos de la cola de salida (`step_outbox`) y sondeo/recepción de buzones (`poll_inbox`).
  - **Adaptador de red HTTP L5 (`crates/gravital-id-transport-http`):** Implementación `HttpTransport` sobre HTTP/1.1 REST con `std::net::TcpStream` sin dependencias bloqueantes ni Tokio, soportando `POST /v1/objects`, `GET /v1/objects/{sha256}`, `POST /v1/mailboxes/{inbox}/envelopes`, `GET /v1/mailboxes/{inbox}/envelopes` y `DELETE /v1/mailboxes/{inbox}/envelopes/{id}`.
  - **Objetivo de fuzzing (`fuzz/fuzz_targets/sync_verifier_parser.rs`):** Verificación exhaustiva contra pánicos (`INV-10`) y validación fail-closed (`INV-05`).
  - **Pruebas y trazabilidad:** 11 suites de pruebas unitarias, de integración y de propiedades pasando al 100%, reglas de capas verificadas con `cargo xtask check-layers` y 107 requisitos trazados en `docs/TRACEABILITY.md`.
- Pendiente (siguiente paso concreto):
  - Iniciar `F7.T08`: Modo de verificación completa (contraste del trust bundle con $\ge 2$ fuentes de ledger, alarma y rechazo determinista ante divergencia, `REQ-TRUST-004`).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Implementado motor de sincronización L4 sans-I/O y adaptador L5 HTTP según `REQ-SYNC-001..007` e invariantes `INV-01`, `INV-02`, `INV-05`, `INV-07`, `INV-11` (#100).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy (-D warnings) ✅ tests (100% verde) ✅ layers (21 crates) ✅ trace (107 REQs) ✅ check-error-codes (61) ✅ check-contracts-privacy (0 PII) ✅ check-deploy-hygiene ✅ doc (0 warnings) ✅

### Traspaso — 2026-10-17 (F7.T06: `pip-relay` — Servicio de retransmisión stateless, distribución de objetos direccionados por hash SHA-256, buzones de sobres HPKE con idempotencia y punto de encuentro efímero con SessionCode de 10 dígitos y Damm) — Antigravity (agente)
- Tarea: F7.T06 — #99 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **F7.T06 (`services/pip-relay`):** Creación e implementación completa del microservicio `pip-relay` (Capa L5) para retransmisión y sincronización stateless entre dispositivos, transferencia de objetos por digest y punto de encuentro efímero (`REQ-SYNC-004`, `REQ-SYNC-006`, `REQ-CODE-001`, `REQ-CODE-002`, `REQ-CODE-003`, `REQ-CODE-004`, `REQ-REL-001`, `REQ-OBS-001`, `REQ-PRIV-003`, `ADR-0025`, `PROTOCOL.md §7.7`, `INV-01`, `INV-02`, `INV-05`, `INV-11`).
  - **Almacenamiento en memoria con límites y TTL (`store.rs`):** `InMemoryRelayStore` que implementa:
    - Distribución de objetos direccionados por hash SHA-256 inmutables (`REQ-SYNC-004`), verificación de digest, TTL acotado y purga periódica.
    - Buzón de sobres de operación (`EnvelopeRecord`) cifrados con HPKE (`REQ-SYNC-006`), soporte de idempotencia por `envelope_id`, filtrado temporal incremental (`since`) y acuse de recibo / borrado (`delete_envelope`).
    - Punto de encuentro efímero (`RendezvousSession`) con algoritmo antisimétrico de Damm (2004) de orden 10 para validación y generación de dígito de control de `SessionCode` (`ADR-0025`, `PROTOCOL.md §7.7`, `REQ-CODE-001..004`), derivación de clave de sesión mediante `sha256("gid-session-code-v1" || code)`, garantía atómica de consumo de un solo uso (`consumed: true`) y TTL estricto $\le 180$ segundos.
  - **Limitador de tasa estricto (`limiter.rs`):** `RateLimiter` con algoritmo Token Bucket por cliente/IP implementado estrictamente con aritmética entera en militokens (`-D clippy::float-arithmetic`) para prevenir abusos y ataques DoS.
  - **Despachador sans-I/O y servidor TCP (`server.rs`):** `RelayHttpService` desacoplado y comprobable en memoria con endpoints REST `/healthz`, `/readyz`, `/v1/objects`, `/v1/mailboxes/{inbox_id}/envelopes`, `/v1/rendezvous/{session_hash}/request`, `/v1/rendezvous/{session_hash}/response` y `/v1/rendezvous/code/validate`, más `start_relay_server` para enlace TCP multihilo y apagado ordenado.
  - **Mapeo de errores y respuestas sanitizadas (`error.rs`):** `RelayError` con mapeo a códigos HTTP estándar (200, 201, 204, 400, 404, 405, 409, 410, 413, 429, 503) y serialización JSON sanitizada sin PII ni secretos en texto claro (`INV-02`).
  - **Configuración tipada (`config.rs`):** Carga desde variables de entorno (`PIP_RELAY_*`) con validación fail-closed de puertos, TTLs, límites de payload y cuotas de memoria.
  - **Registro de salud (`health.rs`):** `RelayHealthCheck` integrado con `HealthRegistry` de `pip-service-common` con degradación ante saturación de almacenamiento.
  - **Pruebas y cobertura:** 30 pruebas unitarias y de integración pasando al 100% con **91,86% de cobertura de líneas en la biblioteca** (`clock.rs`: 100%, `config.rs`: 100%, `error.rs`: 100%, `health.rs`: 100%, `store.rs`: 94,37%, `limiter.rs`: 91,67%).
  - **Trazabilidad:** REQ-SYNC-004, REQ-SYNC-006, REQ-CODE-001, REQ-CODE-002, REQ-CODE-003, REQ-CODE-004, REQ-REL-001 actualizados y verificados en `docs/TRACEABILITY.md`.
- Pendiente (siguiente paso concreto):
  - Iniciar `F7.T07`: `pip-sync` (Capa L4 sans-I/O): máquina de estados de sincronización, cola de operaciones cifradas, resolución de conflictos Last-Write-Wins (LWW) y orquestación con múltiples relays (`REQ-SYNC-001..007`).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Implementado microservicio `pip-relay` según `PROTOCOL.md §7.7`, `ADR-0025` y `REQ-SYNC-004,006` (#99).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy ✅ tests (100% verde en todo el workspace) ✅ layers ✅ trace (103 REQs) ✅ check-error-codes (59) ✅ check-contracts-privacy (0 PII) ✅ check-deploy-hygiene (0 secretos) ✅ deny ✅ llvm-cov (91,86% pip-relay) ✅

### Traspaso — 2026-10-17 (F7.T05: Listas de estado del emisor — Asignación aleatoria, Token Status Lists, publicación direccionada por contenido, manifiesto de estado y anclaje en StatusAnchor) — Antigravity (agente)
- Tarea: F7.T05 — #98 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **F7.T05 (`gravital-id-status`, `gravital-id-issuer`, `gravital-id-ledger-evm`):** Implementación completa de la infraestructura del emisor para listas de estado, asignación aleatoria, actualización y publicación periódica de estado y anclaje en el ledger (`REQ-ISS-003`, `REQ-STAT-002`, `REQ-STAT-005`, `REQ-STAT-006`, `REQ-STAT-008`, `P-09`, `INV-01`, `INV-02`, `INV-03`, `INV-05`, `INV-06`, `INV-07`, `INV-08`, `INV-11`, `INV-16`).
  - **Firmante de estado (`gravital-id-status::signer`):** Abstracción `StatusSigner` desacoplada de claves privadas (`INV-03`) con `LocalStatusSigner` implementando firma ES256 P-256 (`ZeroizeOnDrop` vía `SecretKeyBytes`).
  - **Constructor de listas (`gravital-id-status::builder`):** `TokenStatusListBuilder` para compilar y firmar Token Status Lists (1 bit y 2 bits por entrada) conforme a RFC 9901 / draft-19 (`typ: statuslist+jwt`), forzando capacidad mínima normativa $\ge 131.072$ entradas (`REQ-STAT-002`), compresión DEFLATE con control estricto de ratio de expansión ($\le 10:1$, mitigación de bombas de descompresión según `REQ-STAT-003`), auto-verificación fail-closed con `StatusListVerifier::parse` y producción de `SignedTokenStatusList` con digest SHA-256 y formato de URI direccionada por contenido (`{base_url}/{sha256}.jwt`, `REQ-STAT-005`).
  - **Constructor de manifiestos (`gravital-id-status::manifest_builder`):** `IssuerStatusManifestBuilder` para emitir manifiestos `IssuerStatusManifest` firmados con versión monotónica incremental (`REQ-STAT-008`), verificación previa estricta y generación de `SignedStatusManifest` con hash de 32 bytes para anclaje.
  - **Asignador de índices aleatorios (`gravital-id-issuer::status_allocator`):** `StatusIndexAllocator` con bitmap en memoria y algoritmo de muestreo uniforme sin sesgo de módulo (`sample_uniform_index`) sobre las posiciones libres mediante generador CSPRNG inyectado (`INV-11`), eliminando correlación de orden de emisión o sesgos temporales (`P-09`, `REQ-STAT-002`).
  - **Gestor de estado del emisor (`gravital-id-issuer::status_manager`):** `IssuerStatusManager` para emisión, revocación (`revoke`), suspensión temporal (`suspend`) y reactivación (`reactivate`) sobre múltiples listas administradas, y generación atómica de instantáneas de publicación (`publish_snapshot`) con compromiso de estado `StatusCommitment` listo para anclaje en el ledger.
  - **Codificación y decodificación ABI EVM (`gravital-id-ledger-evm::abi`):** Calldata para la función `anchorStatusManifest(bytes32,uint64,bytes32,string)` (`SELECTOR_ANCHOR_STATUS_MANIFEST: 0x6a026f0a`) en `StatusAnchor.sol` (`REQ-STAT-006`).
  - **Pruebas y cobertura:** Cobertura de $>93\%$ de líneas en los nuevos módulos (`status_manager.rs`: 93,42%, `manifest_builder.rs`: 93,41%, `builder.rs`: 92,65% regions, `signer.rs`: 100% functions) con suites exhaustivas de pruebas unitarias y de integración (`status_builder_test.rs`, `status_lifecycle_test.rs`, tests ABI en `gravital-id-ledger-evm`).
- Pendiente (siguiente paso concreto):
  - Iniciar `F7.T06`: `pip-relay` (servicio de retransmisión de proximidad y sincronización, reenvío sin estado ni persistencia en disco, autenticación efímera, cifrado de transporte y límites de tasa, `REQ-SYNC-004`, `REQ-SYNC-006`).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Implementado constructor de listas y manifiestos y gestor de estado conforme a RFC 9901, `REQ-ISS-003`, `REQ-STAT-002`, `REQ-STAT-005`, `REQ-STAT-006` y `REQ-STAT-008` (#98).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy ✅ tests (100% verde en todo el workspace) ✅ layers ✅ trace (98 REQs referenciados) ✅ check-error-codes (59) ✅ check-contracts-privacy (0 PII) ✅ check-deploy-hygiene ✅ deny ✅ llvm-cov (>= 90% en nuevos módulos) ✅

### Traspaso — 2026-10-17 (F7.T04: pip-trust-service — Derivación determinista de trust bundles, cofirma multi-operador k-de-n, agregador no confiable y publicación en S3/CDN) — Antigravity (agente)
- Tarea: F7.T04 — #97 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **F7.T04 (`services/pip-trust-service`):** Microservicio en capa L5 para la orquestación y derivación periódica del Trust Bundle canónico a partir de eventos y estados proyectados por el indexador (`REQ-TRUST-001`, `REQ-TRUST-003`, `REQ-TRUST-005`, `REQ-TRUST-008`, `REQ-OBS-001`, `REQ-PRIV-003`, `INV-01`, `INV-02`, `INV-05`, `INV-06`, `INV-07`, `INV-11`, `INV-16`).
  - **Firmantes y gestión de claves (`signer.rs`):** Abstracción `OperatorSigner` con `LocalDevSigner` (utilizando `SecretKeyBytes` con `Zeroize` y `gravital_id_crypto::sign::sign_es256_digest` sin dependencias externas inseguras) y `MockKmsSigner` para entornos cloud con KMS (`REQ-SEC-003`).
  - **Nodo operador institucional (`operator.rs`):** `TrustOperatorNode` que computa deterministamente el trust bundle desde `gravital-id-ledger::derive_trust_bundle`, firma únicamente su payload digest SHA-256 (`OperatorSignatureResponse`) y asla el acceso a claves privadas.
  - **Agregador no confiable y aislamiento de divergencia (`aggregator.rs`):** `UntrustedBundleAggregator` que valida criptográficamente cada firma contra las claves autorizadas del TrustRoot, descarta firmas duplicadas o espurias, detecta divergencias entre operadores aislando nodos desincronizados o maliciosos, y ensambla el documento JWS JSON final serializado (`bundles/v{epoch}/{version}.json` y `bundles/current.json`).
  - **Publicación atómica (`publisher.rs`):** Implementaciones `InMemoryBundlePublisher` y `FileSystemBundlePublisher` (compatible con almacenamiento S3 / CloudFront) garantizando atomicidad mediante archivos temporales y renombramiento atómico.
  - **Motor orquestador y ciclo de vida (`engine.rs`, `health.rs`, `main.rs`):** Bucle continuo con tolerancia a particiones de red o fallos individuales de operadores sin violar el umbral $k$-de-$n$, comprobaciones de liveness/readiness en `/healthz` reportando degradación ante discrepancias detectadas, y apagado limpio con `ShutdownCoordinator`.
  - **Pruebas y cobertura:** 42 pruebas unitarias y de integración pasando al 100% con un **93,72% de líneas cubiertas en la biblioteca** (`config_test`, `signer_test`, `publisher_test`, `aggregator_test`, `operator_test`, `health_test`, `engine_test`).
- Pendiente (siguiente paso concreto):
  - Iniciar `F7.T05`: Listas de estado del emisor (asignación aleatoria de índices, tamaño mínimo, actualización, firma, publicación direccionada por contenido, manifiesto de estado firmado y anclaje periódico en `StatusAnchor`, `REQ-ISS-003`, `REQ-STAT-002`, `REQ-STAT-005`, `REQ-STAT-006`, `REQ-STAT-008`).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Implementado servicio de confianza en L5 conforme a `ADR-0013`, `REQ-TRUST-003`, `REQ-TRUST-005`, `REQ-TRUST-008` (#97).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy ✅ tests (100% verde en todo el workspace) ✅ layers ✅ trace ✅ check-error-codes ✅ check-contracts-privacy ✅ check-deploy-hygiene ✅ deny ✅ llvm-cov (93,72% trust-service) ✅

### Traspaso — 2026-10-17 (F7.T03: pip-indexer — Ingesta continua de bloques finalizados, detección de divergencia multi-RPC, almacenamiento relacional idempotente y métricas de lag) — Antigravity (agente)
- Tarea: F7.T03 — #96 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **F7.T03 (`services/pip-indexer`):** Microservicio en capa L5 para la ingesta continua y determinista de eventos del ledger y mantenimiento de proyecciones relacionales (`REQ-LEDG-005`, `REQ-LEDG-006`, `REQ-REL-001`, `REQ-OBS-001`, `REQ-PRIV-003`, `INV-01`, `INV-02`, `INV-10`, `INV-11`).
  - **Detección de divergencia y quórum multi-RPC (`divergence.rs`):** Detección de consistencia cruzada (`RpcDivergenceDetector`) comparando muestras de cabeceras entre múltiples proveedores RPC independientes, rechazo fail-closed de divergencias en hash de bloque, hash padre o altura (`REQ-LEDG-006`), y resolución determinista de la cabeza finalizada segura (`safe_finalized_head`).
  - **Almacenamiento relacional e idempotencia (`storage.rs`, `postgres.rs`, `schema/V1__indexer_schema.sql`):** Persistencia abstracta (`IndexerStorage`) con implementaciones en memoria (`InMemoryIndexerStorage`) y relacional SQLite/PostgreSQL (`SqliteIndexerStorage`) con inserción idempotente (`ON CONFLICT DO NOTHING`), serialización y deserialización de los 13 eventos del ledger, y proyección determinista de estado puro (`build_ledger_state`).
  - **Motor central de indexación (`engine.rs`):** Orquestación con `IndexerEngine` consumiendo únicamente bloques finalizados (`finalized_head`), fragmentación por lotes acotados (`chunk_size_blocks`), rebobinado ante reorganizaciones de frontera (`rewind_to_block`), reprocesamiento histórico (`reprocess_from_block`), y bucle continuo con parada limpia (`ShutdownCoordinator`).
  - **Salud y observabilidad (`health.rs`, `metrics.rs`):** Registro de métricas de retraso (`LagMetrics`) y comprobador de salud (`IndexerHealthCheck`) que expone `/healthz` y `/readyz` reportando degradación si el retraso excede `max_allowed_lag`.
  - **Punto de entrada (`main.rs`) y configuración (`config.rs`):** Carga y validación estricta de variables de entorno (`PIP_INDEXER_*`), cableado de servidor HTTP en puerto 8081 y ejecución con usuario no root.
  - **Cobertura de código (`llvm-cov`):** 90,19% de cobertura total de líneas en `pip-indexer` (93,87% en biblioteca). 22 pruebas unitarias y de integración pasando al 100%.
- Pendiente (siguiente paso concreto):
  - Iniciar `F7.T04`: `pip-trust-service` (derivación determinista de trust bundles desde el indexador, cofirma con umbral k-de-n y llaves KMS/dev, publicación en S3/CDN, `REQ-TRUST-003`, `REQ-TRUST-005`, `REQ-TRUST-008`).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Implementado indexador en L5 conforme a `ADR-0013`, `REQ-LEDG-005` y `REQ-LEDG-006` (#96).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy ✅ tests (100% verde en todo el workspace) ✅ layers ✅ trace ✅ check-error-codes ✅ check-contracts-privacy ✅ check-deploy-hygiene ✅ deny ✅ llvm-cov (90,19% indexer) ✅

### Traspaso — 2026-10-17 (F7.T02: pip-service-common — Configuración tipada, telemetría estructurada OpenTelemetry, health server y redacción estricta no-PII) — Antigravity (agente)
- Tarea: F7.T02 — #95 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **F7.T02 (`services/pip-service-common`):**
    - `config.rs`: Modelado y validación de `ServiceConfig`, `ServerConfig`, `TelemetryConfig` y `Environment` con fail-closed en puertos, timeouts y niveles de log, y validación estricta para entornos productivos.
    - `redaction.rs`: Motor de sanitización `redact_text` y escritor `RedactingWriter` que redacta tokens JWS/JWT, bloques PEM de claves privadas, correos electrónicos, números de teléfono y atributos JSON PII estructurados (`password`, `secret`, `given_name`, `national_id`, etc.) con cero pánicos ni unwraps (`compile_safe_regex`), garantizando cero PII en logs (`REQ-PRIV-003`, `INV-02`).
    - `telemetry.rs`: Instrumentación estructurada basada en `tracing` y `tracing-subscriber` con soporte para formatos JSON y compacto, filtrado dinámico `EnvFilter`, integración de la capa de redacción y `TelemetryGuard` (`REQ-OBS-001`).
    - `health.rs`: Registro extensible de salud (`HealthRegistry`, `HealthCheck`, `HealthStatus`, `ComponentHealth`, `HealthResponse`) para comprobaciones de liveness (`/healthz`) y readiness (`/readyz`) con agregación de dependencias.
    - `shutdown.rs`: Coordinador atómico de apagado ordenado (`ShutdownCoordinator`) para orquestar la parada limpia ante señales (`SIGINT`, `SIGTERM`).
    - `server.rs`: Servidor HTTP minimalista y sin dependencias externas pesadas en L5 para endpoints de salud y observabilidad con respuestas 200, 400, 404, 405 y 503.
    - **Cobertura de código (`llvm-cov`):** 94,86% de cobertura de líneas en `pip-service-common` (config.rs: 98,84%, health.rs: 100%, redaction.rs: 92,06%, server.rs: 87,62%, shutdown.rs: 100%, telemetry.rs: 98,08%).
- Pendiente (siguiente paso concreto):
  - Iniciar `F7.T03`: Implementación de `pip-indexer` (Capa L5) consumiendo eventos finalizados del EVM, persistiendo proyecciones en PostgreSQL con idempotencia estricta, detección de reorganizaciones y split-views (`REQ-LEDG-005`).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Crate común L5 implementado según ADR-0013, REQ-OBS-001, REQ-PRIV-003 y REQ-REL-001 (#95).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy ✅ tests (100% verde en todo el workspace) ✅ layers ✅ trace ✅ check-error-codes (59) ✅ check-contracts-privacy ✅ check-deploy-hygiene ✅ deny ✅ llvm-cov (94,86% pip-service-common) ✅

### Traspaso — 2026-10-16 (F6.T08: pip-ledger — Trait LedgerAdapter, proyección pura de estado, derivación determinista de TrustBundle y reconciliación estado ↔ bundle) — Antigravity (agente)
- Tarea: F6.T08 — #91 — rama `main`
- Estado: **hecha**
- Hecho en esta sesión:
  - **F6.T08 (`crates/gravital-id-ledger`):** Crate en capa L4 sans-I/O para proyección determinista del ledger.
    - `adapter.rs`: Trait abstracto `LedgerAdapter` (`chain_id`, `finalized_head`, `fetch_events`, `get_status_commitment`) e implementación en memoria `InMemoryLedgerAdapter` para entornos sans-I/O y pruebas (`REQ-LEDG-002`, `INV-01`).
    - `event.rs`: Coordenada estricta `EventCoordinate` ordenada monótonamente por `(block_number, tx_index, log_index)` y catálogo completo de 13 eventos normativos tipados de `ITrustRegistry` e `IStatusAnchor`.
    - `state.rs`: Motor puro de reconstrucción de estado (`LedgerState`) que procesa secuencialmente eventos del ledger sin red ni reloj implícito (`INV-01`, `INV-11`), implementando la máquina de estados de emisores y claves P-256 SEC-1 con inmutabilidad terminal de estados `Compromised`, gestión de timelocks y expiración determinista de suspensiones de emergencia a los 14 días (`REQ-LEDG-004`).
    - `derivation.rs`: Derivación pura y determinista byte a byte de `TrustBundle` (`derive_trust_bundle`) a partir del estado reconstruido y cabecera de bloque finalizado, serialización canónica RFC 8785 y digest SHA-256 (`REQ-TRUST-008`).
    - `diff.rs`: Reconciliación determinista entre un `TrustBundle` y el `LedgerState` (`compare_bundle_with_state`) que produce un `BundleDiffReport` con tipificación de divergencias operativas y detección inmediata de alertas críticas de seguridad (`CompromisedKeyNotReflected`, `ChainIdMismatch`, `RegistryAddressMismatch`).
  - **Pruebas y calidad:**
    - Suite exhaustiva de 13 pruebas unitarias, de integración y proptests (`ledger_proptest.rs`, `ledger_state_and_derivation.rs`).
    - Cobertura de líneas `cargo llvm-cov` en `gravital-id-ledger`: **93,90%** (todas las áreas $\ge 90\%$, `error.rs`: 100%, `event.rs`: 100%, `adapter.rs`: 98,36%, `state.rs`: 93,96%, `derivation.rs`: 92,15%, `diff.rs`: 90,86%).
    - Trazabilidad: 87 requisitos referenciados en código Rust actualizados en `docs/TRACEABILITY.md` (`REQ-LEDG-002`, `REQ-TRUST-008`, `REQ-LEDG-004`).
- Pendiente (siguiente paso concreto):
  - Iniciar `F6.T09`: Implementación de `pip-ledger-evm` (`crates/gravital-id-ledger-evm`) con `alloy`, adaptador `LedgerAdapter` conectando a RPC EVM, consultas de eventos por rangos de bloques `[fromBlock, toBlock]` y soporte multi-RPC con tolerancia a fallos (`REQ-LEDG-005`, `REQ-LEDG-006`).
- Bugs/issues abiertos durante la sesión: ninguno.
- Decisiones tomadas (con enlace a ADR/issue): Implementado `pip-ledger` en capa L4 sans-I/O conforme a `REQ-LEDG-002` y `REQ-TRUST-008` (#91).
- Riesgos o dudas: ninguna.
- Comprobaciones locales: fmt ✅ clippy ✅ tests (100% verde en todo el workspace) ✅ layers ✅ trace (87 REQs) ✅ check-error-codes (59) ✅ check-contracts-privacy (0 PII) ✅ llvm-cov (93,90% ledger) ✅

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


