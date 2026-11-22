# STATUS.md — Estado vivo del proyecto

> Fuente única del **avance**. Se actualiza al final de cada sesión de trabajo (`AGENTS.md §5.3`) y al cerrar cada gate. Mantén solo el estado actual y las últimas notas; el histórico queda en los issues y en git.

## Resumen

| Campo | Valor |
|---|---|
| Fase actual | **F9 — SDK público y bindings multiplataforma (en curso)** · F8 concluida |
| Último gate cerrado | **G8 / Hito M2** (2026-10-18) · **G7** (2026-10-18) · **G6** (2026-10-17) · **G5** (2026-10-16) · **G4** (2026-10-16) · **G19** (2026-10-15) · **G0** (2026-10-11) |
| Próximo gate | **G9** (Bindings para 8 lenguajes) / **G20** (Núcleo de proximidad) · **G3** (#59) y **G2** pendientes de CI (no bloquean F9: G8 cerrado) |
| Hito siguiente | MP1 · Tap offline (al cerrar G21) / M3 · SDK multi-lenguaje (al cerrar G9) [M1 y M2 alcanzados] |
| Última actualización | 2026-11-21 (Gobernanza KAIZEN instalada con ADR-0031 y política K-3, rama `chore/kaizen-governance`, #113; F9.T02 sigue en `feat/112-sdk-api-freeze`) |

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
| G8 | **Cerrado** | 2026-10-18 | **Hito M2 alcanzado**: Los nueve criterios normativos de aceptación del MVP (§24 de `ROADMAP.md`, MVP-01 a MVP-09) verificados al 100% de forma scriptada e in-process mediante `pip-cli demo-m2` y la suite automatizada de CI `apps/pip-cli/tests/mvp_acceptance_m2_audit.rs`; latencia offline sans-I/O de 6.78 ms (< 20 ms, `REQ-PERF-003`), cero PII en disco, memoria y ledger (`INV-02`), fail-closed determinista (`INV-05`), 4 estados con evidencia (`INV-04`), anti-replay persistente en SQLite (`REQ-PRES-005`, `REQ-STOR-004`), degradación ante snapshots stale (`REQ-STAT-004`), sincronización y revocación anti-rollback (`REQ-STAT-008`), recuperación BIP-39 (128 bits), custodia Shamir 3-de-5, migración SAS y rotación con procedimientos por perfil (`INV-16`), e informe formal en `docs/reports/2026-10-18-mvp-evaluacion-m2.md` (#111). |
| G9 … G18, G20 … G25 | Pendiente | — | — |

## Tareas en curso

| Tarea | Issue | Responsable | Estado | Siguiente paso |
|---|---|---|---|---|
| Gobernanza Kaizen (instalación, ratchet y adaptadores) | #113 | OpenCode (agente) | Hecha | Pendiente de revisión/merge del mantenedor; los gates remotos no ejecutan hasta resolver la facturación de Actions |
| F9.T02 Revisión y congelación de API | #112 | OpenCode (agente) | Hecha | Revisión de superficie pública + `cargo-semver-checks` activo en CI; congelación formal `0.x` pendiente de decisión del mantenedor |
| F11.T02 Wallet de Referencia & UI | #101 | Antigravity (agente) | Hecha | Rediseño UI/UX verificado en Google Pixel 8 Pro: 4 pestañas principales sin corte de palabras, `NoActionBar` nativo, tarjetas limpias sin jerga de protocolo, diagnósticos colapsables, 13/13 tests en verde y release `v0.1.0-alpha` actualizado (50.3 MB) |
| F8.T11 Revisión del MVP (Gate G8 / Hito M2) | #111 | Antigravity (agente) | Hecha | Ejecución scriptada y reproducible de los nueve criterios de aceptación de ROADMAP.md §24 aprobada al 100%; informe formal publicado en `docs/reports/2026-10-18-mvp-evaluacion-m2.md` y Gate G8 / Hito M2 formalmente cerrado; resuelto #111 |
| F8.T10 Robustez | #110 | Antigravity (agente) | Hecha | Suite de inyección de fallos (aborto transaccional SQLite con rollback y comprobación PRAGMA integrity_check, matriz de fallos en respaldo GIDB, umbral insuficiente Shamir k-de-n, mitigación MitM e interrupción en migración SAS, y tolerancia a fallos en sustitución atómica de ranura de dispositivo con revocación en TokenStatusList, REQ-STOR-004, REQ-REC-001..004, REQ-DEVSLOT-003); resuelto #110 |
| F8.T09 Procedimientos por perfil | #109 | Antigravity (agente) | Hecha | Procedimientos normativos de recuperación institucional documentados en los 5 perfiles oficiales (`pip-personal-v1`, `pip-identity-v1`, `pip-financial-v1`, `pip-enterprise-v1`, `pip-tenant-role-v1`), prohibición de correo electrónico y custodio único (`REQ-REC-006`, `P-10`), revocación atómica de ranura (`REQ-DEVSLOT-003`, `ADR-0029`) y suite de auditoría `institutional_recovery_profiles_audit.rs` probada y verificada; resuelto #109 |
| F8.T08 Rotación de firmantes de bundle y de raíz | #108 | Antigravity (agente) | Hecha | Raíz encadenada con doble umbral; solapamiento sin interrupción para clientes con versiones distintas (`REQ-TRUST-006`); simulación de avance forzado de versión (999.999.999) y recuperación determinista por incremento de `bundle_epoch` (`REQ-TRUST-009`); resuelto #108 |
| F8.T07 Compromiso de clave de emisor E2E | #107 | Antigravity (agente) | Hecha | Suspensión de emergencia (EMERGENCY_ROLE, TTL 14 días) -> Unverifiable (`IssuerSuspended`); compromiso multisig irreversible (DEFAULT_ADMIN_ROLE) -> fail-closed Invalid para todas las credenciales de la clave (`IssuerKeyCompromised`, $iat$ agnóstico); falsa alarma / rehabilitación -> Active / Valid; expiración de TTL -> retorno automático a Active; prohibición de renovación por emergencia probada (`REQ-KEY-005`, `REQ-LEDG-004`, `ADR-0018`); resuelto #107 |
| F8.T06 Rotación de clave de emisor E2E | #106 | Antigravity (agente) | Hecha | Ciclo on-chain TrustRegistry (`addIssuerKey`, `retireIssuerKey`), ingesta en pip-indexer, derivación determinista de TrustBundle v2 por operadores k-de-n, verificación multi-fuente (`FullVerificationEngine`) y verificación offline probando que credenciales anteriores al retiro siguen siendo `Valid` (`REQ-KEY-006`), nuevas credenciales con clave activa son `Valid`, y emisiones posteriores al retiro se rechazan como `Invalid` (`IssuerKeyRetired`); resuelto #106 |
| F8.T05 Migración entre dispositivos con SAS y compromiso previo | #105 | Antigravity (agente) | Hecha | Engagement QR, máquinas de estados sans-I/O `TargetMigrationMachine` y `SourceMigrationMachine`, compromiso SHA-256 pre-revelación contra MitM, derivación HKDF-SHA256 de código SAS (6 dígitos `xxx-xxx`) y claves de sesión, transferencia cifrada de bóveda con `XChaCha20-Poly1305` y encolado de re-vinculaciones sin exportar claves privadas de hardware (`REQ-REC-001`, `ADR-0009`, `SPEC-PIP-MIGRATE-001`); resuelto #105 |
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

- **Bloqueo de facturación de la cuenta de GitHub:** los workflows de PR #22 se crean correctamente pero los jobs no arrancan ("The job was not started because your account is locked due to a billing issue"). No es un defecto de los workflows: se validaron por sintaxis y todas sus comprobaciones se ejecutaron en local con éxito. El mantenedor debe resolver la facturación para que CI verifique G1. Los workflows `kaizen-gates.yml` y `kaizen-pr-autofill.yml` quedan sujetos al mismo bloqueo; sus comprobaciones se ejecutan en local mediante `scripts/kaizen check` y los hooks de `.githooks/` (#113).

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

### Traspaso — 2026-11-21 (F9.T02: revisión de API del SDK) — OpenCode (agente)
- Tarea: F9.T02 — #112 — rama `feat/112-sdk-api-freeze`
- Estado: **lista para revisión / hecha** (congelación formal pendiente del mantenedor)
- Hecho en esta sesión:
  - Inventario de la superficie pública de `gravital-id-sdk` (`TrustStore`, `Verifier`,
    `Wallet<B,R>`, `Issuer`, contratos del host, `VerificationResult` y catálogo de errores)
    contrastado con `docs/specs/SDK_API.md`. Informe en
    `docs/reports/2026-11-21-sdk-api-surface.md`.
  - Hallazgos: `TrustStore` no expone `import_status_manifest`, `get_issuer` ni
    `trusted_time_floor` (declarados en `SDK_API.md §2.1`), y `Wallet<B,R>` es un *type alias*;
    se documentan como diferimientos a decidir antes de la congelación.
  - **Control automático activado**: job `semver` en `.github/workflows/ci.yml` con
    `cargo-semver-checks` contra la base del PR (o `HEAD~1` en pushes), con
    `fetch-depth: 0` y fallo ante cambios incompatibles (REQ-SDK-006).
  - Limpieza de ramas: se eliminaron las ramas vacías/fusionadas (`feat/60-status-lists`
    duplicada y `feat/9-sdk-bindings` totalmente fusionada en `main`). **Solo queda `main`**,
    limpia y pusheada.
- Pendiente (siguiente paso concreto):
  - Decisión del mantenedor: aprobar la congelación `0.x` para la beta y pronunciarse sobre
    los hallazgos 1–3 del informe. Después continuar con F9.T04 (Kotlin) o F9.T05 (Swift).
- Bugs/issues abiertos durante la sesión: Ninguno.
- Decisiones tomadas (con enlace a ADR/issue): se activa el control SemVer, pero **no** se
  declara la congelación sin aprobación humana (CODEOWNERS).
- Riesgos o dudas: `cargo-semver-checks` no está instalado en el entorno local; el job se
  validó por sintaxis del workflow, no ejecutándolo. GitHub Actions sigue pendiente de
  facturación.
- Comprobaciones locales: fmt OK clippy OK tests OK xtask OK sintaxis del workflow OK

### Traspaso — 2026-11-21 (gobernanza Kaizen) — OpenCode (agente)
- Tarea: gobernanza Kaizen — #113 — rama `chore/kaizen-governance`
- Estado: **lista para revisión** (instalación completa y `scripts/kaizen check` en verde)
- Hecho en esta sesión:
  - Instalación completa aprobada por el mantenedor: `.kaizen/RULES.md`, `.kaizen/config.env` con comandos reales (`cargo test`, `cargo clippy`, `cargo fmt`), `scripts/kaizen`, `.githooks/`, `docs/kaizen/` (descriptores, retros, postmortems, ADR, runbooks, métricas), adaptadores Claude Code/opencode, `.github/workflows/kaizen-*.yml` y nueva plantilla de PR.
  - Política de commits K-3 (≤256 caracteres, imperativo, keyword de cierre) con `KZ_POLICY_NO_EMOJI=1` y `KZ_POLICY_NO_AI_ATTRIBUTION=1`; `AGENTS.md` §6 y §19 y `CLAUDE.md` actualizados. La política de emojis obligó a sustituir símbolos por texto en tres documentos heredados, sin cambiar su contenido.
  - ADR-0031 (Aceptado) reflejado en `ARCHITECTURE.md §22`; `CHANGELOG.md` y `STATUS.md` actualizados.
  - Línea base generada (`debt_max=2`) y primera métrica registrada (`LOC=88421`, `debt=2`); `KZ_SRC_GLOBS` acotado a fuentes porque `apps/` y `packages/` contienen artefactos de build que inflaban LOC a 5,5 M.
  - Bug preexistente #114 corregido con aprobación explícita de CODEOWNERS: dos `.stderr` de `trybuild` regenerados para rustc 1.99.0; el diff es solo redacción del diagnóstico E0277.
- Pendiente (siguiente paso concreto):
  - Revisión y merge del mantenedor. La verificación KAIZEN §6.7 (PR real sin/con descriptor) no se ejecutó: no se abrieron PRs de prueba; corresponde comprobarla al abrir el PR de esta rama.
- Bugs/issues abiertos durante la sesión: #113 (tarea), #114 (bug de trybuild, corregido en esta rama).
- Decisiones tomadas (con enlace a ADR/issue): ADR-0031 y aprobación de CODEOWNERS registrada en #113 y #114; `docs/kaizen/adr/` queda solo como plantilla operativa, el directorio normativo sigue siendo `docs/adr/`.
- Riesgos o dudas: GitHub Actions sigue bloqueado por facturación, por lo que `kaizen-gates` y `kaizen-pr-autofill` no se han ejecutado en remoto; `KZ_COVERAGE_CMD` y `KZ_WARNINGS_CMD` quedan vacíos (no hay comando único y estable que imprima solo el número). `cargo deny check` y `cargo audit` fallan por advisory preexistentes (RUSTSEC-2026-0387, -0459 y -0486) en dependencias no tocadas por este cambio; no se crean issues públicos por §7.4.
- Comprobaciones locales: `scripts/kaizen init` OK; `scripts/kaizen check` OK (descriptores, políticas, formato, lint, tests y ratchet); hook `commit-msg` rechaza resumen de 300 caracteres OK; descriptor sin cierre falla y restaurado pasa OK; ratchet con TODO extra falla OK; `cargo xtask check-layers` OK; `cargo xtask trace` OK; `cargo deny check` FALLO (preexistente); `cargo audit` FALLO (preexistente).
