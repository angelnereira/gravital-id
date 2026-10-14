# Changelog

Todos los cambios relevantes de este proyecto se documentan aquí.
Formato: [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/). Versionado: [SemVer](https://semver.org/lang/es/).
Cada componente publicado (SDK, servicios, contratos, especificación) indica su ámbito entre corchetes.

## [Unreleased]

### Added
- [infra] Workspace Cargo con los 20 crates del núcleo (`crates/gravital-id-*`), lints estrictos del workspace (`missing_docs`, `unsafe_code`, `unwrap_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`) y perfiles `release`/`release-mobile` (F1.T01, #6).
- [infra] `rust-toolchain.toml` fija Rust 1.85.0 (MSRV) con los targets de compilación cruzada; ADR-0014 Aceptado (F1.T02, #6).
- [infra] `xtask check-layers`, `xtask trace` y `xtask check-error-codes`: verificación de capas/no_std/aislamiento del verificador/bindings, matriz REQ→pruebas y catálogo de errores contra `ERROR_CODES.md`, con casos negativos probados (F1.T03, F1.T04, F1.T08; #6).
- [infra] `clippy.toml` prohíbe `SystemTime::now`, `std::net` y `std::fs` como segunda barrera tras `no_std` (F1.T09, INV-01, INV-11; #6).
- [core] `gravital-id-types`: catálogo canónico de errores `GidError`/`PipError`/`ErrorCode` (48 códigos, alias `PIP-*` para compatibilidad) y trait `Clock` (SDK_API §3.2) (F1.T07, F1.T08; #6).
- [core] `gravital-id-crypto`: trait `Rng` de inyección de CSPRNG (INV-11) (F1.T07; #6).
- [testkit] `gravital-id-testkit`: `FixedClock` y `SeededRng` (xoshiro256** reproducible) con pruebas de determinismo (F1.T07, REQ-VER-009; #6).
- [sdk] Fachada mínima `gravital-id-sdk`: re-exporta `Clock`, `Rng`, `ErrorCode`, `GidError`/`PipError` (F1.T13; #6).
- [bindings] `bindings/wasm` (`gravital-id-wasm`): binding WASM con pruebas de humo `wasm-pack test --node` que validan la fachada a través de FFI (F1.T13, REQ-PORT-001; #6).
- [ci] Workflows `ci.yml` (fmt, clippy, nextest, doc, xtask×3, MSRV, feature-powerset acotada, compilación cruzada wasm32/android/ios/bare-metal), `security.yml` (cargo-deny, cargo-audit, dependency-review, gitleaks), `docs.yml` (markdownlint, lychee, validación de REQ-IDs), `wasm.yml`, `fuzz.yml`, `mutation.yml` (cargo-mutants + Kani) y `bench.yml` (F1.T05, F1.T10, F1.T11, F1.T14; #6).
- [ci] `deny.toml` con la allowlist de licencias de ADR-0002, sin comodines ni fuentes fuera de crates.io (F1.T06, REQ-COMP-003; #6).
- [governance] `CODEOWNERS` con las rutas sensibles y labels como código (`.github/labels.yml`) con script de sincronización idempotente (F1.T12; #6).
- [test] Objetivo de fuzzing de ejemplo `fuzz/fuzz_targets/gid_error_format.rs` y benchmarks criterion de ejemplo en `gravital-id-types` (F1.T11; #6).
- [test] Objetivos de fuzzing normativos para los 6 parsers del núcleo (`base64url_strict`, `json_bounded`, `cbor_bounded`, `base45_strict`, `deflate_bounded`, `jwk_parser`) con trazabilidad REQ-SEC-005 y matriz de ejecución en `fuzz.yml` (F2.T11, #34).
- [bench] Suite de benchmarks de primitivas criptográficas base en `gravital-id-crypto` (`benches/crypto_primitives.rs`) midiendo ES256 (RFC 6979), SHA-256 (32B–10KiB), XChaCha20-Poly1305 y HPKE; línea base registrada en `docs/STATUS.md` (F2.T12, REQ-PERF-001; #35).
- [test] Suite de pruebas de integración de API para `gravital-id-crypto` (`tests/api_coverage.rs`) elevando la cobertura de líneas al 92,46 %, superando el umbral de Gate G2 (F2.T12, REQ-PERF-001; #35).
- [docs] ADR-0015 (Propuesto): Evaluación de construir frente a reutilizar SD-JWT para Capa L2; decisión de implementar nativamente en `gravital-id-credential` (`no_std`, sin PII, delegación a `KeyStore`, mitigaciones DoS) (F3.T01, #39).
- [core] `gravital-id-credential`: Emisión SD-JWT (RFC 9901) con divulgaciones selectivas de objetos y arrays, sal criptográfica de $\ge 128$ bits (REQ-CRED-002), digests señuelo configurables (REQ-CRED-003), soporte de estructuras anidadas y recursivas, y serialización compacta con firma JWS ES256 delegada a `KeyStore` (F3.T02, #41).
- [core] `gravital-id-credential`: Parseo, verificación y reconstrucción determinista de claims SD-JWT (RFC 9901) con verificación biunívoca de digests, rechazo fail-closed de divulgaciones duplicadas, digests duplicados en `_sd`, claims reservados, colisión de claves (REQ-CRED-009), divulgaciones huérfanas/no referenciadas (REQ-VER-003) y cotas DoS mediante `SdJwtLimits` (REQ-VER-008); objetivo de fuzzing `sd_jwt_parser` (F3.T03, #43).
- [core] `gravital-id-credential`: Creación y verificación de Key Binding JWT (KB-JWT, RFC 9901 §6) con `typ: kb+jwt`, cálculo estricto de `sd_hash` (RFC 9901 §6.2), firma delegada a `KeyStore` con `KeyHandle<HolderBinding>` (INV-03), verificación fail-closed de audiencia (`aud`), nonce y frescura/sesgo de reloj (`iat`), y vinculación probada en presentaciones SD-JWT (F3.T04, REQ-PRES-002, REQ-CRED-001, REQ-VER-003; #45).
- [core] `gravital-id-credential`: Esquemas de perfil en compilación (`profile.rs`) para `pip-personal-v1`, `pip-financial-v1` y `pip-enterprise-v1`, traducidos literalmente de `docs/specs/profiles/*.md` §3 con las palabras clave `type`, `enum`, `pattern`, `format` y `required`; validación en emisión (`SdJwtVcBuilder::profile`) y en verificación (`VcValidityPolicy::with_profile`, tipos de los atributos divulgados + coincidencia de `vct`), con errores `SchemaValidationFailed` (`PIP-E3004`) y fail-closed ante perfiles sin esquema registrado (F3.T06, REQ-CRED-004, REQ-VER-003, INV-05; #48).
- [core] `gravital-id-credential`: Capa SD-JWT VC (`draft-ietf-oauth-sd-jwt-vc-19`) con `typ: dc+sd-jwt`, claims siempre visibles `iss` (URL HTTPS), `vct`, `iat`, `nbf`, `exp`, `cnf.jwk` (serialización canónica RFC 7638 sin material privado) y `status.status_list` (`idx`+`uri`, ADR-0005); `VcValidityPolicy` acota sesgo de reloj, requisitos de `status`/`exp`/`cnf` y la lista de algoritmos del perfil (REQ-CRED-008, INV-08); `ParsedSdJwt::verify_vc` valida de forma fail-closed sobre el payload firmado, impidiendo ocultar metadatos VC tras divulgación selectiva; objetivo de fuzzing `sd_jwt_parser` ampliado para cubrir la nueva ruta de verificación (F3.T05, REQ-CRED-001, REQ-CRED-007, REQ-CRED-008, REQ-VER-003, REQ-VER-005; #47).

- [docs] Paquete documental inicial: `AGENTS.md`, arquitectura, requisitos, estructura del proyecto, hoja de ruta F0–F18, plantillas de issues y PR, índice de ADRs.
- [docs] ADR-0016 a ADR-0020 (Propuestos): confianza por umbral, manifiesto de estado, emergencia limitada a suspensión, núcleo `no_std` con protocolos sans-I/O y fail-closed por tipos.
- [specs] Modelo de amenazas y privacidad `THREAT_MODEL.md` v0.1.0-draft (F0.T05): análisis STRIDE por componente y LINDDUN para privacidad.
- [specs] Especificación normativa `TRUST_BUNDLE.md` v0.1.0-draft (F0.T13): raíz de confianza encadenada, bundle multi-firma determinista, manifiesto de estado y anti-rollback con `bundle_epoch`.
- [specs] Especificación normativa `CRYPTO_PROFILES.md` v0.1.0-draft (F0.T06): algoritmos autorizados (ES256, SHA-256, XChaCha20), versiones fijadas de RFC 9901 y borradores, mitigaciones DoS.
- [specs] Especificación normativa `PROTOCOL.md` v0.1.0-draft (F0.T12): flujos OID4VCI y OID4VP (DCQL), transporte offline en QR bidireccional (transcodificación binaria sin pérdida + CBOR + DEFLATE + Base45), multi-QR y sobres HPKE.
- [specs] Especificación normativa `CONTRACTS.md` v0.1.0-draft (F0.T14): contratos EVM inmutables (`TrustRegistry`, `StatusAnchor`), eventos tipados, timelock ordinario y rol de emergencia acotado a 14 días.
- [specs] Perfiles normativos de credencial v1.0.0-draft (F0.T15): `pip-personal-v1`, `pip-financial-v1` (hardware con atestación obligatorio) y `pip-enterprise-v1`.
- [specs] API pública e interfaces del host `SDK_API.md` v0.1.0-draft (F0.T16): contratos abstractos `KeyStore`, `Clock`, `VerifierStateStore`, `StorageBackend` y `Transport`.
- [specs] Catálogo de códigos de error `ERROR_CODES.md` v0.1.0-draft (F0.T16): códigos de error unificados `PIP-Exxxx` para todas las plataformas y bindings.
- [spikes] Publicación de informes de viabilidad de los 4 spikes técnicos de Fase F0:
  - `spikes/qr/REPORT.md` (F0.T07): viabilidad de transporte QR con transcodificación CBOR + DEFLATE + Base45 (reducción ~51 % en tamaño, presupuesto < 1200 caracteres, multi-QR indexado).
  - `spikes/keystore/REPORT.md` (F0.T08): viabilidad de firmas hardware ES256 desde Rust vía trait `KeyStore` con Secure Enclave y StrongBox; normalización de firmas ASN.1 DER a IEEE P1363 s-low (INV-03).
  - `spikes/wasm/REPORT.md` (F0.T09): compilación cruzada a `wasm32-unknown-unknown` de suites RustCrypto (174 KB / 62 KB brotli), contención de pánicos con aislamiento y código tipado `GID-E9999`.
  - `spikes/ledger/REPORT.md` (F0.T10): auditoría de contratos mínimos EVM en Arbitrum/Base Sepolia (gas < $0.005 por anclaje), validación de INV-02 (cero PII) y respaldo empírico a ADR-0004.
- [specs] Revisión cruzada de especificaciones normativas `docs/specs/CROSS_REVIEW.md` (F0.T21): verificación formal de consistencia y trazabilidad de las invariantes INV-01 a INV-16.
- [gate] **Cierre formal del Gate G0** (Fundación, gobierno y especificación): criterios 100 % completados y verificados.
- [legal] Análisis regulatorio preliminar `docs/legal/2026-analisis-regulatorio-preliminar.md` v0.1.0-draft (F0.T20): conformidad con la Ley 81 de 2019 de Panamá (Protección de Datos), INV-02 en blockchain y requisitos KYC/AML (Ley 23 de 2015).
- [docs] `ADR-0001`: Aceptación de nombre definitivo "Gravital ID" / prefijo de paquetes `gravital-id` y `gid` (F0.T02).
- [docs] `ADR-0003` a `ADR-0012`: Aceptación formal de decisiones de arquitectura para Fase F0 (F0.T11):
  - `ADR-0003`: Formato de credencial v1 (SD-JWT VC + HAIP 1.0 `x5c`).
  - `ADR-0004`: Red blockchain para el registro (EVM / L2 Arbitrum y Base con anclaje).
  - `ADR-0005`: Mecanismo de estado y revocación (Token Status List comprimido).
  - `ADR-0006`: Estrategia de bindings multi-lenguaje (UniFFI, WASM, flutter_rust_bridge, C ABI y aislamiento de pánicos).
  - `ADR-0007`: Backend criptográfico (RustCrypto por defecto, aws-lc-rs condicional por tipos para FIPS).
  - `ADR-0008`: Almacenamiento local (cifrado de sobre con DEK/KEK, índices ciegos HMAC y backend SQLite WAL/IndexedDB).
  - `ADR-0009`: Modelo de recuperación (migración SAS con compromiso previo, claves derivadas por emisor y re-vinculación).
  - `ADR-0010`: Formato del trust bundle (JWS JSON multi-firma k-de-n con canonización JCS RFC 8785 y límites).
  - `ADR-0011`: Transporte offline (QR dos pasos, transcodificación binaria CBOR + DEFLATE + Base45, multi-QR).
  - `ADR-0012`: Modelo de gobernanza (Multisig k-de-n, timelock 48-72h y rol de emergencia limitado a suspender).
- [docs] `ADR-0002`: Aceptación de licencia dual MIT / Apache-2.0 y política DCO 1.1 (F0.T03); archivos `LICENSE-MIT`, `LICENSE-APACHE` y `CONTRIBUTING.md`.
- [security] `SECURITY.md` definitivo (F0.T04): canal privado en GitHub Advisories, tiempos de SLA por severidad y política de Safe Harbor.
- [infra] 57 labels oficiales creados en GitHub según `AGENTS.md §8` y sincronización de los 5 issues pendientes iniciales (#1 a #5).

### Changed
- [docs] Aceptación formal de ADR-0001 a ADR-0012 y ADR-0016 a ADR-0020 por el mantenedor Angel Nereira (#2, #6, #7..#17).
- [docs] Aceptación formal de ADR-0002 (licencia y DCO) por el mantenedor Angel Nereira.
- [governance] Adaptación de `AGENTS.md §6` y `§14` para régimen de mantenedor único en Fase F0 (#1).
- [docs] Revisión de arquitectura v0.2: raíz de confianza y bundles cofirmados k-de-n; manifiesto de estado fuera del bundle; estado `suspended`; claves de recuperación por emisor; SAS con compromiso previo; claves HPKE con propósito propio; estado persistente del verificador; transcodificación binaria para QR; estrategia de pánicos en WASM.
- [docs] Estructura: adaptadores `pip-storage-sqlite` y `pip-transport-http` en L5; `pip-sdk` como esqueleto vertical desde F1; pruebas de mutación, Kani y modelos formales.
- [docs] `PROJECT_STRUCTURE.md` adopta la nomenclatura canónica de crates `gravital-id-*` (ADR-0001).
- [governance] `docs/adr/README.md`: ADR-0014 y ADR-0019 pasan a Aceptados e indexados.

### Fixed
- [docs] Contradicción sobre I/O en L3 (`pip-storage`), configuración de lints inaplicable (`forbid` y herencia de workspace), fase de REQ-STAT-002 y dependencia de F6.T08 respecto de F4.T03 (#3, #4, #5).
- [xtask] `check-error-codes` reportaba duplicados inexistentes porque contaba las menciones de `GID-Exxxx` en doc-comments y pruebas; ahora solo cuenta brazos de `match` de definición y verifica además que los discriminantes del enum coincidan con el catálogo documentado (#6).
- [xtask] `trace`: soporte para tablas transversales de 5 columnas en `REQUIREMENTS.md` con valor por defecto para el principio arquitectónico (#36).

<!-- Secciones permitidas: Added, Changed, Deprecated, Removed, Fixed, Security -->
