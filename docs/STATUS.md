# STATUS.md — Estado vivo del proyecto

> Fuente única del **avance**. Se actualiza al final de cada sesión de trabajo (`AGENTS.md §5.3`) y al cerrar cada gate. Mantén solo el estado actual y las últimas notas; el histórico queda en los issues y en git.

## Resumen

| Campo | Valor |
|---|---|
| Fase actual | **F3 — Credenciales SD-JWT VC (en curso)** |
| Último gate cerrado | **G0** (2026-10-11) |
| Próximo gate | **G2** (Revisión y cierre formal de Fase F2) |
| Hito siguiente | M1 · Núcleo offline (al cerrar G5) |
| Última actualización | 2026-10-13 (F3: T08 completada — `pip-issuer`) |

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
| F3.T01 ADR-0015 construir o reutilizar | #39 | Antigravity (agente) | Hecha | Evaluación de crates SD-JWT existentes; redactado `ADR-0015` propuesto; decisión Opción B (implementar en L2 `gravital-id-credential`); rama `docs/39-adr-0015-sd-jwt` |
| F3.T02 Emisión SD-JWT | #41 | Antigravity (agente) | Hecha | Emisión RFC 9901 en `gravital-id-credential` (objetos/arrays, sal ≥ 128b, decoys, anidación, serialización compacta y firma ES256 vía `KeyStore`); rama `feat/41-sd-jwt-emission` |
| F3.T03 Parseo y verificación SD-JWT | #43 | Antigravity (agente) | Hecha | Parseo RFC 9901 en `gravital-id-credential` (verificación de digests, rechazo de duplicados, claims reservados, huérfanos, colisión de claves, reconstrucción, firma ES256, límites DoS y fuzzing); rama `feat/43-sd-jwt-parsing-verification` |
| F3.T04 KB-JWT | #45 | Antigravity (agente) | Hecha | Creación y verificación de KB-JWT (`typ: kb+jwt`, `nonce`, `aud`, `iat`, `sd_hash`; firma delegada al `KeyStore`; REQ-PRES-002, REQ-CRED-001, REQ-VER-003); rama `feat/45-kb-jwt` |
| F3.T08 `pip-issuer` | #57 | OpenCode (agente) | Hecha | API de construcción y firma; emisión por lotes con claves, sales e índices distintos (REQ-CRED-006); rama `feat/57-issuer-api` |
| F3.T07 Claims de predicado | #49 | OpenCode (agente) | Hecha | Predicados precomputados (`age_over_18`/`age_over_21`) con cálculo por calendario y reloj inyectado; rama `feat/49-predicate-claims` |
| F3.T06 Esquemas de perfil | #48 | OpenCode (agente) | Hecha | Esquemas de `pip-personal-v1`, `pip-financial-v1` y `pip-enterprise-v1` en compilación con validación en emisión y verificación (REQ-CRED-004); rama `feat/48-profile-schemas` |
| F3.T05 Capa SD-JWT VC | #47 | OpenCode (agente) | Hecha | `typ: dc+sd-jwt`, `iss`/`vct`/`iat`/`nbf`/`exp`, `cnf.jwk` canónico, `status.status_list`, lista de algoritmos del perfil y rechazo de `none`; rama `feat/47-sd-jwt-vc` |

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

### Traspaso — 2026-10-13 (F3.T08: `pip-issuer`) — OpenCode (agente)
- Tarea: F3.T08 — #57 — rama `feat/57-issuer-api`
- Estado: **lista para revisión / hecha**
- Hecho en esta sesión:
  - F3.T08 (#57):
    - `gravital-id-issuer` (L3) deja de ser un esqueleto: `CredentialRequest`
      (perfil, atributos llanos o selectivos, `exp`, `status`, `cnf.jwk`, señuelos),
      `StatusAllocation`, `Attribute` y `IssuedCredential` con los metadatos operables
      (serialización compacta, divulgaciones, índice de estado, `iat`/`exp`).
    - `Issuer::issue`: valida la solicitud (atributos duplicados, claims siempre visibles,
      ventana de vigencia), resuelve el esquema del perfil, **precomputa los predicados**
      declarados a partir de `birth_date` (REQ-CRED-005) y delega la firma al `KeyStore`
      (INV-03) con `typ: dc+sd-jwt` + `ES256` (INV-08).
    - `Issuer::issue_batch` + `BatchPlan`: N copias con **clave de vinculación, sales e
      índice de estado distintos por copia** (ARCHITECTURE §8.3, REQ-CRED-006). El plan
      rechaza claves repetidas, índices repetidos, desajustes de tamaño, lote vacío y lotes
      de más de `MAX_BATCH_COPIES` (64). Si una copia falla, el lote entero falla (INV-05).
    - Suite `crates/gravital-id-issuer/tests/issuer_api.rs` (7 pruebas): credencial nominal
      verificada contra el esquema y con predicado precomputado, unicidad de claves/sales/
      índices en el lote, validez individual de cada copia, planes inválidos, solicitud de
      lote con clave propia o sin URI de lista, violaciones de esquema y determinismo con
      RNG sembrada (REQ-VER-009).
    - `crates/gravital-id-credential/src/vc.rs`: `is_always_visible_claim` pasa a ser pública
      para que la API de emisión rechace esos claims como atributos.
    - Añadidas las dependencias del crate (`gravital-id-types`, `-codec`, `-crypto`) y
      `gravital-id-testkit` en dev-dependencies.
    - Documentación: README del crate (funcionalidades + ejemplo), `CHANGELOG.md`,
      `docs/TRACEABILITY.md` (REQ-CRED-006 pasa a *Cubierto*) y `docs/STATUS.md`.
- Pendiente (siguiente paso concreto):
  - Iniciar tarea F3.T09: `Vectores de conformidad v1` — `conformance/vectors/sd-jwt-vc/`
    con positivos y negativos (al menos uno por regla de rechazo, REQ-MAINT-003).
- Bugs/issues abiertos durante la sesión: Ninguno.
- Decisiones tomadas (con enlace a ADR/issue):
  - La solicitud de lote no admite clave de titular propia: cada copia fija la suya para
    evitar correlación (ARCHITECTURE §8.3).
  - La URI de la lista de estado es común al lote y el índice se reparte una entrada por copia.
- Riesgos o dudas:
  - La asignación real de índices vive en el servicio de emisión (F7.T05); aquí solo se
    exige unicidad dentro del lote.
- Comprobaciones locales: fmt ✅ clippy ✅ tests ✅ (299 pruebas del workspace, 0 fallos)
  layers ✅ trace ✅ check-error-codes ✅ doc ✅ deny ✅ wasm32 ✅ bare-metal ✅
  (`cargo nextest` no está instalado en este entorno; se usó `cargo test`)
