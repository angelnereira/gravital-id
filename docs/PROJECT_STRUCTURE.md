# PROJECT_STRUCTURE.md — Estructura del repositorio

> **Estado:** Borrador normativo v0.2 · **Depende de:** `ARCHITECTURE.md`, `REQUIREMENTS.md`
> **Revisión v0.2 (2026-10-10):** incorpora la revisión de arquitectura (ADR-0016 a ADR-0020, en estado **Propuesto**); lo que depende de ellos es propuesta hasta su aceptación por un mantenedor humano.
> Este documento fija **dónde vive cada cosa** y **qué puede depender de qué**. Crear un directorio, crate o paquete fuera de esta estructura requiere actualizar este documento en el mismo PR (y un ADR si cambia una regla de capas).

---

## 1. Decisión: monorepo

Un único repositorio contiene núcleo, bindings, servicios, contratos, conformidad y documentación. Motivos:

- Un cambio de protocolo toca especificación, núcleo, vectores, bindings y servicios a la vez; un monorepo permite hacerlo en un solo PR atómico y revisable.
- Los vectores de conformidad son la fuente de verdad compartida por todas las implementaciones.
- Los agentes de código ven todo el contexto con una sola lectura.

Los artefactos se **publican por separado** (crates, paquetes por lenguaje, imágenes de servicios, contratos), cada uno con su versión.

---

## 2. Árbol del repositorio

```text
pip/
├── AGENTS.md                     # Reglas para agentes y desarrolladores (obligatorio leer)
├── CLAUDE.md                     # Importa AGENTS.md (compatibilidad con herramientas)
├── README.md                     # Puerta de entrada y mapa de documentación
├── SECURITY.md                   # Divulgación responsable (vulnerabilidades NO van a issues públicos)
├── CHANGELOG.md                  # Keep a Changelog, por componente
├── CONTRIBUTING.md               # (F1) Guía para humanos; remite a AGENTS.md
├── LICENSE-MIT / LICENSE-APACHE  # (F0, según ADR-0002)
├── Cargo.toml                    # Workspace: miembros, lints, perfiles, dependencias compartidas
├── Cargo.lock                    # Versionado siempre
├── rust-toolchain.toml           # Toolchain fijada (ADR-0014)
├── deny.toml                     # Política de cargo-deny (licencias, fuentes, advisories)
├── clippy.toml / rustfmt.toml
├── .cargo/config.toml            # Alias (xtask), flags por target (wasm getrandom, etc.)
│
├── .github/
│   ├── ISSUE_TEMPLATE/           # bug, tarea de roadmap, hueco de especificación, decisión
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── CODEOWNERS                # Rutas sensibles exigen revisión humana
│   └── workflows/                # ci, security, mobile, wasm, contracts, fuzz, release, docs
│
├── .issues/
│   ├── pending/                  # Respaldo cuando un agente no puede crear issues en GitHub
│   └── synced/                   # Registros ya convertidos en issues
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── REQUIREMENTS.md
│   ├── PROJECT_STRUCTURE.md      # Este documento
│   ├── ROADMAP.md
│   ├── STATUS.md                 # Estado vivo: fase, tareas en curso, bloqueos, traspaso
│   ├── adr/                      # Architecture Decision Records (NNNN-titulo.md)
│   ├── specs/                    # Especificaciones normativas (creadas en F0)
│   │   ├── THREAT_MODEL.md
│   │   ├── CRYPTO_PROFILES.md
│   │   ├── PROTOCOL.md
│   │   ├── TRUST_FRAMEWORK.md
│   │   ├── TRUST_BUNDLE.md
│   │   ├── STORAGE_FORMAT.md
│   │   ├── SDK_API.md
│   │   ├── ERROR_CODES.md
│   │   ├── TEST_STRATEGY.md
│   │   ├── models/               # (F13) Modelos formales de protocolo
│   │   ├── CONTRACTS.md
│   │   └── profiles/
│   │       ├── pip-personal-v1.md
│   │       ├── pip-financial-v1.md
│   │       └── pip-enterprise-v1.md
│   ├── guides/                   # (F9) Integración por lenguaje
│   ├── runbooks/                 # (F15) Operación, incidentes, ceremonias
│   ├── postmortems/              # Análisis de incidentes y bugs S0/S1
│   └── legal/                    # (F14) DPIA, análisis regulatorio (sin datos personales)
│
├── crates/                       # Núcleo Rust (ver §3)
│   ├── pip-types/
│   ├── pip-codec/
│   ├── pip-crypto/
│   ├── pip-keys/
│   ├── pip-credential/
│   ├── pip-status/
│   ├── pip-trust/
│   ├── pip-verifier/
│   ├── pip-holder/
│   ├── pip-issuer/
│   ├── pip-storage/
│   ├── pip-storage-sqlite/       # Adaptador L5
│   ├── pip-protocol/
│   ├── pip-recovery/
│   ├── pip-sync/
│   ├── pip-transport-http/       # Adaptador L5
│   ├── pip-ledger/
│   ├── pip-ledger-evm/
│   ├── pip-sdk/
│   └── pip-testkit/              # Solo dev-dependency
│
├── bindings/
│   ├── uniffi/                   # Crate pip-ffi-uniffi → Kotlin, Swift, Python
│   │   ├── kotlin/               # Proyecto Gradle (AAR/JAR) + pruebas + ejemplo
│   │   ├── swift/                # Swift Package + XCFramework + pruebas + ejemplo
│   │   └── python/               # Paquete Python + pruebas
│   ├── wasm/                     # Crate pip-wasm → paquete npm (navegador y Node)
│   ├── c/                        # Crate pip-ffi-c + cabecera generada (cbindgen)
│   │   ├── go/                   # Módulo Go (cgo)
│   │   └── dotnet/               # Paquete NuGet (P/Invoke)
│   └── dart/                     # flutter_rust_bridge (sujeto a ADR-0006)
│
├── services/
│   ├── pip-service-common/       # Config, telemetría, salud, errores HTTP compartidos
│   ├── pip-issuer-service/
│   ├── pip-trust-service/
│   ├── pip-indexer/
│   └── pip-relay/
│
├── contracts/                    # Foundry
│   ├── src/                      # TrustRegistry.sol, StatusAnchor.sol
│   ├── test/                     # Unitarias, fuzz, invariantes
│   ├── script/                   # Despliegue reproducible
│   └── foundry.toml
│
├── apps/
│   ├── pip-cli/                  # Herramienta de desarrollo y operación
│   ├── reference-wallet/         # (F11) Wallet de referencia
│   ├── reference-verifier/       # (F11) Verificador de referencia
│   └── issuer-console/           # (F11) Consola mínima de emisor
│
├── conformance/
│   ├── vectors/                  # Vectores JSON inmutables, versionados por perfil
│   ├── suites/                   # Definición de casos (positivos y negativos)
│   ├── runner/                   # Crate pip-conformance (ejecuta vectores contra cualquier SDK)
│   └── interop/                  # Adaptadores a implementaciones externas
│
├── fuzz/                         # cargo-fuzz: un objetivo por parser
├── benches/                      # Benchmarks transversales (criterion); los locales viven en cada crate
├── deploy/
│   ├── docker/                   # Dockerfiles reproducibles
│   ├── iac/                      # OpenTofu/Terraform por entorno
│   └── environments/             # dev, testnet, pilot, production (sin secretos)
├── spikes/                       # PoCs de F0. Código desechable: NUNCA importado por crates/
└── xtask/                        # Automatización: check-layers, trace, bindgen, vectors, release
```

---

## 3. Crates del núcleo

| Crate | Capa | Responsabilidad | I/O | WASM | Depende de (internos) |
|---|---|---|---|---|---|
| `pip-types` | L1 | Identificadores (`IssuerId`, `Kid`, `Vct`, `ProfileId`), tiempo (`UnixTime`), versiones, newtypes validados | No | Sí | — |
| `pip-codec` | L1 | base64url estricto, JSON con límites y rechazo de duplicados, CBOR con límites, DEFLATE con límite, Base45 | No | Sí | types |
| `pip-crypto` | L1 | Trait `CryptoBackend`; ES256, SHA-256, HMAC, HKDF, XChaCha20-Poly1305, ECDH P-256, HPKE, JWK, thumbprints, comparación en tiempo constante | No | Sí | types, codec |
| `pip-keys` | L1 | `KeyPurpose`, `KeyHandle`, trait `KeyStore` (firma y acuerdo de claves), normalización de firmas DER → P1363, keystore software (feature `software-keystore`) | No | Sí | types, crypto |
| `pip-credential` | L2 | SD-JWT (RFC 9901), SD-JWT VC, KB-JWT, esquemas de perfil | No | Sí | types, codec, crypto, keys |
| `pip-status` | L2 | Token Status List: parseo, verificación, índice, frescura | No | Sí | types, codec, crypto |
| `pip-trust` | L2 | Raíz de confianza, trust bundle multi-firma, manifiesto de estado, anti-rollback, piso de tiempo, `Policy`, trait `VerifierStateStore` | No | Sí | types, codec, crypto, status |
| `pip-verifier` | L3 | Pipeline de verificación con typestate, caché de nonces (sobre `VerifierStateStore`), `VerificationResult` | No | Sí | credential, status, trust |
| `pip-holder` | L3 | Gestión de credenciales, lotes, preparar/confirmar presentaciones | No* | Sí | credential, keys, storage (trait) |
| `pip-issuer` | L3 | Construcción y firma de credenciales, asignación de índices | No | Sí | credential, status, keys |
| `pip-storage` | L3 | Trait `StorageBackend`, cifrado de sobre, índices ciegos, migraciones, backend en memoria | No | Sí | types, crypto |
| `pip-recovery` | L3 | Respaldo, código de recuperación, Shamir, migración SAS, solicitudes de re-vinculación | No | Sí | crypto, keys, holder |
| `pip-protocol` | L4 | Mensajes OID4VCI/OID4VP, perfil offline QR, sobres de operación | No | Sí | credential, verifier, holder, recovery |
| `pip-sync` | L4 | Cola de operaciones y sincronización como máquina de estado sans-I/O; trait `Transport` (lo implementa L5 o el host) | No | Sí | protocol, trust, status, storage |
| `pip-ledger` | L4 | Trait `LedgerAdapter`, tipos de eventos, reconstrucción pura del estado, derivación determinista del bundle, contraste bundle ↔ estado | No | Sí | trust, types |
| `pip-storage-sqlite` | L5 | Backend SQLite (`rusqlite`) de `StorageBackend` y de `VerifierStateStore` | Sí | No | storage, trust |
| `pip-transport-http` | L5 | Implementación por defecto de `Transport`; conduce las máquinas de `pip-sync` y `pip-protocol` | Sí | No (en web el host inyecta `fetch`) | sync |
| `pip-ledger-evm` | L5 | Implementación EVM con `alloy`; solo servicios y modo completo | Sí | No | ledger |
| `pip-sdk` | L6 | API pública estable; fachada sobre L1–L4; features `verifier`, `holder`, `issuer`, `sync`, `full-verification` | Según features | Sí (sin `full-verification`) | todos salvo testkit |
| `pip-testkit` | — | `FixedClock`, `SeededRng`, emisores y bundles de prueba, generadores proptest | — | Sí | todos (solo dev) |

\* `pip-holder` usa el trait de almacenamiento; el I/O real lo hace el backend.

Los crates L1–L3 son `#![no_std]` + `alloc` (ADR-0019): no pueden hacer I/O, leer el reloj ni obtener aleatoriedad del sistema, porque esas APIs no existen para ellos. Los crates L4 pueden usar `std`, pero son sans-I/O: exponen máquinas de estado que emiten efectos y consumen resultados. Solo L5 (adaptadores) y el host ejecutan I/O.

---

## 4. Reglas de dependencias (verificadas por `cargo xtask check-layers`)

1. Un crate solo puede depender de crates de **su capa o inferiores** según `xtask/layers.toml`.
2. Los crates L1–L4 **no** pueden depender de: `tokio` ni otro runtime async, `reqwest`, `hyper`, `alloy`, `rusqlite`, ni de ningún crate de `services/`. Los crates L1–L3 son además `#![no_std]`: `check-layers` falla si alguno enlaza `std`.
3. `pip-verifier` **no** puede depender de `pip-sync`, `pip-ledger*`, `pip-storage*` ni `pip-transport-http` (persiste su estado mediante el trait `VerifierStateStore` de `pip-trust`).
4. Ningún crate de `crates/` puede depender de `bindings/`, `services/`, `apps/` o `spikes/`.
5. `pip-testkit` solo puede aparecer en `[dev-dependencies]`.
6. Los bindings solo pueden depender de `pip-sdk` (nunca de crates internos directamente).
7. Los servicios pueden depender de `pip-sdk` y de los adaptadores L5 (`pip-ledger-evm`, `pip-storage-sqlite`, `pip-transport-http`); no de crates internos salvo que `layers.toml` lo autorice explícitamente con justificación.

Violaciones ⇒ CI falla. Cambiar `layers.toml` requiere ADR.

```mermaid
flowchart BT
    types[pip-types] --> codec[pip-codec]
    codec --> crypto[pip-crypto]
    crypto --> keys[pip-keys]
    keys --> credential[pip-credential]
    crypto --> status[pip-status]
    status --> trust[pip-trust]
    credential --> verifier[pip-verifier]
    trust --> verifier
    credential --> holder[pip-holder]
    credential --> issuer[pip-issuer]
    crypto --> storage[pip-storage]
    storage --> holder
    holder --> recovery[pip-recovery]
    verifier --> protocol[pip-protocol]
    holder --> protocol
    recovery --> protocol
    protocol --> sync[pip-sync]
    trust --> ledger[pip-ledger]
    ledger --> evm[pip-ledger-evm]
    storage --> sqlite[pip-storage-sqlite]
    trust --> sqlite
    sync --> http[pip-transport-http]
    sync --> sdk[pip-sdk]
    issuer --> sdk
    ledger --> sdk
```

---

## 5. Configuración del workspace

### 5.1 Lints (en `Cargo.toml` del workspace)

```toml
[workspace.lints.rust]
unsafe_code = "deny"            # Ver nota sobre unsafe: "forbid" no admite excepciones ni sobrescritura por crate
missing_docs = "deny"
unused_must_use = "deny"

[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
indexing_slicing = "deny"
todo = "deny"
unimplemented = "deny"
dbg_macro = "deny"
print_stdout = "deny"
print_stderr = "deny"
float_arithmetic = "deny"          # CI compila con -D warnings: declararlos "deny" evita diferencias entre local y CI
arithmetic_side_effects = "deny"   # Usar checked_*/saturating_* en cálculos de tamaños e índices
```

**`unsafe`:** Cargo no permite heredar los lints del workspace y sobrescribir uno en un crate, y `forbid` no admite `allow` posteriores. Por eso el workspace declara `deny`, cada crate fuera de `bindings/` añade `#![forbid(unsafe_code)]` en su `lib.rs` (§6) y `cargo xtask check-layers` falla si falta. En `bindings/`, cada bloque lleva `#[allow(unsafe_code)]` local junto a su `// SAFETY:` (INV-09).

En pruebas (`#[cfg(test)]`, `tests/`, `benches/`, `xtask`, `pip-cli`) se permite `unwrap`/`expect` mediante `#![allow(...)]` local con comentario.

### 5.2 Perfiles de compilación

```toml
[profile.release]
lto = "fat"
codegen-units = 1
panic = "unwind"      # Necesario para catch_unwind en FFI
strip = "symbols"

[profile.release-mobile]
inherits = "release"
opt-level = "z"
```

`wasm32-unknown-unknown` no desenrolla aunque el perfil pida `unwind`: el binding WASM usa la estrategia de instancia envenenada de `ARCHITECTURE.md §3`. `opt-level = "z"` puede penalizar la criptografía; el valor definitivo (`z` o `s`) se fija con las mediciones de F2.T12.

### 5.3 Feature flags

- **Aditivas**: activar una feature nunca elimina comportamiento.
- Nombres en kebab-case; features peligrosas llevan `insecure-`/`dangerous-` (p. ej., `dangerous-allow-software-keys-financial` **no existirá**: es un ejemplo de lo que no se acepta).
- Cada combinación relevante se compila en CI con `cargo hack --feature-powerset` acotado.
- La elección de backend criptográfico **no** es una feature (sería excluyente, no aditiva): se hace por tipo (ADR-0007).

---

## 6. Estructura interna de cada crate

```text
crates/pip-<nombre>/
├── Cargo.toml          # lints.workspace = true; versión del workspace
├── README.md           # Propósito, capa, invariantes, requisitos que implementa
├── src/
│   ├── lib.rs          # Docs del crate, re-exports públicos, #![forbid(unsafe_code)]
│   ├── error.rs        # Enum de error con thiserror; #[non_exhaustive]
│   └── ...             # Un módulo por concepto; sin "utils.rs" genéricos
├── tests/              # Pruebas de integración (incluye vectores negativos)
└── benches/            # criterion (si aplica)
```

Reglas:

- Enums públicos: `#[non_exhaustive]`. Resultados importantes: `#[must_use]`.
- Tipos con secretos: `Zeroize`/`ZeroizeOnDrop`; `Debug` manual que imprime `[REDACTED]`.
- Ningún `pub` sin documentación con al menos un ejemplo en los tipos principales.
- Constructores validan invariantes (newtypes); no existen estados inválidos representables cuando el tipo lo permite.

---

## 7. Modelo de errores

- Cada crate define su error con `thiserror`. `anyhow` solo en binarios, `xtask` y pruebas.
- `pip-sdk` define `PipError` con **código estable** `PIP-Exxxx` (catálogo en `docs/specs/ERROR_CODES.md`):

| Rango | Área |
|---|---|
| E0001–E0999 | Codificación y entrada |
| E1000–E1999 | Criptografía y claves |
| E2000–E2999 | Credenciales y presentaciones |
| E3000–E3999 | Estado y confianza |
| E4000–E4999 | Almacenamiento |
| E5000–E5999 | Sincronización y transporte |
| E6000–E6999 | Ledger |
| E7000–E7999 | Recuperación |
| E9000–E9999 | Interno (E9999 = pánico capturado en FFI) |

- **Los resultados de verificación no son errores**: `Invalid` o `Unverifiable` son valores de `VerificationResult`, no `Err`. `Err` se reserva para fallos de uso de la API o del entorno.
- Un código publicado nunca cambia de significado.

---

## 8. Pruebas

| Tipo | Ubicación | Herramienta | Obligatorio en |
|---|---|---|---|
| Unitarias | `src/**` (`#[cfg(test)]`) | `cargo test` / `cargo nextest` | Todo crate |
| Integración y negativas | `crates/*/tests/` | `cargo nextest` | Todo crate L1–L4 |
| Propiedades | `tests/` | `proptest` | codec, credential, status, trust, verifier, storage |
| Vectores de conformidad | `conformance/vectors/` | `pip-conformance` | Desde F3 en Rust; desde F9 en cada lenguaje |
| Vectores externos | `crates/pip-crypto/tests/vectors/` | Project Wycheproof, ejemplos de RFC | pip-crypto, credential |
| Fuzzing | `fuzz/fuzz_targets/` | `cargo-fuzz` | Todo parser |
| Mutación | — | `cargo-mutants` | Reglas de rechazo de credential, status, trust y verifier (desde F4) |
| Comprobación acotada de modelos | `src/**` (`#[cfg(kani)]`) | Kani | pip-codec: ausencia de pánicos y de desbordamientos |
| Modelos formales de protocolo | `docs/specs/models/` | Tamarin o ProVerif | Presentación, re-vinculación y migración (F13) |
| Benchmarks | `benches/` | `criterion` | Desde F2 |
| Contratos | `contracts/test/` | Foundry (unit, fuzz, invariantes), Slither | F6 |
| Servicios | `services/*/tests/` | Testcontainers (PostgreSQL, nodo EVM local) | F7 |
| End-to-end | `apps/*/tests/`, `conformance/e2e/` | Escenarios scripted | F11 |

Reglas:

- Las pruebas **no** usan red real, reloj real ni aleatoriedad sin semilla (`pip-testkit`).
- Los vectores en `conformance/vectors/` son **inmutables**: un vector publicado nunca se edita; se añade uno nuevo y el antiguo se marca obsoleto con referencia a ADR.
- Nombres de prueba: `<comportamiento>_<condición>_<resultado>`, con `// Verifies: REQ-...` cuando aplique.

---

## 9. Integración continua

| Workflow | Disparador | Contenido |
|---|---|---|
| `ci.yml` | Cada PR y push a `main` | fmt, clippy (todas las features), build, nextest, doc (`-D warnings`), `xtask check-layers`, `xtask trace`, MSRV, `cargo hack` acotado, build `wasm32-unknown-unknown` y build *bare-metal* de L1–L3 (`no_std`) |
| `security.yml` | Cada PR + diario | `cargo-deny`, `cargo-audit`, revisión de nuevas dependencias, búsqueda de secretos |
| `mobile.yml` | Push a `main` + nocturno + PR con label `ci:mobile` | Android (cargo-ndk, todas las ABIs) e iOS (XCFramework); pruebas de bindings en emulador/simulador |
| `wasm.yml` | PR que toque `bindings/wasm` o crates L1–L4 | wasm-pack, pruebas en Node y navegador headless |
| `contracts.yml` | PR que toque `contracts/` | `forge build/test`, fuzz, invariantes, gas snapshot, Slither |
| `fuzz.yml` | Nocturno | Cada objetivo durante un tiempo fijo; corpus persistido; un crash ⇒ issue automático `type:bug` + `area:security` **privado** |
| `bench.yml` | Nocturno + PR con label `ci:bench` | criterion con comparación contra `main` (gate desde G9) |
| `release.yml` | Tag | Builds reproducibles, firma de artefactos, SBOM, publicación por canal |
| `docs.yml` | PR que toque `docs/` | Enlaces rotos, lint de Markdown, IDs de requisitos válidos |

`main` está protegida: PR obligatorio, CI verde, revisión de CODEOWNERS en rutas sensibles, historial lineal (squash merge).

---

## 10. Bindings

- Generados desde `pip-sdk` por `cargo xtask bindgen <lenguaje>`. El código generado **no se edita a mano** y **no se versiona** (salvo cabecera C, que se versiona y CI verifica que esté actualizada).
- Cada binding contiene: envoltorio idiomático mínimo (solo ergonomía, sin lógica), implementación de `KeyStore` de plataforma, pruebas que ejecutan `conformance/vectors/`, ejemplo ejecutable.
- Los adaptadores de plataforma (Android Keystore, Secure Enclave, WebCrypto, IndexedDB) viven en el binding de su plataforma y tienen pruebas en dispositivo/emulador.

---

## 11. Servicios

```text
services/pip-<servicio>/
├── src/
│   ├── main.rs        # Arranque: config, telemetría, señales
│   ├── config.rs      # Config tipada desde entorno; secretos solo por referencia a KMS/gestor
│   ├── http/          # Rutas axum (si aplica)
│   ├── domain/        # Lógica; llama a pip-sdk
│   └── store/         # Persistencia (sqlx + PostgreSQL con migraciones)
├── migrations/
├── tests/
└── Dockerfile -> deploy/docker/
```

Principios: sin estado en memoria entre peticiones (escalado horizontal y serverless), idempotencia en toda mutación, endpoints `/healthz` y `/readyz`, apagado ordenado, ninguna credencial completa ni PII en logs.

---

## 12. Contratos

- Solidity con Foundry; versión del compilador fijada.
- Dependencias externas (p. ej., OpenZeppelin) fijadas por commit.
- Sin proxies actualizables (REQ-LEDG-003).
- Cada función que muta estado emite un evento; funciones, roles, eventos y errores están versionados y documentados en `docs/specs/CONTRACTS.md`.
- Scripts de despliegue deterministas; direcciones desplegadas registradas en `deploy/environments/<entorno>/contracts.json` (públicas, sin secretos).

---

## 13. Convenciones

| Elemento | Convención |
|---|---|
| Ramas | `<tipo>/<issue>-<slug>` — p. ej., `feat/142-status-list-parser`, `fix/201-kb-jwt-aud` |
| Commits | Conventional Commits: `feat(pip-status): parse token status list (#142)` |
| Tipos de commit | `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`, `security` |
| PRs | Un issue por PR; título en formato de commit; plantilla completa |
| Versiones | SemVer. Crates del SDK en *lockstep* (misma versión). Servicios y contratos con versión propia |
| Tags | `sdk-vX.Y.Z`, `svc-<servicio>-vX.Y.Z`, `contracts-vX.Y.Z`, `spec-vX.Y` |
| ADRs | `docs/adr/NNNN-titulo-en-kebab.md`, numeración consecutiva |
| Idioma | Documentación de gobierno en español; código, identificadores, rustdoc, commits y mensajes de error en inglés |
