# Gravital ID — Protocolo de Identidad Portable

> **Portabilidad real · Verificación offline sans-I/O · Divulgación selectiva · Cero datos personales en cadena · Recuperación segura**

Gravital ID es un protocolo de identidad portable con núcleo en Rust (`#![no_std]` + `alloc` en L1–L3, sans-I/O en L4). Permite emitir credenciales verificables, almacenarlas cifradas en el dispositivo del titular, presentar únicamente los atributos consentidos y **verificarlas completamente sin conexión y sin depender de un servidor central**. Una blockchain pública actúa exclusivamente como registro de confianza compartido (qué emisores y claves son válidos), **nunca** para almacenar datos personales ni sus hashes.

El núcleo se distribuye como biblioteca Rust pura y se integra a través de bindings y SDKs multiplataforma para Kotlin (Android), Swift (iOS), TypeScript/JavaScript (Web/Node), Dart (Flutter), Python, Go, C# y C ABI.

---

## Principios y Diferenciadores

1. **Verificación Offline Real (sans-I/O):** La verificación de presentaciones nunca realiza llamadas de red (INV-01). Todas las claves de emisor se obtienen exclusivamente del *trust bundle* multi-firma autenticado localmente (INV-06).
2. **Privacidad Radical (Cero PII en Blockchain y Logs):** Ningún dato personal, ni hash de dato personal, ni identificador de titular se publica en el ledger, ni en logs, ni en métricas, ni en mensajes de error (INV-02).
3. **Sin Custodia de Claves Privadas:** Ningún servicio custodia claves privadas de titulares. Las firmas del titular se delegan a hardware seguro (Secure Enclave, StrongBox) o almacenes de claves locales; las claves privadas nunca cruzan FFI (INV-03).
4. **Confianza Distribuida por Umbral:** Ninguna clave única decide la confianza de un dispositivo offline: la raíz y el trust bundle exigen cofirmas $k$-de-$n$ de operadores independientes (INV-16).
5. **Resultado de Verificación de 4 Estados:** El resultado de verificación proporciona evidencia exhaustiva y nunca se colapsa a un booleano: `Valid`, `ValidWithStaleStatus`, `Unverifiable`, `Invalid` (INV-04), con precedencia estricta y filosofía *fail-closed* (INV-05).
6. **Determinismo Absoluto:** El núcleo no lee el reloj del sistema ni fuentes de entropía implícitas; el instante temporal (`UnixTime`) y los generadores CSPRNG se inyectan explícitamente (INV-11).

---

## Invariantes No Negociables del Protocolo

Cualquier cambio que viole estos invariantes es automáticamente rechazado:

| Invariante | Descripción |
|---|---|
| **INV-01** | La verificación **nunca** realiza I/O de red. Capas L1–L3 son `no_std`, L4 es sans-I/O; el I/O vive en adaptadores L5 y en el host. |
| **INV-02** | **Ningún dato personal**, ni hash de dato personal, ni identificador de titular va al ledger, logs, métricas ni errores. |
| **INV-03** | Ningún servicio custodia claves privadas de titulares. Las claves privadas de titulares nunca cruzan FFI. |
| **INV-04** | El resultado de verificación tiene **cuatro estados** con evidencia: `Valid`, `ValidWithStaleStatus`, `Unverifiable`, `Invalid`. |
| **INV-05** | **Fail-closed**: ante cualquier error, dato faltante, ambigüedad o excepción, el resultado nunca es `Valid`. |
| **INV-06** | Las claves de emisor se obtienen **solo** del trust bundle; nunca de cabeceras `jku`, `x5u`, `x5c` o `jwk`, ni de la red. |
| **INV-07** | Ninguna primitiva criptográfica propia; uso exclusivo de suites auditadas a través de `gravital-id-crypto`. |
| **INV-08** | Algoritmos fijados en `CRYPTO_PROFILES.md`: ES256 y SHA-256. `alg: none` siempre es rechazado. |
| **INV-09** | Sin código `unsafe` fuera de `bindings/`. Cada bloque lleva justificación `// SAFETY:`. |
| **INV-10** | Sin `unwrap`, `expect`, `panic!`, `todo!` ni indexación con riesgo de pánico en bibliotecas. |
| **INV-11** | El núcleo no lee el reloj ni aleatoriedad implícitamente: se inyectan (`Clock`, CSPRNG inyectado). |
| **INV-12** | Los vectores de conformidad publicados en `conformance/vectors/` son **inmutables**. |
| **INV-13** | Ninguna fase de la hoja de ruta se salta; ningún criterio de aceptación se marca sin cumplir. |
| **INV-14** | Las vulnerabilidades se gestionan exclusivamente mediante avisos privados de seguridad (`SECURITY.md`). |
| **INV-15** | Los bindings no contienen lógica de negocio; solo ergonomía y adaptadores de plataforma. |
| **INV-16** | Ninguna clave única decide la confianza offline: raíz y trust bundle exigen umbral multi-firma $k$-de-$n$. |

---

## Arquitectura de Capas y Crates del Workspace

El repositorio organiza el protocolo en 20 crates modulares con límites de dependencia estrictos verificados por `cargo xtask check-layers`:

```text
┌────────────────────────────────────────────────────────────────────────┐
│ L6 / Bindings / Aplicaciones: gravital-id-sdk, bindings/wasm, CLI      │
├────────────────────────────────────────────────────────────────────────┤
│ L5 (Host & I/O): -storage-sqlite, -transport-http, -ledger-evm         │
├────────────────────────────────────────────────────────────────────────┤
│ L4 (Sans-I/O & Flujos): gravital-id-holder, -protocol, -sync           │
├────────────────────────────────────────────────────────────────────────┤
│ L3 (Lógica de Verificación & Emisión): -issuer, -verifier, -recovery   │
├────────────────────────────────────────────────────────────────────────┤
│ L2 (Dominio Criptográfico & Confianza): -keys, -credential, -status,   │
│                                         -trust, -ledger, -storage      │
├────────────────────────────────────────────────────────────────────────┤
│ L1 (Tipos Fundamentales & Codecs): -types, -codec, -crypto             │
└────────────────────────────────────────────────────────────────────────┘
```

### Componentes Implementados

| Capa | Crate | Estado | Descripción |
|---|---|---|---|
| **L1** | `gravital-id-types` | **Listo** | Identificadores validados (`IssuerId`, `Kid`, `Vct`, `ProfileId`, `UnixTime`), catálogo de errores `GidError` con 48 códigos normativos y trait `Clock`. |
| **L1** | `gravital-id-codec` | **Listo** | Parsers acotados anti-DoS: `base64url` estricto sin relleno, JSON acotado RFC 8259, CBOR determinista RFC 8949, DEFLATE acotado (2 MiB, 10:1) y Base45 RFC 9285. |
| **L1** | `gravital-id-crypto` | **Listo** | Primitivas criptográficas fijadas: ES256 (RFC 6979), SHA-256, HMAC, HKDF (RFC 5869), XChaCha20-Poly1305, HPKE Base (RFC 9180), JWK EC P-256 (RFC 7517/7638) e higiene de secretos con `Zeroize`. |
| **L2** | `gravital-id-keys` | **Listo** | Abstracción `KeyStore`, handles tipados por propósito (`SigningPurpose`: `IssuerSigning`, `HolderBinding`, `BundleSigning`), `SoftwareKeyStore` y normalización DER↔P1363. |
| **L2** | `gravital-id-credential` | **Listo** | Emisión, parseo y verificación SD-JWT (RFC 9901): divulgaciones de objetos y arrays, sal $\ge 128$ bits, decoys, Key Binding JWT (`typ: kb+jwt`), capa SD-JWT VC (`typ: dc+sd-jwt`), esquemas de perfil (`pip-personal-v1`, `pip-financial-v1`, `pip-enterprise-v1`) y predicados de calendario. |
| **L2** | `gravital-id-status` | **Listo** | Token Status List JWT comprimido (1 y 2 bits), manifiesto de emisor `IssuerStatusManifest` con versión monotónica, `StatusSnapshot` y `StatusCache` acotada con políticas de frescura por perfil. |
| **L2** | `gravital-id-trust` | **Listo** | Raíz de confianza `TrustRoot` con encadenamiento multi-firma, `TrustBundle` derivado con cofirmas $k$-de-$n$ de operadores independientes, estados de clave (`active`, `retired`, `suspended`, `compromised`) y anti-rollback. |
| **L3** | `gravital-id-issuer` | **Listo** | API de construcción y firma de credenciales; emisión individual y por lotes con claves, sales e índices independientes. |
| **L3** | `gravital-id-verifier` | **En curso (F4)** | Piso de tiempo confiable `TimeFloorGuard` anti-rollback, `VerifierStateStore`, caché de nonces anti-replay, `VerificationPolicy` y pipeline de comprobaciones ordenadas con typestate. |
| **L6** | `gravital-id-sdk` | **Listo** | Fachada unificada del SDK para integradores. |
| **Test** | `gravital-id-testkit` | **Listo** | Entorno determinista para pruebas: `FixedClock` y `SeededRng` (xoshiro256** reproducible). |
| **WASM**| `bindings/wasm` | **Listo** | Bindings WebAssembly (`wasm32-unknown-unknown`) con pruebas de humo FFI en Node.js. |

---

## Verificación y Calidad de Código

El repositorio cuenta con una batería integral de pruebas unitarias, de integración, vectores normativos externos, análisis estático estricto y fuzzing continuo:

- **Vectores de conformidad normativos:** Suite de 24 vectores de prueba para SD-JWT VC (`conformance/vectors/sd-jwt-vc/`).
- **Vectores criptográficos externos superados al 100 %:** RFC 7515 (JWS ES256), RFC 7638 (Thumbprints), RFC 5869 (HKDF), RFC 9180 (HPKE) y Proyecto Wycheproof (484/484 ECDSA P-256 y 315/315 AEAD).
- **Cobertura de pruebas:** $\ge 90\,\%$ de cobertura de líneas en crates criptográficos y del verificador.
- **Parsers con fuzzing en CI:** Objetivos de fuzzing dedicados para todos los parsers de frontera (`base64url`, `json`, `cbor`, `base45`, `deflate`, `jwk`, `sd_jwt`).
- **Verificación cruzada de arquitecturas:** Compilación y pruebas locales y en CI para x86_64, aarch64, WebAssembly (`wasm32-unknown-unknown`) y bare-metal embebido (`thumbv7em-none-eabihf`).

### Comandos de Verificación Local

```bash
# 1. Compilación de todo el workspace
cargo build --workspace --all-targets

# 2. Ejecución de la suite completa de pruebas
cargo test --workspace

# 3. Lints estrictos sin advertencias permitidas
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check

# 4. Verificación de reglas de capas arquitectónicas y no_std
cargo xtask check-layers

# 5. Validación de la matriz de trazabilidad de requisitos (REQUIREMENTS.md)
cargo xtask trace

# 6. Verificación del catálogo canónico de errores (ERROR_CODES.md)
cargo xtask check-error-codes

# 7. Ejecución de vectores de conformidad SD-JWT VC
cargo xtask conformance

# 8. Auditoría de seguridad y dependencias
cargo deny check
cargo audit

# 9. Verificación de compilación en targets no_std y WebAssembly
cargo check -p gravital-id-credential --target wasm32-unknown-unknown
cargo check -p gravital-id-credential --target thumbv7em-none-eabihf
```

---

## Gobernanza y Documentación del Proyecto

El desarrollo se rige por el principio **spec-first**: la documentación técnica y las decisiones de arquitectura preceden al código.

| Documento | Propósito |
|---|---|
| [`AGENTS.md`](AGENTS.md) | **Reglas obligatorias** para agentes y desarrolladores: protocolo de sesión, Definition of Done y manejo de issues. |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Arquitectura del sistema, modelo de confianza, amenazas, protocolos y especificación técnica general. |
| [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md) | Catálogo de requisitos funcionales y no funcionales trazables (`REQ-*`). |
| [`docs/PROJECT_STRUCTURE.md`](docs/PROJECT_STRUCTURE.md) | Jerarquía de capas, reglas de dependencia entre crates y directrices de implementación. |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Hoja de ruta completa en 19 fases (F0–F18) y sus respectivos gates de calidad (G0–G17). |
| [`docs/STATUS.md`](docs/STATUS.md) | Estado vivo del avance del proyecto y notas de traspaso de cada sesión. |
| [`docs/TRACEABILITY.md`](docs/TRACEABILITY.md) | Matriz viva de trazabilidad entre requisitos normativos y pruebas del repositorio. |
| [`docs/specs/`](docs/specs/) | Especificaciones normativas: `CRYPTO_PROFILES`, `TRUST_BUNDLE`, `PROTOCOL`, `CONTRACTS`, `SDK_API`, `ERROR_CODES` y perfiles de credencial. |
| [`docs/adr/`](docs/adr/) | Registros de Decisiones de Arquitectura (ADRs aceptados y propuestos). |
| [`SECURITY.md`](SECURITY.md) | Política de reporte responsable de vulnerabilidades y seguridad del proyecto. |

---

## Licencia

Este proyecto se distribuye bajo **licencia dual MIT y Apache-2.0** (a elección del receptor), conforme a la decisión formal documentada en [`ADR-0002`](docs/adr/0002-licencia-y-contribucion.md).

- [`LICENSE-MIT`](LICENSE-MIT)
- [`LICENSE-APACHE`](LICENSE-APACHE)
- [`CONTRIBUTING.md`](CONTRIBUTING.md)
