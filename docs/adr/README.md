# Architecture Decision Records

Un ADR registra una decisión difícil de revertir: contexto, opciones, decisión y consecuencias. Reglas en `AGENTS.md §12`.

- Archivo: `NNNN-titulo-en-kebab.md`, numeración consecutiva, plantilla [`0000-template.md`](0000-template.md).
- Estados: **Propuesto** → **Aceptado** / **Rechazado** · **Diferido** (con fase límite) · **Sustituido por NNNN**.
- Un ADR propuesto por un agente solo lo acepta un mantenedor humano.
- Al aceptar un ADR que cambie la arquitectura, `docs/ARCHITECTURE.md` se actualiza en el mismo PR.

## Índice

| ADR | Título | Estado | Propuesta inicial (ver `ARCHITECTURE.md §22`) | Debe decidirse en |
|---|---|---|---|---|
| [0001](0001-nombre-definitivo.md) | Nombre definitivo del proyecto y prefijo de paquetes | Aceptado | Gravital ID (`gravital-id` / `gid`); sin colisiones | F0 |
| [0002](0002-licencia-y-contribucion.md) | Licencia y política de contribución | Aceptado | Dual MIT / Apache-2.0; DCO 1.1 | F0 |
| [0003](0003-formato-credencial-v1.md) | Formato de credencial v1 | Aceptado | SD-JWT VC (RFC 9901 + borrador SD-JWT VC fijado); alineación con HAIP 1.0 (`x5c`) | F0 |
| [0004](0004-red-blockchain.md) | Red blockchain | Aceptado | EVM; Arbitrum / Base (L2) con anclaje tras spike | F0 |
| [0005](0005-mecanismo-estado-revocacion.md) | Mecanismo de estado y revocación | Aceptado | Token Status List (IETF) | F0 |
| [0006](0006-estrategia-bindings.md) | Estrategia de bindings | Aceptado | UniFFI + wasm-bindgen + C ABI + flutter_rust_bridge; estrategia de pánicos en WASM | F0 |
| [0007](0007-backend-criptografico.md) | Backend criptográfico | Aceptado | RustCrypto por defecto; aws-lc-rs (FIPS) condicional y seleccionado por tipo, no por feature | F0 |
| [0008](0008-almacenamiento-local.md) | Almacenamiento local | Aceptado | SQLite WAL + AEAD por registro; backend inyectable | F0 |
| [0009](0009-modelo-recuperacion.md) | Modelo de recuperación | Aceptado | Código de recuperación + Shamir opcional + re-vinculación con claves por emisor + SAS con compromiso previo | F0 |
| [0010](0010-formato-trust-bundle.md) | Formato del trust bundle | Aceptado | JWS JSON multi-firma (ES256) sobre payload canónico (JCS) acotado | F0 |
| [0011](0011-transporte-offline.md) | Transporte offline | Aceptado | QR en dos pasos, transcodificación binaria + DEFLATE + Base45, multi-QR (indexado frente a códigos fuente) | F0 |
| [0012](0012-modelo-gobernanza.md) | Modelo de gobernanza del registro | Aceptado | Multisig + timelock + rol de emergencia limitado a suspender | F0 |
| [0013](0013-infraestructura-y-despliegue.md) | Proveedor de nube inicial e infraestructura | Aceptado | Neutral (imágenes OCI + IaC con OpenTofu/Terraform; AWS referencia testnet) | F7 |
| [0014](0014-toolchain-rust-y-msrv.md) | Toolchain de Rust y MSRV | Aceptado | Rust 1.85.0 fijado; MSRV declarado y verificado en CI | F1 |
| [0015](0015-sd-jwt-construir-o-reutilizar.md) | SD-JWT: construir o reutilizar | Propuesto | Construir en `gravital-id-credential` (L2 `no_std`) sobre L1 | F3 |
| [0016](0016-confianza-por-umbral.md) | Confianza por umbral: raíz encadenada y bundles cofirmados | Aceptado | Raíz offline k-de-n + bundles k-de-n con derivación determinista | F0 |
| [0017](0017-manifiesto-de-estado.md) | Manifiesto de estado separado del trust bundle | Aceptado | Punteros a listas de estado fuera del bundle | F0 |
| [0018](0018-emergencia-solo-suspension.md) | Alcance del rol de emergencia | Aceptado | Solo suspensión reversible con caducidad | F0 |
| [0019](0019-nucleo-no-std-y-sans-io.md) | Núcleo `no_std` y protocolos sans-I/O | Aceptado | L1–L3 `no_std` + `alloc`; L4 sans-I/O; adaptadores en L5 | F1 |
| [0020](0020-fail-closed-por-tipos.md) | Fail-closed por tipos y resultado por comprobación | Aceptado | Typestate + `Passed`/`Failed`/`Indeterminate`/`Skipped` | F0 |
| [0021](0021-ampliacion-alcance-identidad-portable.md) | Ampliación de alcance: NFC, tarjeta física, código numérico e identidad portable | Aceptado | Añadir pista F19–F25 (hitos MP1–MP3), adelantar subconjuntos F9 y mover NFC a F21 | F19 |
| [0022](0022-transporte-proximidad-gid-apdu.md) | Transporte de proximidad y protocolo GID-APDU | Aceptado | GID-APDU (ISO 7816-4) sobre SD-JWT VC + BLE condicional; mdoc en F25 | F19 |
| [0023](0023-cifrado-sesion-proximidad-transcrito.md) | Cifrado de sesión de proximidad y vinculación al transcrito | Aceptado | Respuesta sellada con HPKE (RFC 9180) + AAD y KB-JWT ligados a `SessionTranscript` | F19 |
| [0024](0024-tarjeta-fisica-javacard.md) | Arquitectura de tarjeta física Java Card y personalización | Aceptado | Applet Java Card 3.0.5+ con P-256 en hardware, PIN por niveles y `gid-perso` | F19 |
| [0025](0025-identificadores-numericos-sesion.md) | Modelo de identificadores numéricos de 9–10 dígitos | Aceptado | `SessionCode` efímero (10 dígitos + Damm) en línea; número por emisor opcional | F19 |
| [0026](0026-perfil-identidad-retrato.md) | Perfil de identidad portable `pip-identity-v1` y tratamiento del retrato | Aceptado | Variantes oficial/derivada con `vct` distintos; retrato JPEG $\le 16\text{ KiB}$ solo por NFC/BLE | F19 |

_Los ADRs de F0 (0001–0012, 0016–0018 y 0020), los ADRs de F1 (0014 y 0019), los ADRs de F19 (0021–0026) y el ADR de F7 (0013) han sido redactados y aceptados formalmente. El ADR-0015 (F3.T01) se encuentra redactado en estado **Propuesto**._
