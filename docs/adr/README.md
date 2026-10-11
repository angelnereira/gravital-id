# Architecture Decision Records

Un ADR registra una decisión difícil de revertir: contexto, opciones, decisión y consecuencias. Reglas en `AGENTS.md §12`.

- Archivo: `NNNN-titulo-en-kebab.md`, numeración consecutiva, plantilla [`0000-template.md`](0000-template.md).
- Estados: **Propuesto** → **Aceptado** / **Rechazado** · **Diferido** (con fase límite) · **Sustituido por NNNN**.
- Un ADR propuesto por un agente solo lo acepta un mantenedor humano.
- Al aceptar un ADR que cambie la arquitectura, `docs/ARCHITECTURE.md` se actualiza en el mismo PR.

## Índice

| ADR | Título | Estado | Propuesta inicial (ver `ARCHITECTURE.md §22`) | Debe decidirse en |
|---|---|---|---|---|
| 0001 | Nombre del proyecto y de los paquetes | Propuesto | Nombre sin colisiones en registros de paquetes | F0 |
| [0002](0002-licencia-y-contribucion.md) | Licencia y política de contribución | Aceptado | Dual MIT / Apache-2.0; DCO 1.1 | F0 |
| 0003 | Formato de credencial v1 | Propuesto | SD-JWT VC (RFC 9901 + borrador SD-JWT VC fijado); alineación con HAIP 1.0 (`x5c`) | F0 |
| 0004 | Red blockchain | Propuesto | EVM; Ethereum L1 vs L2 madura tras spike | F0 |
| 0005 | Mecanismo de estado y revocación | Propuesto | Token Status List (IETF) | F0 |
| 0006 | Estrategia de bindings | Propuesto | UniFFI + wasm-bindgen + C ABI + flutter_rust_bridge; estrategia de pánicos en WASM | F0 |
| 0007 | Backend criptográfico | Propuesto | RustCrypto por defecto; aws-lc-rs (FIPS) condicional y seleccionado por tipo, no por feature | F0 |
| 0008 | Almacenamiento local | Propuesto | SQLite + AEAD por registro; backend inyectable | F0 |
| 0009 | Modelo de recuperación | Propuesto | Código de recuperación + Shamir opcional + re-vinculación con claves por emisor + SAS con compromiso previo | F0 |
| 0010 | Formato del trust bundle | Propuesto | JWS JSON multi-firma (ES256) sobre payload canónico (JCS) acotado | F0 |
| 0011 | Transporte offline | Propuesto | QR en dos pasos, transcodificación binaria + DEFLATE + Base45, multi-QR (indexado frente a códigos fuente) | F0 |
| 0012 | Modelo de gobernanza del registro | Propuesto | Multisig + timelock + rol de emergencia limitado a suspender | F0 |
| 0013 | Proveedor de nube inicial | Propuesto | Neutral (imágenes OCI + IaC) | F7 |
| 0014 | Toolchain de Rust y MSRV | Propuesto | Rust estable fijado; MSRV declarado | F1 |
| 0015 | SD-JWT: construir o reutilizar | Propuesto | Evaluar crates existentes vs implementación propia | F3 |
| [0016](0016-confianza-por-umbral.md) | Confianza por umbral: raíz encadenada y bundles cofirmados | Aceptado | Raíz offline k-de-n + bundles k-de-n con derivación determinista | F0 |
| [0017](0017-manifiesto-de-estado.md) | Manifiesto de estado separado del trust bundle | Aceptado | Punteros a listas de estado fuera del bundle | F0 |
| [0018](0018-emergencia-solo-suspension.md) | Alcance del rol de emergencia | Aceptado | Solo suspensión reversible con caducidad | F0 |
| [0019](0019-nucleo-no-std-y-sans-io.md) | Núcleo `no_std` y protocolos sans-I/O | Aceptado | L1–L3 `no_std` + `alloc`; L4 sans-I/O; adaptadores en L5 | F1 |
| [0020](0020-fail-closed-por-tipos.md) | Fail-closed por tipos y resultado por comprobación | Aceptado | Typestate + `Passed`/`Failed`/`Indeterminate`/`Skipped` | F0 |

_Los archivos de cada ADR se crean cuando se redacta su propuesta completa (tarea F0.T11 y siguientes). Los ADR 0016–0020 proceden de la revisión de arquitectura del 2026-10-10; la columna de propuesta de 0003, 0006, 0007, 0009, 0010, 0011 y 0012 se ajustó en esa misma revisión._
