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
| 0002 | Licencia y política de contribución | Propuesto | Dual MIT / Apache-2.0; DCO | F0 |
| 0003 | Formato de credencial v1 | Propuesto | SD-JWT VC (RFC 9901 + borrador SD-JWT VC fijado) | F0 |
| 0004 | Red blockchain | Propuesto | EVM; Ethereum L1 vs L2 madura tras spike | F0 |
| 0005 | Mecanismo de estado y revocación | Propuesto | Token Status List (IETF) | F0 |
| 0006 | Estrategia de bindings | Propuesto | UniFFI + wasm-bindgen + C ABI + flutter_rust_bridge | F0 |
| 0007 | Backend criptográfico | Propuesto | RustCrypto por defecto; aws-lc-rs (FIPS) solo servicios | F0 |
| 0008 | Almacenamiento local | Propuesto | SQLite + AEAD por registro; backend inyectable | F0 |
| 0009 | Modelo de recuperación | Propuesto | Código de recuperación + Shamir opcional + re-vinculación | F0 |
| 0010 | Formato del trust bundle | Propuesto | JWS ES256 sobre JSON acotado | F0 |
| 0011 | Transporte offline | Propuesto | QR en dos pasos, DEFLATE + Base45, multi-QR | F0 |
| 0012 | Modelo de gobernanza del registro | Propuesto | Multisig + timelock + rol de emergencia | F0 |
| 0013 | Proveedor de nube inicial | Propuesto | Neutral (imágenes OCI + IaC) | F7 |
| 0014 | Toolchain de Rust y MSRV | Propuesto | Rust estable fijado; MSRV declarado | F1 |
| 0015 | SD-JWT: construir o reutilizar | Propuesto | Evaluar crates existentes vs implementación propia | F3 |

_Los archivos de cada ADR se crean cuando se redacta su propuesta completa (tarea F0.T11 y siguientes)._
