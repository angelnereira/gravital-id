# gravital-id-types

> **Capa:** L1 · **no_std:** Sí (`#![no_std]` + `alloc`)

## Propósito

Identificadores validados, marcas de tiempo y tipos fundamentales del protocolo Gravital ID.

## Contenido actual (F1)

- Catálogo canónico de errores `GidError`/`PipError` (`error.rs`, `ERROR_CODES.md`).
- Trait `Clock` de inyección de tiempo (`clock.rs`, `SDK_API.md §3.2`, INV-11).

## Invariantes aplicables

- **INV-01:** Cero I/O en L1–L4 (L1–L3 `no_std`, L4 sans-I/O).
- **INV-09:** Sin código `unsafe` (`#![forbid(unsafe_code)]`).
- **INV-10:** Sin pánicos en código de biblioteca.
