# gravital-id-keys

> **Capa:** L1 · **no_std:** Sí (`#![no_std]` + `alloc`)

## Propósito

Gestión y traits de claves, propósitos de clave y normalización de firmas para Gravital ID.

## Invariantes aplicables

- **INV-01:** Cero I/O en L1–L4 (L1–L3 `no_std`, L4 sans-I/O).
- **INV-09:** Sin código `unsafe` (`#![forbid(unsafe_code)]`).
- **INV-10:** Sin pánicos en código de biblioteca.
