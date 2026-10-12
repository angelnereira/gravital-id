# gravital-id-trust

> **Capa:** L2 · **no_std:** Sí (`#![no_std]` + `alloc`)

## Propósito

Raíz de confianza, trust bundle multi-firma y políticas de verificación para Gravital ID.

## Invariantes aplicables

- **INV-01:** Cero I/O en L1–L4 (L1–L3 `no_std`, L4 sans-I/O).
- **INV-09:** Sin código `unsafe` (`#![forbid(unsafe_code)]`).
- **INV-10:** Sin pánicos en código de biblioteca.
