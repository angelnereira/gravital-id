# gravital-id-sdk

> **Capa:** L6 · **no_std:** No (utiliza `std`)

## Propósito

Fachada y API pública del SDK de Gravital ID.

## Invariantes aplicables

- **INV-01:** Cero I/O en L1–L4 (L1–L3 `no_std`, L4 sans-I/O).
- **INV-09:** Sin código `unsafe` (`#![forbid(unsafe_code)]`).
- **INV-10:** Sin pánicos en código de biblioteca.
