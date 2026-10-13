# gravital-id-codec

> **Capa:** L1 · **no_std:** Sí (`#![no_std]` + `alloc`)

## Propósito

Codificación y serialización acotada (base64url, JSON, CBOR, Base45) para Gravital ID.

## Contenido actual (F2)

- `base64url` estricta (`base64url.rs`, F2.T02): alfabeto URL-safe, sin relleno,
  rechazo de caracteres no canónicos y de bits sobrantes no nulos, con cota de
  entrada/salida (`MAX_INPUT_LEN`). Pruebas con vectores RFC 4648 §10 y objeto
  de fuzzing (`fuzz/fuzz_targets/base64url_strict.rs`).

- Lector JSON acotado y estricto (`json.rs`, F2.T03): límites de entrada,
  profundidad, elementos por contenedor y longitud de cadena; rechazo de
  miembros duplicados (REQ-CRED-009); UTF-8 estricto (suplentes `\uD800`–`\uDFFF`
  huérfanos y CESU-8 rechazados); enteros fuera de `i64`/`u64` y flotantes no
  finitos rechazados. Los valores conservan el orden del documento. Prueba
  diferencial frente a `serde_json` (solo en tests; en producción el crate es
  `no_std` y no depende de ella) y objetivo de fuzzing
  (`fuzz/fuzz_targets/json_bounded.rs`).

## Invariantes aplicables

- **INV-01:** Cero I/O en L1–L4 (L1–L3 `no_std`, L4 sans-I/O).
- **INV-09:** Sin código `unsafe` (`#![forbid(unsafe_code)]`).
- **INV-10:** Sin pánicos en código de biblioteca.
