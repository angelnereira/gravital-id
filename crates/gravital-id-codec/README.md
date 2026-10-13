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

- Lector CBOR acotado (`cbor.rs`, F2.T04): límites de entrada, profundidad,
  elementos y texto; enteros sin pérdida (`-(1+n)` con `n` en `u64`); etiquetas y
  valores simples. Modo determinista por defecto (RFC 8949 §4.2): argumentos más
  cortos, sin longitudes indefinidas, claves de mapa únicas y ordenadas por
  *(longitud, bytes)*, sin NaN/Infinity y flotantes en su anchura mínima. Vector
  de prueba: apéndice A de RFC 8949 y objetivo de fuzzing
  (`fuzz/fuzz_targets/cbor_bounded.rs`, 5.2M ejecuciones sin fallos).

- DEFLATE acotado (`deflate.rs`, F2.T05): contenedor zlib (RFC 1950/1951) con
  backend puro Rust `no_std` (`miniz_oxide`, ADR-0007); descompresión con
  **límite efectivo** = mínimo entre 2 MiB absolutos y ratio 10:1 de la entrada
  (`CRYPTO_PROFILES.md §5.1`), con verificación de integridad adler32. El
  perfil predeterminado (`inflate`) es el de listas de estado; el transporte QR
  usa `inflate_bounded` con sus propios límites.
- Base45 (`base45.rs`, F2.T05): RFC 9285 con los vectores del RFC ("AB"→"BB8",
  "Hello!!"→"%69 VD92EX0", "base-45"→"UJCLQE7W581", "QED8WEX0"→"ietf!") y
  validación estricta §6 (alfabeto, longitudes, tríos ≤ 65535).

## Invariantes aplicables

- **INV-01:** Cero I/O en L1–L4 (L1–L3 `no_std`, L4 sans-I/O).
- **INV-09:** Sin código `unsafe` (`#![forbid(unsafe_code)]`).
- **INV-10:** Sin pánicos en código de biblioteca.
