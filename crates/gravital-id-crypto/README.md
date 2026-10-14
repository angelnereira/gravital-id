# gravital-id-crypto

> **Capa:** L1 · **no_std:** Sí (`#![no_std]` + `alloc`)

## Propósito

Abstracciones y backend criptográfico (ES256, SHA-256, HMAC, XChaCha20-Poly1305, HPKE) para Gravital ID.

## Contenido (F2.T06, F2.T07, F2.T08, F2.T09)

- **Firmas ES256 (`sign.rs`):** Firma determinista RFC 6979 en IEEE P1363 (`r‖s`, 64 bytes), conversión DER ↔ P1363 y verificación flexible (sin exigir *low-S*, REQ-KEY-010).
- **Funciones hash (`sha.rs`):** SHA-256 en un solo paso (`sha256`) y streaming (`Sha256Hasher`).
- **Autenticación de mensajes (`mac.rs`):** HMAC-SHA-256 y comparación en tiempo constante (`constant_time_eq`, `subtle`).
- **Derivación de claves (`kdf.rs`):** HKDF-SHA256 (`hkdf_sha256`, `hkdf_extract_sha256`, RFC 5869).
- **Cifrado autenticado (`aead.rs`):** XChaCha20-Poly1305 (`seal`, `open`, REQ-SEC-002).
- **Acuerdo de claves (`ecdh.rs`):** ECDH P-256 (`agree`, `agree_ephemeral`).
- **HPKE modo base (`hpke.rs`):** RFC 9180 con `DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + ChaCha20Poly1305` (modo base, suite ID completo).
- **Aleatoriedad inyectada (`rng.rs`):** Trait `Rng` sin entropía implícita (INV-11).
- **JWK y Thumbprints (`jwk.rs`):** Parseo estricto de JWK EC P-256 con validación de punto en curva, rechazo estricto de parámetros privados (`d`) y cálculo de huellas RFC 7638 en base64url y SHA-256 (REQ-KEY-007).
- **Vectores externos (`tests/external_vectors.rs`):** Verificación contra RFC 7515, RFC 7638, RFC 5869, RFC 9180, y Project Wycheproof (ECDSA P-256 484/484 y XChaCha20-Poly1305 315/315) (F2.T08, REQ-SEC-002).
- **Higiene de secretos (`secret.rs`):** Tipos `SecretBytes`, `SecretVec`, `SecretKeyBytes`, `AeadKeyBytes`, `SharedSecret`, `HmacKeyBytes` con zeroización segura en drop (`Zeroize`, `ZeroizeOnDrop`), representación `Debug`/`Display` redactada permanentemente (`[REDACTED]`), y comparación en tiempo constante (`subtle::ConstantTimeEq`) (F2.T09, REQ-SEC-003, REQ-SEC-004).

## Invariantes aplicables

- **INV-01:** Cero I/O en L1–L4 (L1–L3 `no_std`, L4 sans-I/O).
- **INV-09:** Sin código `unsafe` (`#![forbid(unsafe_code)]`).
- **INV-10:** Sin pánicos en código de biblioteca.
