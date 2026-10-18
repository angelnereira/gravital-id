# gravital-id-recovery

> **Capa:** L3 (Negocio y Flujos) · **no_std:** Sí (`#![no_std]` + `alloc`) · **Unsafe:** Prohibido (`#![forbid(unsafe_code)]`)

## Propósito

Implementa los protocolos de respaldo cifrado, código de recuperación de 128 bits de entropía, partición de secreto de Shamir $k$-de-$n$ para recuperación social y derivación de credenciales para re-vinculación en el ecosistema Gravital ID.

## Trazabilidad y Requisitos

- **`REQ-REC-002`**: Generación de código de recuperación con ≥ 128 bits de entropía, mnemónico estándar BIP-39 de 12 palabras con suma de verificación SHA-256 (4 bits) y formato compacto Crockford Base32 (26 caracteres + dígito de control).
- **`REQ-REC-003`**: Recuperación social con Shamir ($k$-de-$n$ sobre $GF(2^8)$) para custodia distribuida entre guardianes sin custodio único (`P-10`).
- **`REQ-REC-004`**: Derivación de claves de recuperación de propósito exclusivo (`HolderRecovery`) para autorización de re-vinculación ante emisores.
- **`REQ-REC-007`**: Aislamiento estricto de huellas por emisor mediante HKDF determinista ($\text{RecoveryKey}_{\text{Issuer}} = \text{HKDF}(\text{RecoverySecret}, \text{IssuerId})$), impidiendo correlación cruzada de titulares entre entidades (`INV-02`, `P-09`).
- **`SPEC-PIP-BACKUP-001`**: Especificación canónica del contenedor binario de respaldo (`GIDB`) con cabecera AAD autenticada y cifrado `XChaCha20-Poly1305` (`STORAGE_FORMAT.md §7`).
- **`SPEC-PIP-SHAMIR-001`**: Especificación canónica de fragmentos Shamir (`GIDS`) en $GF(2^8)$ con polinomio de Rijndael/AES (`0x11B`), interpolación de Lagrange en tiempo constante y formato compacto Crockford Base32 (`STORAGE_FORMAT.md §8`).

## Componentes Principales

- `RecoveryCode`: Entropía protegida en memoria con `Zeroize`, serialización a mnemónico BIP-39 y código compacto Crockford Base32 con validación fail-closed de checksum.
- `ShamirSecretSharing`: Partición polinómica en $GF(2^8)$ y reconstrucción de Lagrange a partir de al menos $k$ fragmentos, aplicable tanto a bytes arbitrarios como a `RecoveryCode` tipado.
- `ShamirShare`: Fragmento autosuficiente con cabecera canónica `GIDS`, umbral $k$, total $n$, índice $x \in [1, 255]$, identificador de secreto `secret_id` de 4 bytes, valor evaluado protegido con `ZeroizeOnDrop` y suma de verificación de integridad SHA-256.
- `derive_backup_keys`: Jerarquía HKDF-SHA256 que extrae la clave de cifrado AEAD de 256 bits y el secreto maestro de recuperación a partir del código y una sal criptográfica de 128 bits.
- `derive_issuer_recovery_secret` / `derive_issuer_recovery_jwk`: Derivación por emisor de claves privadas y públicas JWK `P-256` para re-vinculación no correlacionable.
- `BackupPayload`: Estructura canónica con versión de esquema, secreto de recuperación, credenciales (`BackupCredential`), ranuras de dispositivo (`BackupDeviceSlot`) y roles de tenant (`BackupTenantRole`), serializada en JSON canónico determinista con límites estrictos de DoS.
- `EncryptedBackupPackage`: Empaquetador binario que aplica compresión DEFLATE previa, vinculación criptográfica AAD y cifrado AEAD autenticado (`XChaCha20-Poly1305`).
- `RecoveryManager`: Fachada de alto nivel para exportar y restaurar la bóveda del titular.

## Invariantes Aplicables

- **INV-01**: Cero I/O de red en L1–L4 (`no_std` + `alloc`).
- **INV-02**: Ningún dato personal ni identificador de titular en claro en los fragmentos Shamir, paquete de respaldo ni logs.
- **INV-03**: Sin custodia de claves privadas en servidores; la restauración se realiza íntegramente en el dispositivo del titular.
- **INV-05**: Fail-closed: ante fragmentos insuficientes ($< k$), fragmentos corruptos o alterados, la reconstrucción falla de forma estricta.
- **INV-09**: `#![forbid(unsafe_code)]`.
- **INV-10**: Cero pánicos (`unwrap`, `expect`, `panic!`) en el código de biblioteca.
- **INV-11**: Relojes y generadores de entropía (`Rng`, `UnixTime`) inyectados explícitamente.
