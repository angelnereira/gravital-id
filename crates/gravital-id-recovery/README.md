# gravital-id-recovery

> **Capa:** L3 (Negocio y Flujos) · **no_std:** Sí (`#![no_std]` + `alloc`) · **Unsafe:** Prohibido (`#![forbid(unsafe_code)]`)

## Propósito

Implementa los protocolos de respaldo cifrado, código de recuperación de 128 bits de entropía y derivación de credenciales para re-vinculación en el ecosistema Gravital ID.

## Trazabilidad y Requisitos

- **`REQ-REC-002`**: Generación de código de recuperación con ≥ 128 bits de entropía, mnemónico estándar BIP-39 de 12 palabras con suma de verificación SHA-256 (4 bits) y formato compacto Crockford Base32 (26 caracteres + dígito de control).
- **`REQ-REC-004`**: Derivación de claves de recuperación de propósito exclusivo (`HolderRecovery`) para autorización de re-vinculación ante emisores.
- **`REQ-REC-007`**: Aislamiento estricto de huellas por emisor mediante HKDF determinista ($\text{RecoveryKey}_{\text{Issuer}} = \text{HKDF}(\text{RecoverySecret}, \text{IssuerId})$), impidiendo correlación cruzada de titulares entre entidades (`INV-02`, `P-09`).
- **`SPEC-PIP-BACKUP-001`**: Especificación canónica del contenedor binario de respaldo (`GIDB`) con cabecera AAD autenticada y cifrado `XChaCha20-Poly1305` (`STORAGE_FORMAT.md §7`).

## Componentes Principales

- `RecoveryCode`: Entropía protegida en memoria con `Zeroize`, serialización a mnemónico BIP-39 y código compacto Crockford Base32 con validación fail-closed de checksum.
- `derive_backup_keys`: Jerarquía HKDF-SHA256 que extrae la clave de cifrado AEAD de 256 bits y el secreto maestro de recuperación a partir del código y una sal criptográfica de 128 bits.
- `derive_issuer_recovery_secret` / `derive_issuer_recovery_jwk`: Derivación por emisor de claves privadas y públicas JWK `P-256` para re-vinculación no correlacionable.
- `BackupPayload`: Estructura canónica con versión de esquema, secreto de recuperación, credenciales (`BackupCredential`), ranuras de dispositivo (`BackupDeviceSlot`) y roles de tenant (`BackupTenantRole`), serializada en JSON canónico determinista con límites estrictos de DoS.
- `EncryptedBackupPackage`: Empaquetador binario que aplica compresión DEFLATE previa, vinculación criptográfica AAD y cifrado AEAD autenticado (`XChaCha20-Poly1305`).
- `RecoveryManager`: Fachada de alto nivel para exportar y restaurar la bóveda del titular.

## Invariantes Aplicables

- **INV-01**: Cero I/O de red en L1–L4 (`no_std` + `alloc`).
- **INV-02**: Ningún dato personal ni identificador de titular en claro en el paquete de respaldo ni en logs.
- **INV-03**: Sin custodia de claves privadas en servidores; la restauración se realiza íntegramente en el dispositivo del titular.
- **INV-05**: Fail-closed: alteración de cualquier bit del paquete binario invalida la autenticación AEAD y produce `DecryptionFailed`.
- **INV-09**: `#![forbid(unsafe_code)]`.
- **INV-10**: Cero pánicos (`unwrap`, `expect`, `panic!`) en el código de biblioteca.
- **INV-11**: Relojes y generadores de entropía (`Rng`, `UnixTime`) inyectados explícitamente.
