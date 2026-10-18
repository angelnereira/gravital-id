//! Empaquetado binario, compresión y cifrado AEAD de respaldos (`EncryptedBackupPackage`).
//!
//! Trazabilidad:
//! - `SPEC-PIP-BACKUP-001 §7`: Formato canónico de paquete de respaldo.
//! - `REQ-REC-002`: Respaldo cifrado protegido con código de recuperación.
//! - `REQ-STOR-001`: Cifrado de sobre con AEAD y AAD ligado a la cabecera.
//! - `INV-01`: Cero dependencias de red.
//! - `INV-05`: Fail-closed ante cualquier alteración de bytes o tag inválido.

use alloc::vec::Vec;

use gravital_id_codec::deflate::{deflate, inflate_bounded, DEFAULT_MAX_OUTPUT_BYTES};
use gravital_id_crypto::aead::{
    open as aead_open, seal as aead_seal, AEAD_NONCE_LEN, AEAD_TAG_LEN,
};
use gravital_id_crypto::Rng;
use gravital_id_types::UnixTime;
use zeroize::Zeroize;

use crate::code::RecoveryCode;
use crate::error::RecoveryError;
use crate::kdf::{derive_backup_keys, BACKUP_SALT_LEN};

/// Constante mágica oficial del paquete de respaldo: `GIDB` (Gravital ID Backup).
pub const BACKUP_MAGIC_GIDB: [u8; 4] = *b"GIDB";

/// Constante mágica legada aceptada para compatibilidad: `PIPB`.
pub const BACKUP_MAGIC_PIPB: [u8; 4] = *b"PIPB";

/// Versión actual del formato de paquete binario de respaldo.
pub const BACKUP_PACKAGE_FORMAT_VERSION: u16 = 1;

/// Identificador de suite de cifrado: `0x01` = XChaCha20-Poly1305.
pub const CIPHER_SUITE_XCHACHA20_POLY1305: u8 = 0x01;

/// Longitud fija de la cabecera del paquete de respaldo (59 bytes).
pub const BACKUP_HEADER_LEN: usize = 4 + 2 + 1 + 8 + BACKUP_SALT_LEN + AEAD_NONCE_LEN + 4;

/// Prefijo canónico de los Datos Asociados Autenticados (AAD) del respaldo.
pub const BACKUP_AAD_PREFIX: &[u8] = b"GID-BACKUP-AAD-v1";

/// Longitud máxima de texto cifrado permitida en el paquete (16 MiB).
pub const MAX_BACKUP_CIPHERTEXT_LEN: usize = 16 * 1024 * 1024;

/// Ratio de expansión máxima admitido en descompresión para prevenir Zip Bombs.
pub const MAX_DECOMPRESSION_RATIO: usize = 10;

/// Paquete de respaldo cifrado y autenticado conforme a `SPEC-PIP-BACKUP-001`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedBackupPackage {
    /// Versión de formato de respaldo.
    pub format_version: u16,
    /// Suite criptográfica empleada.
    pub cipher_suite: u8,
    /// Instante de creación del respaldo.
    pub created_at: UnixTime,
    /// Sal aleatoria para derivación HKDF.
    pub salt: [u8; BACKUP_SALT_LEN],
    /// Nonce aleatorio de 192 bits para XChaCha20.
    pub nonce: [u8; AEAD_NONCE_LEN],
    /// Texto cifrado (contenido comprimido con DEFLATE).
    pub ciphertext: Vec<u8>,
    /// Etiqueta de autenticación Poly1305.
    pub auth_tag: [u8; AEAD_TAG_LEN],
}

impl EncryptedBackupPackage {
    /// Calcula los Datos Asociados Autenticados (AAD) vinculados a la cabecera.
    #[must_use]
    pub fn compute_aad(
        format_version: u16,
        cipher_suite: u8,
        created_at: UnixTime,
        salt: &[u8; BACKUP_SALT_LEN],
    ) -> Vec<u8> {
        let cap = BACKUP_AAD_PREFIX
            .len()
            .saturating_add(2)
            .saturating_add(1)
            .saturating_add(8)
            .saturating_add(BACKUP_SALT_LEN);
        let mut aad = Vec::with_capacity(cap);
        aad.extend_from_slice(BACKUP_AAD_PREFIX);
        aad.extend_from_slice(&format_version.to_be_bytes());
        aad.push(cipher_suite);
        aad.extend_from_slice(&created_at.as_seconds().to_be_bytes());
        aad.extend_from_slice(salt);
        aad
    }

    /// Comprime, cifra y empaqueta un payload en claro utilizando el código de recuperación dado.
    pub fn seal<R: Rng>(
        payload_bytes: &[u8],
        code: &RecoveryCode,
        created_at: UnixTime,
        rng: &R,
    ) -> Result<Vec<u8>, RecoveryError> {
        let mut salt = [0u8; BACKUP_SALT_LEN];
        rng.fill_bytes(&mut salt)
            .map_err(|_| RecoveryError::InsufficientEntropy)?;

        let mut nonce = [0u8; AEAD_NONCE_LEN];
        rng.fill_bytes(&mut nonce)
            .map_err(|_| RecoveryError::InsufficientEntropy)?;

        let (aead_key, _rec_secret) = derive_backup_keys(code.entropy(), &salt)?;

        // 1. Comprimir payload con DEFLATE
        let compressed = deflate(payload_bytes);

        // 2. Construir AAD
        let aad = Self::compute_aad(
            BACKUP_PACKAGE_FORMAT_VERSION,
            CIPHER_SUITE_XCHACHA20_POLY1305,
            created_at,
            &salt,
        );

        // 3. Cifrar con XChaCha20-Poly1305
        let sealed = aead_seal(aead_key.expose_secret(), &nonce, &compressed, &aad)
            .map_err(|_| RecoveryError::DecryptionFailed)?;

        if sealed.len() < AEAD_TAG_LEN {
            return Err(RecoveryError::DecryptionFailed);
        }
        let ciphertext_len = sealed.len().saturating_sub(AEAD_TAG_LEN);

        if ciphertext_len > MAX_BACKUP_CIPHERTEXT_LEN {
            return Err(RecoveryError::PayloadLimitExceeded(ciphertext_len));
        }

        // 4. Serializar paquete binario
        let total_size = BACKUP_HEADER_LEN
            .checked_add(sealed.len())
            .ok_or(RecoveryError::PayloadLimitExceeded(usize::MAX))?;

        let mut out = Vec::with_capacity(total_size);
        out.extend_from_slice(&BACKUP_MAGIC_GIDB);
        out.extend_from_slice(&BACKUP_PACKAGE_FORMAT_VERSION.to_be_bytes());
        out.push(CIPHER_SUITE_XCHACHA20_POLY1305);
        out.extend_from_slice(&created_at.as_seconds().to_be_bytes());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&(ciphertext_len as u32).to_be_bytes());
        out.extend_from_slice(&sealed);

        salt.zeroize();
        nonce.zeroize();

        Ok(out)
    }

    /// Desempaqueta, autentica, descifra y descomprime un paquete de respaldo binario.
    pub fn open(package_bytes: &[u8], code: &RecoveryCode) -> Result<Vec<u8>, RecoveryError> {
        if package_bytes.len() < BACKUP_HEADER_LEN.saturating_add(AEAD_TAG_LEN) {
            return Err(RecoveryError::InvalidBackupHeader(
                "tamaño de paquete inferior a la cabecera mínima",
            ));
        }

        // 1. Validar magic
        let magic: [u8; 4] = package_bytes
            .get(..4)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0; 4]);
        if magic != BACKUP_MAGIC_GIDB && magic != BACKUP_MAGIC_PIPB {
            return Err(RecoveryError::InvalidBackupHeader(
                "constante mágica desconocida (se esperaba GIDB o PIPB)",
            ));
        }

        // 2. Extraer campos de cabecera
        let format_version = u16::from_be_bytes(
            package_bytes
                .get(4..6)
                .and_then(|s| s.try_into().ok())
                .ok_or(RecoveryError::InvalidBackupHeader("formato de versión inválido"))?,
        );
        if format_version != BACKUP_PACKAGE_FORMAT_VERSION {
            return Err(RecoveryError::InvalidBackupHeader(
                "versión de formato de respaldo no soportada",
            ));
        }

        let cipher_suite = package_bytes.get(6).copied().unwrap_or(0);
        if cipher_suite != CIPHER_SUITE_XCHACHA20_POLY1305 {
            return Err(RecoveryError::InvalidBackupHeader(
                "suite criptográfica no soportada",
            ));
        }

        let created_at_sec = u64::from_be_bytes(
            package_bytes
                .get(7..15)
                .and_then(|s| s.try_into().ok())
                .ok_or(RecoveryError::InvalidBackupHeader("created_at inválido"))?,
        );
        let created_at = UnixTime::from_seconds(created_at_sec);

        let salt: [u8; BACKUP_SALT_LEN] = package_bytes
            .get(15..31)
            .and_then(|s| s.try_into().ok())
            .ok_or(RecoveryError::InvalidBackupHeader("salt inválido"))?;

        let nonce: [u8; AEAD_NONCE_LEN] = package_bytes
            .get(31..55)
            .and_then(|s| s.try_into().ok())
            .ok_or(RecoveryError::InvalidBackupHeader("nonce inválido"))?;

        let ciphertext_len = u32::from_be_bytes(
            package_bytes
                .get(55..59)
                .and_then(|s| s.try_into().ok())
                .ok_or(RecoveryError::InvalidBackupHeader("ciphertext_len inválido"))?,
        ) as usize;

        if ciphertext_len > MAX_BACKUP_CIPHERTEXT_LEN {
            return Err(RecoveryError::PayloadLimitExceeded(ciphertext_len));
        }

        let expected_total_len = BACKUP_HEADER_LEN
            .checked_add(ciphertext_len)
            .and_then(|s| s.checked_add(AEAD_TAG_LEN))
            .ok_or(RecoveryError::PayloadLimitExceeded(usize::MAX))?;

        if package_bytes.len() != expected_total_len {
            return Err(RecoveryError::InvalidBackupHeader(
                "longitud del archivo no coincide con ciphertext_len declarado",
            ));
        }

        let ciphertext_and_tag = package_bytes
            .get(BACKUP_HEADER_LEN..expected_total_len)
            .ok_or(RecoveryError::InvalidBackupHeader("rango de criptograma inválido"))?;

        // 3. Reconstruir AAD
        let aad = Self::compute_aad(format_version, cipher_suite, created_at, &salt);

        // 4. Derivar clave y descifrar AEAD
        let (aead_key, _rec_secret) = derive_backup_keys(code.entropy(), &salt)?;
        let compressed = aead_open(aead_key.expose_secret(), &nonce, ciphertext_and_tag, &aad)
            .map_err(|_| RecoveryError::DecryptionFailed)?;

        // 5. Descomprimir con límite de expansión anti-DoS
        let decompressed = inflate_bounded(
            &compressed,
            DEFAULT_MAX_OUTPUT_BYTES,
            MAX_DECOMPRESSION_RATIO,
        )
        .map_err(|_| RecoveryError::DecompressionFailed)?;

        Ok(decompressed)
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use gravital_id_testkit::SeededRng;

    #[test]
    fn test_seal_and_open_roundtrip() {
        let rng = SeededRng::new(0x1234);
        let code = RecoveryCode::generate(&rng).expect("generate recovery code");
        let now = UnixTime::from_seconds(1_770_000_000);
        let payload = b"{\"hello\":\"gravital_id_secure_backup_test\"}";

        let package =
            EncryptedBackupPackage::seal(payload, &code, now, &rng).expect("seal debe ser exitoso");
        assert_eq!(&package[..4], &BACKUP_MAGIC_GIDB);

        let opened = EncryptedBackupPackage::open(&package, &code).expect("open debe ser exitoso");
        assert_eq!(&opened, payload);
    }

    #[test]
    fn test_wrong_recovery_code_fails_decryption() {
        let rng = SeededRng::new(0x5678);
        let code_correct = RecoveryCode::generate(&rng).expect("generate recovery code");
        let code_wrong = RecoveryCode::generate(&rng).expect("generate recovery code");
        let now = UnixTime::from_seconds(1_770_000_000);
        let payload = b"secret payload data";

        let package = EncryptedBackupPackage::seal(payload, &code_correct, now, &rng).unwrap();

        // Intentar abrir con código erróneo debe fallar con DecryptionFailed (INV-05)
        let res = EncryptedBackupPackage::open(&package, &code_wrong);
        assert!(
            matches!(res, Err(RecoveryError::DecryptionFailed)),
            "Código incorrecto debe fallar con DecryptionFailed"
        );
    }

    #[test]
    fn test_tampered_ciphertext_fails_auth() {
        let rng = SeededRng::new(0x9999);
        let code = RecoveryCode::generate(&rng).expect("generate recovery code");
        let now = UnixTime::from_seconds(1_770_000_000);
        let payload = b"payload data to be corrupted";

        let mut package = EncryptedBackupPackage::seal(payload, &code, now, &rng).unwrap();

        // Corromper un byte dentro del ciphertext
        if let Some(byte) = package.get_mut(BACKUP_HEADER_LEN + 2) {
            *byte ^= 0xFF;
        }

        let res = EncryptedBackupPackage::open(&package, &code);
        assert!(matches!(res, Err(RecoveryError::DecryptionFailed)));
    }

    #[test]
    fn test_tampered_header_fails_aad_or_header_check() {
        let rng = SeededRng::new(0xAAAA);
        let code = RecoveryCode::generate(&rng).expect("generate recovery code");
        let now = UnixTime::from_seconds(1_770_000_000);
        let payload = b"tamper header test";

        let mut package = EncryptedBackupPackage::seal(payload, &code, now, &rng).unwrap();

        // Modificar timestamp created_at en cabecera
        if let Some(byte) = package.get_mut(10) {
            *byte ^= 0x01;
        }

        let res = EncryptedBackupPackage::open(&package, &code);
        assert!(matches!(res, Err(RecoveryError::DecryptionFailed)));
    }
}
