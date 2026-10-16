//! Formato binario de registro cifrado y tipos fundamentales (F5.T01, F5.T02).
//!
//! Trazabilidad:
//! - `REQ-STOR-001`: Cifrado de sobre (DEK/KEK) con AEAD y datos asociados (AAD).
//! - `STORAGE_FORMAT.md §3`: Estructura binaria de `EncryptedRecord` y construcción canónica del AAD.
//! - `INV-02`: Cero datos personales o identificadores en claro en el almacenamiento.
//! - `INV-05`: Fail-closed ante cualquier alteración de bytes, cabecera o AAD.
//! - `INV-10`: Sin indexación propensa a fallos ni pánicos.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use gravital_id_crypto::AEAD_TAG_LEN;
use gravital_id_types::{ErrorCode, GidError};

/// Constante mágica para registros de almacenamiento (`STORAGE_FORMAT.md §3`).
pub const STORAGE_MAGIC: [u8; 4] = *b"PIP$";

/// Versión inicial del esquema de almacenamiento (`STORAGE_FORMAT.md §3`).
pub const SCHEMA_VERSION_V1: u16 = 1;

/// Prefijo canónico de los datos asociados autenticados (`STORAGE_FORMAT.md §3`).
pub const AAD_PREFIX: &[u8] = b"PIP-STORAGE-AAD-v1";

/// Longitud fija de la cabecera del registro en bytes.
///
/// 4 (magic) + 2 (schema_version) + 1 (cipher_suite) + 24 (nonce) + 16 (record_id_hash) = 47 bytes.
pub const RECORD_HEADER_LEN: usize = 4 + 2 + 1 + 24 + 16;

/// Longitud mínima del registro binario (cabecera + tag de autenticación).
pub const RECORD_MIN_LEN: usize = RECORD_HEADER_LEN + AEAD_TAG_LEN;

/// Suite criptográfica AEAD para el almacenamiento local (`STORAGE_FORMAT.md §3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum CipherSuite {
    /// XChaCha20-Poly1305 (24-byte nonce, 16-byte tag). Suite por defecto (ADR-0008).
    XChaCha20Poly1305 = 0x01,
    /// AES-256-GCM (suite alternativa reservada).
    Aes256Gcm = 0x02,
}

impl CipherSuite {
    /// Parsea un byte de suite criptográfica.
    ///
    /// # Errores
    /// [`ErrorCode::UnsupportedAlgorithm`] si el valor no corresponde a una suite soportada.
    pub fn from_u8(value: u8) -> Result<Self, GidError> {
        match value {
            0x01 => Ok(Self::XChaCha20Poly1305),
            0x02 => Ok(Self::Aes256Gcm),
            _ => Err(GidError::new(
                ErrorCode::UnsupportedAlgorithm,
                "unsupported storage cipher suite",
            )),
        }
    }

    /// Valor numérico de la suite.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Identificador validado de registro en el almacenamiento local.
///
/// Longitud acotada entre 1 y 128 caracteres ASCII sin espacios ni caracteres de control.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordId(String);

impl RecordId {
    /// Longitud máxima permitida para un `RecordId`.
    pub const MAX_LEN: usize = 128;

    /// Construye y valida un nuevo `RecordId`.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedMessage`] si la cadena está vacía, excede [`MAX_LEN`],
    /// o contiene caracteres inválidos.
    pub fn new(id: impl Into<String>) -> Result<Self, GidError> {
        let s = id.into();
        if s.is_empty() {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "record ID must not be empty",
            ));
        }
        if s.len() > Self::MAX_LEN {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "record ID exceeds maximum length of 128 characters",
            ));
        }
        for b in s.bytes() {
            let valid =
                b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b':';
            if !valid {
                return Err(GidError::new(
                    ErrorCode::MalformedMessage,
                    "record ID contains invalid characters (allowed: ASCII alphanumeric, '-', '_', '.', ':')",
                ));
            }
        }
        Ok(Self(s))
    }

    /// Retorna una referencia al identificador subyacente.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for RecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecordId(\"{}\")", self.0)
    }
}

/// Nombre de colección validado en el almacenamiento local (`STORAGE_FORMAT.md §4`).
///
/// Colecciones estándar: `credentials`, `keys`, `sessions`, `state`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CollectionName(String);

impl CollectionName {
    /// Longitud máxima permitida para un `CollectionName`.
    pub const MAX_LEN: usize = 64;

    /// Colección estándar para credenciales verificables (`credentials`).
    pub const CREDENTIALS: &'static str = "credentials";
    /// Colección estándar para claves del titular (`keys`).
    pub const KEYS: &'static str = "keys";
    /// Colección estándar para sesiones de proximidad o presentación (`sessions`).
    pub const SESSIONS: &'static str = "sessions";
    /// Colección estándar para estado persistente del sistema (`state`).
    pub const STATE: &'static str = "state";

    /// Construye y valida un nuevo `CollectionName`.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedMessage`] si la cadena está vacía, excede [`MAX_LEN`],
    /// o no sigue formato kebab-case/snake_case permitido.
    pub fn new(name: impl Into<String>) -> Result<Self, GidError> {
        let s = name.into();
        if s.is_empty() {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "collection name must not be empty",
            ));
        }
        if s.len() > Self::MAX_LEN {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "collection name exceeds maximum length of 64 characters",
            ));
        }
        for b in s.bytes() {
            let valid = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_';
            if !valid {
                return Err(GidError::new(
                    ErrorCode::MalformedMessage,
                    "collection name contains invalid characters (allowed: ASCII lowercase, digits, '-', '_')",
                ));
            }
        }
        Ok(Self(s))
    }

    /// Retorna una referencia al nombre de colección.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CollectionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for CollectionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CollectionName(\"{}\")", self.0)
    }
}

/// Construye canónicamente los Datos Asociados Autenticados (AAD) para un registro.
///
/// $$\text{AAD} = \texttt{"PIP-STORAGE-AAD-v1"} \parallel \text{schema\_version} \parallel \text{record\_id} \parallel \text{collection\_type}$$
///
/// Trazabilidad: `REQ-STOR-001`, `STORAGE_FORMAT.md §3`.
#[must_use]
pub fn compute_aad(
    schema_version: u16,
    record_id: &RecordId,
    collection: &CollectionName,
) -> Vec<u8> {
    let rec_bytes = record_id.as_str().as_bytes();
    let col_bytes = collection.as_str().as_bytes();
    let total_len = AAD_PREFIX
        .len()
        .saturating_add(2)
        .saturating_add(rec_bytes.len())
        .saturating_add(col_bytes.len());

    let mut aad = Vec::with_capacity(total_len);
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(&schema_version.to_be_bytes());
    aad.extend_from_slice(rec_bytes);
    aad.extend_from_slice(col_bytes);
    aad
}

/// Registro binario cifrado según la especificación `STORAGE_FORMAT.md §3`.
///
/// Estructura binaria serializada:
/// - `magic`: `[u8; 4]` (`b"PIP$"`)
/// - `schema_version`: `u16` (Big-Endian)
/// - `cipher_suite`: `u8` (`0x01` para XChaCha20-Poly1305)
/// - `nonce`: `[u8; 24]` (192 bits)
/// - `record_id_hash`: `[u8; 16]` (128 bits truncados de índice ciego)
/// - `ciphertext`: `Vec<u8>` (contenido cifrado)
/// - `auth_tag`: `[u8; 16]` (etiqueta Poly1305)
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedRecord {
    magic: [u8; 4],
    schema_version: u16,
    cipher_suite: CipherSuite,
    nonce: [u8; 24],
    record_id_hash: [u8; 16],
    ciphertext: Vec<u8>,
    auth_tag: [u8; 16],
}

impl EncryptedRecord {
    /// Construye una nueva instancia de `EncryptedRecord`.
    #[must_use]
    pub fn new(
        schema_version: u16,
        cipher_suite: CipherSuite,
        nonce: [u8; 24],
        record_id_hash: [u8; 16],
        ciphertext: Vec<u8>,
        auth_tag: [u8; 16],
    ) -> Self {
        Self {
            magic: STORAGE_MAGIC,
            schema_version,
            cipher_suite,
            nonce,
            record_id_hash,
            ciphertext,
            auth_tag,
        }
    }

    /// Retorna los bytes mágicos del registro (`b"PIP$"`).
    #[must_use]
    pub const fn magic(&self) -> &[u8; 4] {
        &self.magic
    }

    /// Retorna la versión del esquema.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Retorna la suite criptográfica utilizada.
    #[must_use]
    pub const fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    /// Retorna el nonce extendido de 24 bytes.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }

    /// Retorna el hash truncado del identificador (16 bytes).
    #[must_use]
    pub const fn record_id_hash(&self) -> &[u8; 16] {
        &self.record_id_hash
    }

    /// Retorna el ciphertext cifrado.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Retorna la etiqueta de autenticación de 16 bytes.
    #[must_use]
    pub const fn auth_tag(&self) -> &[u8; 16] {
        &self.auth_tag
    }

    /// Serializa el registro completo en su representación binaria canónica.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let total_len = RECORD_HEADER_LEN
            .saturating_add(self.ciphertext.len())
            .saturating_add(AEAD_TAG_LEN);

        let mut out = Vec::with_capacity(total_len);
        out.extend_from_slice(&self.magic);
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        out.push(self.cipher_suite.as_u8());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.record_id_hash);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.auth_tag);
        out
    }

    /// Deserializa un registro binario validando la cabecera canónica y las cotas de tamaño.
    ///
    /// # Errores
    /// - [`ErrorCode::StorageReadFailed`] si la longitud es inferior a [`RECORD_MIN_LEN`]
    ///   o los bytes mágicos no coinciden con `PIP$`.
    /// - [`ErrorCode::UnsupportedAlgorithm`] si la suite criptográfica no es soportada.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GidError> {
        if bytes.len() < RECORD_MIN_LEN {
            return Err(GidError::new(
                ErrorCode::StorageReadFailed,
                "serialized record payload is shorter than minimum header and tag size",
            ));
        }

        let magic_slice = bytes.get(0..4).ok_or_else(|| {
            GidError::new(ErrorCode::StorageReadFailed, "failed to read storage magic")
        })?;
        if magic_slice != STORAGE_MAGIC {
            return Err(GidError::new(
                ErrorCode::StorageReadFailed,
                "invalid storage record magic (expected 'PIP$')",
            ));
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(magic_slice);

        let version_slice = bytes.get(4..6).ok_or_else(|| {
            GidError::new(
                ErrorCode::StorageReadFailed,
                "failed to read schema version",
            )
        })?;
        let schema_version = u16::from_be_bytes([
            *version_slice.first().unwrap_or(&0),
            *version_slice.get(1).unwrap_or(&0),
        ]);

        let suite_byte = *bytes.get(6).ok_or_else(|| {
            GidError::new(ErrorCode::StorageReadFailed, "failed to read cipher suite")
        })?;
        let cipher_suite = CipherSuite::from_u8(suite_byte)?;

        let nonce_slice = bytes.get(7..31).ok_or_else(|| {
            GidError::new(ErrorCode::StorageReadFailed, "failed to read record nonce")
        })?;
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(nonce_slice);

        let hash_slice = bytes.get(31..47).ok_or_else(|| {
            GidError::new(
                ErrorCode::StorageReadFailed,
                "failed to read record ID hash",
            )
        })?;
        let mut record_id_hash = [0u8; 16];
        record_id_hash.copy_from_slice(hash_slice);

        let tag_start = bytes.len().saturating_sub(AEAD_TAG_LEN);
        let ciphertext_slice = bytes.get(RECORD_HEADER_LEN..tag_start).ok_or_else(|| {
            GidError::new(
                ErrorCode::StorageReadFailed,
                "failed to read record ciphertext",
            )
        })?;
        let ciphertext = ciphertext_slice.to_vec();

        let tag_slice = bytes.get(tag_start..).ok_or_else(|| {
            GidError::new(
                ErrorCode::StorageReadFailed,
                "failed to read record auth tag",
            )
        })?;
        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(tag_slice);

        Ok(Self {
            magic,
            schema_version,
            cipher_suite,
            nonce,
            record_id_hash,
            ciphertext,
            auth_tag,
        })
    }
}

impl fmt::Debug for EncryptedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedRecord")
            .field("schema_version", &self.schema_version)
            .field("cipher_suite", &self.cipher_suite)
            .field("ciphertext_len", &self.ciphertext.len())
            .field("auth_tag", &"[REDACTED]")
            .finish()
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
    use alloc::vec;

    #[test]
    fn record_id_validation() {
        assert!(RecordId::new("cred-123_456:panama.v1").is_ok());
        assert!(RecordId::new("").is_err());
        assert!(RecordId::new("has space").is_err());
        assert!(RecordId::new("has/slash").is_err());
        let too_long = "a".repeat(129);
        assert!(RecordId::new(too_long).is_err());
    }

    #[test]
    fn collection_name_validation() {
        assert!(CollectionName::new(CollectionName::CREDENTIALS).is_ok());
        assert!(CollectionName::new("keys-v1_local").is_ok());
        assert!(CollectionName::new("").is_err());
        assert!(CollectionName::new("UPPERCASE").is_err());
        assert!(CollectionName::new("has space").is_err());
        let too_long = "a".repeat(65);
        assert!(CollectionName::new(too_long).is_err());
    }

    #[test]
    fn compute_aad_deterministic() {
        let rec = RecordId::new("rec-001").expect("valid id");
        let col = CollectionName::new(CollectionName::CREDENTIALS).expect("valid col");
        let aad1 = compute_aad(1, &rec, &col);
        let aad2 = compute_aad(1, &rec, &col);
        assert_eq!(aad1, aad2);

        // Cambiar colección altera AAD
        let col2 = CollectionName::new(CollectionName::KEYS).expect("valid col");
        let aad3 = compute_aad(1, &rec, &col2);
        assert_ne!(aad1, aad3);

        // Cambiar versión altera AAD
        let aad4 = compute_aad(2, &rec, &col);
        assert_ne!(aad1, aad4);
    }

    #[test]
    fn encrypted_record_binary_round_trip() {
        let nonce = [0x42u8; 24];
        let record_id_hash = [0x99u8; 16];
        let ciphertext = b"encrypted payload bytes".to_vec();
        let auth_tag = [0x77u8; 16];

        let record = EncryptedRecord::new(
            SCHEMA_VERSION_V1,
            CipherSuite::XChaCha20Poly1305,
            nonce,
            record_id_hash,
            ciphertext.clone(),
            auth_tag,
        );

        let bytes = record.to_bytes();
        assert_eq!(bytes.len(), RECORD_HEADER_LEN + ciphertext.len() + 16);

        let decoded = EncryptedRecord::from_bytes(&bytes).expect("decoding must succeed");
        assert_eq!(record, decoded);
        assert_eq!(decoded.magic(), &STORAGE_MAGIC);
        assert_eq!(decoded.schema_version(), 1);
        assert_eq!(decoded.cipher_suite(), CipherSuite::XChaCha20Poly1305);
        assert_eq!(decoded.nonce(), &nonce);
        assert_eq!(decoded.record_id_hash(), &record_id_hash);
        assert_eq!(decoded.ciphertext(), &ciphertext);
        assert_eq!(decoded.auth_tag(), &auth_tag);
    }

    #[test]
    fn encrypted_record_rejects_corrupted_magic_or_short_payload() {
        assert!(EncryptedRecord::from_bytes(&[0u8; 20]).is_err());

        let mut valid_bytes = EncryptedRecord::new(
            1,
            CipherSuite::XChaCha20Poly1305,
            [0u8; 24],
            [0u8; 16],
            vec![],
            [0u8; 16],
        )
        .to_bytes();

        // Corromper magic byte
        valid_bytes[0] = b'X';
        assert_eq!(
            EncryptedRecord::from_bytes(&valid_bytes)
                .expect_err("magic")
                .code,
            ErrorCode::StorageReadFailed
        );
    }

    #[test]
    fn encrypted_record_rejects_unsupported_suite() {
        let mut valid_bytes = EncryptedRecord::new(
            1,
            CipherSuite::XChaCha20Poly1305,
            [0u8; 24],
            [0u8; 16],
            vec![],
            [0u8; 16],
        )
        .to_bytes();

        // Suite byte inválido (offset 6)
        valid_bytes[6] = 0xFF;
        assert_eq!(
            EncryptedRecord::from_bytes(&valid_bytes)
                .expect_err("suite")
                .code,
            ErrorCode::UnsupportedAlgorithm
        );
    }
}
