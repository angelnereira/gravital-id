//! Errores tipados del módulo de recuperación y respaldo (`gravital-id-recovery`).
//!
//! Trazabilidad: `REQ-REC-002`, `INV-05`.

use core::fmt;
use gravital_id_types::{ErrorCode, GidError};

/// Errores durante la generación de código, empaquetado o restauración de respaldo.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecoveryError {
    /// Código de recuperación malformado (palabras desconocidas, longitud errónea, caracteres inválidos).
    InvalidRecoveryCode(&'static str),
    /// Suma de verificación del código de recuperación incorrecta.
    InvalidChecksum,
    /// Cabecera binaria del paquete de respaldo corrupta o mágica desconocida.
    InvalidBackupHeader(&'static str),
    /// Fallo al descifrar el paquete de respaldo (tag Poly1305 no coincide o clave incorrecta).
    DecryptionFailed,
    /// Fallo durante la compresión del contenido.
    CompressionFailed,
    /// Fallo durante la descompresión del contenido (o ratio DoS excedido).
    DecompressionFailed,
    /// Fallo al serializar los datos del respaldo.
    SerializationFailed(&'static str),
    /// Fallo al deserializar los datos del respaldo.
    DeserializationFailed(&'static str),
    /// Tamaño del paquete de respaldo excede el límite máximo permitido.
    PayloadLimitExceeded(usize),
    /// Fallo en la derivación criptográfica de claves.
    KeyDerivationFailed(&'static str),
    /// Entropía insuficiente en la fuente RNG inyectada.
    InsufficientEntropy,
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRecoveryCode(msg) => write!(f, "Código de recuperación inválido: {msg}"),
            Self::InvalidChecksum => {
                write!(
                    f,
                    "Suma de verificación del código de recuperación no coincide"
                )
            }
            Self::InvalidBackupHeader(msg) => write!(f, "Cabecera de respaldo inválida: {msg}"),
            Self::DecryptionFailed => {
                write!(
                    f,
                    "Fallo al descifrar respaldo: tag de autenticación AEAD no coincide"
                )
            }
            Self::CompressionFailed => write!(f, "Fallo al comprimir el contenido del respaldo"),
            Self::DecompressionFailed => {
                write!(f, "Fallo al descomprimir el contenido del respaldo")
            }
            Self::SerializationFailed(msg) => write!(f, "Fallo al serializar respaldo: {msg}"),
            Self::DeserializationFailed(msg) => write!(f, "Fallo al deserializar respaldo: {msg}"),
            Self::PayloadLimitExceeded(len) => {
                write!(f, "Tamaño de respaldo {len} B excede el límite permitido")
            }
            Self::KeyDerivationFailed(msg) => write!(f, "Fallo en derivación HKDF: {msg}"),
            Self::InsufficientEntropy => {
                write!(f, "Entropía insuficiente en la fuente aleatoria inyectada")
            }
        }
    }
}

impl From<RecoveryError> for GidError {
    fn from(err: RecoveryError) -> Self {
        match err {
            RecoveryError::InvalidRecoveryCode(_) | RecoveryError::InvalidChecksum => {
                GidError::new(
                    ErrorCode::MalformedMessage,
                    "código de recuperación inválido",
                )
            }
            RecoveryError::InvalidBackupHeader(_) => {
                GidError::new(ErrorCode::MalformedMessage, "cabecera de respaldo inválida")
            }
            RecoveryError::DecryptionFailed => GidError::new(
                ErrorCode::AeadAuthenticationFailed,
                "fallo de autenticación en respaldo",
            ),
            RecoveryError::DecompressionFailed => GidError::new(
                ErrorCode::DecompressionRatioExceeded,
                "descompresión de respaldo fallida",
            ),
            RecoveryError::PayloadLimitExceeded(_) => GidError::new(
                ErrorCode::DecompressionRatioExceeded,
                "límite de tamaño de respaldo excedido",
            ),
            RecoveryError::InsufficientEntropy => GidError::new(
                ErrorCode::InsufficientEntropy,
                "entropía insuficiente en recuperación",
            ),
            _ => GidError::new(
                ErrorCode::MalformedMessage,
                "error en recuperación o respaldo",
            ),
        }
    }
}
