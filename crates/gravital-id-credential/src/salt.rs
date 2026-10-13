//! Sal criptográfica para divulgaciones SD-JWT (REQ-CRED-002, RFC 9901 §5.2).
//!
//! Cada divulgación en una credencial o presentación SD-JWT debe utilizar una sal
//! aleatoria e impredecible generada por un CSPRNG con al menos 128 bits de entropía
//! (16 bytes), previniendo ataques de diccionario o inversión de hashes en claims
//! de baja entropía.

use alloc::format;
use alloc::string::{String, ToString};
use core::fmt;

use gravital_id_codec::base64url;
use gravital_id_crypto::Rng;
use gravital_id_types::{ErrorCode, GidError};

/// Longitud mínima de la sal en bytes: 16 bytes = 128 bits de entropía (REQ-CRED-002).
pub const MIN_SALT_BYTES: usize = 16;

/// Sal criptográfica validada con al menos 128 bits de entropía (REQ-CRED-002).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Salt {
    encoded: String,
}

impl Salt {
    /// Genera una sal criptográfica de 128 bits (16 bytes) utilizando el CSPRNG inyectado.
    ///
    /// // Verifies: REQ-CRED-002
    pub fn generate(rng: &impl Rng) -> Result<Self, GidError> {
        let mut bytes = [0u8; MIN_SALT_BYTES];
        rng.fill_bytes(&mut bytes)?;
        Ok(Self {
            encoded: base64url::encode(&bytes),
        })
    }

    /// Construye una sal a partir de bytes crudos, validando que contenga al menos 128 bits (16 bytes).
    ///
    /// // Verifies: REQ-CRED-002
    pub fn from_slice(bytes: &[u8]) -> Result<Self, GidError> {
        if bytes.len() < MIN_SALT_BYTES {
            return Err(GidError::new(
                ErrorCode::InsufficientEntropy,
                "salt must contain at least 128 bits (16 bytes) of entropy",
            ));
        }
        Ok(Self {
            encoded: base64url::encode(bytes),
        })
    }

    /// Construye y valida una sal a partir de una cadena codificada en base64url.
    ///
    /// Verifica que la cadena sea base64url válida y que decodifique a al menos 128 bits.
    ///
    /// // Verifies: REQ-CRED-002
    pub fn from_base64url(s: &str) -> Result<Self, GidError> {
        let decoded = base64url::decode(s).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("invalid base64url in salt: {e}"),
            )
        })?;

        if decoded.len() < MIN_SALT_BYTES {
            return Err(GidError::new(
                ErrorCode::InsufficientEntropy,
                "decoded salt has less than 128 bits (16 bytes) of entropy",
            ));
        }

        Ok(Self {
            encoded: s.to_string(),
        })
    }

    /// Retorna la representación en cadena base64url de la sal.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.encoded
    }
}

impl fmt::Display for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encoded)
    }
}

impl fmt::Debug for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Salt(\"{}\")", self.encoded)
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
    fn salt_generation_produces_valid_128_bit_base64url() {
        let rng = SeededRng::new(42);
        let salt = Salt::generate(&rng).expect("generate salt");
        assert!(!salt.as_str().is_empty());
        let decoded = base64url::decode(salt.as_str()).expect("salt must be valid base64url");
        assert_eq!(decoded.len(), MIN_SALT_BYTES);
    }

    #[test]
    fn salt_from_slice_rejects_under_128_bits() {
        let short_bytes = [0x42u8; 15]; // 15 bytes < 16 bytes (120 bits < 128 bits)
        let err = Salt::from_slice(&short_bytes).unwrap_err();
        assert_eq!(err.code, ErrorCode::InsufficientEntropy);

        let valid_bytes = [0x42u8; 16];
        let salt = Salt::from_slice(&valid_bytes).expect("16 bytes must pass");
        assert_eq!(salt.as_str().len(), 22); // 16 bytes in base64url without padding
    }

    #[test]
    fn salt_from_base64url_validates_entropy_and_format() {
        // Base64url for 15 bytes
        let short_b64 = base64url::encode(&[0x01u8; 15]);
        let err = Salt::from_base64url(&short_b64).unwrap_err();
        assert_eq!(err.code, ErrorCode::InsufficientEntropy);

        // Invalid base64url characters
        let invalid_b64 = "invalid salt with spaces!";
        let err = Salt::from_base64url(invalid_b64).unwrap_err();
        assert_eq!(err.code, ErrorCode::MalformedSdJwt);

        // Valid 16-byte salt
        let valid_b64 = base64url::encode(&[0xA5u8; 16]);
        let salt = Salt::from_base64url(&valid_b64).expect("valid salt");
        assert_eq!(salt.as_str(), valid_b64);
    }
}
