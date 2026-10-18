//! Firmantes para Token Status Lists y Manifiestos de Estado (F7.T05, REQ-ISS-003, REQ-STAT-008).
//!
//! Abstracción [`StatusSigner`] desacoplada de la custodia de claves privadas (`INV-03`),
//! con implementación [`LocalStatusSigner`] para entornos de prueba y desarrollo.

use alloc::format;
use alloc::string::String;
use gravital_id_crypto::secret::SecretKeyBytes;
use gravital_id_crypto::sign::{
    generate_p256_secret_key, public_key_from_secret_key, sign_es256_digest, ES256_SIGNATURE_LEN,
};
use gravital_id_crypto::{JwkEcP256, Rng};
use gravital_id_types::{ErrorCode, GidError};

/// Abstracción de un firmante de estado de emisor (Token Status Lists y manifiestos).
pub trait StatusSigner {
    /// Firma el digest SHA-256 de 32 bytes con ES256 (P-256 + SHA-256) devolviendo
    /// 64 bytes IEEE P1363 (r || s).
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], GidError>;

    /// Key ID opcional (`kid`) del firmante.
    fn kid(&self) -> Option<&str>;

    /// Clave pública JWK P-256 del firmante.
    fn public_key(&self) -> &JwkEcP256;
}

/// Implementación local de [`StatusSigner`] para desarrollo y pruebas.
///
/// Custodia la clave privada en memoria mediante [`SecretKeyBytes`], que limpia
/// la memoria al destruirse (`ZeroizeOnDrop`, REQ-SEC-003).
#[derive(Clone)]
pub struct LocalStatusSigner {
    kid: Option<String>,
    secret_key: SecretKeyBytes,
    public_key: JwkEcP256,
}

impl LocalStatusSigner {
    /// Crea un firmante a partir de una clave privada existente y un `kid` opcional.
    pub fn new(kid: Option<String>, secret_key: SecretKeyBytes) -> Result<Self, GidError> {
        let public_key = public_key_from_secret_key(&secret_key)?;
        Ok(Self {
            kid,
            secret_key,
            public_key,
        })
    }

    /// Genera una clave nueva utilizando el generador aleatorio inyectado (INV-11).
    pub fn generate_with_rng<R: Rng>(kid: Option<String>, rng: &R) -> Result<Self, GidError> {
        let secret_key = generate_p256_secret_key(rng)?;
        Self::new(kid, secret_key)
    }

    /// Retorna una referencia a la clave secreta.
    #[must_use]
    pub fn secret_key(&self) -> &SecretKeyBytes {
        &self.secret_key
    }

    /// Retorna una referencia a la clave pública JWK P-256.
    #[must_use]
    pub fn public_key(&self) -> &JwkEcP256 {
        &self.public_key
    }
}

impl StatusSigner for LocalStatusSigner {
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], GidError> {
        let sig = sign_es256_digest(&self.secret_key, digest)?;
        if sig.len() != ES256_SIGNATURE_LEN {
            return Err(GidError::new(
                ErrorCode::InvalidSignature,
                format!(
                    "unexpected signature length: expected {}, got {}",
                    ES256_SIGNATURE_LEN,
                    sig.len()
                ),
            ));
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig);
        Ok(out)
    }

    fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    fn public_key(&self) -> &JwkEcP256 {
        &self.public_key
    }
}
