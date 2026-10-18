//! Clave de recuperación del titular específica por emisor (`REQ-REC-004`, `REQ-REC-007`).
//!
//! Trazabilidad:
//! - **REQ-REC-004:** La clave de recuperación DEBE tener propósito exclusivo (`KeyPurpose::HolderRecovery`) y habilitar la re-vinculación.
//! - **REQ-REC-007:** Las claves de recuperación DEBEN derivarse por emisor; la misma huella NO DEBE registrarse ante dos emisores.
//! - **REQ-KEY-001:** Separación tipada de propósitos de clave.
//! - **P-07 / P-09:** Aislamiento y no correlación entre emisores.
//! - **INV-02:** Ningún dato personal o secreto en logs o errores.

use alloc::string::String;
use core::fmt;

use gravital_id_crypto::jwk::JwkEcP256;
use gravital_id_crypto::secret::{SecretBytes, SecretKeyBytes};
use gravital_id_crypto::sign::public_key_from_secret_key;
use gravital_id_types::{DeviceFactorClass, UnixTime};
use zeroize::ZeroizeOnDrop;

use crate::error::RecoveryError;
use crate::kdf::derive_issuer_recovery_secret;
use crate::rebinding::{RebindingChallenge, RebindingRequest};

/// Clave de recuperación del titular específica para un emisor concreto (`REQ-REC-004`, `REQ-REC-007`).
///
/// Encapsula el par de claves derivado deterministamente a partir del secreto maestro de recuperación
/// y del identificador del emisor (`IssuerId`). Posee propósito exclusivo `HolderRecovery` y nunca
/// debe utilizarse para firmas de presentación de credenciales (`HolderBinding`).
#[derive(Clone, ZeroizeOnDrop)]
pub struct HolderRecoveryKey {
    issuer_id: String,
    secret_key: SecretBytes<32>,
    #[zeroize(skip)]
    public_key: JwkEcP256,
}

impl fmt::Debug for HolderRecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HolderRecoveryKey")
            .field("issuer_id", &self.issuer_id)
            .field("public_key", &self.public_key)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

impl HolderRecoveryKey {
    /// Deriva la clave de recuperación para un emisor específico a partir del secreto maestro (`REQ-REC-007`).
    ///
    /// # Errores
    /// [`RecoveryError::KeyDerivationFailed`] si el emisor está vacío o la derivación criptográfica falla.
    pub fn derive(
        recovery_secret: &SecretBytes<32>,
        issuer_id: impl Into<String>,
    ) -> Result<Self, RecoveryError> {
        let issuer_id = issuer_id.into();
        let priv_bytes = derive_issuer_recovery_secret(recovery_secret, &issuer_id)?;
        let sec_key = SecretKeyBytes::new(*priv_bytes.expose_secret());
        let public_key = public_key_from_secret_key(&sec_key).map_err(|_| {
            RecoveryError::KeyDerivationFailed("error al derivar clave pública P-256")
        })?;

        Ok(Self {
            issuer_id,
            secret_key: priv_bytes,
            public_key,
        })
    }

    /// Identificador del emisor para el cual fue derivada esta clave.
    #[must_use]
    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    /// Clave pública JWK EC P-256 de recuperación.
    #[must_use]
    pub fn public_key(&self) -> &JwkEcP256 {
        &self.public_key
    }

    /// Bytes de la clave secreta de recuperación (32 bytes).
    #[must_use]
    pub fn secret_bytes(&self) -> &SecretBytes<32> {
        &self.secret_key
    }

    /// Huella binaria SHA-256 según RFC 7638.
    #[must_use]
    pub fn thumbprint_sha256(&self) -> [u8; 32] {
        self.public_key.thumbprint_sha256()
    }

    /// Huella canónica RFC 7638 en base64url sin relleno.
    #[must_use]
    pub fn thumbprint_base64url(&self) -> String {
        self.public_key.thumbprint_base64url()
    }

    /// Huella canónica en formato URI según RFC 9278:
    /// `urn:ietf:params:oauth:jwk-thumbprint:sha-256:<base64url>`.
    #[must_use]
    pub fn thumbprint_uri(&self) -> String {
        self.public_key.thumbprint_uri()
    }

    /// Genera una solicitud de re-vinculación firmada para este emisor (`SPEC-PIP-REBIND-001`, `REQ-REC-004`).
    ///
    /// # Errores
    /// - [`RecoveryError::RebindingExpired`] si el desafío expiró.
    /// - [`RecoveryError::InvalidRebindingParameter`] si el emisor no coincide.
    /// - [`RecoveryError::InvalidRebindingSignature`] si la firma criptográfica falla.
    pub fn create_rebinding_request(
        &self,
        challenge: &RebindingChallenge,
        device_class: DeviceFactorClass,
        new_holder_key: JwkEcP256,
        now: UnixTime,
    ) -> Result<RebindingRequest, RecoveryError> {
        RebindingRequest::create(self, challenge, device_class, new_holder_key, now)
    }
}
