//! Solicitudes y protocolos de re-vinculación de credenciales (`REQ-REC-004`, `REQ-ISS-006`, `REQ-DEVSLOT-001..004`, `ADR-0029`, `SPEC-PIP-REBIND-001`).
//!
//! Trazabilidad:
//! - **REQ-REC-004:** La clave de recuperación DEBE tener propósito exclusivo (`KeyPurpose::HolderRecovery`).
//! - **REQ-REC-007:** Claves de recuperación aisladas por emisor; huellas no correlacionables.
//! - **REQ-DEVSLOT-001 / REQ-DEVSLOT-003:** Ranura única por clase de factor de dispositivo y reemplazo atómico.
//! - **REQ-DEVSLOT-004:** Cero identificadores de silicio o hardware en claro (privacidad).
//! - **INV-01:** Sin I/O de red (`no_std` + `alloc`).
//! - **INV-02:** Cero datos personales o secretos en logs, errores o transcritos.
//! - **INV-03:** Claves privadas del titular protegidas en el dispositivo.
//! - **INV-05:** Fail-closed ante firma inválida o desafío expirado.
//! - **INV-10:** Sin unwraps ni panics.
//! - **INV-11:** Instante de tiempo inyectado.

use alloc::format;
use alloc::string::{String, ToString};

use gravital_id_crypto::jwk::JwkEcP256;
use gravital_id_crypto::secret::SecretKeyBytes;
use gravital_id_crypto::sha::sha256;
use gravital_id_crypto::sign::{sign_es256_digest, verify_es256_digest_jwk};
use gravital_id_types::{DeviceFactorClass, UnixTime};

use crate::error::RecoveryError;
use crate::key::HolderRecoveryKey;

/// Prefijo normativo canónico para el transcrito de re-vinculación según `SPEC-PIP-REBIND-001`.
pub const REBINDING_TRANSCRIPT_PREFIX: &str = "pip-rebinding-v1";

/// Calcula la cadena canónica UTF-8 del transcrito de re-vinculación según `SPEC-PIP-REBIND-001`.
///
/// Formato normativo:
/// `"pip-rebinding-v1:" || issuer_uri || ":" || nonce || ":" || device_class || ":" || new_holder_key_thumbprint`
#[must_use]
pub fn compute_rebinding_transcript(
    issuer_uri: &str,
    nonce: &str,
    device_class: DeviceFactorClass,
    new_holder_key_thumbprint: &str,
) -> String {
    format!(
        "{REBINDING_TRANSCRIPT_PREFIX}:{}:{}:{}:{}",
        issuer_uri.trim(),
        nonce.trim(),
        device_class.as_str(),
        new_holder_key_thumbprint.trim()
    )
}

/// Calcula el digest SHA-256 de 32 bytes del transcrito canónico de re-vinculación.
#[must_use]
pub fn compute_rebinding_digest(
    issuer_uri: &str,
    nonce: &str,
    device_class: DeviceFactorClass,
    new_holder_key_thumbprint: &str,
) -> [u8; 32] {
    let transcript =
        compute_rebinding_transcript(issuer_uri, nonce, device_class, new_holder_key_thumbprint);
    sha256(transcript.as_bytes())
}

/// Desafío emitido por el emisor para autorizar una re-vinculación de credencial (`SPEC-PIP-REBIND-001`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebindingChallenge {
    issuer_uri: String,
    nonce: String,
    expires_at: UnixTime,
}

impl RebindingChallenge {
    /// Construye un nuevo desafío de re-vinculación con validación de entradas.
    ///
    /// # Errores
    /// [`RecoveryError::InvalidRebindingParameter`] si `issuer_uri` o `nonce` están vacíos.
    pub fn new(
        issuer_uri: impl Into<String>,
        nonce: impl Into<String>,
        expires_at: UnixTime,
    ) -> Result<Self, RecoveryError> {
        let uri = issuer_uri.into();
        let trimmed_uri = uri.trim();
        if trimmed_uri.is_empty() {
            return Err(RecoveryError::InvalidRebindingParameter(
                "issuer_uri no puede estar vacío",
            ));
        }
        let nonce_str = nonce.into();
        let trimmed_nonce = nonce_str.trim();
        if trimmed_nonce.is_empty() {
            return Err(RecoveryError::InvalidRebindingParameter(
                "nonce no puede estar vacío",
            ));
        }
        Ok(Self {
            issuer_uri: trimmed_uri.to_string(),
            nonce: trimmed_nonce.to_string(),
            expires_at,
        })
    }

    /// URI del emisor que emitió este desafío.
    #[must_use]
    pub fn issuer_uri(&self) -> &str {
        &self.issuer_uri
    }

    /// Nonce aleatorio de un solo uso emitido por el emisor.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Instante Unix en que expira este desafío.
    #[must_use]
    pub fn expires_at(&self) -> UnixTime {
        self.expires_at
    }

    /// Verifica si el desafío ha expirado con respecto al instante `now` (INV-11).
    #[must_use]
    pub fn is_expired(&self, now: UnixTime) -> bool {
        now.as_seconds() > self.expires_at.as_seconds()
    }
}

/// Solicitud firmada de re-vinculación por clase de dispositivo (`REQ-REC-004`, `REQ-DEVSLOT-001..004`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebindingRequest {
    issuer_uri: String,
    nonce: String,
    device_class: DeviceFactorClass,
    new_holder_key: JwkEcP256,
    recovery_thumbprint: String,
    signature: [u8; 64],
}

impl RebindingRequest {
    /// Genera y firma una solicitud de re-vinculación utilizando la clave de recuperación del titular (`REQ-REC-004`).
    ///
    /// # Errores
    /// - [`RecoveryError::RebindingExpired`] si el desafío ha expirado.
    /// - [`RecoveryError::InvalidRebindingParameter`] si el emisor no coincide con el de la clave.
    /// - [`RecoveryError::InvalidRebindingSignature`] si la firma criptográfica falla.
    pub fn create(
        recovery_key: &HolderRecoveryKey,
        challenge: &RebindingChallenge,
        device_class: DeviceFactorClass,
        new_holder_key: JwkEcP256,
        now: UnixTime,
    ) -> Result<Self, RecoveryError> {
        if challenge.is_expired(now) {
            return Err(RecoveryError::RebindingExpired);
        }

        // Validar que el emisor coincida con el alcance de la clave derivada (REQ-REC-007)
        if recovery_key.issuer_id() != challenge.issuer_uri() {
            return Err(RecoveryError::InvalidRebindingParameter(
                "el emisor de la clave de recuperación no coincide con el emisor del desafío",
            ));
        }

        let new_holder_thumbprint = new_holder_key.thumbprint_base64url();
        let digest = compute_rebinding_digest(
            challenge.issuer_uri(),
            challenge.nonce(),
            device_class,
            &new_holder_thumbprint,
        );

        let sec_key = SecretKeyBytes::new(*recovery_key.secret_bytes().expose_secret());
        let signature = sign_es256_digest(&sec_key, &digest)
            .map_err(|_| RecoveryError::InvalidRebindingSignature)?;

        Ok(Self {
            issuer_uri: challenge.issuer_uri().to_string(),
            nonce: challenge.nonce().to_string(),
            device_class,
            new_holder_key,
            recovery_thumbprint: recovery_key.thumbprint_uri(),
            signature,
        })
    }

    /// URI del emisor destino.
    #[must_use]
    pub fn issuer_uri(&self) -> &str {
        &self.issuer_uri
    }

    /// Nonce del desafío respondido.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Clase de factor de dispositivo solicitado (`mobile`, `card`, `other`).
    #[must_use]
    pub fn device_class(&self) -> DeviceFactorClass {
        self.device_class
    }

    /// Clave pública P-256 generada en el silicio del nuevo dispositivo.
    #[must_use]
    pub fn new_holder_key(&self) -> &JwkEcP256 {
        &self.new_holder_key
    }

    /// Huella RFC 9278 URI de la clave de recuperación utilizada para firmar.
    #[must_use]
    pub fn recovery_thumbprint(&self) -> &str {
        &self.recovery_thumbprint
    }

    /// Firma digital P1363 (64 bytes) generada con la clave de recuperación (`KeyPurpose::HolderRecovery`).
    #[must_use]
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Verifica la firma digital y los parámetros de la solicitud contra la clave pública de recuperación (`INV-05`).
    ///
    /// # Errores
    /// - [`RecoveryError::SecretIdMismatch`] si la huella declarada no corresponde a `recovery_public_key`.
    /// - [`RecoveryError::InvalidRebindingSignature`] si la firma digital no verifica.
    pub fn verify_signature(&self, recovery_public_key: &JwkEcP256) -> Result<(), RecoveryError> {
        let expected_uri = recovery_public_key.thumbprint_uri();
        let expected_b64 = recovery_public_key.thumbprint_base64url();
        if self.recovery_thumbprint != expected_uri && self.recovery_thumbprint != expected_b64 {
            return Err(RecoveryError::SecretIdMismatch);
        }

        let new_holder_thumbprint = self.new_holder_key.thumbprint_base64url();
        let digest = compute_rebinding_digest(
            &self.issuer_uri,
            &self.nonce,
            self.device_class,
            &new_holder_thumbprint,
        );

        verify_es256_digest_jwk(recovery_public_key, &digest, &self.signature)
            .map_err(|_| RecoveryError::InvalidRebindingSignature)?;

        Ok(())
    }

    /// Verifica completamente la solicitud contra el desafío y la clave pública (frescura, nonce y firma) (`INV-05`).
    ///
    /// # Errores
    /// - [`RecoveryError::RebindingExpired`] si el desafío expiró.
    /// - [`RecoveryError::InvalidRebindingParameter`] si el nonce o issuer_uri no coinciden.
    /// - [`RecoveryError::InvalidRebindingSignature`] si la firma es inválida.
    pub fn verify(
        &self,
        challenge: &RebindingChallenge,
        recovery_public_key: &JwkEcP256,
        now: UnixTime,
    ) -> Result<(), RecoveryError> {
        if challenge.is_expired(now) {
            return Err(RecoveryError::RebindingExpired);
        }
        if self.issuer_uri != challenge.issuer_uri() {
            return Err(RecoveryError::InvalidRebindingParameter(
                "issuer_uri no coincide con el desafío",
            ));
        }
        if self.nonce != challenge.nonce() {
            return Err(RecoveryError::InvalidRebindingParameter(
                "nonce no coincide con el desafío",
            ));
        }
        self.verify_signature(recovery_public_key)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use gravital_id_crypto::secret::SecretBytes;
    use gravital_id_crypto::sign::generate_p256_secret_key;
    use gravital_id_crypto::Rng;

    struct DummyRng;
    impl Rng for DummyRng {
        fn fill_32_bytes(&self) -> Result<[u8; 32], gravital_id_types::GidError> {
            Ok([0x42; 32])
        }
        fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), gravital_id_types::GidError> {
            dest.fill(0x42);
            Ok(())
        }
    }

    #[test]
    fn test_compute_rebinding_transcript_canonical() {
        let transcript = compute_rebinding_transcript(
            "https://issuer.example.com",
            "nonce-xyz-123",
            DeviceFactorClass::Mobile,
            "thumbprint-new-key",
        );
        assert_eq!(
            transcript,
            "pip-rebinding-v1:https://issuer.example.com:nonce-xyz-123:mobile:thumbprint-new-key"
        );

        let digest = compute_rebinding_digest(
            "https://issuer.example.com",
            "nonce-xyz-123",
            DeviceFactorClass::Card,
            "thumbprint-new-key",
        );
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_rebinding_request_lifecycle() {
        let master_secret = SecretBytes::new([0x7a; 32]);
        let issuer_uri = "https://identity.panama.gob.pa";
        let recovery_key = HolderRecoveryKey::derive(&master_secret, issuer_uri).unwrap();

        let now = UnixTime::from_seconds(1700000000);
        let challenge = RebindingChallenge::new(
            issuer_uri,
            "challenge-nonce-998877665544",
            UnixTime::from_seconds(1700000300),
        )
        .unwrap();

        let rng = DummyRng;
        let new_holder_sec = generate_p256_secret_key(&rng).unwrap();
        let new_holder_jwk =
            gravital_id_crypto::sign::public_key_from_secret_key(&new_holder_sec).unwrap();

        // Crear solicitud para clase Mobile
        let req = RebindingRequest::create(
            &recovery_key,
            &challenge,
            DeviceFactorClass::Mobile,
            new_holder_jwk.clone(),
            now,
        )
        .unwrap();

        assert_eq!(req.issuer_uri(), issuer_uri);
        assert_eq!(req.device_class(), DeviceFactorClass::Mobile);
        assert_eq!(req.new_holder_key(), &new_holder_jwk);
        assert_eq!(req.recovery_thumbprint(), recovery_key.thumbprint_uri());

        // Verificación exitosa
        assert!(req
            .verify(&challenge, recovery_key.public_key(), now)
            .is_ok());

        // Falla si el desafío expiró
        let expired_now = UnixTime::from_seconds(1700000301);
        assert_eq!(
            req.verify(&challenge, recovery_key.public_key(), expired_now),
            Err(RecoveryError::RebindingExpired)
        );

        // Falla si la firma se altera
        let mut tampered_req = req.clone();
        tampered_req.signature[0] ^= 0xff;
        assert_eq!(
            tampered_req.verify(&challenge, recovery_key.public_key(), now),
            Err(RecoveryError::InvalidRebindingSignature)
        );

        // Falla si la clase de dispositivo se altera
        let mut tampered_class_req = req.clone();
        tampered_class_req.device_class = DeviceFactorClass::Card;
        assert_eq!(
            tampered_class_req.verify(&challenge, recovery_key.public_key(), now),
            Err(RecoveryError::InvalidRebindingSignature)
        );
    }
}
