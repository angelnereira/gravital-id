//! Derivación determinista de claves para respaldo y re-vinculación por emisor (`HKDF-SHA256`).
//!
//! Trazabilidad:
//! - `REQ-REC-002`: Claves de respaldo derivadas mediante HKDF a partir del código de recuperación.
//! - `REQ-REC-004`: Clave de recuperación con propósito exclusivo (`HolderRecovery`).
//! - `REQ-REC-007`: Las claves de recuperación DEBEN derivarse por emisor; dos emisores nunca reciben la misma huella.
//! - `ADR-0009`: Jerarquía de derivación determinista $\text{RecoveryKey}_{\text{Issuer}} = \text{HKDF}(\text{RecoverySecret}, \text{IssuerId})$.
//! - `INV-02`: Aislamiento estricto de huellas para prevenir correlación del titular entre entidades.

use alloc::string::String;
use gravital_id_crypto::jwk::JwkEcP256;
use gravital_id_crypto::kdf::{hkdf_expand_sha256, hkdf_extract_sha256};
use gravital_id_crypto::secret::{AeadKeyBytes, SecretBytes, SecretKeyBytes};
use gravital_id_crypto::sign::public_key_from_secret_key;
use zeroize::Zeroize;

use crate::code::RECOVERY_ENTROPY_LEN;
use crate::error::RecoveryError;

/// Longitud de la sal criptográfica de respaldo (128 bits / 16 bytes).
pub const BACKUP_SALT_LEN: usize = 16;

/// Contexto de derivación HKDF para la clave de cifrado del paquete de respaldo.
pub const INFO_BACKUP_ENCRYPTION: &[u8] = b"pip-backup-encryption-v1";

/// Contexto de derivación HKDF para el secreto maestro de recuperación del titular.
pub const INFO_RECOVERY_SECRET: &[u8] = b"pip-recovery-secret-v1";

/// Contexto de derivación HKDF para las claves de recuperación específicas por emisor.
pub const INFO_ISSUER_RECOVERY_KEY: &[u8] = b"pip-issuer-recovery-key-v1";

/// Deriva la clave de cifrado AEAD y el secreto maestro de recuperación a partir de la entropía y una sal.
pub fn derive_backup_keys(
    entropy: &[u8; RECOVERY_ENTROPY_LEN],
    salt: &[u8; BACKUP_SALT_LEN],
) -> Result<(AeadKeyBytes, SecretBytes<32>), RecoveryError> {
    let prk = hkdf_extract_sha256(salt, entropy)
        .map_err(|_| RecoveryError::KeyDerivationFailed("extracción HKDF de respaldo falló"))?;

    let mut enc_key_vec = hkdf_expand_sha256(&prk, INFO_BACKUP_ENCRYPTION, 32).map_err(|_| {
        RecoveryError::KeyDerivationFailed("expansión de clave de cifrado de respaldo falló")
    })?;
    let mut rec_sec_vec = hkdf_expand_sha256(&prk, INFO_RECOVERY_SECRET, 32).map_err(|_| {
        RecoveryError::KeyDerivationFailed("expansión de secreto de recuperación falló")
    })?;

    let mut enc_key = [0u8; 32];
    if let Some(src) = enc_key_vec.get(..32) {
        enc_key.copy_from_slice(src);
    }
    enc_key_vec.zeroize();

    let mut rec_sec = [0u8; 32];
    if let Some(src) = rec_sec_vec.get(..32) {
        rec_sec.copy_from_slice(src);
    }
    rec_sec_vec.zeroize();

    let aead_key = AeadKeyBytes::new(enc_key);
    let secret = SecretBytes::new(rec_sec);
    enc_key.zeroize();
    rec_sec.zeroize();

    Ok((aead_key, secret))
}

/// Deriva el escalar de la clave privada de recuperación (`P-256`) específica para un emisor concreto (`REQ-REC-007`).
///
/// La clave resultante es determinista, matemáticamente independiente entre emisores, y tiene como
/// propósito exclusivo la autorización de re-vinculaciones (`REQ-REC-004`).
pub fn derive_issuer_recovery_secret(
    recovery_secret: &SecretBytes<32>,
    issuer_id: &str,
) -> Result<SecretBytes<32>, RecoveryError> {
    if issuer_id.is_empty() {
        return Err(RecoveryError::KeyDerivationFailed(
            "el identificador de emisor no puede estar vacío",
        ));
    }

    let prk = hkdf_extract_sha256(issuer_id.as_bytes(), recovery_secret.expose_secret())
        .map_err(|_| RecoveryError::KeyDerivationFailed("extracción HKDF para emisor falló"))?;
    let mut scalar_vec = hkdf_expand_sha256(&prk, INFO_ISSUER_RECOVERY_KEY, 32).map_err(|_| {
        RecoveryError::KeyDerivationFailed("expansión de clave de recuperación por emisor falló")
    })?;

    let mut scalar = [0u8; 32];
    if let Some(src) = scalar_vec.get(..32) {
        scalar.copy_from_slice(src);
    }
    scalar_vec.zeroize();

    let res = Ok(SecretBytes::new(scalar));
    scalar.zeroize();
    res
}

/// Deriva la clave pública JWK de recuperación correspondiente a un emisor específico.
pub fn derive_issuer_recovery_jwk(
    recovery_secret: &SecretBytes<32>,
    issuer_id: &str,
) -> Result<JwkEcP256, RecoveryError> {
    let priv_key = derive_issuer_recovery_secret(recovery_secret, issuer_id)?;
    let secret_key = SecretKeyBytes::new(*priv_key.expose_secret());
    public_key_from_secret_key(&secret_key)
        .map_err(|_| RecoveryError::KeyDerivationFailed("error al derivar clave pública P-256"))
}

/// Deriva el thumbprint canónico RFC 7638 en base64url de la clave de recuperación para un emisor (`REQ-REC-007`).
pub fn derive_issuer_recovery_thumbprint(
    recovery_secret: &SecretBytes<32>,
    issuer_id: &str,
) -> Result<String, RecoveryError> {
    let jwk = derive_issuer_recovery_jwk(recovery_secret, issuer_id)?;
    Ok(jwk.thumbprint_base64url())
}

/// Deriva el thumbprint canónico RFC 7638 en formato URI (`urn:ietf:params:oauth:jwk-thumbprint:sha-256:<b64u>`)
/// de la clave de recuperación para un emisor (`REQ-REC-004`, `REQ-REC-007`).
pub fn derive_issuer_recovery_thumbprint_uri(
    recovery_secret: &SecretBytes<32>,
    issuer_id: &str,
) -> Result<String, RecoveryError> {
    let jwk = derive_issuer_recovery_jwk(recovery_secret, issuer_id)?;
    Ok(jwk.thumbprint_uri())
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

    #[test]
    fn test_derive_backup_keys_deterministic() {
        let entropy = [0x42u8; 16];
        let salt = [0x11u8; 16];

        let (key1, sec1) = derive_backup_keys(&entropy, &salt).expect("derive 1");
        let (key2, sec2) = derive_backup_keys(&entropy, &salt).expect("derive 2");

        assert_eq!(key1, key2);
        assert_eq!(sec1, sec2);
    }

    #[test]
    fn test_derive_issuer_recovery_keys_uncorrelated() {
        let recovery_secret = SecretBytes::new([0x99u8; 32]);

        let iss_te = "https://issuer.te.gob.pa";
        let iss_bank = "https://issuer.banco-nacional.pa";
        let iss_univ = "https://issuer.utp.ac.pa";

        let priv_te = derive_issuer_recovery_secret(&recovery_secret, iss_te).expect("te");
        let priv_bank = derive_issuer_recovery_secret(&recovery_secret, iss_bank).expect("bank");
        let priv_univ = derive_issuer_recovery_secret(&recovery_secret, iss_univ).expect("univ");

        // Tres emisores distintos deben obtener claves privadas distintas
        assert_ne!(priv_te, priv_bank);
        assert_ne!(priv_te, priv_univ);
        assert_ne!(priv_bank, priv_univ);

        let jwk_te = derive_issuer_recovery_jwk(&recovery_secret, iss_te).expect("jwk te");
        let jwk_bank = derive_issuer_recovery_jwk(&recovery_secret, iss_bank).expect("jwk bank");
        let jwk_univ = derive_issuer_recovery_jwk(&recovery_secret, iss_univ).expect("jwk univ");

        // Sus JWKs públicos e identificadores thumbprints deben ser completamente distintos (REQ-REC-007, P-09)
        assert_ne!(jwk_te.to_canonical_json(), jwk_bank.to_canonical_json());
        assert_ne!(jwk_te.to_canonical_json(), jwk_univ.to_canonical_json());
        assert_ne!(jwk_bank.to_canonical_json(), jwk_univ.to_canonical_json());
    }

    #[test]
    fn test_empty_issuer_id_fails() {
        let recovery_secret = SecretBytes::new([0x33u8; 32]);
        let res = derive_issuer_recovery_secret(&recovery_secret, "");
        assert!(matches!(res, Err(RecoveryError::KeyDerivationFailed(_))));
    }
}
