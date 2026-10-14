//! Implementación software de `KeyStore` para desarrollo y pruebas (`SoftwareKeyStore`).
//!
//! Trazabilidad:
//! - **REQ-KEY-004:** Implementación software para pruebas y perfiles que la permitan.
//! - **REQ-KEY-007:** Identificadores de clave derivados como JWK Thumbprint (RFC 7638 SHA-256).
//! - **REQ-SEC-003:** Secretos protegidos en memoria con `Zeroize` en drop.
//! - **INV-11:** Generación de claves condicionada a un `Rng` inyectado (cero aleatoriedad implícita).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use gravital_id_crypto::{
    ecdh_agree_keys, generate_p256_secret_key, jwk_thumbprint_base64url,
    public_key_from_secret_key, sign_es256_digest, JwkEcP256, Rng, SecretKeyBytes, SharedSecret,
    ES256_SIGNATURE_LEN,
};
use gravital_id_types::{ErrorCode, GidError};

use crate::keystore::KeyStore;
use crate::purpose::KeyPurpose;

/// Registro interno de una clave almacenada en memoria.
struct SoftwareKeyEntry {
    purpose: KeyPurpose,
    secret_key: SecretKeyBytes,
    public_key: JwkEcP256,
    attestation: Option<Vec<u8>>,
}

/// Almacén de claves en memoria para pruebas y perfiles de software.
///
/// Todas las claves privadas residen como [`SecretKeyBytes`], garantizando que
/// la memoria se limpie de forma segura (`ZeroizeOnDrop`) cuando las claves son
/// eliminadas o cuando el almacén se destruye.
///
/// Trazabilidad: `REQ-KEY-004`, `REQ-KEY-007`.
pub struct SoftwareKeyStore<R = Box<dyn Rng>> {
    rng: R,
    keys: BTreeMap<String, SoftwareKeyEntry>,
}

impl<R: Rng> SoftwareKeyStore<R> {
    /// Crea un nuevo almacén con el generador de entropía inyectado.
    #[must_use]
    pub fn new(rng: R) -> Self {
        Self {
            rng,
            keys: BTreeMap::new(),
        }
    }
}

impl SoftwareKeyStore<Box<dyn Rng>> {
    /// Crea un almacén a partir de un generador empaquetado dinámicamente (`Box<dyn Rng>`).
    #[must_use]
    pub fn with_boxed_rng(rng: Box<dyn Rng>) -> Self {
        Self {
            rng,
            keys: BTreeMap::new(),
        }
    }
}

impl<R> SoftwareKeyStore<R> {
    /// Inserta manualmente una clave existente en el almacén (útil para pruebas con vectores fijos).
    pub fn insert_key(
        &mut self,
        kid: impl Into<String>,
        purpose: KeyPurpose,
        secret_key: SecretKeyBytes,
        public_key: JwkEcP256,
        attestation: Option<Vec<u8>>,
    ) {
        let kid_str = kid.into();
        let pub_with_kid = public_key.with_kid(&kid_str);
        self.keys.insert(
            kid_str,
            SoftwareKeyEntry {
                purpose,
                secret_key,
                public_key: pub_with_kid,
                attestation,
            },
        );
    }

    /// Número total de claves almacenadas.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Comprueba si existe una clave con el identificador dado.
    #[must_use]
    pub fn contains_key(&self, kid: &str) -> bool {
        self.keys.contains_key(kid)
    }
}

impl<R: Rng> KeyStore for SoftwareKeyStore<R> {
    fn generate_key_for_purpose(&mut self, purpose: KeyPurpose) -> Result<String, GidError> {
        let secret_key = generate_p256_secret_key(&self.rng)?;
        let public_key = public_key_from_secret_key(&secret_key)?;
        let kid = jwk_thumbprint_base64url(&public_key);
        let pub_with_kid = public_key.with_kid(&kid);

        self.keys.insert(
            kid.clone(),
            SoftwareKeyEntry {
                purpose,
                secret_key,
                public_key: pub_with_kid,
                attestation: None,
            },
        );

        Ok(kid)
    }

    fn public_key_by_id(&self, kid: &str) -> Result<JwkEcP256, GidError> {
        let entry = self
            .keys
            .get(kid)
            .ok_or_else(|| GidError::new(ErrorCode::KeyNotFound, "key not found in keystore"))?;
        Ok(entry.public_key.clone())
    }

    fn sign_digest(
        &self,
        kid: &str,
        digest: &[u8; 32],
    ) -> Result<[u8; ES256_SIGNATURE_LEN], GidError> {
        let entry = self
            .keys
            .get(kid)
            .ok_or_else(|| GidError::new(ErrorCode::KeyNotFound, "key not found in keystore"))?;

        if !entry.purpose.allows_signing() {
            return Err(GidError::new(
                ErrorCode::InvalidKeyFormat,
                "key purpose does not permit signing operations",
            ));
        }

        sign_es256_digest(&entry.secret_key, digest)
    }

    fn agree_key_by_id(
        &self,
        kid: &str,
        peer_public_key: &JwkEcP256,
    ) -> Result<SharedSecret, GidError> {
        let entry = self
            .keys
            .get(kid)
            .ok_or_else(|| GidError::new(ErrorCode::KeyNotFound, "key not found in keystore"))?;

        if !entry.purpose.allows_key_agreement() {
            return Err(GidError::new(
                ErrorCode::InvalidKeyFormat,
                "key purpose does not permit key agreement operations",
            ));
        }

        ecdh_agree_keys(&entry.secret_key, peer_public_key)
    }

    fn delete_key_by_id(&mut self, kid: &str) -> Result<(), GidError> {
        self.keys
            .remove(kid)
            .map(|_| ())
            .ok_or_else(|| GidError::new(ErrorCode::KeyNotFound, "key not found in keystore"))
    }

    fn key_attestation_by_id(&self, kid: &str) -> Result<Option<Vec<u8>>, GidError> {
        let entry = self
            .keys
            .get(kid)
            .ok_or_else(|| GidError::new(ErrorCode::KeyNotFound, "key not found in keystore"))?;
        Ok(entry.attestation.clone())
    }
}
