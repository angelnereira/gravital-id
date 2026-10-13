//! Trait abstracto `KeyStore` para operaciones de hardware o software seguro.
//!
//! Trazabilidad:
//! - **REQ-KEY-001:** El sistema de tipos impide usar una clave para un propósito distinto.
//! - **REQ-KEY-004:** Trait `KeyStore` implementable por el host con implementación software.
//! - **REQ-KEY-009:** Claves de acuerdo (HPKE) separadas de las de firma.
//! - **SDK_API.md §3.1:** Contrato normativo de `KeyStore`.

use alloc::string::String;
use alloc::vec::Vec;
use gravital_id_crypto::{JwkEcP256, SharedSecret, ES256_SIGNATURE_LEN};
use gravital_id_types::GidError;

use crate::purpose::{
    KeyAgreementPurpose, KeyHandle, KeyPurpose, KeyPurposeMarker, SigningPurpose,
};

/// Contrato abstracto para gestión y operaciones con claves criptográficas.
///
/// Puede ser respaldado en hardware seguro (Secure Enclave, StrongBox, HSM, PKCS#11)
/// o en una implementación software en memoria para pruebas (`SoftwareKeyStore`).
///
/// Invariante de seguridad: las claves privadas nunca abandonan el módulo de seguridad
/// en claro (INV-03, REQ-KEY-003).
pub trait KeyStore {
    // --- Métodos de bajo nivel (object-safe para backends dinámicos y FFI) ---

    /// Genera un nuevo par de claves en el almacén para el propósito especificado.
    ///
    /// Devuelve el identificador único de la clave (`kid`, típicamente JWK thumbprint).
    fn generate_key_for_purpose(&mut self, purpose: KeyPurpose) -> Result<String, GidError>;

    /// Obtiene la clave pública JWK EC P-256 asociada a un identificador de clave (`kid`).
    fn public_key_by_id(&self, kid: &str) -> Result<JwkEcP256, GidError>;

    /// Firma un digest SHA-256 (32 bytes) precalculado utilizando la clave especificada.
    ///
    /// Devuelve la firma en formato estándar IEEE P1363 (64 bytes).
    fn sign_digest(
        &self,
        kid: &str,
        digest: &[u8; 32],
    ) -> Result<[u8; ES256_SIGNATURE_LEN], GidError>;

    /// Realiza un acuerdo Diffie-Hellman (ECDH / HPKE) entre la clave privada identificada por `kid`
    /// y la clave pública del par `peer_public_key`.
    fn agree_key_by_id(
        &self,
        kid: &str,
        peer_public_key: &JwkEcP256,
    ) -> Result<SharedSecret, GidError>;

    /// Elimina la clave identificada por `kid` del almacén seguro.
    fn delete_key_by_id(&mut self, kid: &str) -> Result<(), GidError>;

    /// Obtiene la atestación de clave emitida por el fabricante del hardware (opcional).
    fn key_attestation_by_id(&self, kid: &str) -> Result<Option<Vec<u8>>, GidError> {
        let _ = kid;
        Ok(None)
    }

    // --- Métodos tipados por propósito (garantizados en compilación) ---

    /// Genera una clave tipada por el marcador de propósito `P`.
    ///
    /// Trazabilidad: `REQ-KEY-001`.
    fn generate_key<P: KeyPurposeMarker>(&mut self) -> Result<KeyHandle<P>, GidError>
    where
        Self: Sized,
    {
        let kid = self.generate_key_for_purpose(P::PURPOSE)?;
        Ok(KeyHandle::new(kid))
    }

    /// Obtiene la clave pública JWK asociada a un handle tipado.
    fn public_key<P: KeyPurposeMarker>(&self, handle: &KeyHandle<P>) -> Result<JwkEcP256, GidError>
    where
        Self: Sized,
    {
        self.public_key_by_id(handle.id())
    }

    /// Firma un digest SHA-256 exigiendo en tiempo de compilación que el handle pertenezca a un [`SigningPurpose`].
    ///
    /// Impide en compilación firmar con claves de acuerdo HPKE (REQ-KEY-001, REQ-KEY-009).
    fn sign<P: SigningPurpose>(
        &self,
        handle: &KeyHandle<P>,
        digest: &[u8; 32],
    ) -> Result<[u8; ES256_SIGNATURE_LEN], GidError>
    where
        Self: Sized,
    {
        self.sign_digest(handle.id(), digest)
    }

    /// Realiza un acuerdo de claves exigiendo en tiempo de compilación que el handle pertenezca a un [`KeyAgreementPurpose`].
    ///
    /// Impide en compilación acordar claves con claves de firma (REQ-KEY-001, REQ-KEY-009).
    fn agree_key<P: KeyAgreementPurpose>(
        &self,
        handle: &KeyHandle<P>,
        peer_public_key: &JwkEcP256,
    ) -> Result<SharedSecret, GidError>
    where
        Self: Sized,
    {
        self.agree_key_by_id(handle.id(), peer_public_key)
    }

    /// Elimina una clave tipada del almacén.
    fn delete_key<P: KeyPurposeMarker>(&mut self, handle: &KeyHandle<P>) -> Result<(), GidError>
    where
        Self: Sized,
    {
        self.delete_key_by_id(handle.id())
    }

    /// Obtiene la atestación de clave asociada al handle tipado.
    fn key_attestation<P: KeyPurposeMarker>(
        &self,
        handle: &KeyHandle<P>,
    ) -> Result<Option<Vec<u8>>, GidError>
    where
        Self: Sized,
    {
        self.key_attestation_by_id(handle.id())
    }
}

impl<K: KeyStore + ?Sized> KeyStore for &mut K {
    fn generate_key_for_purpose(&mut self, purpose: KeyPurpose) -> Result<String, GidError> {
        (**self).generate_key_for_purpose(purpose)
    }

    fn public_key_by_id(&self, kid: &str) -> Result<JwkEcP256, GidError> {
        (**self).public_key_by_id(kid)
    }

    fn sign_digest(
        &self,
        kid: &str,
        digest: &[u8; 32],
    ) -> Result<[u8; ES256_SIGNATURE_LEN], GidError> {
        (**self).sign_digest(kid, digest)
    }

    fn agree_key_by_id(
        &self,
        kid: &str,
        peer_public_key: &JwkEcP256,
    ) -> Result<SharedSecret, GidError> {
        (**self).agree_key_by_id(kid, peer_public_key)
    }

    fn delete_key_by_id(&mut self, kid: &str) -> Result<(), GidError> {
        (**self).delete_key_by_id(kid)
    }

    fn key_attestation_by_id(&self, kid: &str) -> Result<Option<Vec<u8>>, GidError> {
        (**self).key_attestation_by_id(kid)
    }
}
