//! Cifrado de sobre (Envelope Encryption) con DEK/KEK y datos asociados (F5.T02).
//!
//! Trazabilidad:
//! - `REQ-STOR-001`: Cifrado de sobre con AEAD y datos asociados (AAD).
//! - `REQ-STOR-002`: Clave maestra de cifrado (KEK) provista por hardware de la plataforma.
//! - `STORAGE_FORMAT.md §2`: Jerarquía KEK -> DEK / BIK con HKDF-SHA256.
//! - `INV-02`: Ausencia de claves privadas o datos en claro.
//! - `INV-03`: Higiene estricta de secretos en memoria (`Zeroize`, `SecretBytes`).
//! - `INV-05`: Fail-closed ante fallo de autenticación de datos asociados o tag AEAD.

use alloc::vec::Vec;
use gravital_id_crypto::aead::{
    open as aead_open, seal as aead_seal, AEAD_KEY_LEN, AEAD_NONCE_LEN, AEAD_TAG_LEN,
};
use gravital_id_crypto::kdf::hkdf_expand_sha256;
use gravital_id_crypto::mac::hmac_sha256;
use gravital_id_crypto::rng::Rng;
use gravital_id_crypto::secret::SecretBytes;
use gravital_id_types::{ErrorCode, GidError};

use crate::record::{
    compute_aad, CipherSuite, CollectionName, EncryptedRecord, RecordId, SCHEMA_VERSION_V1,
};

/// Contexto de información para derivación de DEK por registro (`STORAGE_FORMAT.md §2`).
pub const KDF_INFO_DEK_PREFIX: &[u8] = b"pip-storage-dek-v1";

/// Contexto de información para derivación de BIK (`STORAGE_FORMAT.md §2`).
pub const KDF_INFO_BIK: &[u8] = b"pip-storage-bik-v1";

/// Contrato para el proveedor de la clave maestra de cifrado de claves (KEK).
///
/// Implementado por adaptadores L5 que interactúan con el almacén seguro de hardware
/// de la plataforma (Android StrongBox / iOS Keychain) (`REQ-STOR-002`).
pub trait KekProvider {
    /// Obtiene la KEK de 256 bits protegida por hardware.
    ///
    /// # Errores
    /// [`ErrorCode::HardwareKeystoreFailed`] si el enclave de hardware falla o no está disponible.
    fn get_kek(&self) -> Result<SecretBytes<32>, GidError>;
}

/// Proveedor de KEK en memoria para entornos de prueba o software aislado.
#[derive(Clone)]
pub struct StaticKekProvider {
    kek: SecretBytes<32>,
}

impl StaticKekProvider {
    /// Crea un nuevo proveedor con una KEK fija.
    #[must_use]
    pub const fn new(kek: SecretBytes<32>) -> Self {
        Self { kek }
    }
}

impl KekProvider for StaticKekProvider {
    fn get_kek(&self) -> Result<SecretBytes<32>, GidError> {
        Ok(self.kek.clone())
    }
}

/// Deriva la clave de cifrado de datos (DEK) de 256 bits para un registro específico.
///
/// $$\text{DEK} = \text{HKDF-Expand}(\text{KEK}, \text{info: } \texttt{"pip-storage-dek-v1"} \parallel \text{record\_id})$$
///
/// Trazabilidad: `REQ-STOR-001`, `STORAGE_FORMAT.md §2`.
pub fn derive_dek(kek: &SecretBytes<32>, record_id: &str) -> Result<SecretBytes<32>, GidError> {
    let mut info = Vec::with_capacity(KDF_INFO_DEK_PREFIX.len().saturating_add(record_id.len()));
    info.extend_from_slice(KDF_INFO_DEK_PREFIX);
    info.extend_from_slice(record_id.as_bytes());

    let okm = hkdf_expand_sha256(kek.expose_secret(), &info, AEAD_KEY_LEN)?;
    SecretBytes::from_slice(&okm)
}

/// Deriva la clave maestra de índices ciegos (BIK) de 256 bits a partir de la KEK.
///
/// $$\text{BIK} = \text{HKDF-Expand}(\text{KEK}, \text{info: } \texttt{"pip-storage-bik-v1"})$$
///
/// Trazabilidad: `REQ-STOR-003`, `STORAGE_FORMAT.md §2`.
pub fn derive_bik(kek: &SecretBytes<32>) -> Result<SecretBytes<32>, GidError> {
    let okm = hkdf_expand_sha256(kek.expose_secret(), KDF_INFO_BIK, AEAD_KEY_LEN)?;
    SecretBytes::from_slice(&okm)
}

/// Computa el hash truncado del identificador primario para particionado (16 bytes).
///
/// $$\text{record\_id\_hash} = \text{truncate}_{16}(\text{HMAC-SHA256}(\text{BIK}, \texttt{"idx:id:"} \parallel \text{record\_id}))$$
pub fn compute_record_id_hash(
    bik: &SecretBytes<32>,
    record_id: &str,
) -> Result<[u8; 16], GidError> {
    let mut data = Vec::with_capacity(7usize.saturating_add(record_id.len()));
    data.extend_from_slice(b"idx:id:");
    data.extend_from_slice(record_id.as_bytes());

    let full_hmac = hmac_sha256(bik.expose_secret(), &data)?;
    let mut truncated = [0u8; 16];
    if let Some(src) = full_hmac.get(0..16) {
        truncated.copy_from_slice(src);
    }
    Ok(truncated)
}

/// Cifrador de sobre para registros locales (`STORAGE_FORMAT.md §2, §3`).
pub struct EnvelopeEncryption;

impl EnvelopeEncryption {
    /// Cifra un contenido en claro produciendo un [`EncryptedRecord`] canónico.
    ///
    /// # Pasos
    /// 1. Deriva la BIK y calcula el `record_id_hash` para indexación/particionado.
    /// 2. Deriva la DEK única del registro mediante `HKDF-Expand(KEK, info: "pip-storage-dek-v1" || record_id)`.
    /// 3. Genera un nonce criptográfico de 24 bytes inyectado desde `rng`.
    /// 4. Construye el AAD canónico con versión, ID de registro y colección.
    /// 5. Cifra con `XChaCha20-Poly1305` generando `ciphertext` y `auth_tag`.
    ///
    /// # Errores
    /// [`ErrorCode::InsufficientEntropy`] si falla el CSPRNG.
    pub fn encrypt<R: Rng>(
        kek: &SecretBytes<32>,
        record_id: &RecordId,
        collection: &CollectionName,
        plaintext: &[u8],
        rng: &R,
    ) -> Result<EncryptedRecord, GidError> {
        let bik = derive_bik(kek)?;
        let record_id_hash = compute_record_id_hash(&bik, record_id.as_str())?;
        let dek = derive_dek(kek, record_id.as_str())?;

        let mut nonce = [0u8; AEAD_NONCE_LEN];
        rng.fill_bytes(&mut nonce)?;

        let aad = compute_aad(SCHEMA_VERSION_V1, record_id, collection);
        let sealed = aead_seal(dek.expose_secret(), &nonce, plaintext, &aad)?;

        if sealed.len() < AEAD_TAG_LEN {
            return Err(GidError::new(
                ErrorCode::StorageWriteFailed,
                "AEAD output payload shorter than authentication tag",
            ));
        }

        let tag_start = sealed.len().saturating_sub(AEAD_TAG_LEN);
        let ciphertext = sealed.get(0..tag_start).unwrap_or(&[]).to_vec();
        let tag_slice = sealed.get(tag_start..).unwrap_or(&[]);
        let mut auth_tag = [0u8; AEAD_TAG_LEN];
        auth_tag.copy_from_slice(tag_slice);

        Ok(EncryptedRecord::new(
            SCHEMA_VERSION_V1,
            CipherSuite::XChaCha20Poly1305,
            nonce,
            record_id_hash,
            ciphertext,
            auth_tag,
        ))
    }

    /// Descifra y autentica un [`EncryptedRecord`].
    ///
    /// # Errores
    /// [`ErrorCode::AeadAuthenticationFailed`] si el registro fue manipulado, el AAD no coincide,
    /// se intercambió de colección o la KEK es incorrecta (fail-closed, `INV-05`).
    pub fn decrypt(
        kek: &SecretBytes<32>,
        record_id: &RecordId,
        collection: &CollectionName,
        record: &EncryptedRecord,
    ) -> Result<Vec<u8>, GidError> {
        if record.cipher_suite() != CipherSuite::XChaCha20Poly1305 {
            return Err(GidError::new(
                ErrorCode::UnsupportedAlgorithm,
                "unsupported cipher suite for decryption",
            ));
        }

        let dek = derive_dek(kek, record_id.as_str())?;
        let aad = compute_aad(record.schema_version(), record_id, collection);

        let mut sealed = Vec::with_capacity(record.ciphertext().len().saturating_add(AEAD_TAG_LEN));
        sealed.extend_from_slice(record.ciphertext());
        sealed.extend_from_slice(record.auth_tag());

        aead_open(dek.expose_secret(), record.nonce(), &sealed, &aad)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use gravital_id_testkit::SeededRng;

    fn test_kek() -> SecretBytes<32> {
        SecretBytes::new([0x33u8; 32])
    }

    #[test]
    fn derive_dek_is_deterministic_and_unique_per_record() {
        let kek = test_kek();
        let dek1 = derive_dek(&kek, "rec-001").expect("dek1");
        let dek1_repeat = derive_dek(&kek, "rec-001").expect("dek1_repeat");
        let dek2 = derive_dek(&kek, "rec-002").expect("dek2");

        assert_eq!(dek1.expose_secret(), dek1_repeat.expose_secret());
        assert_ne!(dek1.expose_secret(), dek2.expose_secret());
    }

    #[test]
    fn derive_bik_is_deterministic() {
        let kek = test_kek();
        let bik1 = derive_bik(&kek).expect("bik1");
        let bik2 = derive_bik(&kek).expect("bik2");
        assert_eq!(bik1.expose_secret(), bik2.expose_secret());
    }

    // // Verifies: REQ-STOR-001 (ciclo de cifrado de sobre y round-trip)
    #[test]
    fn envelope_round_trip() {
        let kek = test_kek();
        let rng = SeededRng::new(12345);
        let record_id = RecordId::new("cred-user-42").expect("valid id");
        let collection = CollectionName::new(CollectionName::CREDENTIALS).expect("valid col");
        let plaintext = b"{\n  \"sub\": \"holder-did-123\",\n  \"status\": \"active\"\n}";

        let encrypted = EnvelopeEncryption::encrypt(&kek, &record_id, &collection, plaintext, &rng)
            .expect("encryption succeeds");

        assert_eq!(encrypted.schema_version(), SCHEMA_VERSION_V1);
        assert_eq!(encrypted.cipher_suite(), CipherSuite::XChaCha20Poly1305);
        assert_ne!(encrypted.ciphertext(), plaintext);

        let decrypted = EnvelopeEncryption::decrypt(&kek, &record_id, &collection, &encrypted)
            .expect("decryption succeeds");
        assert_eq!(decrypted, plaintext);
    }

    // // Verifies: REQ-STOR-001 (intercambio de registros entre colecciones falla)
    #[test]
    fn swapping_collection_fails_authentication() {
        let kek = test_kek();
        let rng = SeededRng::new(12345);
        let record_id = RecordId::new("rec-sensitive").expect("valid id");
        let col_cred = CollectionName::new(CollectionName::CREDENTIALS).expect("valid col");
        let col_keys = CollectionName::new(CollectionName::KEYS).expect("valid col");
        let plaintext = b"secret payload";

        let encrypted = EnvelopeEncryption::encrypt(&kek, &record_id, &col_cred, plaintext, &rng)
            .expect("encrypt");

        // Intentar descifrar bajo otra colección debe fallar autenticación
        let err = EnvelopeEncryption::decrypt(&kek, &record_id, &col_keys, &encrypted)
            .expect_err("swapping collection must fail");
        assert_eq!(err.code, ErrorCode::AeadAuthenticationFailed);
    }

    // // Verifies: REQ-STOR-001 (intercambio de record_id falla)
    #[test]
    fn swapping_record_id_fails_authentication() {
        let kek = test_kek();
        let rng = SeededRng::new(12345);
        let record_id1 = RecordId::new("rec-001").expect("valid id");
        let record_id2 = RecordId::new("rec-002").expect("valid id");
        let collection = CollectionName::new(CollectionName::CREDENTIALS).expect("valid col");
        let plaintext = b"secret payload";

        let encrypted =
            EnvelopeEncryption::encrypt(&kek, &record_id1, &collection, plaintext, &rng)
                .expect("encrypt");

        // Intentar descifrar con otro record_id debe fallar autenticación
        let err = EnvelopeEncryption::decrypt(&kek, &record_id2, &collection, &encrypted)
            .expect_err("swapping record_id must fail");
        assert_eq!(err.code, ErrorCode::AeadAuthenticationFailed);
    }

    // // Verifies: REQ-STOR-001 (corrupción de ciphertext o tag falla autenticación)
    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let kek = test_kek();
        let rng = SeededRng::new(12345);
        let record_id = RecordId::new("rec-tamper").expect("valid id");
        let collection = CollectionName::new(CollectionName::STATE).expect("valid col");
        let plaintext = b"sensitive state data";

        let encrypted = EnvelopeEncryption::encrypt(&kek, &record_id, &collection, plaintext, &rng)
            .expect("encrypt");

        let mut tampered_ciphertext = encrypted.ciphertext().to_vec();
        if let Some(b) = tampered_ciphertext.first_mut() {
            *b ^= 0x01;
        }

        let tampered_record = EncryptedRecord::new(
            encrypted.schema_version(),
            encrypted.cipher_suite(),
            *encrypted.nonce(),
            *encrypted.record_id_hash(),
            tampered_ciphertext,
            *encrypted.auth_tag(),
        );

        let err = EnvelopeEncryption::decrypt(&kek, &record_id, &collection, &tampered_record)
            .expect_err("tampering must fail");
        assert_eq!(err.code, ErrorCode::AeadAuthenticationFailed);
    }

    // // Verifies: REQ-STOR-002 (KekProvider estático)
    #[test]
    fn static_kek_provider_works() {
        let kek = test_kek();
        let provider = StaticKekProvider::new(kek.clone());
        let retrieved = provider.get_kek().expect("provider works");
        assert_eq!(retrieved.expose_secret(), kek.expose_secret());
    }
}
