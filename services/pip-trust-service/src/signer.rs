//! Firmantes criptográficos para operadores del Trust Framework (F7.T04, REQ-TRUST-001, REQ-TRUST-008).

use crate::error::TrustServiceError;
use gravital_id_crypto::jwk::JwkEcP256;
use gravital_id_crypto::secret::SecretKeyBytes;
use gravital_id_crypto::sign::{
    generate_p256_secret_key, public_key_from_secret_key, sign_es256_digest,
};
use gravital_id_trust::jws_json::JwsSignature;

/// Construye la cabecera protegida normada en base64url para un firmante (`{"alg":"ES256","kid":"..."}`).
#[must_use]
pub fn build_protected_header(kid: &str) -> String {
    let header_json = format!(r#"{{"alg":"ES256","kid":"{kid}"}}"#);
    gravital_id_codec::base64url::encode(header_json.as_bytes())
}

/// Trait abstracto de backend de firma para un operador institucional.
pub trait BundleSignerBackend: Send + Sync {
    /// Identificador de la organización del operador (ej. "operator-1").
    fn operator_id(&self) -> &str;

    /// Key ID registrado para este firmante en la raíz de confianza.
    fn kid(&self) -> &str;

    /// Clave pública JWK EC P-256 asociada al firmante.
    fn public_key(&self) -> &JwkEcP256;

    /// Firma la entrada firmada JWS (`BASE64URL(protected) || '.' || BASE64URL(payload)`).
    ///
    /// # Errores
    /// Devuelve [`TrustServiceError::Crypto`] ante fallos de firma.
    fn sign_input(&self, signing_input: &str) -> Result<Vec<u8>, TrustServiceError>;

    /// Genera la estructura completa [`JwsSignature`] para un payload en base64url.
    ///
    /// # Errores
    /// Devuelve [`TrustServiceError`] si la firma falla.
    fn sign_payload_b64(&self, payload_b64: &str) -> Result<JwsSignature, TrustServiceError> {
        let protected_b64 = build_protected_header(self.kid());
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let sig_bytes = self.sign_input(&signing_input)?;

        Ok(JwsSignature {
            kid: Some(self.kid().to_string()),
            protected_b64,
            signature: sig_bytes,
        })
    }
}

/// Firmante local para desarrollo y pruebas con clave privada en memoria.
pub struct LocalDevSigner {
    operator_id: String,
    kid: String,
    secret_key: SecretKeyBytes,
    public_key: JwkEcP256,
}

impl LocalDevSigner {
    /// Crea un firmante a partir de una clave secreta existente.
    ///
    /// # Errores
    /// Devuelve [`TrustServiceError::Crypto`] si los bytes de la clave son inválidos.
    pub fn from_secret_key(
        operator_id: impl Into<String>,
        kid: impl Into<String>,
        secret_key: &SecretKeyBytes,
    ) -> Result<Self, TrustServiceError> {
        let public_key = public_key_from_secret_key(secret_key)
            .map_err(|e| TrustServiceError::Crypto(format!("Error extrayendo JWK: {e}")))?;

        Ok(Self {
            operator_id: operator_id.into(),
            kid: kid.into(),
            secret_key: secret_key.clone(),
            public_key,
        })
    }

    /// Genera un nuevo par de claves P-256 utilizando el generador determinista provisto.
    ///
    /// # Errores
    /// Devuelve [`TrustServiceError::Crypto`] si la generación falla.
    pub fn generate_with_rng(
        operator_id: impl Into<String>,
        kid: impl Into<String>,
        rng: &impl gravital_id_crypto::rng::Rng,
    ) -> Result<Self, TrustServiceError> {
        let secret = generate_p256_secret_key(rng)
            .map_err(|e| TrustServiceError::Crypto(format!("Fallo generando clave: {e}")))?;
        Self::from_secret_key(operator_id, kid, &secret)
    }

    /// Crea un firmante a partir de una cadena hexadecimal de 32 bytes (64 caracteres hex).
    ///
    /// # Errores
    /// Devuelve [`TrustServiceError::Crypto`] si el hex es inválido o no representa un escalar P-256 válido.
    pub fn from_hex(
        operator_id: impl Into<String>,
        kid: impl Into<String>,
        hex_str: &str,
    ) -> Result<Self, TrustServiceError> {
        let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str).trim();
        let bytes = pip_indexer::storage::hex_decode(clean)
            .map_err(|e| TrustServiceError::Crypto(format!("Hex inválido: {e}")))?;
        if bytes.len() != 32 {
            return Err(TrustServiceError::Crypto(format!(
                "Se esperaban 32 bytes para clave privada P-256, se obtuvieron {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let secret = SecretKeyBytes::new(arr);
        Self::from_secret_key(operator_id, kid, &secret)
    }
}

impl BundleSignerBackend for LocalDevSigner {
    fn operator_id(&self) -> &str {
        &self.operator_id
    }

    fn kid(&self) -> &str {
        &self.kid
    }

    fn public_key(&self) -> &JwkEcP256 {
        &self.public_key
    }

    fn sign_input(&self, signing_input: &str) -> Result<Vec<u8>, TrustServiceError> {
        let digest = gravital_id_crypto::sha::sha256(signing_input.as_bytes());
        let sig = sign_es256_digest(&self.secret_key, &digest)
            .map_err(|e| TrustServiceError::Crypto(format!("Fallo en firma ES256: {e}")))?;
        Ok(sig.to_vec())
    }
}

/// Firmante simulado para entornos de prueba que emula un KMS (AWS KMS, GCP Cloud KMS, Azure Key Vault).
pub struct MockKmsSigner {
    operator_id: String,
    kid: String,
    kms_key_arn: String,
    inner_signer: LocalDevSigner,
}

impl MockKmsSigner {
    /// Crea una nueva instancia de firmante KMS simulado.
    #[must_use]
    pub fn new(
        operator_id: impl Into<String>,
        kid: impl Into<String>,
        kms_key_arn: impl Into<String>,
        inner_signer: LocalDevSigner,
    ) -> Self {
        Self {
            operator_id: operator_id.into(),
            kid: kid.into(),
            kms_key_arn: kms_key_arn.into(),
            inner_signer,
        }
    }

    /// Retorna el identificador o ARN de la clave en el KMS.
    #[must_use]
    pub fn kms_key_arn(&self) -> &str {
        &self.kms_key_arn
    }
}

impl BundleSignerBackend for MockKmsSigner {
    fn operator_id(&self) -> &str {
        &self.operator_id
    }

    fn kid(&self) -> &str {
        &self.kid
    }

    fn public_key(&self) -> &JwkEcP256 {
        self.inner_signer.public_key()
    }

    fn sign_input(&self, signing_input: &str) -> Result<Vec<u8>, TrustServiceError> {
        // En producción real, aquí se efectúa la llamada KMS:Sign
        self.inner_signer.sign_input(signing_input)
    }
}
