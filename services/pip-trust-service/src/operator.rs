//! Nodo operador institucional independiente de cofirma (F7.T04, REQ-TRUST-003, REQ-TRUST-008).

use crate::error::TrustServiceError;
use crate::signer::BundleSignerBackend;
use gravital_id_ledger::{derive_trust_bundle, BundleDerivationParams, DerivedBundle};
use gravital_id_trust::jws_json::JwsSignature;
use pip_indexer::storage::IndexerStorage;
use std::sync::Arc;

/// Respuesta de firma emitida por un operador institucional para un bundle derivado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorSignatureResponse {
    /// Identificador del operador (ej. "operator-1").
    pub operator_id: String,
    /// Key ID registrado para la clave de firma.
    pub kid: String,
    /// Digest SHA-256 del payload canónico que el operador calculó de forma independiente.
    pub payload_sha256: [u8; 32],
    /// Payload canónico codificado en base64url.
    pub payload_b64: String,
    /// Firma generada con cabecera protegida (`kid` + `ES256`).
    pub signature: JwsSignature,
}

/// Nodo operador del Trust Framework que mantiene su propio indexador y firma independientemente.
pub struct TrustOperatorNode {
    storage: Arc<dyn IndexerStorage>,
    signer: Arc<dyn BundleSignerBackend>,
    chain_id: u64,
}

impl TrustOperatorNode {
    /// Crea un nuevo nodo operador institucional.
    #[must_use]
    pub fn new(
        storage: Arc<dyn IndexerStorage>,
        signer: Arc<dyn BundleSignerBackend>,
        chain_id: u64,
    ) -> Self {
        Self {
            storage,
            signer,
            chain_id,
        }
    }

    /// Retorna el identificador del operador.
    #[must_use]
    pub fn operator_id(&self) -> &str {
        self.signer.operator_id()
    }

    /// Retorna el Key ID registrado del operador.
    #[must_use]
    pub fn kid(&self) -> &str {
        self.signer.kid()
    }

    /// Retorna la referencia al backend firmante del operador.
    #[must_use]
    pub fn signer(&self) -> &dyn BundleSignerBackend {
        self.signer.as_ref()
    }

    /// Deriva el estado puro desde su propio indexador y produce el bundle determinista.
    ///
    /// # Errores
    /// Devuelve [`TrustServiceError`] si la reconstrucción o derivación determinista fallan.
    pub fn derive_local_bundle(
        &self,
        params: &BundleDerivationParams,
    ) -> Result<DerivedBundle, TrustServiceError> {
        let state = self
            .storage
            .build_ledger_state(self.chain_id)
            .map_err(|e| TrustServiceError::Indexer(e.to_string()))?;

        derive_trust_bundle(&state, params)
            .map_err(|e| TrustServiceError::Derivation(e.to_string()))
    }

    /// Ejecuta la derivación determinista sobre sus propios datos y firma el resultado.
    ///
    /// # Invariante (REQ-TRUST-008):
    /// El operador **solo firma lo que derivó**. Si su indexador calculó un estado distinto
    /// al de otros operadores, su `payload_sha256` y `signature` serán sobre ese digest distinto,
    /// permitiendo al agregador detectar la divergencia.
    ///
    /// # Errores
    /// Devuelve [`TrustServiceError`] si la derivación o la firma criptográfica fallan.
    pub fn evaluate_and_sign(
        &self,
        params: &BundleDerivationParams,
    ) -> Result<OperatorSignatureResponse, TrustServiceError> {
        let derived = self.derive_local_bundle(params)?;
        let payload_b64 = gravital_id_codec::base64url::encode(&derived.canonical_json_bytes);
        let signature = self.signer.sign_payload_b64(&payload_b64)?;

        Ok(OperatorSignatureResponse {
            operator_id: self.signer.operator_id().to_string(),
            kid: self.signer.kid().to_string(),
            payload_sha256: derived.sha256_digest,
            payload_b64,
            signature,
        })
    }
}
