//! Agregador no confiable de firmas para el Trust Bundle (F7.T04, REQ-TRUST-001, REQ-TRUST-008).

use crate::error::TrustServiceError;
use crate::operator::OperatorSignatureResponse;
use gravital_id_crypto::jwk::JwkEcP256;
use gravital_id_crypto::sign::verify_es256_jwk;
use gravital_id_ledger::DerivedBundle;
use gravital_id_trust::jws_json::{JwsJsonParser, JwsSignature};
use gravital_id_trust::root::TrustRoot;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Resultado de la agregación de firmas multi-operador para un trust bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatedSignedBundle {
    /// Documento completo en formato JWS Serialización JSON General (RFC 7515 §7.2).
    pub jws_json: String,
    /// Payload canónico en base64url.
    pub payload_b64: String,
    /// Digest SHA-256 del payload canónico sobre el que se acumuló quórum.
    pub canonical_digest: [u8; 32],
    /// Número de firmas válidas incluidas en el documento.
    pub valid_signatures_count: usize,
    /// Número de operadores institucionales distintos que firmaron válidamente.
    pub distinct_operators: u32,
    /// Lista de operadores cuyas firmas fueron rechazadas por divergencia en el digest o estado.
    pub divergent_operators: Vec<String>,
}

/// Agregador no confiable que recopila firmas de múltiples operadores,
/// verifica su coincidencia y umbral $k$-de-$n$, y ensambla el JWS final.
#[derive(Debug, Clone)]
pub struct UntrustedBundleAggregator {
    threshold: u32,
    root: Option<TrustRoot>,
}

impl UntrustedBundleAggregator {
    /// Crea un nuevo agregador con un umbral de operadores mínimos requerido.
    #[must_use]
    pub fn new(threshold: u32) -> Self {
        Self {
            threshold,
            root: None,
        }
    }

    /// Asocia una raíz de confianza fija para verificar firmantes autorizados contra el registro.
    #[must_use]
    pub fn with_root(mut self, root: TrustRoot) -> Self {
        self.root = Some(root);
        self
    }

    /// Retorna el umbral mínimo configurado.
    #[must_use]
    pub const fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Agrega y valida un conjunto de respuestas de operadores contra el bundle de referencia.
    ///
    /// # Flujo y Reglas:
    /// 1. Compara el `payload_sha256` y `payload_b64` de cada operador contra el bundle canónico de referencia.
    /// 2. Si un operador calculó un digest distinto, **se aísla como divergente** y su firma no se incluye.
    /// 3. Verifica la firma ES256 contra la clave pública del operador (declarada o en la raíz).
    /// 4. Cuenta operadores distintos (un operador con múltiples firmas duplicadas cuenta como 1).
    /// 5. Si `distinct_operators < threshold`, falla cerrado con [`TrustServiceError::InsufficientSignatures`].
    /// 6. Ensambla el documento final JWS General JSON Serialization conforme a RFC 7515 §7.2.
    ///
    /// # Errores
    /// - [`TrustServiceError::InsufficientSignatures`]: Si no se alcanza el umbral de operadores distintos.
    /// - [`TrustServiceError::Aggregation`]: Si la estructura JWS ensamblada no es válida.
    pub fn aggregate(
        &self,
        reference_bundle: &DerivedBundle,
        operator_responses: &[OperatorSignatureResponse],
        keys_by_kid: &BTreeMap<String, JwkEcP256>,
    ) -> Result<AggregatedSignedBundle, TrustServiceError> {
        let expected_payload_b64 =
            gravital_id_codec::base64url::encode(&reference_bundle.canonical_json_bytes);
        let expected_digest = reference_bundle.sha256_digest;

        let mut valid_signatures: Vec<JwsSignature> = Vec::new();
        let mut distinct_operators: BTreeSet<String> = BTreeSet::new();
        let mut divergent_operators: Vec<String> = Vec::new();

        for resp in operator_responses {
            // 1. Detección de divergencia: ¿el operador derivó los mismos bytes canónicos? (REQ-TRUST-008)
            if resp.payload_sha256 != expected_digest || resp.payload_b64 != expected_payload_b64 {
                tracing::warn!(
                    operator = %resp.operator_id,
                    calculated_hash = %hex_fmt(&resp.payload_sha256),
                    expected_hash = %hex_fmt(&expected_digest),
                    "Operador con cálculo divergente detectado: firma rechazada"
                );
                divergent_operators.push(resp.operator_id.clone());
                continue;
            }

            // 2. Resolver clave pública para verificación
            let jwk_opt = if let Some(root) = &self.root {
                root.bundle_signer(&resp.kid).map(|s| s.jwk.clone())
            } else {
                keys_by_kid.get(&resp.kid).cloned()
            };

            let Some(jwk) = jwk_opt else {
                tracing::warn!(
                    operator = %resp.operator_id,
                    kid = %resp.kid,
                    "Clave del operador no encontrada o no autorizada en la raíz"
                );
                continue;
            };

            // 3. Verificar criptográficamente la firma
            let signing_input = format!("{}.{}", resp.signature.protected_b64, resp.payload_b64);
            if let Err(e) =
                verify_es256_jwk(&jwk, signing_input.as_bytes(), &resp.signature.signature)
            {
                tracing::warn!(
                    operator = %resp.operator_id,
                    kid = %resp.kid,
                    error = %e,
                    "Firma del operador no verificó criptográficamente"
                );
                continue;
            }

            // 4. Prevenir firmas duplicadas por el mismo operador
            if distinct_operators.contains(&resp.operator_id) {
                tracing::debug!(
                    operator = %resp.operator_id,
                    "Firma duplicada del mismo operador ignorada para el cómputo del umbral"
                );
                continue;
            }

            distinct_operators.insert(resp.operator_id.clone());
            valid_signatures.push(resp.signature.clone());
        }

        // 5. Verificar umbral k-de-n de operadores distintos (REQ-TRUST-001, INV-16)
        let distinct_count = u32::try_from(distinct_operators.len()).unwrap_or(0);
        if distinct_count < self.threshold {
            return Err(TrustServiceError::InsufficientSignatures {
                required: self.threshold,
                valid: distinct_count,
            });
        }

        // 6. Ensamblar documento JWS General JSON (RFC 7515 §7.2)
        let jws_json = assemble_jws_json(&expected_payload_b64, &valid_signatures);

        // 7. Validar integridad estructural con el parser canónico de gravital-id-trust
        JwsJsonParser::parse(&jws_json).map_err(|e| {
            TrustServiceError::Aggregation(format!("JWS multi-firma generado inválido: {e}"))
        })?;

        Ok(AggregatedSignedBundle {
            jws_json,
            payload_b64: expected_payload_b64,
            canonical_digest: expected_digest,
            valid_signatures_count: valid_signatures.len(),
            distinct_operators: distinct_count,
            divergent_operators,
        })
    }
}

/// Ensambla un documento JWS en Serialización JSON General (RFC 7515 §7.2).
#[must_use]
pub fn assemble_jws_json(payload_b64: &str, signatures: &[JwsSignature]) -> String {
    let mut sigs_json = String::new();
    sigs_json.push('[');
    for (idx, sig) in signatures.iter().enumerate() {
        if idx > 0 {
            sigs_json.push(',');
        }
        let sig_b64 = gravital_id_codec::base64url::encode(&sig.signature);
        let item = format!(
            r#"{{"protected":"{}","signature":"{}"}}"#,
            sig.protected_b64, sig_b64
        );
        sigs_json.push_str(&item);
    }
    sigs_json.push(']');

    format!(r#"{{"payload":"{payload_b64}","signatures":{sigs_json}}}"#)
}

fn hex_fmt(bytes: &[u8; 32]) -> String {
    pip_indexer::storage::hex_encode(bytes)
}
