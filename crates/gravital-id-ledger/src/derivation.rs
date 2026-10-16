//! Derivación determinista del trust bundle canónico desde el estado del ledger (F6.T08).
//!
//! Trazabilidad:
//! - **REQ-TRUST-008:** El bundle DEBE derivarse de forma determinista del estado finalizado
//!   (payload canónico), de modo que operadores independientes obtengan bytes idénticos.
//! - **REQ-LEDG-002:** Derivación sobre la abstracción del ledger.
//! - **INV-01:** Proceso sans-I/O sin acceso a red.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use gravital_id_codec::json::{self, Number, Value};
use gravital_id_crypto::sha256;
use gravital_id_trust::{PolicyEntry, TrustBundle};

use crate::adapter::BlockHeader;
use crate::error::{LedgerError, LedgerResult};
use crate::state::LedgerState;

/// Parámetros de configuración para la derivación del trust bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleDerivationParams {
    /// Identificador del marco de confianza (ej. `"pip-global-mainnet"`).
    pub framework_id: String,
    /// Época vigente del trust bundle.
    pub bundle_epoch: u64,
    /// Versión monotónica incremental del bundle dentro de la época.
    pub bundle_version: u64,
    /// Cabecera del bloque finalizado sobre el que se proyecta el estado.
    pub finalized_block: BlockHeader,
    /// Duración de vigencia en segundos (típicamente 7 días = 604.800 s).
    pub validity_duration_seconds: u64,
    /// Políticas normativas de perfil referenciadas en el bundle.
    pub policies: Vec<PolicyEntry>,
}

impl BundleDerivationParams {
    /// Crea nuevos parámetros de derivación con valores nominales.
    #[must_use]
    pub fn new(
        framework_id: impl Into<String>,
        bundle_epoch: u64,
        bundle_version: u64,
        finalized_block: BlockHeader,
        validity_duration_seconds: u64,
        policies: Vec<PolicyEntry>,
    ) -> Self {
        Self {
            framework_id: framework_id.into(),
            bundle_epoch,
            bundle_version,
            finalized_block,
            validity_duration_seconds,
            policies,
        }
    }
}

/// Resultado de la derivación determinista de un trust bundle.
#[derive(Debug, Clone, PartialEq)]
pub struct DerivedBundle {
    /// Bytes serializados en JSON canónico (RFC 8785 / JCS).
    pub canonical_json_bytes: Vec<u8>,
    /// Digest SHA-256 de los bytes canónicos (material de firma multi-operador).
    pub sha256_digest: [u8; 32],
    /// Instancia parseada y validada del `TrustBundle`.
    pub bundle: TrustBundle,
}

/// Deriva deterministamente el payload canónico de `TrustBundle` a partir del estado consolidado.
///
/// Implementa los requisitos normativos de `TRUST_BUNDLE.md §4` y `REQ-TRUST-008`:
/// 1. Entradas ordenadas canónicamente (emisores, claves, perfiles, verificadores y políticas).
/// 2. Serialización en JSON canónico (RFC 8785) sin espacios ni orden dependiente de hash-map.
/// 3. Garantía matemática: dos operadores independientes que ejecuten esta función con el
///    mismo `LedgerState` y `BundleDerivationParams` obtendrán **exactamente los mismos bytes**.
///
/// # Errores
/// - [`LedgerError::BundleError`]: Si el documento resultante no supera las validaciones
///   estructurales o de límites de `TrustBundle::from_json_bytes`.
/// - [`LedgerError::Serialization`]: Si ocurre un fallo al codificar JSON canónico.
pub fn derive_trust_bundle(
    state: &LedgerState,
    params: &BundleDerivationParams,
) -> LedgerResult<DerivedBundle> {
    let issued_at = params.finalized_block.timestamp;
    let valid_until = issued_at.saturating_add(params.validity_duration_seconds);

    // 1. Construir lista ordenada de emisores (solo con estado activo o suspendido y con claves)
    let mut issuers_map: BTreeMap<String, Value> = BTreeMap::new();

    for (issuer_id_bytes, issuer) in state.issuers() {
        let Some(effective_state) = state.effective_issuer_state(issuer_id_bytes, issued_at) else {
            // Emisor dado de baja se omite
            continue;
        };

        let issuer_id_str = if issuer.uri.is_empty() {
            hex_string(issuer_id_bytes)
        } else {
            issuer.uri.clone()
        };

        // Claves del emisor ordenadas por kid
        let mut keys_map: BTreeMap<String, Value> = BTreeMap::new();
        for (kid_bytes, key_record) in &issuer.keys {
            let Some(key_state) = state.effective_key_state(issuer_id_bytes, kid_bytes, issued_at)
            else {
                continue;
            };

            let kid_str = hex_string(kid_bytes);

            // Parsear el JWK canónico a Value
            let jwk_canonical_json = key_record.jwk.to_canonical_json();
            let jwk_val = json::parse(&jwk_canonical_json).map_err(|e| {
                LedgerError::Serialization(format!("failed to parse jwk json: {e}"))
            })?;

            let key_obj = vec![
                ("jwk".to_string(), jwk_val),
                ("kid".to_string(), Value::String(kid_str.clone())),
                (
                    "state".to_string(),
                    Value::String(key_state.as_str().to_string()),
                ),
                (
                    "state_since".to_string(),
                    Value::Number(Number::PosInt(key_record.state_since)),
                ),
            ];

            let _ = keys_map.insert(kid_str, Value::Object(key_obj));
        }

        // Si el emisor no tiene claves vigentes, se omite según TRUST_BUNDLE.md §8
        if keys_map.is_empty() {
            continue;
        }

        let keys_array: Vec<Value> = keys_map.into_values().collect();

        // Ordenar perfiles y vcts lexicográficamente
        let mut sorted_profiles = issuer.profiles.clone();
        sorted_profiles.sort();
        let profiles_vals: Vec<Value> = sorted_profiles.into_iter().map(Value::String).collect();

        let mut sorted_vcts = issuer.vcts.clone();
        sorted_vcts.sort();
        let vcts_vals: Vec<Value> = sorted_vcts.into_iter().map(Value::String).collect();

        let issuer_obj = vec![
            (
                "issuer_id".to_string(),
                Value::String(issuer_id_str.clone()),
            ),
            ("keys".to_string(), Value::Array(keys_array)),
            ("profiles".to_string(), Value::Array(profiles_vals)),
            (
                "state".to_string(),
                Value::String(effective_state.as_str().to_string()),
            ),
            ("status_keys".to_string(), Value::Array(Vec::new())),
            (
                "valid_from".to_string(),
                Value::Number(Number::PosInt(issuer.valid_from)),
            ),
            (
                "valid_until".to_string(),
                Value::Number(Number::PosInt(issuer.valid_until)),
            ),
            ("vcts".to_string(), Value::Array(vcts_vals)),
        ];

        let _ = issuers_map.insert(issuer_id_str, Value::Object(issuer_obj));
    }

    let issuers_array: Vec<Value> = issuers_map.into_values().collect();

    // 2. Construir lista ordenada de verificadores
    let mut verifiers_map: BTreeMap<String, Value> = BTreeMap::new();
    for (verifier_id_bytes, verifier) in state.verifiers() {
        if !verifier.active {
            continue;
        }

        let verifier_id_str = if verifier.uri.is_empty() {
            hex_string(verifier_id_bytes)
        } else {
            verifier.uri.clone()
        };

        let mut sorted_profiles = verifier.profiles.clone();
        sorted_profiles.sort();
        let profiles_vals: Vec<Value> = sorted_profiles.into_iter().map(Value::String).collect();

        let mut verifier_obj: Vec<(String, Value)> = Vec::new();
        if let Some(jwk) = &verifier.jwk {
            let jwk_json = jwk.to_canonical_json();
            let jwk_val = json::parse(&jwk_json).map_err(|e| {
                LedgerError::Serialization(format!("failed to parse verifier jwk json: {e}"))
            })?;
            verifier_obj.push(("public_key".to_string(), jwk_val));
        }

        verifier_obj.push(("profiles".to_string(), Value::Array(profiles_vals)));
        verifier_obj.push((
            "valid_from".to_string(),
            Value::Number(Number::PosInt(verifier.valid_from)),
        ));
        verifier_obj.push((
            "valid_until".to_string(),
            Value::Number(Number::PosInt(verifier.valid_until)),
        ));
        verifier_obj.push((
            "verifier_id".to_string(),
            Value::String(verifier_id_str.clone()),
        ));

        let _ = verifiers_map.insert(verifier_id_str, Value::Object(verifier_obj));
    }

    let verifiers_array: Vec<Value> = verifiers_map.into_values().collect();

    // 3. Construir lista ordenada de políticas
    let mut policies_map: BTreeMap<String, Value> = BTreeMap::new();
    for policy in &params.policies {
        let policy_obj = vec![
            (
                "policy_hash".to_string(),
                Value::String(policy.policy_hash.clone()),
            ),
            (
                "profile_id".to_string(),
                Value::String(policy.profile_id.clone()),
            ),
            ("version".to_string(), Value::String(policy.version.clone())),
        ];

        let _ = policies_map.insert(policy.profile_id.clone(), Value::Object(policy_obj));
    }

    let policies_array: Vec<Value> = policies_map.into_values().collect();

    // 4. Asamblar objeto raíz del TrustBundle
    let root_obj = vec![
        (
            "bundle_epoch".to_string(),
            Value::Number(Number::PosInt(params.bundle_epoch)),
        ),
        (
            "bundle_version".to_string(),
            Value::Number(Number::PosInt(params.bundle_version)),
        ),
        (
            "chain_id".to_string(),
            Value::Number(Number::PosInt(state.chain_id())),
        ),
        (
            "finalized_block_hash".to_string(),
            Value::String(format!(
                "0x{}",
                hex_string(&params.finalized_block.block_hash)
            )),
        ),
        (
            "finalized_block_number".to_string(),
            Value::Number(Number::PosInt(params.finalized_block.block_number)),
        ),
        (
            "framework_id".to_string(),
            Value::String(params.framework_id.clone()),
        ),
        (
            "issued_at".to_string(),
            Value::Number(Number::PosInt(issued_at)),
        ),
        ("issuers".to_string(), Value::Array(issuers_array)),
        ("policies".to_string(), Value::Array(policies_array)),
        (
            "registry_address".to_string(),
            Value::String(state.registry_address().to_string()),
        ),
        (
            "valid_until".to_string(),
            Value::Number(Number::PosInt(valid_until)),
        ),
        ("verifiers".to_string(), Value::Array(verifiers_array)),
    ];

    let root_val = Value::Object(root_obj);

    // 5. Serializar en JSON canónico (RFC 8785)
    let canonical_str = gravital_id_trust::to_canonical_json(&root_val);
    let canonical_bytes = canonical_str.into_bytes();

    // 6. Calcular SHA-256 digest
    let sha256_digest = sha256(&canonical_bytes);

    // 7. Parsear y verificar que el bundle construido es 100% válido
    let bundle = TrustBundle::from_json_bytes(&canonical_bytes).map_err(|e| {
        LedgerError::BundleError(format!("derived bundle failed structural validation: {e}"))
    })?;

    Ok(DerivedBundle {
        canonical_json_bytes: canonical_bytes,
        sha256_digest,
        bundle,
    })
}

/// Convierte una porción de bytes en cadena hexadecimal minúscula.
#[must_use]
pub fn hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        use core::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}
