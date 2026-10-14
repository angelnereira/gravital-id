//! Parseo y verificación estricta de SD-JWT (F3.T03, RFC 9901).
//!
//! Trazabilidad:
//! - **REQ-CRED-001:** Formato normativo SD-JWT según RFC 9901.
//! - **REQ-CRED-009:** Rechazo de miembros duplicados en JSON y colisiones de claims divulgados.
//! - **REQ-VER-003:** Fail-closed: ante cualquier error, dato faltante o ambigüedad, no se acepta.
//! - **REQ-VER-008:** Límites acotados de tamaño, profundidad y elementos por contenedor.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str;

use gravital_id_codec::base64url;
use gravital_id_codec::json::{parse_bytes, Limits as JsonLimits, Value};
use gravital_id_crypto::{verify_es256_jwk, JwkEcP256, ES256_SIGNATURE_LEN};
use gravital_id_types::{ErrorCode, GidError};

use crate::disclosure::{Disclosure, DisclosureDigest, DisclosureKind};

/// Tamaño máximo de entrada en bytes por defecto (64 KiB, CRYPTO_PROFILES §5.2).
pub const DEFAULT_MAX_SD_JWT_INPUT_BYTES: usize = 64 * 1024;

/// Número máximo de divulgaciones permitidas por defecto.
pub const DEFAULT_MAX_DISCLOSURES: usize = 128;

/// Profundidad máxima de recursión permitida por defecto.
pub const DEFAULT_MAX_RECURSION_DEPTH: usize = 16;

/// Número máximo de elementos por contenedor en la reconstrucción por defecto.
pub const DEFAULT_MAX_ELEMENTS_PER_CONTAINER: usize = 256;

/// Límites de tamaño y complejidad para el parseo y verificación de SD-JWT (REQ-VER-008).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdJwtLimits {
    /// Tamaño máximo en bytes de la cadena compacta SD-JWT.
    pub max_input_bytes: usize,
    /// Número máximo de divulgaciones permitidas en la presentación.
    pub max_disclosures: usize,
    /// Profundidad máxima de anidamiento de estructuras recursivas.
    pub max_recursion_depth: usize,
    /// Número máximo de claims en un objeto o elementos en un array.
    pub max_elements_per_container: usize,
}

impl Default for SdJwtLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_SD_JWT_INPUT_BYTES,
            max_disclosures: DEFAULT_MAX_DISCLOSURES,
            max_recursion_depth: DEFAULT_MAX_RECURSION_DEPTH,
            max_elements_per_container: DEFAULT_MAX_ELEMENTS_PER_CONTAINER,
        }
    }
}

/// Representación parseada y validada de un SD-JWT emitido o presentado (RFC 9901).
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedSdJwt {
    raw_issuer_jwt: String,
    signing_input: String,
    signature: [u8; ES256_SIGNATURE_LEN],
    header: Value,
    raw_payload: Value,
    reconstructed_claims: Value,
    disclosures: Vec<Disclosure>,
    kb_jwt: Option<String>,
}

impl ParsedSdJwt {
    /// Parsea y valida una cadena SD-JWT compacta utilizando los límites por defecto.
    pub fn parse(compact: &str) -> Result<Self, GidError> {
        Self::parse_with_limits(compact, &SdJwtLimits::default())
    }

    /// Parsea y valida una cadena SD-JWT compacta con límites configurables (REQ-VER-008).
    pub fn parse_with_limits(compact: &str, limits: &SdJwtLimits) -> Result<Self, GidError> {
        if compact.len() > limits.max_input_bytes {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!(
                    "SD-JWT compact size {} exceeds limit of {} bytes",
                    compact.len(),
                    limits.max_input_bytes
                ),
            ));
        }

        if !compact.contains('~') {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "SD-JWT must contain at least one '~' delimiter",
            ));
        }

        let parts: Vec<&str> = compact.split('~').collect();
        let Some(&issuer_jwt_str) = parts.first() else {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "empty SD-JWT input",
            ));
        };

        if issuer_jwt_str.is_empty() {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "issuer JWT segment cannot be empty",
            ));
        }

        let Some(&last_part) = parts.last() else {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "empty SD-JWT input",
            ));
        };

        let (disclosure_strs, kb_jwt) = if last_part.is_empty() {
            // Termina en '~': no hay KB-JWT
            let end_idx = parts.len().saturating_sub(1);
            let slice = parts.get(1..end_idx).unwrap_or(&[]);
            (slice, None)
        } else {
            // No termina en '~': la última parte es el KB-JWT
            let end_idx = parts.len().saturating_sub(1);
            let slice = parts.get(1..end_idx).unwrap_or(&[]);
            (slice, Some(last_part))
        };

        // Valida el formato del KB-JWT si está presente
        if let Some(kb) = kb_jwt {
            let kb_parts: Vec<&str> = kb.split('.').collect();
            if kb_parts.len() != 3 {
                return Err(GidError::new(
                    ErrorCode::MalformedSdJwt,
                    format!(
                        "Key Binding JWT must contain 3 dot-separated segments, got {}",
                        kb_parts.len()
                    ),
                ));
            }
        }

        // Extracción y validación sintáctica de las divulgaciones
        let raw_disclosure_list = if kb_jwt.is_some() && disclosure_strs == [""] {
            // Caso especial RFC 9901 §5.2: "<jwt>~~<kb_jwt>" representa 0 divulgaciones
            Vec::new()
        } else {
            let mut list = Vec::with_capacity(disclosure_strs.len());
            for &disc_str in disclosure_strs {
                if disc_str.is_empty() {
                    return Err(GidError::new(
                        ErrorCode::MalformedSdJwt,
                        "empty disclosure segment found in SD-JWT",
                    ));
                }
                list.push(disc_str);
            }
            list
        };

        if raw_disclosure_list.len() > limits.max_disclosures {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!(
                    "number of disclosures {} exceeds limit of {}",
                    raw_disclosure_list.len(),
                    limits.max_disclosures
                ),
            ));
        }

        // 1. Verificación de divulgaciones duplicadas (RFC 9901 §5.3)
        let mut seen_strings = BTreeSet::new();
        let mut disclosures = Vec::with_capacity(raw_disclosure_list.len());
        let mut disclosures_map = BTreeMap::new();

        for disc_str in raw_disclosure_list {
            if !seen_strings.insert(disc_str) {
                return Err(GidError::new(
                    ErrorCode::MalformedSdJwt,
                    "duplicate disclosure string found in SD-JWT",
                ));
            }

            let disc = Disclosure::parse(disc_str)?;
            let digest = disc.digest().clone();

            if disclosures_map.contains_key(&digest) {
                return Err(GidError::new(
                    ErrorCode::MalformedSdJwt,
                    "duplicate disclosure digest found in SD-JWT",
                ));
            }

            disclosures_map.insert(digest, disc.clone());
            disclosures.push(disc);
        }

        // 2. Parseo y validación del JWT del emisor
        let jwt_parts: Vec<&str> = issuer_jwt_str.split('.').collect();
        if jwt_parts.len() != 3 {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!(
                    "issuer JWT must contain 3 dot-separated segments, got {}",
                    jwt_parts.len()
                ),
            ));
        }

        let Some(&header_b64) = jwt_parts.first() else {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "missing JWT header",
            ));
        };
        let Some(&payload_b64) = jwt_parts.get(1) else {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "missing JWT payload",
            ));
        };
        let Some(&sig_b64) = jwt_parts.get(2) else {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "missing JWT signature",
            ));
        };

        let signing_input = format!("{header_b64}.{payload_b64}");

        let json_limits = JsonLimits {
            max_input_bytes: limits.max_input_bytes,
            max_depth: limits.max_recursion_depth,
            max_elements: limits.max_elements_per_container,
            max_string_bytes: 8 * 1024,
        };

        // Decodificación de cabecera
        let header_bytes = base64url::decode(header_b64).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("invalid base64url in JWT header: {e}"),
            )
        })?;
        let header_val = parse_bytes(&header_bytes, &json_limits).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("failed to parse JWT header JSON: {e}"),
            )
        })?;

        // Verificación de algoritmo en cabecera (INV-08: ES256 obligatorio, alg: none prohibido)
        match header_val.member("alg") {
            Some(Value::String(alg)) if alg == "ES256" => {}
            Some(Value::String(alg)) => {
                return Err(GidError::new(
                    ErrorCode::UnsupportedAlgorithm,
                    format!("unsupported algorithm '{alg}': only ES256 is supported"),
                ));
            }
            _ => {
                return Err(GidError::new(
                    ErrorCode::UnsupportedAlgorithm,
                    "JWT header must contain a string 'alg' claim with 'ES256'",
                ));
            }
        }

        // Decodificación de payload
        let payload_bytes = base64url::decode(payload_b64).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("invalid base64url in JWT payload: {e}"),
            )
        })?;
        let payload_val = parse_bytes(&payload_bytes, &json_limits).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("failed to parse JWT payload JSON: {e}"),
            )
        })?;

        let payload_entries = match &payload_val {
            Value::Object(entries) => entries,
            _ => {
                return Err(GidError::new(
                    ErrorCode::MalformedSdJwt,
                    "JWT payload must be a JSON object",
                ));
            }
        };

        // Verificación del algoritmo de digest _sd_alg (RFC 9901 §5.1.1)
        if let Some(alg_val) = payload_val.member("_sd_alg") {
            match alg_val {
                Value::String(alg) if alg == "sha-256" => {}
                Value::String(alg) => {
                    return Err(GidError::new(
                        ErrorCode::UnsupportedAlgorithm,
                        format!("unsupported _sd_alg '{alg}': only 'sha-256' is supported"),
                    ));
                }
                _ => {
                    return Err(GidError::new(
                        ErrorCode::MalformedSdJwt,
                        "_sd_alg claim must be a string",
                    ));
                }
            }
        }

        // Decodificación de firma
        let sig_bytes = base64url::decode(sig_b64).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("invalid base64url in JWT signature: {e}"),
            )
        })?;

        if sig_bytes.len() != ES256_SIGNATURE_LEN {
            return Err(GidError::new(
                ErrorCode::InvalidSignature,
                format!("JWT signature must be 64 bytes (got {})", sig_bytes.len()),
            ));
        }

        let mut signature = [0u8; ES256_SIGNATURE_LEN];
        if let Some(slot) = signature.get_mut(..sig_bytes.len()) {
            slot.copy_from_slice(&sig_bytes);
        }

        // 3. Reconstrucción de claims y verificación de digests
        let mut referenced_digests = BTreeSet::new();
        let reconstructed_claims = reconstruct_object(
            payload_entries,
            &disclosures_map,
            &mut referenced_digests,
            0,
            limits,
        )?;

        // 4. Verificación de divulgaciones no referenciadas (RFC 9901 §5.3)
        if referenced_digests.len() != disclosures_map.len() {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!(
                    "unreferenced disclosure(s) found in SD-JWT: {} provided, but only {} referenced",
                    disclosures_map.len(),
                    referenced_digests.len()
                ),
            ));
        }

        Ok(Self {
            raw_issuer_jwt: issuer_jwt_str.to_string(),
            signing_input,
            signature,
            header: header_val,
            raw_payload: payload_val,
            reconstructed_claims,
            disclosures,
            kb_jwt: kb_jwt.map(ToString::to_string),
        })
    }

    /// Retorna la cadena cruda del JWT del emisor (`<header>.<payload>.<sig>`).
    #[must_use]
    pub fn raw_issuer_jwt(&self) -> &str {
        &self.raw_issuer_jwt
    }

    /// Retorna la entrada firmada del JWS del emisor (`<header_b64>.<payload_b64>`).
    #[must_use]
    pub fn signing_input(&self) -> &str {
        &self.signing_input
    }

    /// Retorna los 64 bytes de la firma ES256 del emisor (P1363 `r||s`).
    #[must_use]
    pub fn signature(&self) -> &[u8; ES256_SIGNATURE_LEN] {
        &self.signature
    }

    /// Retorna la cabecera JWS decodificada como [`Value`].
    #[must_use]
    pub fn header(&self) -> &Value {
        &self.header
    }

    /// Retorna el payload crudo del JWT del emisor con metadatos `_sd` y `_sd_alg`.
    #[must_use]
    pub fn raw_payload(&self) -> &Value {
        &self.raw_payload
    }

    /// Retorna el objeto JSON con todos los claims revelados reconstruidos (RFC 9901 §5.3).
    #[must_use]
    pub fn reconstructed_claims(&self) -> &Value {
        &self.reconstructed_claims
    }

    /// Retorna las divulgaciones válidas presentes en la credencial.
    #[must_use]
    pub fn disclosures(&self) -> &[Disclosure] {
        &self.disclosures
    }

    /// Retorna el Key Binding JWT si está presente en la serialización compacta.
    #[must_use]
    pub fn kb_jwt(&self) -> Option<&str> {
        self.kb_jwt.as_deref()
    }

    /// Retorna `true` si la presentación incluye un Key Binding JWT.
    #[must_use]
    pub fn has_kb_jwt(&self) -> bool {
        self.kb_jwt.is_some()
    }

    /// Verifica la firma JWS del emisor contra una clave pública JWK EC P-256.
    pub fn verify_issuer_signature(&self, jwk: &JwkEcP256) -> Result<(), GidError> {
        verify_es256_jwk(jwk, self.signing_input.as_bytes(), &self.signature)
    }
}

/// Reconstruye recursivamente un objeto JSON procesando `_sd` e insertando claims divulgados.
fn reconstruct_object(
    entries: &[(String, Value)],
    disclosures_map: &BTreeMap<DisclosureDigest, Disclosure>,
    referenced_digests: &mut BTreeSet<DisclosureDigest>,
    depth: usize,
    limits: &SdJwtLimits,
) -> Result<Value, GidError> {
    if depth > limits.max_recursion_depth {
        return Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            format!(
                "recursion depth limit of {} exceeded during SD-JWT reconstruction",
                limits.max_recursion_depth
            ),
        ));
    }

    // Comprueba duplicados en _sd si existe
    let sd_opt = entries.iter().find(|(k, _)| k == "_sd").map(|(_, v)| v);
    if let Some(sd_val) = sd_opt {
        let digests = match sd_val {
            Value::Array(arr) => arr,
            _ => {
                return Err(GidError::new(
                    ErrorCode::MalformedSdJwt,
                    "_sd claim must be a JSON array",
                ));
            }
        };

        let mut seen = BTreeSet::new();
        for d in digests {
            let Some(d_str) = d.as_str() else {
                return Err(GidError::new(
                    ErrorCode::MalformedSdJwt,
                    "_sd array elements must be strings",
                ));
            };
            if !seen.insert(d_str) {
                return Err(GidError::new(
                    ErrorCode::MalformedSdJwt,
                    format!("duplicate digest '{d_str}' in _sd array"),
                ));
            }
        }
    }

    let mut reconstructed = Vec::with_capacity(entries.len());

    // 1. Procesa claims llanos (excluyendo metadatos _sd y _sd_alg)
    for (key, val) in entries {
        if key == "_sd" || key == "_sd_alg" {
            continue;
        }

        let processed_val = reconstruct_value(
            val,
            disclosures_map,
            referenced_digests,
            depth.saturating_add(1),
            limits,
        )?;
        reconstructed.push((key.clone(), processed_val));
    }

    // 2. Procesa digests de _sd e inserta los claims divulgados
    if let Some(Value::Array(digests)) = sd_opt {
        for d_val in digests {
            let Some(d_str) = d_val.as_str() else {
                return Err(GidError::new(
                    ErrorCode::MalformedSdJwt,
                    "_sd digest must be a string",
                ));
            };

            let digest = DisclosureDigest::from_base64url(d_str)?;

            if let Some(disc) = disclosures_map.get(&digest) {
                let (claim_name, claim_value) = match disc.kind() {
                    DisclosureKind::ObjectProperty {
                        claim_name,
                        claim_value,
                    } => (claim_name, claim_value),
                    DisclosureKind::ArrayElement { .. } => {
                        return Err(GidError::new(
                            ErrorCode::MalformedSdJwt,
                            "digest in _sd refers to an array element disclosure instead of object property",
                        ));
                    }
                };

                // REQ-CRED-009: Rechazo de colisión de nombres de miembros en objeto
                if reconstructed.iter().any(|(k, _)| k == claim_name) {
                    return Err(GidError::new(
                        ErrorCode::MalformedSdJwt,
                        format!(
                            "duplicate claim name '{claim_name}' in object (collision with disclosure)"
                        ),
                    ));
                }

                // Claims reservados prohibidos
                if claim_name == "_sd" || claim_name == "..." {
                    return Err(GidError::new(
                        ErrorCode::MalformedSdJwt,
                        format!("reserved claim name '{claim_name}' cannot be disclosed"),
                    ));
                }

                let processed_val = reconstruct_value(
                    claim_value,
                    disclosures_map,
                    referenced_digests,
                    depth.saturating_add(1),
                    limits,
                )?;

                reconstructed.push((claim_name.clone(), processed_val));
                referenced_digests.insert(digest);
            }
            // Si el digest no está en disclosures_map, es un claim no revelado o señuelo
        }
    }

    if reconstructed.len() > limits.max_elements_per_container {
        return Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            format!(
                "object element count {} exceeds limit of {}",
                reconstructed.len(),
                limits.max_elements_per_container
            ),
        ));
    }

    Ok(Value::Object(reconstructed))
}

/// Reconstruye recursivamente un array JSON procesando elementos "..." e insertando valores divulgados.
fn reconstruct_array(
    elements: &[Value],
    disclosures_map: &BTreeMap<DisclosureDigest, Disclosure>,
    referenced_digests: &mut BTreeSet<DisclosureDigest>,
    depth: usize,
    limits: &SdJwtLimits,
) -> Result<Value, GidError> {
    if depth > limits.max_recursion_depth {
        return Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            format!(
                "recursion depth limit of {} exceeded during SD-JWT reconstruction",
                limits.max_recursion_depth
            ),
        ));
    }

    let mut reconstructed = Vec::with_capacity(elements.len());

    for item in elements {
        // Un placeholder de divulgación de array es un objeto con exactamente un miembro "..."
        let is_placeholder = match item {
            Value::Object(entries) if entries.len() == 1 => {
                if let Some((k, v)) = entries.first() {
                    if k == "..." {
                        v.as_str()
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(digest_str) = is_placeholder {
            let digest = DisclosureDigest::from_base64url(digest_str)?;

            if let Some(disc) = disclosures_map.get(&digest) {
                let element_value = match disc.kind() {
                    DisclosureKind::ArrayElement { element_value } => element_value,
                    DisclosureKind::ObjectProperty { .. } => {
                        return Err(GidError::new(
                            ErrorCode::MalformedSdJwt,
                            "digest in '...' refers to an object property disclosure instead of array element",
                        ));
                    }
                };

                let processed_val = reconstruct_value(
                    element_value,
                    disclosures_map,
                    referenced_digests,
                    depth.saturating_add(1),
                    limits,
                )?;

                reconstructed.push(processed_val);
                referenced_digests.insert(digest);
            }
            // Si el digest no está en disclosures_map, el elemento no fue revelado o es un decoy
        } else {
            // Elemento ordinario
            let processed_val = reconstruct_value(
                item,
                disclosures_map,
                referenced_digests,
                depth.saturating_add(1),
                limits,
            )?;
            reconstructed.push(processed_val);
        }
    }

    if reconstructed.len() > limits.max_elements_per_container {
        return Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            format!(
                "array element count {} exceeds limit of {}",
                reconstructed.len(),
                limits.max_elements_per_container
            ),
        ));
    }

    Ok(Value::Array(reconstructed))
}

/// Reconstruye cualquier valor JSON de forma recursiva.
fn reconstruct_value(
    val: &Value,
    disclosures_map: &BTreeMap<DisclosureDigest, Disclosure>,
    referenced_digests: &mut BTreeSet<DisclosureDigest>,
    depth: usize,
    limits: &SdJwtLimits,
) -> Result<Value, GidError> {
    match val {
        Value::Object(entries) => {
            reconstruct_object(entries, disclosures_map, referenced_digests, depth, limits)
        }
        Value::Array(elements) => {
            reconstruct_array(elements, disclosures_map, referenced_digests, depth, limits)
        }
        primitive => Ok(primitive.clone()),
    }
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
    use alloc::string::ToString;
    use gravital_id_keys::{IssuerSigning, KeyStore, SoftwareKeyStore};
    use gravital_id_testkit::SeededRng;

    use crate::issuer::{JwsHeader, SdArrayBuilder, SdIssuer, SdObjectBuilder};

    #[test]
    fn parse_and_reconstruct_nominal_sd_jwt() {
        let rng = SeededRng::new(5001);
        let mut key_store = SoftwareKeyStore::new(rng);
        let handle = key_store
            .generate_key::<IssuerSigning>()
            .expect("generate signing key");
        let jwk = key_store.public_key(&handle).expect("public key");

        let rng_emit = SeededRng::new(5002);
        let builder = SdObjectBuilder::new()
            .add_plain_claim("iss", Value::String("https://issuer.example".to_string()))
            .add_plain_claim("sub", Value::String("subject_01".to_string()))
            .add_sd_claim("email", Value::String("alice@example.com".to_string()))
            .add_sd_claim(
                "age",
                Value::Number(gravital_id_codec::json::Number::PosInt(25)),
            )
            .set_decoys(2);

        let issued = SdIssuer::issue_signed(
            builder,
            &key_store,
            &handle,
            JwsHeader::default(),
            &rng_emit,
        )
        .expect("issue sd-jwt");

        let compact = issued.to_compact_serialization();

        // Parsea con parser
        let parsed = ParsedSdJwt::parse(compact).expect("parse sd-jwt");

        assert_eq!(parsed.disclosures().len(), 2);
        assert!(!parsed.has_kb_jwt());
        assert_eq!(parsed.kb_jwt(), None);

        // Verifica firma del emisor
        parsed
            .verify_issuer_signature(&jwk)
            .expect("verify signature");

        // Verifica claims reconstruidos
        let claims = parsed.reconstructed_claims();
        assert_eq!(
            claims.member("iss"),
            Some(&Value::String("https://issuer.example".to_string()))
        );
        assert_eq!(
            claims.member("sub"),
            Some(&Value::String("subject_01".to_string()))
        );
        assert_eq!(
            claims.member("email"),
            Some(&Value::String("alice@example.com".to_string()))
        );
        assert_eq!(
            claims.member("age"),
            Some(&Value::Number(gravital_id_codec::json::Number::PosInt(25)))
        );

        // _sd y _sd_alg no deben estar en los claims reconstruidos
        assert_eq!(claims.member("_sd"), None);
        assert_eq!(claims.member("_sd_alg"), None);
    }

    #[test]
    fn parse_and_reconstruct_nested_and_array_structures() {
        let rng = SeededRng::new(6001);
        let mut key_store = SoftwareKeyStore::new(rng);
        let handle = key_store
            .generate_key::<IssuerSigning>()
            .expect("generate signing key");

        let rng_emit = SeededRng::new(6002);

        let address = SdObjectBuilder::new()
            .add_sd_claim("street", Value::String("Calle 50".to_string()))
            .add_plain_claim("city", Value::String("Panama".to_string()));

        let nationalities = SdArrayBuilder::new()
            .add_plain_element(Value::String("PA".to_string()))
            .add_sd_element(Value::String("ES".to_string()));

        let root = SdObjectBuilder::new()
            .add_plain_claim("iss", Value::String("https://issuer.example".to_string()))
            .add_nested_object_sd("address", address)
            .add_nested_array_plain("nationalities", nationalities);

        let issued =
            SdIssuer::issue_signed(root, &key_store, &handle, JwsHeader::default(), &rng_emit)
                .expect("issue sd-jwt");

        let compact = issued.to_compact_serialization();
        let parsed = ParsedSdJwt::parse(compact).expect("parse sd-jwt");

        let claims = parsed.reconstructed_claims();
        assert_eq!(
            claims.member("iss"),
            Some(&Value::String("https://issuer.example".to_string()))
        );

        // Reconstrucción del objeto address anidado
        match claims.member("address") {
            Some(Value::Object(addr_entries)) => {
                let street = addr_entries
                    .iter()
                    .find(|(k, _)| k == "street")
                    .map(|(_, v)| v);
                assert_eq!(street, Some(&Value::String("Calle 50".to_string())));
                let city = addr_entries
                    .iter()
                    .find(|(k, _)| k == "city")
                    .map(|(_, v)| v);
                assert_eq!(city, Some(&Value::String("Panama".to_string())));
                assert!(addr_entries.iter().all(|(k, _)| k != "_sd"));
            }
            _ => panic!("expected reconstructed object for address"),
        }

        // Reconstrucción del array nationalities
        match claims.member("nationalities") {
            Some(Value::Array(items)) => {
                assert_eq!(items.len(), 2);
                assert_eq!(items[0], Value::String("PA".to_string()));
                assert_eq!(items[1], Value::String("ES".to_string()));
            }
            _ => panic!("expected reconstructed array for nationalities"),
        }
    }

    #[test]
    fn parse_compact_with_key_binding_jwt() {
        let rng = SeededRng::new(7001);
        let mut key_store = SoftwareKeyStore::new(rng);
        let handle = key_store
            .generate_key::<IssuerSigning>()
            .expect("generate signing key");

        let rng_emit = SeededRng::new(7002);
        let builder = SdObjectBuilder::new()
            .add_plain_claim("iss", Value::String("https://issuer.example".to_string()))
            .add_sd_claim("sub", Value::String("user_123".to_string()));

        let issued = SdIssuer::issue_signed(
            builder,
            &key_store,
            &handle,
            JwsHeader::default(),
            &rng_emit,
        )
        .expect("issue sd-jwt");

        // Simula presentación con KB-JWT adjunto al final
        let kb_jwt_mock =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJub25jZSI6IjEyMzQ1NiJ9.c2lnbmF0dXJlX21vY2s";
        let mut compact_with_kb = issued.to_compact_serialization().to_string();
        // issued.to_compact_serialization() termina en '~'
        compact_with_kb.push_str(kb_jwt_mock);

        let parsed = ParsedSdJwt::parse(&compact_with_kb).expect("parse with kb-jwt");
        assert!(parsed.has_kb_jwt());
        assert_eq!(parsed.kb_jwt(), Some(kb_jwt_mock));
        assert_eq!(parsed.disclosures().len(), 1);
    }
}
