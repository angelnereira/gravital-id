//! JWS en Serialización JSON General (RFC 7515 §7.2) para documentos multi-firma.
//!
//! La raíz de confianza y el trust bundle se distribuyen con varias firmas sobre el mismo
//! payload, cada una con su cabecera protegida (`kid` incluido). Este módulo aísla el
//! parseo de esa estructura: no interpreta el payload, solo lo entrega junto con las firmas
//! verificables.
//!
//! Trazabilidad:
//! - **REQ-TRUST-001:** el bundle se cofirma por un umbral k-de-n de firmantes distintos.
//! - **REQ-TRUST-009:** la cadena de raíces exige umbrales de la raíz anterior y de la nueva.
//! - **INV-08:** solo `ES256`; `alg: none` siempre rechazado.
//! - **INV-10:** sin pánicos: entradas mal formadas devuelven error.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use gravital_id_codec::base64url;
use gravital_id_codec::json::{parse_bytes, Limits as JsonLimits, Value};
use gravital_id_types::{ErrorCode, GidError};

/// Algoritmo normativo de firma de los documentos de confianza (INV-08).
pub const JWS_ALG: &str = "ES256";

/// Una firma dentro de la serialización JSON general.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwsSignature {
    /// Identificador de clave declarado en la cabecera protegida.
    pub kid: Option<String>,
    /// Cabecera protegida en base64url (necesaria para reconstruir la entrada firmada).
    pub protected_b64: String,
    /// Bytes de la firma (64 bytes IEEE P1363 `r||s`).
    pub signature: Vec<u8>,
}

/// Documento JWS multi-firma ya parseado.
#[derive(Debug, Clone, PartialEq)]
pub struct MultiSignedJws {
    /// Payload decodificado (JSON canónico del documento).
    pub payload_bytes: Vec<u8>,
    /// Payload en base64url, tal como aparece en el documento.
    pub payload_b64: String,
    /// Payload como valor JSON.
    pub payload: Value,
    /// Firmas presentes, en el orden del documento.
    pub signatures: Vec<JwsSignature>,
}

impl MultiSignedJws {
    /// Payload en base64url, tal como aparece en el documento.
    #[must_use]
    pub fn payload_b64(&self) -> &str {
        &self.payload_b64
    }

    /// Entrada firmada de una firma concreta (`protected_b64.payload_b64`).
    #[must_use]
    pub fn signing_input_for(&self, signature: &JwsSignature) -> String {
        format!("{}.{}", signature.protected_b64, self.payload_b64)
    }

    /// Verifica cada firma contra la clave indicada por su `kid`.
    ///
    /// Cada firma se comprueba sobre **su propia** entrada firmada
    /// (`BASE64URL(protected) || '.' || BASE64URL(payload)`), porque en la serialización
    /// JSON general cada firma puede llevar una cabecera protegida distinta (RFC 7515
    /// §7.2).
    ///
    /// Devuelve la lista de `kid` que han verificado correctamente; los `kid` sin clave
    /// disponible simplemente no aparecen (el llamador decide si eso incumple el umbral).
    ///
    /// # Errores
    /// [`ErrorCode::InvalidSignature`] si una firma tiene longitud inválida; en ese caso
    /// el documento se considera corrupto, no \"sin verificar\".
    pub fn verified_kids(
        &self,
        key_for: impl Fn(&str) -> Option<gravital_id_crypto::JwkEcP256>,
    ) -> Result<Vec<String>, GidError> {
        let mut verified = Vec::new();
        for entry in &self.signatures {
            let Some(kid) = entry.kid.as_deref() else {
                continue;
            };
            let Some(key) = key_for(kid) else {
                continue;
            };
            if entry.signature.len() != gravital_id_crypto::ES256_SIGNATURE_LEN {
                return Err(GidError::new(
                    ErrorCode::InvalidSignature,
                    format!(
                        "signature of '{kid}' must be {} bytes, got {}",
                        gravital_id_crypto::ES256_SIGNATURE_LEN,
                        entry.signature.len()
                    ),
                ));
            }
            let mut signature = [0u8; gravital_id_crypto::ES256_SIGNATURE_LEN];
            if let Some(slot) = signature.get_mut(..entry.signature.len()) {
                slot.copy_from_slice(&entry.signature);
            }
            let signing_input = format!("{}.{}", entry.protected_b64, self.payload_b64);
            if gravital_id_crypto::verify_es256_jwk(&key, signing_input.as_bytes(), &signature)
                .is_ok()
            {
                verified.push(kid.to_string());
            }
        }
        Ok(verified)
    }
}

/// Parseador de documentos JWS multi-firma.
pub struct JwsJsonParser;

impl JwsJsonParser {
    /// Parsea una serialización JSON general (RFC 7515 §7.2).
    ///
    /// # Errores
    /// - [`ErrorCode::MalformedSdJwt`] si la estructura no es válida, si hay firmas
    ///   duplicadas por `kid`, si el base64url no es canónico o si el payload no es JSON.
    /// - [`ErrorCode::UnsupportedAlgorithm`] si alguna cabecera protegida declara `none` o
    ///   un algoritmo distinto de `ES256`.
    pub fn parse(document: &str) -> Result<MultiSignedJws, GidError> {
        let limits = JsonLimits::profile_default();
        let root = parse_bytes(document.as_bytes(), &limits).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("invalid JWS JSON document: {e}"),
            )
        })?;

        let payload_b64 = root
            .member("payload")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                GidError::new(
                    ErrorCode::MalformedSdJwt,
                    "JWS document missing the base64url 'payload' member",
                )
            })?;
        let payload_bytes = base64url::decode(payload_b64).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("invalid base64url in JWS payload: {e}"),
            )
        })?;
        let payload = parse_bytes(&payload_bytes, &limits).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("JWS payload is not valid JSON: {e}"),
            )
        })?;

        let Some(Value::Array(raw_signatures)) = root.member("signatures") else {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "JWS document missing the 'signatures' array",
            ));
        };
        if raw_signatures.is_empty() {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "JWS document declares no signatures",
            ));
        }

        let mut signatures = Vec::with_capacity(raw_signatures.len());
        let mut seen_kids: Vec<String> = Vec::new();
        for entry in raw_signatures {
            let protected_b64 = entry
                .member("protected")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    GidError::new(
                        ErrorCode::MalformedSdJwt,
                        "JWS signature entry missing 'protected'",
                    )
                })?;
            let protected_bytes = base64url::decode(protected_b64).map_err(|e| {
                GidError::new(
                    ErrorCode::MalformedSdJwt,
                    format!("invalid base64url in JWS protected header: {e}"),
                )
            })?;
            let protected = parse_bytes(&protected_bytes, &limits).map_err(|e| {
                GidError::new(
                    ErrorCode::MalformedSdJwt,
                    format!("JWS protected header is not valid JSON: {e}"),
                )
            })?;

            match protected.member("alg").and_then(Value::as_str) {
                Some(alg) if alg == JWS_ALG => {}
                Some(alg) if alg.eq_ignore_ascii_case("none") => {
                    return Err(GidError::new(
                        ErrorCode::UnsupportedAlgorithm,
                        "algorithm 'none' is strictly prohibited (INV-08)",
                    ));
                }
                Some(alg) => {
                    return Err(GidError::new(
                        ErrorCode::UnsupportedAlgorithm,
                        format!("unsupported algorithm '{alg}': only {JWS_ALG} is supported"),
                    ));
                }
                None => {
                    return Err(GidError::new(
                        ErrorCode::UnsupportedAlgorithm,
                        "JWS protected header missing 'alg'",
                    ));
                }
            }

            let kid = protected
                .member("kid")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            if let Some(kid) = kid.as_deref() {
                if seen_kids.iter().any(|seen| seen == kid) {
                    return Err(GidError::new(
                        ErrorCode::MalformedSdJwt,
                        format!("duplicate signature for kid '{kid}'"),
                    ));
                }
                seen_kids.push(kid.to_string());
            }

            let signature_b64 = entry
                .member("signature")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    GidError::new(
                        ErrorCode::MalformedSdJwt,
                        "JWS signature entry missing 'signature'",
                    )
                })?;
            let signature = base64url::decode(signature_b64).map_err(|e| {
                GidError::new(
                    ErrorCode::MalformedSdJwt,
                    format!("invalid base64url in JWS signature: {e}"),
                )
            })?;

            signatures.push(JwsSignature {
                kid,
                protected_b64: protected_b64.to_string(),
                signature,
            });
        }

        Ok(MultiSignedJws {
            payload_bytes,
            payload_b64: payload_b64.to_string(),
            payload,
            signatures,
        })
    }

    /// Entrada firmada para una cabecera protegida concreta.
    ///
    /// RFC 7515 §7.2: la entrada es `BASE64URL(UTF8(protected)) || '.' || BASE64URL(payload)`,
    /// que en la serialización JSON general coincide con los campos del documento.
    #[must_use]
    pub fn signing_input(payload_b64: &str, protected_b64: &str) -> String {
        format!("{protected_b64}.{payload_b64}")
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
    use gravital_id_codec::base64url;

    fn protected(kid: &str) -> String {
        format!(r#"{{"alg":"ES256","kid":"{kid}"}}"#)
    }

    #[test]
    fn parse_rejects_documents_without_signatures() {
        let document = format!(
            r#"{{"payload":"{}","signatures":[]}}"#,
            base64url::encode(br#"{"a":1}"#)
        );
        let error = JwsJsonParser::parse(&document).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedSdJwt);
    }

    #[test]
    fn parse_rejects_alg_none_and_unsupported_alg() {
        let payload = base64url::encode(br#"{"a":1}"#);
        let document = format!(
            r#"{{"payload":"{payload}","signatures":[{{"protected":"{}","signature":"{}"}}]}}"#,
            base64url::encode(br#"{"alg":"none","kid":"k1"}"#),
            base64url::encode(&[0u8; 64])
        );
        let error = JwsJsonParser::parse(&document).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedAlgorithm);

        let document = format!(
            r#"{{"payload":"{payload}","signatures":[{{"protected":"{}","signature":"{}"}}]}}"#,
            base64url::encode(br#"{"alg":"RS256","kid":"k1"}"#),
            base64url::encode(&[0u8; 64])
        );
        let error = JwsJsonParser::parse(&document).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedAlgorithm);
    }

    #[test]
    fn parse_rejects_duplicate_kids() {
        let payload = base64url::encode(br#"{"a":1}"#);
        let signature = base64url::encode(&[0u8; 64]);
        let document = format!(
            r#"{{"payload":"{payload}","signatures":[{{"protected":"{}","signature":"{signature}"}},{{"protected":"{}","signature":"{signature}"}}]}}"#,
            base64url::encode(protected("k1").as_bytes()),
            base64url::encode(protected("k1").as_bytes())
        );
        let error = JwsJsonParser::parse(&document).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedSdJwt);
        assert!(error.message.contains("duplicate"));
    }

    #[test]
    fn signing_input_matches_the_jws_parts() {
        assert_eq!(
            JwsJsonParser::signing_input("payload", "protected"),
            "protected.payload"
        );
    }
}
