//! Divulgaciones y digests para SD-JWT (RFC 9901 §5.2).
//!
//! Cada divulgación representa un claim de objeto (`[salt, claim_name, claim_value]`)
//! o un elemento de array (`[salt, element_value]`), serializado en JSON canónico y
//! codificado en base64url sin relleno.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use core::fmt;

use gravital_id_codec::base64url;
use gravital_id_codec::json::{parse_bytes, Limits, Value};
use gravital_id_crypto::sha256;
use gravital_id_types::{ErrorCode, GidError};

use crate::json_canonical::to_canonical_json;
use crate::salt::Salt;

/// Longitud de un digest SHA-256 en base64url sin relleno: 32 bytes * 8 / 6 = 43 caracteres.
pub const DIGEST_BASE64URL_LEN: usize = 43;

/// Resumen criptográfico (digest) de una divulgación o digest señuelo (RFC 9901 §5.1.1).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DisclosureDigest {
    encoded: String,
}

impl DisclosureDigest {
    /// Crea un digest a partir de los 32 bytes de un hash SHA-256.
    #[must_use]
    pub fn from_hash_bytes(hash: &[u8; 32]) -> Self {
        Self {
            encoded: base64url::encode(hash),
        }
    }

    /// Valida y construye un digest a partir de una cadena base64url.
    pub fn from_base64url(s: &str) -> Result<Self, GidError> {
        let decoded = base64url::decode(s).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("invalid base64url in disclosure digest: {e}"),
            )
        })?;

        if decoded.len() != 32 {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!(
                    "disclosure digest must be exactly 32 bytes (got {})",
                    decoded.len()
                ),
            ));
        }

        Ok(Self {
            encoded: s.to_string(),
        })
    }

    /// Retorna la cadena base64url del digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.encoded
    }
}

impl fmt::Display for DisclosureDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encoded)
    }
}

impl fmt::Debug for DisclosureDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DisclosureDigest(\"{}\")", self.encoded)
    }
}

/// Tipo de divulgación (RFC 9901 §5.2.1 / §5.2.2).
#[derive(Debug, Clone, PartialEq)]
pub enum DisclosureKind {
    /// Divulgación de claim de objeto: `[salt, claim_name, claim_value]`.
    ObjectProperty {
        /// Nombre del claim divulgado.
        claim_name: String,
        /// Valor del claim divulgado.
        claim_value: Value,
    },
    /// Divulgación de elemento de array: `[salt, element_value]`.
    ArrayElement {
        /// Valor del elemento divulgado.
        element_value: Value,
    },
}

/// Divulgación individual SD-JWT (RFC 9901 §5.2).
#[derive(Clone, PartialEq)]
pub struct Disclosure {
    kind: DisclosureKind,
    salt: Salt,
    encoded: String,
    digest: DisclosureDigest,
}

impl Disclosure {
    /// Crea una nueva divulgación para un claim de un objeto JSON (RFC 9901 §5.2.1).
    ///
    /// Valida que el nombre del claim no sea `_sd` ni `...` (nombres reservados prohibidos).
    ///
    /// // Verifies: REQ-CRED-002
    pub fn new_object(
        salt: Salt,
        claim_name: impl Into<String>,
        claim_value: Value,
    ) -> Result<Self, GidError> {
        let name = claim_name.into();
        if name == "_sd" || name == "..." {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("reserved claim name '{name}' cannot be used in a disclosure"),
            ));
        }

        let array_val = Value::Array(vec![
            Value::String(salt.as_str().to_string()),
            Value::String(name.clone()),
            claim_value.clone(),
        ]);

        let json_bytes = to_canonical_json(&array_val);
        let encoded = base64url::encode(json_bytes.as_bytes());
        let hash = sha256(encoded.as_bytes());
        let digest = DisclosureDigest::from_hash_bytes(&hash);

        Ok(Self {
            kind: DisclosureKind::ObjectProperty {
                claim_name: name,
                claim_value,
            },
            salt,
            encoded,
            digest,
        })
    }

    /// Crea una nueva divulgación para un elemento de un array JSON (RFC 9901 §5.2.2).
    ///
    /// // Verifies: REQ-CRED-002
    #[must_use]
    pub fn new_array(salt: Salt, element_value: Value) -> Self {
        let array_val = Value::Array(vec![
            Value::String(salt.as_str().to_string()),
            element_value.clone(),
        ]);

        let json_bytes = to_canonical_json(&array_val);
        let encoded = base64url::encode(json_bytes.as_bytes());
        let hash = sha256(encoded.as_bytes());
        let digest = DisclosureDigest::from_hash_bytes(&hash);

        Self {
            kind: DisclosureKind::ArrayElement { element_value },
            salt,
            encoded,
            digest,
        }
    }

    /// Parsea y valida una divulgación a partir de su cadena base64url (RFC 9901 §5.2).
    pub fn parse(encoded: &str) -> Result<Self, GidError> {
        let raw_bytes = base64url::decode(encoded).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("failed to base64url decode disclosure: {e}"),
            )
        })?;

        let parsed_json = parse_bytes(&raw_bytes, &Limits::profile_default()).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("invalid JSON in disclosure payload: {e}"),
            )
        })?;

        let mut items = match parsed_json {
            Value::Array(items) => items,
            _ => {
                return Err(GidError::new(
                    ErrorCode::MalformedSdJwt,
                    "disclosure must be a JSON array",
                ));
            }
        };

        let hash = sha256(encoded.as_bytes());
        let digest = DisclosureDigest::from_hash_bytes(&hash);

        if items.len() == 2 {
            let val = items.pop().unwrap_or(Value::Null);
            let salt_val = items.pop().unwrap_or(Value::Null);
            let salt_str = match salt_val {
                Value::String(s) => s,
                _ => {
                    return Err(GidError::new(
                        ErrorCode::MalformedSdJwt,
                        "disclosure salt must be a JSON string",
                    ));
                }
            };
            let salt = Salt::from_base64url(&salt_str)?;

            Ok(Self {
                kind: DisclosureKind::ArrayElement { element_value: val },
                salt,
                encoded: encoded.to_string(),
                digest,
            })
        } else if items.len() == 3 {
            let val = items.pop().unwrap_or(Value::Null);
            let name_val = items.pop().unwrap_or(Value::Null);
            let salt_val = items.pop().unwrap_or(Value::Null);

            let salt_str = match salt_val {
                Value::String(s) => s,
                _ => {
                    return Err(GidError::new(
                        ErrorCode::MalformedSdJwt,
                        "disclosure salt must be a JSON string",
                    ));
                }
            };
            let salt = Salt::from_base64url(&salt_str)?;

            let claim_name = match name_val {
                Value::String(name) => name,
                _ => {
                    return Err(GidError::new(
                        ErrorCode::MalformedSdJwt,
                        "claim name in disclosure must be a JSON string",
                    ));
                }
            };

            if claim_name == "_sd" || claim_name == "..." {
                return Err(GidError::new(
                    ErrorCode::MalformedSdJwt,
                    format!("reserved claim name '{claim_name}' found in disclosure"),
                ));
            }

            Ok(Self {
                kind: DisclosureKind::ObjectProperty {
                    claim_name,
                    claim_value: val,
                },
                salt,
                encoded: encoded.to_string(),
                digest,
            })
        } else {
            Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!(
                    "disclosure array must contain exactly 2 or 3 elements, found {}",
                    items.len()
                ),
            ))
        }
    }

    /// Retorna el digest SHA-256 de la divulgación en base64url.
    #[must_use]
    pub fn digest(&self) -> &DisclosureDigest {
        &self.digest
    }

    /// Retorna la cadena codificada en base64url de la divulgación.
    #[must_use]
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    /// Retorna la sal criptográfica de la divulgación.
    #[must_use]
    pub fn salt(&self) -> &Salt {
        &self.salt
    }

    /// Retorna el tipo de divulgación.
    #[must_use]
    pub fn kind(&self) -> &DisclosureKind {
        &self.kind
    }

    /// Retorna el nombre del claim si es una divulgación de objeto.
    #[must_use]
    pub fn claim_name(&self) -> Option<&str> {
        match &self.kind {
            DisclosureKind::ObjectProperty { claim_name, .. } => Some(claim_name),
            DisclosureKind::ArrayElement { .. } => None,
        }
    }

    /// Retorna el valor del claim si es una divulgación de objeto.
    #[must_use]
    pub fn claim_value(&self) -> Option<&Value> {
        match &self.kind {
            DisclosureKind::ObjectProperty { claim_value, .. } => Some(claim_value),
            DisclosureKind::ArrayElement { .. } => None,
        }
    }

    /// Retorna el valor del elemento si es una divulgación de array.
    #[must_use]
    pub fn element_value(&self) -> Option<&Value> {
        match &self.kind {
            DisclosureKind::ArrayElement { element_value } => Some(element_value),
            DisclosureKind::ObjectProperty { .. } => None,
        }
    }
}

impl fmt::Display for Disclosure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encoded)
    }
}

impl fmt::Debug for Disclosure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Disclosure(digest={}, encoded={})",
            self.digest, self.encoded
        )
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
    use gravital_id_codec::json::Number;
    use gravital_id_testkit::SeededRng;

    #[test]
    fn object_disclosure_emission_and_parse_roundtrip() {
        let rng = SeededRng::new(101);
        let salt = Salt::generate(&rng).expect("generate salt");
        let claim_value = Value::String("Möbius".to_string());

        let disclosure = Disclosure::new_object(salt.clone(), "family_name", claim_value.clone())
            .expect("new object disclosure");

        assert_eq!(disclosure.claim_name(), Some("family_name"));
        assert_eq!(disclosure.claim_value(), Some(&claim_value));
        assert_eq!(disclosure.element_value(), None);
        assert_eq!(disclosure.digest().as_str().len(), DIGEST_BASE64URL_LEN);

        let parsed = Disclosure::parse(disclosure.encoded()).expect("parse disclosure");
        assert_eq!(parsed.digest(), disclosure.digest());
        assert_eq!(parsed.salt(), &salt);
        assert_eq!(parsed.claim_name(), Some("family_name"));
        assert_eq!(parsed.claim_value(), Some(&claim_value));
    }

    #[test]
    fn array_disclosure_emission_and_parse_roundtrip() {
        let rng = SeededRng::new(202);
        let salt = Salt::generate(&rng).expect("generate salt");
        let element_value = Value::Number(Number::PosInt(1984));

        let disclosure = Disclosure::new_array(salt.clone(), element_value.clone());

        assert_eq!(disclosure.claim_name(), None);
        assert_eq!(disclosure.claim_value(), None);
        assert_eq!(disclosure.element_value(), Some(&element_value));

        let parsed = Disclosure::parse(disclosure.encoded()).expect("parse array disclosure");
        assert_eq!(parsed.digest(), disclosure.digest());
        assert_eq!(parsed.salt(), &salt);
        assert_eq!(parsed.element_value(), Some(&element_value));
    }

    #[test]
    fn object_disclosure_rejects_reserved_claim_names() {
        let rng = SeededRng::new(303);
        let salt = Salt::generate(&rng).expect("generate salt");

        let err_sd = Disclosure::new_object(salt.clone(), "_sd", Value::Null).unwrap_err();
        assert_eq!(err_sd.code, ErrorCode::MalformedSdJwt);

        let err_dots = Disclosure::new_object(salt, "...", Value::Null).unwrap_err();
        assert_eq!(err_dots.code, ErrorCode::MalformedSdJwt);
    }
}
