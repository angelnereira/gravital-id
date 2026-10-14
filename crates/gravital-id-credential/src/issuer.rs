//! Motor de emisión SD-JWT (RFC 9901, REQ-CRED-002, REQ-CRED-003).
//!
//! Permite construir credenciales SD-JWT con divulgaciones de objeto (`_sd`),
//! divulgaciones de array (`...`), claim explícito de algoritmo (`_sd_alg`),
//! digests señuelo (decoys) configurables y estructuras anidadas/recursivas.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use gravital_id_codec::base64url;
use gravital_id_codec::json::Value;
use gravital_id_crypto::{sha256, Rng};
use gravital_id_keys::{KeyHandle, KeyStore, SigningPurpose};
use gravital_id_types::{ErrorCode, GidError, Kid};

use crate::decoy::generate_decoy_digest;
use crate::disclosure::Disclosure;
use crate::json_canonical::to_canonical_json;
use crate::salt::Salt;

/// Cabecera JWS para el token SD-JWT (RFC 7515 / RFC 9901).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwsHeader {
    /// Algoritmo criptográfico de firma (por defecto "ES256").
    pub alg: String,
    /// Tipo de token (por defecto "dc+sd-jwt" según draft-19 de SD-JWT VC).
    pub typ: String,
    /// Identificador de clave pública del emisor (JWK Thumbprint RFC 7638).
    pub kid: Option<Kid>,
}

impl Default for JwsHeader {
    fn default() -> Self {
        Self {
            alg: "ES256".to_string(),
            typ: "dc+sd-jwt".to_string(),
            kid: None,
        }
    }
}

impl JwsHeader {
    /// Convierte la cabecera a [`Value`].
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = vec![
            ("alg".to_string(), Value::String(self.alg.clone())),
            ("typ".to_string(), Value::String(self.typ.clone())),
        ];
        if let Some(kid) = &self.kid {
            entries.push(("kid".to_string(), Value::String(kid.as_str().to_string())));
        }
        Value::Object(entries)
    }
}

/// Token SD-JWT emitido en serialización compacta (RFC 9901 §5.3).
#[derive(Debug, Clone, PartialEq)]
pub struct IssuedSdJwt {
    jwt: String,
    disclosures: Vec<Disclosure>,
    compact: String,
}

impl IssuedSdJwt {
    /// Construye un SD-JWT a partir del JWS firmado y sus divulgaciones.
    #[must_use]
    pub fn new(jwt: String, mut disclosures: Vec<Disclosure>) -> Self {
        // Ordena las divulgaciones lexicográficamente por su representación base64url
        // para garantizar reproducibilidad y privacidad estructural (RFC 9901 §5.3).
        disclosures.sort_by(|a, b| a.encoded().cmp(b.encoded()));

        let cap = jwt
            .len()
            .saturating_add(2)
            .saturating_add(disclosures.len().saturating_mul(64));
        let mut compact = String::with_capacity(cap);
        compact.push_str(&jwt);
        compact.push('~');
        for d in &disclosures {
            compact.push_str(d.encoded());
            compact.push('~');
        }

        Self {
            jwt,
            disclosures,
            compact,
        }
    }

    /// Parsea un SD-JWT compacto emitido (`<jwt>~<d1>~...~<dn>~`).
    pub fn from_compact(compact: &str) -> Result<Self, GidError> {
        if !compact.contains('~') {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "SD-JWT must contain at least one '~' delimiter",
            ));
        }

        let parts: Vec<&str> = compact.split('~').collect();
        let Some(&jwt) = parts.first() else {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "empty SD-JWT input",
            ));
        };

        let jwt_segments: Vec<&str> = jwt.split('.').collect();
        if jwt_segments.len() != 3 {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!(
                    "issuer JWT must contain 3 dot-separated segments, got {}",
                    jwt_segments.len()
                ),
            ));
        }

        let mut disclosures = Vec::new();
        // Las partes entre el JWT y la parte final vacía son las divulgaciones
        let disclosure_parts: &[&str] = if parts.len() > 1 {
            let end_idx = parts.len().saturating_sub(1);
            parts.get(1..end_idx).unwrap_or(&[])
        } else {
            &[]
        };

        for &part in disclosure_parts {
            if !part.is_empty() {
                disclosures.push(Disclosure::parse(part)?);
            }
        }

        Ok(Self::new(jwt.to_string(), disclosures))
    }

    /// Retorna la serialización compacta del SD-JWT (`<jwt>~<d1>~...~<dn>~`).
    #[must_use]
    pub fn to_compact_serialization(&self) -> &str {
        &self.compact
    }

    /// Retorna el JWS firmado del emisor.
    #[must_use]
    pub fn jwt(&self) -> &str {
        &self.jwt
    }

    /// Retorna las divulgaciones emitidas asociadas al token.
    #[must_use]
    pub fn disclosures(&self) -> &[Disclosure] {
        &self.disclosures
    }

    /// Descompone el SD-JWT en el JWS y su lista de divulgaciones.
    #[must_use]
    pub fn into_parts(self) -> (String, Vec<Disclosure>) {
        (self.jwt, self.disclosures)
    }
}

/// Resultado de emitir un objeto JSON con soporte de divulgación selectiva.
#[derive(Debug, Clone, PartialEq)]
pub struct EmittedObject {
    /// Objeto JSON resultante con `_sd`, `_sd_alg` y claims en claro.
    pub value: Value,
    /// Lista acumulada de todas las divulgaciones generadas (directas y anidadas).
    pub disclosures: Vec<Disclosure>,
}

/// Resultado de emitir un array JSON con soporte de divulgación selectiva.
#[derive(Debug, Clone, PartialEq)]
pub struct EmittedArray {
    /// Array JSON resultante con elementos en claro y elementos ofuscados `{ "...": "<digest>" }`.
    pub value: Value,
    /// Lista acumulada de todas las divulgaciones generadas (directas y anidadas).
    pub disclosures: Vec<Disclosure>,
}

/// Elemento interno para construir arrays con divulgación selectiva.
enum ArrayItem {
    Plain(Value),
    Sd(Value, Option<Salt>),
    PlainNestedObject(SdObjectBuilder),
    SdNestedObject(SdObjectBuilder, Option<Salt>),
    PlainNestedArray(SdArrayBuilder),
    SdNestedArray(SdArrayBuilder, Option<Salt>),
}

/// Builder para construir arrays JSON con divulgación selectiva (RFC 9901 §5.1.2).
#[derive(Default)]
pub struct SdArrayBuilder {
    items: Vec<ArrayItem>,
    decoy_count: usize,
}

impl SdArrayBuilder {
    /// Crea un nuevo constructor de array.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Añade un elemento en claro (no divulgado selectivamente).
    #[must_use]
    pub fn add_plain_element(mut self, value: Value) -> Self {
        self.items.push(ArrayItem::Plain(value));
        self
    }

    /// Añade un elemento con divulgación selectiva con sal generada automáticamente.
    #[must_use]
    pub fn add_sd_element(mut self, value: Value) -> Self {
        self.items.push(ArrayItem::Sd(value, None));
        self
    }

    /// Añade un elemento con divulgación selectiva con sal explícita.
    #[must_use]
    pub fn add_sd_element_with_salt(mut self, value: Value, salt: Salt) -> Self {
        self.items.push(ArrayItem::Sd(value, Some(salt)));
        self
    }

    /// Añade un sub-objeto anidado en claro cuyos claims internos pueden ser selectivos.
    #[must_use]
    pub fn add_nested_object_plain(mut self, child: SdObjectBuilder) -> Self {
        self.items.push(ArrayItem::PlainNestedObject(child));
        self
    }

    /// Añade un sub-objeto anidado que es a su vez selectivamente divulgado.
    #[must_use]
    pub fn add_nested_object_sd(mut self, child: SdObjectBuilder) -> Self {
        self.items.push(ArrayItem::SdNestedObject(child, None));
        self
    }

    /// Añade un sub-array anidado en claro cuyos elementos pueden ser selectivos.
    #[must_use]
    pub fn add_nested_array_plain(mut self, child: SdArrayBuilder) -> Self {
        self.items.push(ArrayItem::PlainNestedArray(child));
        self
    }

    /// Añade un sub-array anidado que es a su vez selectivamente divulgado.
    #[must_use]
    pub fn add_nested_array_sd(mut self, child: SdArrayBuilder) -> Self {
        self.items.push(ArrayItem::SdNestedArray(child, None));
        self
    }

    /// Configura el número de elementos señuelo (decoys) a incluir en el array (REQ-CRED-003).
    #[must_use]
    pub fn set_decoys(mut self, count: usize) -> Self {
        self.decoy_count = count;
        self
    }

    /// Procesa y construye el array emitiendo elementos y acumulando divulgaciones.
    pub fn build(self, rng: &impl Rng) -> Result<EmittedArray, GidError> {
        let mut elements = Vec::with_capacity(self.items.len().saturating_add(self.decoy_count));
        let mut disclosures = Vec::new();

        for item in self.items {
            match item {
                ArrayItem::Plain(val) => {
                    elements.push(val);
                }
                ArrayItem::Sd(val, salt_opt) => {
                    let salt = match salt_opt {
                        Some(s) => s,
                        None => Salt::generate(rng)?,
                    };
                    let disclosure = Disclosure::new_array(salt, val);
                    let digest = disclosure.digest().as_str().to_string();
                    disclosures.push(disclosure);
                    elements.push(Value::Object(vec![(
                        "...".to_string(),
                        Value::String(digest),
                    )]));
                }
                ArrayItem::PlainNestedObject(child) => {
                    let emitted = child.build(rng)?;
                    elements.push(emitted.value);
                    disclosures.extend(emitted.disclosures);
                }
                ArrayItem::SdNestedObject(child, salt_opt) => {
                    let emitted = child.build(rng)?;
                    let salt = match salt_opt {
                        Some(s) => s,
                        None => Salt::generate(rng)?,
                    };
                    let disclosure = Disclosure::new_array(salt, emitted.value);
                    let digest = disclosure.digest().as_str().to_string();
                    disclosures.push(disclosure);
                    disclosures.extend(emitted.disclosures);
                    elements.push(Value::Object(vec![(
                        "...".to_string(),
                        Value::String(digest),
                    )]));
                }
                ArrayItem::PlainNestedArray(child) => {
                    let emitted = child.build(rng)?;
                    elements.push(emitted.value);
                    disclosures.extend(emitted.disclosures);
                }
                ArrayItem::SdNestedArray(child, salt_opt) => {
                    let emitted = child.build(rng)?;
                    let salt = match salt_opt {
                        Some(s) => s,
                        None => Salt::generate(rng)?,
                    };
                    let disclosure = Disclosure::new_array(salt, emitted.value);
                    let digest = disclosure.digest().as_str().to_string();
                    disclosures.push(disclosure);
                    disclosures.extend(emitted.disclosures);
                    elements.push(Value::Object(vec![(
                        "...".to_string(),
                        Value::String(digest),
                    )]));
                }
            }
        }

        // Incorpora elementos señuelo en el array (REQ-CRED-003)
        for _ in 0..self.decoy_count {
            let decoy = generate_decoy_digest(rng)?;
            elements.push(Value::Object(vec![(
                "...".to_string(),
                Value::String(decoy.as_str().to_string()),
            )]));
        }

        Ok(EmittedArray {
            value: Value::Array(elements),
            disclosures,
        })
    }
}

/// Claim interno para construir objetos con divulgación selectiva.
enum ObjectClaim {
    Plain(String, Value),
    Sd(String, Value, Option<Salt>),
    PlainNestedObject(String, SdObjectBuilder),
    SdNestedObject(String, SdObjectBuilder, Option<Salt>),
    PlainNestedArray(String, SdArrayBuilder),
    SdNestedArray(String, SdArrayBuilder, Option<Salt>),
}

/// Builder para construir objetos JSON con divulgación selectiva (RFC 9901 §5.1.1).
#[derive(Default)]
pub struct SdObjectBuilder {
    claims: Vec<ObjectClaim>,
    decoy_count: usize,
}

impl SdObjectBuilder {
    /// Crea un nuevo constructor de objeto.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Añade un claim en claro (no divulgado selectivamente).
    #[must_use]
    pub fn add_plain_claim(mut self, key: impl Into<String>, value: Value) -> Self {
        self.claims.push(ObjectClaim::Plain(key.into(), value));
        self
    }

    /// Añade un claim con divulgación selectiva y sal generada automáticamente.
    #[must_use]
    pub fn add_sd_claim(mut self, key: impl Into<String>, value: Value) -> Self {
        self.claims.push(ObjectClaim::Sd(key.into(), value, None));
        self
    }

    /// Añade un claim con divulgación selectiva y sal explícita.
    #[must_use]
    pub fn add_sd_claim_with_salt(
        mut self,
        key: impl Into<String>,
        value: Value,
        salt: Salt,
    ) -> Self {
        self.claims
            .push(ObjectClaim::Sd(key.into(), value, Some(salt)));
        self
    }

    /// Añade un sub-objeto anidado en claro cuyos claims internos pueden ser selectivos.
    #[must_use]
    pub fn add_nested_object_plain(
        mut self,
        key: impl Into<String>,
        child: SdObjectBuilder,
    ) -> Self {
        self.claims
            .push(ObjectClaim::PlainNestedObject(key.into(), child));
        self
    }

    /// Añade un sub-objeto anidado que es a su vez selectivamente divulgado (recursivo).
    #[must_use]
    pub fn add_nested_object_sd(mut self, key: impl Into<String>, child: SdObjectBuilder) -> Self {
        self.claims
            .push(ObjectClaim::SdNestedObject(key.into(), child, None));
        self
    }

    /// Añade un sub-array anidado en claro cuyos elementos pueden ser selectivos.
    #[must_use]
    pub fn add_nested_array_plain(mut self, key: impl Into<String>, child: SdArrayBuilder) -> Self {
        self.claims
            .push(ObjectClaim::PlainNestedArray(key.into(), child));
        self
    }

    /// Añade un sub-array anidado que es a su vez selectivamente divulgado.
    #[must_use]
    pub fn add_nested_array_sd(mut self, key: impl Into<String>, child: SdArrayBuilder) -> Self {
        self.claims
            .push(ObjectClaim::SdNestedArray(key.into(), child, None));
        self
    }

    /// Configura el número de digests señuelo (decoys) a incluir en el array `_sd` (REQ-CRED-003).
    #[must_use]
    pub fn set_decoys(mut self, count: usize) -> Self {
        self.decoy_count = count;
        self
    }

    /// Procesa y construye el objeto JSON resultante con sus divulgaciones asociadas.
    pub fn build(self, rng: &impl Rng) -> Result<EmittedObject, GidError> {
        let mut object_entries = Vec::with_capacity(self.claims.len().saturating_add(2));
        let mut sd_digests = Vec::new();
        let mut disclosures = Vec::new();

        for claim in self.claims {
            match claim {
                ObjectClaim::Plain(k, v) => {
                    object_entries.push((k, v));
                }
                ObjectClaim::Sd(k, v, salt_opt) => {
                    let salt = match salt_opt {
                        Some(s) => s,
                        None => Salt::generate(rng)?,
                    };
                    let disclosure = Disclosure::new_object(salt, k, v)?;
                    sd_digests.push(disclosure.digest().clone());
                    disclosures.push(disclosure);
                }
                ObjectClaim::PlainNestedObject(k, child) => {
                    let emitted = child.build(rng)?;
                    object_entries.push((k, emitted.value));
                    disclosures.extend(emitted.disclosures);
                }
                ObjectClaim::SdNestedObject(k, child, salt_opt) => {
                    let emitted = child.build(rng)?;
                    let salt = match salt_opt {
                        Some(s) => s,
                        None => Salt::generate(rng)?,
                    };
                    let disclosure = Disclosure::new_object(salt, k, emitted.value)?;
                    sd_digests.push(disclosure.digest().clone());
                    disclosures.push(disclosure);
                    disclosures.extend(emitted.disclosures);
                }
                ObjectClaim::PlainNestedArray(k, child) => {
                    let emitted = child.build(rng)?;
                    object_entries.push((k, emitted.value));
                    disclosures.extend(emitted.disclosures);
                }
                ObjectClaim::SdNestedArray(k, child, salt_opt) => {
                    let emitted = child.build(rng)?;
                    let salt = match salt_opt {
                        Some(s) => s,
                        None => Salt::generate(rng)?,
                    };
                    let disclosure = Disclosure::new_object(salt, k, emitted.value)?;
                    sd_digests.push(disclosure.digest().clone());
                    disclosures.push(disclosure);
                    disclosures.extend(emitted.disclosures);
                }
            }
        }

        // Genera digests señuelo (REQ-CRED-003)
        for _ in 0..self.decoy_count {
            sd_digests.push(generate_decoy_digest(rng)?);
        }

        // Si existen divulgaciones o decoys a este nivel, genera el array `_sd` ordenado lexicográficamente (RFC 9901 §5.1.1)
        if !sd_digests.is_empty() {
            sd_digests.sort();
            let sd_array_values = sd_digests
                .into_iter()
                .map(|d| Value::String(d.as_str().to_string()))
                .collect();
            object_entries.push(("_sd".to_string(), Value::Array(sd_array_values)));
        }

        // Si hay divulgaciones o decoys presentes en el objeto o descendientes, incluye `_sd_alg` (RFC 9901 §5.1.1)
        let has_disclosures_or_decoys = !disclosures.is_empty()
            || self.decoy_count > 0
            || object_entries.iter().any(|(k, _)| k == "_sd");

        if has_disclosures_or_decoys && !object_entries.iter().any(|(k, _)| k == "_sd_alg") {
            object_entries.push(("_sd_alg".to_string(), Value::String("sha-256".to_string())));
        }

        Ok(EmittedObject {
            value: Value::Object(object_entries),
            disclosures,
        })
    }
}

/// Emisor de credenciales y presentaciones SD-JWT (RFC 9901).
pub struct SdIssuer;

impl SdIssuer {
    /// Emite solo el payload y la lista de divulgaciones sin firmar.
    pub fn emit_payload(
        builder: SdObjectBuilder,
        rng: &impl Rng,
    ) -> Result<EmittedObject, GidError> {
        builder.build(rng)
    }

    /// Emite y firma un token SD-JWT utilizando el [`KeyStore`] del host.
    ///
    /// Delega la operación de firma asimétrica ES256 al trait abstracto `KeyStore` sin
    /// extraer ni exponer material de clave privada (INV-03).
    pub fn issue_signed<K: KeyStore, P: SigningPurpose>(
        builder: SdObjectBuilder,
        key_store: &K,
        key_handle: &KeyHandle<P>,
        header: JwsHeader,
        rng: &impl Rng,
    ) -> Result<IssuedSdJwt, GidError> {
        let emitted = builder.build(rng)?;

        // Serializa cabecera JWS en base64url
        let header_val = header.to_value();
        let header_json = to_canonical_json(&header_val);
        let header_b64 = base64url::encode(header_json.as_bytes());

        // Serializa payload JWS en base64url
        let payload_json = to_canonical_json(&emitted.value);
        let payload_b64 = base64url::encode(payload_json.as_bytes());

        // Mensaje a firmar: "header_b64.payload_b64" (RFC 7515 §3.1)
        let signing_input = format!("{header_b64}.{payload_b64}");
        let digest = sha256(signing_input.as_bytes());

        // Firma mediante KeyStore (produce 64 bytes IEEE P1363 r||s)
        let signature_p1363 = key_store.sign(key_handle, &digest)?;
        let signature_b64 = base64url::encode(&signature_p1363);

        let compact_jwt = format!("{signing_input}.{signature_b64}");

        Ok(IssuedSdJwt::new(compact_jwt, emitted.disclosures))
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
    use gravital_id_crypto::verify_es256_jwk;
    use gravital_id_keys::{IssuerSigning, SoftwareKeyStore};
    use gravital_id_testkit::SeededRng;

    #[test]
    fn sd_object_builder_emits_sd_array_and_sd_alg() {
        let rng = SeededRng::new(707);

        let builder = SdObjectBuilder::new()
            .add_plain_claim(
                "iss",
                Value::String("https://issuer.example.com".to_string()),
            )
            .add_sd_claim("sub", Value::String("user_42".to_string()))
            .add_sd_claim("email", Value::String("user@example.com".to_string()));

        let emitted = builder.build(&rng).expect("build object");

        assert_eq!(emitted.disclosures.len(), 2);

        // Value must be Object with plain claims, _sd and _sd_alg
        match emitted.value {
            Value::Object(entries) => {
                let iss = entries.iter().find(|(k, _)| k == "iss").map(|(_, v)| v);
                assert_eq!(
                    iss,
                    Some(&Value::String("https://issuer.example.com".to_string()))
                );

                let sd_alg = entries.iter().find(|(k, _)| k == "_sd_alg").map(|(_, v)| v);
                assert_eq!(sd_alg, Some(&Value::String("sha-256".to_string())));

                let sd = entries.iter().find(|(k, _)| k == "_sd").map(|(_, v)| v);
                match sd {
                    Some(Value::Array(digests)) => {
                        assert_eq!(digests.len(), 2);
                        // Sorted lexicographically
                        let d0 = digests[0].as_str().expect("string digest");
                        let d1 = digests[1].as_str().expect("string digest");
                        assert!(d0 <= d1);
                    }
                    _ => panic!("expected Value::Array for _sd"),
                }
            }
            _ => panic!("expected Value::Object"),
        }
    }

    #[test]
    fn sd_object_builder_with_decoys() {
        let rng = SeededRng::new(808);

        let builder = SdObjectBuilder::new()
            .add_plain_claim("vct", Value::String("urn:example:vct".to_string()))
            .add_sd_claim("given_name", Value::String("Alice".to_string()))
            .set_decoys(3);

        let emitted = builder.build(&rng).expect("build object with decoys");

        // Exactly 1 real disclosure, but 4 digests in _sd (1 real + 3 decoys)
        assert_eq!(emitted.disclosures.len(), 1);

        match emitted.value {
            Value::Object(entries) => {
                let sd = entries.iter().find(|(k, _)| k == "_sd").map(|(_, v)| v);
                match sd {
                    Some(Value::Array(digests)) => {
                        assert_eq!(digests.len(), 4);
                    }
                    _ => panic!("expected _sd array"),
                }
            }
            _ => panic!("expected object"),
        }
    }

    #[test]
    fn sd_array_builder_emits_array_disclosures_and_decoys() {
        let rng = SeededRng::new(909);

        let builder = SdArrayBuilder::new()
            .add_plain_element(Value::String("DE".to_string()))
            .add_sd_element(Value::String("FR".to_string()))
            .set_decoys(2);

        let emitted = builder.build(&rng).expect("build array");

        // 1 real disclosure
        assert_eq!(emitted.disclosures.len(), 1);

        match emitted.value {
            Value::Array(items) => {
                // 1 plain + 1 real sd + 2 decoys = 4 items
                assert_eq!(items.len(), 4);
                assert_eq!(items[0], Value::String("DE".to_string()));
                // Next items must be Objects with "..."
                for item in &items[1..] {
                    match item {
                        Value::Object(entries) => {
                            assert_eq!(entries.len(), 1);
                            assert_eq!(entries[0].0, "...");
                        }
                        _ => panic!("expected {{'...': digest}}"),
                    }
                }
            }
            _ => panic!("expected array"),
        }
    }

    #[test]
    fn nested_and_recursive_structures() {
        let rng = SeededRng::new(1010);

        // Address sub-object with selective disclosures
        let address_builder = SdObjectBuilder::new()
            .add_sd_claim("street_address", Value::String("123 Main St".to_string()))
            .add_plain_claim("country", Value::String("Panama".to_string()));

        // Parent object where address is ITSELF selectively disclosable
        let root_builder = SdObjectBuilder::new()
            .add_plain_claim("iss", Value::String("https://example.com".to_string()))
            .add_nested_object_sd("address", address_builder);

        let emitted = root_builder.build(&rng).expect("build nested");

        // Must have 2 disclosures: one for "address", and one for "street_address" inside it!
        assert_eq!(emitted.disclosures.len(), 2);

        let address_disclosure = emitted
            .disclosures
            .iter()
            .find(|d| d.claim_name() == Some("address"))
            .expect("address disclosure must exist");

        let street_disclosure = emitted
            .disclosures
            .iter()
            .find(|d| d.claim_name() == Some("street_address"))
            .expect("street_address disclosure must exist");

        // The value of address disclosure is an object containing _sd with street_disclosure's digest!
        match address_disclosure.claim_value() {
            Some(Value::Object(entries)) => {
                let sd = entries.iter().find(|(k, _)| k == "_sd").map(|(_, v)| v);
                match sd {
                    Some(Value::Array(digests)) => {
                        assert_eq!(digests.len(), 1);
                        assert_eq!(
                            digests[0].as_str(),
                            Some(street_disclosure.digest().as_str())
                        );
                    }
                    _ => panic!("expected _sd in nested address"),
                }
            }
            _ => panic!("expected object as address value"),
        }
    }

    #[test]
    fn issue_signed_sd_jwt_with_keystore_and_verify_signature() {
        let rng = SeededRng::new(2020);
        let mut key_store = SoftwareKeyStore::new(rng);
        let handle: KeyHandle<IssuerSigning> =
            key_store.generate_key().expect("generate signing key");
        let jwk = key_store.public_key(&handle).expect("public JWK");

        let rng2 = SeededRng::new(2021);
        let builder = SdObjectBuilder::new()
            .add_plain_claim(
                "iss",
                Value::String("https://issuer.example.com".to_string()),
            )
            .add_sd_claim("email", Value::String("alice@example.com".to_string()));

        let issued =
            SdIssuer::issue_signed(builder, &key_store, &handle, JwsHeader::default(), &rng2)
                .expect("issue signed sd-jwt");

        assert_eq!(issued.disclosures().len(), 1);

        // Verify compact format
        let compact = issued.to_compact_serialization();
        assert!(compact.starts_with("eyJ"));
        assert!(compact.ends_with('~'));

        // Parse from compact
        let parsed = IssuedSdJwt::from_compact(compact).expect("parse compact");
        assert_eq!(parsed.jwt(), issued.jwt());
        assert_eq!(parsed.disclosures().len(), 1);

        // Verify JWS signature with public key JWK
        let jwt_parts: Vec<&str> = issued.jwt().split('.').collect();
        assert_eq!(jwt_parts.len(), 3);
        let signing_input = format!("{}.{}", jwt_parts[0], jwt_parts[1]);
        let sig_bytes = base64url::decode(jwt_parts[2]).expect("decode sig");
        let mut sig_fixed = [0u8; 64];
        sig_fixed.copy_from_slice(&sig_bytes);

        verify_es256_jwk(&jwk, signing_input.as_bytes(), &sig_fixed)
            .expect("signature must be valid ES256");
    }
}
