//! Parseo y validación de JSON Web Key (JWK) EC P-256 y thumbprints RFC 7638 (F2.T07).
//!
//! Implementa los perfiles normativos:
//! - **RFC 7517:** JSON Web Key (JWK) para claves públicas.
//! - **RFC 7518 §6.2.1:** Parámetros para curvas elípticas (`kty: "EC"`, `crv: "P-256"`, `x`, `y`).
//! - **RFC 7638:** JWK Thumbprint determinista (SHA-256, orden lexicográfico `crv, kty, x, y`).
//! - **REQ-KEY-007:** Huellas de clave canónicas.
//!
//! Reglas de seguridad e invariantes:
//! - **Rechazo de miembros privados (INV-02, INV-03):** en contextos públicos, la presencia del parámetro
//!   privado `d` (o parámetros privados RSA/simétricos como `p`, `q`, `k`, etc.) invalida la clave.
//! - **Validación de punto en la curva:** las coordenadas `(x, y)` deben corresponder a un punto válido
//!   que satisface la ecuación de la curva P-256 (`secp256r1`). Puntos fuera de la curva o en el infinito
//!   son estrictamente rechazados con [`ErrorCode::InvalidKeyFormat`].
//! - **Longitudes exactas:** tanto `x` como `y` deben decodificarse exactamente a 32 bytes (256 bits).

use alloc::format;
use alloc::string::String;
use core::fmt;

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;

use gravital_id_codec::base64url;
use gravital_id_codec::json::{self, Value};
use gravital_id_types::{ErrorCode, GidError};

/// Longitud de una coordenada afín P-256 en bytes.
pub const ES256_COORDINATE_LEN: usize = 32;

/// Longitud de la clave pública SEC1 sin comprimir en bytes (`0x04 || x || y`).
pub const ES256_PUBLIC_KEY_LEN: usize = 65;

/// Curva admitida en el perfil (`P-256`).
pub const JWK_CRV_P256: &str = "P-256";

/// Tipo de clave admitido en el perfil (`EC`).
pub const JWK_KTY_EC: &str = "EC";

/// Clave pública JWK EC P-256 validada criptográficamente.
///
/// Invariante: una instancia de [`JwkEcP256`] siempre representa un punto válido
/// en la curva NIST P-256, y nunca contiene componentes de clave privada.
#[derive(Clone, PartialEq, Eq)]
pub struct JwkEcP256 {
    pubkey: PublicKey,
    x: [u8; ES256_COORDINATE_LEN],
    y: [u8; ES256_COORDINATE_LEN],
    kid: Option<String>,
    key_use: Option<String>,
    alg: Option<String>,
}

impl fmt::Debug for JwkEcP256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwkEcP256")
            .field("crv", &JWK_CRV_P256)
            .field("kty", &JWK_KTY_EC)
            .field("x", &self.x_base64url())
            .field("y", &self.y_base64url())
            .field("kid", &self.kid)
            .field("use", &self.key_use)
            .field("alg", &self.alg)
            .finish()
    }
}

impl JwkEcP256 {
    /// Parsea una clave pública JWK desde una cadena JSON con validación estricta.
    ///
    /// # Errores
    /// - [`ErrorCode::MalformedMessage`]: Si el JSON es sintácticamente inválido, excede límites o contiene claves duplicadas.
    /// - [`ErrorCode::InvalidKeyFormat`]: Si `kty != "EC"`, `crv != "P-256"`, contiene miembros privados (`d`),
    ///   las coordenadas tienen longitud incorrecta o el punto no pertenece a la curva P-256.
    pub fn parse(json_str: &str) -> Result<Self, GidError> {
        let root = json::parse(json_str)?;
        Self::from_json_value(&root)
    }

    /// Parsea una clave pública JWK desde bytes UTF-8 de JSON.
    ///
    /// # Errores
    /// Igual que [`parse`](Self::parse).
    pub fn parse_bytes(bytes: &[u8]) -> Result<Self, GidError> {
        let root = json::parse_bytes(bytes, &json::Limits::profile_default())?;
        Self::from_json_value(&root)
    }

    /// Construye una clave pública JWK a partir de un [`Value`] JSON ya parseado.
    fn from_json_value(value: &Value) -> Result<Self, GidError> {
        let entries = match value {
            Value::Object(entries) => entries,
            _ => {
                return Err(GidError::new(
                    ErrorCode::InvalidKeyFormat,
                    "JWK must be a JSON object",
                ))
            }
        };

        // Regla: rechazo explícito de cualquier miembro privado o confidencial.
        for (key, _) in entries {
            if is_forbidden_private_member(key.as_str()) {
                return Err(GidError::new(
                    ErrorCode::InvalidKeyFormat,
                    "private key parameter is strictly forbidden in public JWK",
                ));
            }
        }

        let kty = value
            .member("kty")
            .and_then(Value::as_str)
            .ok_or_else(|| GidError::new(ErrorCode::InvalidKeyFormat, "missing or invalid kty"))?;
        if kty != JWK_KTY_EC {
            return Err(GidError::new(
                ErrorCode::InvalidKeyFormat,
                "unsupported kty; only EC is allowed",
            ));
        }

        let crv = value
            .member("crv")
            .and_then(Value::as_str)
            .ok_or_else(|| GidError::new(ErrorCode::InvalidKeyFormat, "missing or invalid crv"))?;
        if crv != JWK_CRV_P256 {
            return Err(GidError::new(
                ErrorCode::InvalidKeyFormat,
                "unsupported crv; only P-256 is allowed",
            ));
        }

        let x_str = value
            .member("x")
            .and_then(Value::as_str)
            .ok_or_else(|| GidError::new(ErrorCode::InvalidKeyFormat, "missing or invalid x"))?;

        let y_str = value
            .member("y")
            .and_then(Value::as_str)
            .ok_or_else(|| GidError::new(ErrorCode::InvalidKeyFormat, "missing or invalid y"))?;

        let x_bytes = base64url::decode(x_str).map_err(|_| {
            GidError::new(
                ErrorCode::InvalidKeyFormat,
                "invalid base64url in x coordinate",
            )
        })?;
        let y_bytes = base64url::decode(y_str).map_err(|_| {
            GidError::new(
                ErrorCode::InvalidKeyFormat,
                "invalid base64url in y coordinate",
            )
        })?;

        if x_bytes.len() != ES256_COORDINATE_LEN {
            return Err(GidError::new(
                ErrorCode::InvalidKeyFormat,
                "x coordinate must be exactly 32 bytes",
            ));
        }
        if y_bytes.len() != ES256_COORDINATE_LEN {
            return Err(GidError::new(
                ErrorCode::InvalidKeyFormat,
                "y coordinate must be exactly 32 bytes",
            ));
        }

        let mut x = [0u8; ES256_COORDINATE_LEN];
        let mut y = [0u8; ES256_COORDINATE_LEN];
        if let Some(slice) = x.get_mut(..ES256_COORDINATE_LEN) {
            slice.copy_from_slice(&x_bytes);
        }
        if let Some(slice) = y.get_mut(..ES256_COORDINATE_LEN) {
            slice.copy_from_slice(&y_bytes);
        }

        // Validación matemática: verificar que el punto (x, y) pertenece a la curva P-256.
        let pubkey = validate_p256_point(&x, &y)?;

        let kid = value
            .member("kid")
            .and_then(Value::as_str)
            .map(String::from);
        let key_use = value
            .member("use")
            .and_then(Value::as_str)
            .map(String::from);
        let alg = value
            .member("alg")
            .and_then(Value::as_str)
            .map(String::from);

        Ok(Self {
            pubkey,
            x,
            y,
            kid,
            key_use,
            alg,
        })
    }

    /// Construye un JWK desde una clave pública `p256::PublicKey`.
    #[must_use]
    pub fn from_public_key(key: &PublicKey) -> Self {
        let point = key.to_encoded_point(false);
        let mut x = [0u8; ES256_COORDINATE_LEN];
        let mut y = [0u8; ES256_COORDINATE_LEN];

        if let Some(x_bytes) = point.x() {
            if let Some(slice) = x.get_mut(..x_bytes.len()) {
                slice.copy_from_slice(x_bytes.as_slice());
            }
        }
        if let Some(y_bytes) = point.y() {
            if let Some(slice) = y.get_mut(..y_bytes.len()) {
                slice.copy_from_slice(y_bytes.as_slice());
            }
        }

        Self {
            pubkey: *key,
            x,
            y,
            kid: None,
            key_use: None,
            alg: None,
        }
    }

    /// Construye un JWK desde coordenadas afines binarias (32 bytes cada una).
    ///
    /// # Errores
    /// [`ErrorCode::InvalidKeyFormat`] si el punto no pertenece a la curva P-256.
    pub fn from_coordinates(
        x: [u8; ES256_COORDINATE_LEN],
        y: [u8; ES256_COORDINATE_LEN],
    ) -> Result<Self, GidError> {
        let pubkey = validate_p256_point(&x, &y)?;
        Ok(Self {
            pubkey,
            x,
            y,
            kid: None,
            key_use: None,
            alg: None,
        })
    }

    /// Construye un JWK desde los bytes SEC1 sin comprimir (65 bytes, prefijo `0x04`).
    ///
    /// # Errores
    /// [`ErrorCode::InvalidKeyFormat`] si la longitud no es 65, el prefijo no es `0x04`
    /// o el punto no pertenece a la curva P-256.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, GidError> {
        if bytes.len() != ES256_PUBLIC_KEY_LEN {
            return Err(GidError::new(
                ErrorCode::InvalidKeyFormat,
                "uncompressed SEC1 public key must be exactly 65 bytes",
            ));
        }
        let pubkey = PublicKey::from_sec1_bytes(bytes).map_err(|_| {
            GidError::new(ErrorCode::InvalidKeyFormat, "curve point validation failed")
        })?;
        Ok(Self::from_public_key(&pubkey))
    }

    /// Devuelve la clave pública como [`p256::PublicKey`].
    #[must_use]
    pub fn to_public_key(&self) -> PublicKey {
        self.pubkey
    }

    /// Devuelve la representación SEC1 sin comprimir de 65 bytes (`0x04 || x || y`).
    #[must_use]
    pub fn to_sec1_bytes(&self) -> [u8; ES256_PUBLIC_KEY_LEN] {
        let mut sec1 = [0u8; ES256_PUBLIC_KEY_LEN];
        if let Some(prefix) = sec1.get_mut(0) {
            *prefix = 0x04;
        }
        if let Some(slice) = sec1.get_mut(1..33) {
            slice.copy_from_slice(&self.x);
        }
        if let Some(slice) = sec1.get_mut(33..65) {
            slice.copy_from_slice(&self.y);
        }
        sec1
    }

    /// Devuelve la coordenada X afín (32 bytes).
    #[must_use]
    pub fn x(&self) -> &[u8; ES256_COORDINATE_LEN] {
        &self.x
    }

    /// Devuelve la coordenada Y afín (32 bytes).
    #[must_use]
    pub fn y(&self) -> &[u8; ES256_COORDINATE_LEN] {
        &self.y
    }

    /// Devuelve la coordenada X codificada en base64url estricto sin relleno.
    #[must_use]
    pub fn x_base64url(&self) -> String {
        base64url::encode(&self.x)
    }

    /// Devuelve la coordenada Y codificada en base64url estricto sin relleno.
    #[must_use]
    pub fn y_base64url(&self) -> String {
        base64url::encode(&self.y)
    }

    /// Identificador de clave opcional (`kid`).
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// Asigna un identificador de clave (`kid`).
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// Uso previsto de la clave (`use`, p. ej. `"sig"` o `"enc"`).
    #[must_use]
    pub fn key_use(&self) -> Option<&str> {
        self.key_use.as_deref()
    }

    /// Asigna el uso de la clave (`use`).
    #[must_use]
    pub fn with_key_use(mut self, key_use: impl Into<String>) -> Self {
        self.key_use = Some(key_use.into());
        self
    }

    /// Algoritmo previsto de la clave (`alg`, p. ej. `"ES256"`).
    #[must_use]
    pub fn alg(&self) -> Option<&str> {
        self.alg.as_deref()
    }

    /// Asigna el algoritmo de la clave (`alg`).
    #[must_use]
    pub fn with_alg(mut self, alg: impl Into<String>) -> Self {
        self.alg = Some(alg.into());
        self
    }

    /// Serialización JSON canónica según RFC 7638 §3.
    ///
    /// Contiene exactamente los miembros requeridos para claves EC (`crv`, `kty`, `x`, `y`)
    /// en orden lexicográfico UTF-8, sin espacios en blanco.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
            JWK_CRV_P256,
            JWK_KTY_EC,
            self.x_base64url(),
            self.y_base64url()
        )
    }

    /// Serializa la clave completa a JSON compacto, incluyendo metadatos opcionales.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}""#,
            JWK_CRV_P256,
            JWK_KTY_EC,
            self.x_base64url(),
            self.y_base64url()
        );
        if let Some(kid) = &self.kid {
            out.push_str(r#","kid":""#);
            out.push_str(kid);
            out.push('"');
        }
        if let Some(u) = &self.key_use {
            out.push_str(r#","use":""#);
            out.push_str(u);
            out.push('"');
        }
        if let Some(a) = &self.alg {
            out.push_str(r#","alg":""#);
            out.push_str(a);
            out.push('"');
        }
        out.push('}');
        out
    }

    /// Calcula el JWK Thumbprint SHA-256 binario (32 bytes) según RFC 7638.
    #[must_use]
    pub fn thumbprint_sha256(&self) -> [u8; 32] {
        let canonical = self.to_canonical_json();
        crate::sha::sha256(canonical.as_bytes())
    }

    /// Calcula el JWK Thumbprint codificado en base64url estricto (43 caracteres) según RFC 7638.
    #[must_use]
    pub fn thumbprint_base64url(&self) -> String {
        let digest = self.thumbprint_sha256();
        base64url::encode(&digest)
    }

    /// Formatea la huella en formato URI estándar RFC 9278:
    /// `urn:ietf:params:oauth:jwk-thumbprint:sha-256:<base64url>`.
    #[must_use]
    pub fn thumbprint_uri(&self) -> String {
        format!(
            "urn:ietf:params:oauth:jwk-thumbprint:sha-256:{}",
            self.thumbprint_base64url()
        )
    }
}

/// Función auxiliar para calcular el JWK Thumbprint SHA-256 (RFC 7638).
#[must_use]
pub fn jwk_thumbprint_sha256(jwk: &JwkEcP256) -> [u8; 32] {
    jwk.thumbprint_sha256()
}

/// Función auxiliar para calcular el JWK Thumbprint en base64url (RFC 7638).
#[must_use]
pub fn jwk_thumbprint_base64url(jwk: &JwkEcP256) -> String {
    jwk.thumbprint_base64url()
}

/// Comprueba si un nombre de miembro corresponde a un parámetro privado prohibido en JWK público.
fn is_forbidden_private_member(name: &str) -> bool {
    matches!(name, "d" | "p" | "q" | "dp" | "dq" | "qi" | "oth" | "k")
}

/// Valida matemáticamente que las coordenadas `(x, y)` formen un punto en la curva P-256.
fn validate_p256_point(
    x: &[u8; ES256_COORDINATE_LEN],
    y: &[u8; ES256_COORDINATE_LEN],
) -> Result<PublicKey, GidError> {
    let mut sec1 = [0u8; ES256_PUBLIC_KEY_LEN];
    if let Some(prefix) = sec1.get_mut(0) {
        *prefix = 0x04;
    }
    if let Some(slice) = sec1.get_mut(1..33) {
        slice.copy_from_slice(x);
    }
    if let Some(slice) = sec1.get_mut(33..65) {
        slice.copy_from_slice(y);
    }

    PublicKey::from_sec1_bytes(&sec1).map_err(|_| {
        GidError::new(
            ErrorCode::InvalidKeyFormat,
            "curve point validation failed: coordinates do not lie on P-256",
        )
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    // Vector de prueba oficial RFC 7638 / JOSE para EC P-256.
    const TEST_X_B64: &str = "jJ6Flys3zK9jUhnOHf6G49Dyp5hah6CNP84-gY-n9eo";
    const TEST_Y_B64: &str = "nhI6iD5eFXgBTLt_1p3aip-5VbZeMhxeFSpjfEAf7Ww";
    const EXPECTED_THUMBPRINT_B64: &str = "w9eYdC6_s_tLQ8lH6PUpc0mddazaqtPgeC2IgWDiqY8";

    // // Verifies: REQ-KEY-007 (parseo JWK y cálculo de thumbprint RFC 7638)
    #[test]
    fn parses_valid_jwk_and_computes_rfc7638_thumbprint() {
        let json = format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}"#,
            TEST_X_B64, TEST_Y_B64
        );

        let jwk = JwkEcP256::parse(&json).expect("valid jwk");
        assert_eq!(jwk.x_base64url(), TEST_X_B64);
        assert_eq!(jwk.y_base64url(), TEST_Y_B64);

        // Canónico debe tener exactamente las 4 claves en orden alfabético sin espacios
        let expected_canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            TEST_X_B64, TEST_Y_B64
        );
        assert_eq!(jwk.to_canonical_json(), expected_canonical);

        // Thumbprint base64url debe coincidir exactamente con el vector de referencia
        assert_eq!(jwk.thumbprint_base64url(), EXPECTED_THUMBPRINT_B64);
        assert_eq!(jwk_thumbprint_base64url(&jwk), EXPECTED_THUMBPRINT_B64);

        let expected_uri = format!(
            "urn:ietf:params:oauth:jwk-thumbprint:sha-256:{}",
            EXPECTED_THUMBPRINT_B64
        );
        assert_eq!(jwk.thumbprint_uri(), expected_uri);
    }

    // // Verifies: REQ-KEY-007 (rechazo estricto de miembro privado 'd')
    #[test]
    fn rejects_private_parameter_d() {
        let json = format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","d":"jhsNCDjqgzSTmvibWoD6w-kJXl5uFCSfC3z0Slco41U"}}"#,
            TEST_X_B64, TEST_Y_B64
        );

        let err = JwkEcP256::parse(&json).expect_err("must reject private key");
        assert_eq!(err.code, ErrorCode::InvalidKeyFormat);
    }

    // // Verifies: REQ-KEY-007 (rechazo de otros miembros privados/secretos)
    #[test]
    fn rejects_other_private_parameters() {
        for forbidden in ["p", "q", "dp", "dq", "qi", "oth", "k"] {
            let json = format!(
                r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","{}":"abc"}}"#,
                TEST_X_B64, TEST_Y_B64, forbidden
            );
            let err = JwkEcP256::parse(&json).expect_err("must reject private parameter");
            assert_eq!(err.code, ErrorCode::InvalidKeyFormat);
        }
    }

    // // Verifies: REQ-KEY-007 (rechazo de tipo de clave o curva no permitida)
    #[test]
    fn rejects_unsupported_kty_or_crv() {
        let rsa_json = r#"{"kty":"RSA","n":"abc","e":"AQAB"}"#;
        assert_eq!(
            JwkEcP256::parse(rsa_json).unwrap_err().code,
            ErrorCode::InvalidKeyFormat
        );

        let p384_json = format!(
            r#"{{"kty":"EC","crv":"P-384","x":"{}","y":"{}"}}"#,
            TEST_X_B64, TEST_Y_B64
        );
        assert_eq!(
            JwkEcP256::parse(&p384_json).unwrap_err().code,
            ErrorCode::InvalidKeyFormat
        );
    }

    // // Verifies: REQ-KEY-007 (rechazo de punto que no está en la curva P-256)
    #[test]
    fn rejects_point_not_on_curve() {
        // Alterar un byte de la coordenada y de modo que ya no satisfaga y^2 = x^3 - 3x + b
        let invalid_y = "nhI6iD5eFXgBTLt_1p3aip-5VbZeMhxeFSpjfEAf7W0";
        let json = format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}"#,
            TEST_X_B64, invalid_y
        );

        let err = JwkEcP256::parse(&json).expect_err("must reject off-curve point");
        assert_eq!(err.code, ErrorCode::InvalidKeyFormat);
    }

    // // Verifies: REQ-KEY-007 (rechazo de coordenadas con longitud distinta de 32 bytes)
    #[test]
    fn rejects_invalid_coordinate_lengths() {
        // Coordenada x de 31 bytes
        let short_x = base64url::encode(&[0x01u8; 31]);
        let json = format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}"#,
            short_x, TEST_Y_B64
        );
        let err = JwkEcP256::parse(&json).expect_err("must reject 31-byte coordinate");
        assert_eq!(err.code, ErrorCode::InvalidKeyFormat);

        // Coordenada x de 33 bytes
        let long_x = base64url::encode(&[0x01u8; 33]);
        let json2 = format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}"#,
            long_x, TEST_Y_B64
        );
        let err2 = JwkEcP256::parse(&json2).expect_err("must reject 33-byte coordinate");
        assert_eq!(err2.code, ErrorCode::InvalidKeyFormat);
    }

    // // Verifies: REQ-KEY-007 (round-trip entre PublicKey y JWK)
    #[test]
    fn round_trip_public_key_and_jwk() {
        let json = format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}"#,
            TEST_X_B64, TEST_Y_B64
        );
        let jwk = JwkEcP256::parse(&json).expect("parse");
        let pubkey = jwk.to_public_key();
        let from_pubkey = JwkEcP256::from_public_key(&pubkey);

        assert_eq!(jwk.x(), from_pubkey.x());
        assert_eq!(jwk.y(), from_pubkey.y());
        assert_eq!(jwk.to_sec1_bytes(), from_pubkey.to_sec1_bytes());
        assert_eq!(jwk.thumbprint_sha256(), from_pubkey.thumbprint_sha256());
    }

    // // Verifies: REQ-KEY-007 (preservación de metadatos públicos opcionales)
    #[test]
    fn preserves_optional_public_metadata() {
        let json = format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","kid":"test-key-1","use":"sig","alg":"ES256"}}"#,
            TEST_X_B64, TEST_Y_B64
        );
        let jwk = JwkEcP256::parse(&json).expect("parse");
        assert_eq!(jwk.kid(), Some("test-key-1"));
        assert_eq!(jwk.key_use(), Some("sig"));
        assert_eq!(jwk.alg(), Some("ES256"));

        // El thumbprint canónico IGNORA los metadatos opcionales por RFC 7638
        assert_eq!(jwk.thumbprint_base64url(), EXPECTED_THUMBPRINT_B64);
    }
}
