//! Solicitud de verificación offline (REQ-PRES-005, PROTOCOL.md §3.1).
//!
//! Trazabilidad:
//! - `REQ-PRES-005`: Transporte QR bidireccional offline entre verificador y titular.
//! - `PROTOCOL.md §3.1`: Estructura JSON canónica y validación de vigencia y nonce.
//! - `INV-01`: Cero dependencias de red durante la verificación.
//! - `INV-05`: Fail-closed ante cualquier error o expiración de la solicitud.
//! - `INV-11`: Reloj inyectado (`UnixTime`), sin lectura implícita de tiempo del sistema.

use alloc::format;
use alloc::string::{String, ToString};

use gravital_id_codec::json::{parse_bytes, Limits, Number, Value};
use gravital_id_credential::to_canonical_json;
use gravital_id_crypto::JwkEcP256;
use gravital_id_holder::DcqlQuery;
use gravital_id_types::{ErrorCode, GidError, UnixTime};

/// Tipo canónico normativo para solicitudes de verificación offline.
pub const VERIFICATION_REQUEST_TYPE: &str = "pip-verification-request-v1";

/// Longitud mínima del nonce en bytes (128 bits de entropía).
pub const MIN_NONCE_LEN: usize = 16;

/// Longitud máxima del identificador del verificador.
pub const MAX_VERIFIER_ID_LEN: usize = 128;

/// Longitud máxima de la audiencia.
pub const MAX_AUDIENCE_LEN: usize = 256;

fn member_str<'a>(val: &'a Value, name: &str) -> Option<&'a str> {
    val.member(name).and_then(Value::as_str)
}

fn member_u64(val: &Value, name: &str) -> Option<u64> {
    match val.member(name) {
        Some(Value::Number(Number::PosInt(n))) => Some(*n),
        _ => None,
    }
}

/// Solicitud de verificación generada por el verificador offline (`PROTOCOL.md §3.1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationRequest {
    /// Identificador del verificador solicitante (ej. "org.gov.security.gate-4").
    pub verifier_id: String,
    /// Nonce único generado con CSPRNG para prevenir ataques de repetición (REQ-PRES-004).
    pub nonce: String,
    /// Audiencia esperada en la presentación (`aud` del KB-JWT).
    pub audience: String,
    /// Instante de emisión de la solicitud.
    pub issued_at: UnixTime,
    /// Instante de expiración de la solicitud.
    pub expires_at: UnixTime,
    /// Consulta DCQL que especifica los tipos y claims requeridos (REQ-PRES-003).
    pub query: DcqlQuery,
    /// Clave pública efímera opcional del verificador para cifrado de respuesta en transporte (ADR-0023).
    pub eph_pub: Option<JwkEcP256>,
}

impl VerificationRequest {
    /// Crea una nueva solicitud de verificación validando los parámetros normativos.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedMessage`] si algún parámetro excede límites o es inválido.
    pub fn new(
        verifier_id: impl Into<String>,
        nonce: impl Into<String>,
        audience: impl Into<String>,
        issued_at: UnixTime,
        expires_at: UnixTime,
        query: DcqlQuery,
        eph_pub: Option<JwkEcP256>,
    ) -> Result<Self, GidError> {
        let v_id = verifier_id.into();
        if v_id.is_empty() || v_id.len() > MAX_VERIFIER_ID_LEN {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                format!(
                    "verifier_id length must be between 1 and {MAX_VERIFIER_ID_LEN} bytes (got {})",
                    v_id.len()
                ),
            ));
        }

        let n = nonce.into();
        if n.len() < MIN_NONCE_LEN {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                format!(
                    "nonce must contain at least {MIN_NONCE_LEN} bytes of entropy (got {})",
                    n.len()
                ),
            ));
        }

        let aud = audience.into();
        if aud.is_empty() || aud.len() > MAX_AUDIENCE_LEN {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                format!(
                    "audience length must be between 1 and {MAX_AUDIENCE_LEN} bytes (got {})",
                    aud.len()
                ),
            ));
        }

        if expires_at.as_seconds() <= issued_at.as_seconds() {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "expires_at must be strictly greater than issued_at",
            ));
        }

        Ok(Self {
            verifier_id: v_id,
            nonce: n,
            audience: aud,
            issued_at,
            expires_at,
            query,
            eph_pub,
        })
    }

    /// Valida la vigencia temporal de la solicitud contra el reloj inyectado (`INV-11`).
    ///
    /// # Errores
    /// [`ErrorCode::CredentialExpired`] si la solicitud ha caducado.
    /// [`ErrorCode::CredentialNotYetValid`] si la solicitud fue emitida en el futuro.
    pub fn validate_timing(
        &self,
        current_time: UnixTime,
        clock_skew_seconds: u64,
    ) -> Result<(), GidError> {
        let now_sec = current_time.as_seconds();
        let exp_sec = self.expires_at.as_seconds();
        let iat_sec = self.issued_at.as_seconds();

        // Expira si current_time > expires_at + clock_skew
        if now_sec > exp_sec.saturating_add(clock_skew_seconds) {
            return Err(GidError::new(
                ErrorCode::ExpiredRequest,
                "verification request has expired",
            ));
        }

        // Falla si issued_at > current_time + clock_skew
        if iat_sec > now_sec.saturating_add(clock_skew_seconds) {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "verification request issued_at is in the future",
            ));
        }

        Ok(())
    }

    /// Serializa la solicitud a JSON canónico (`PROTOCOL.md §3.1`).
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut obj = vec![
            ("audience".to_string(), Value::String(self.audience.clone())),
            (
                "expires_at".to_string(),
                Value::Number(Number::PosInt(self.expires_at.as_seconds())),
            ),
            (
                "issued_at".to_string(),
                Value::Number(Number::PosInt(self.issued_at.as_seconds())),
            ),
            ("nonce".to_string(), Value::String(self.nonce.clone())),
            (
                "type".to_string(),
                Value::String(VERIFICATION_REQUEST_TYPE.to_string()),
            ),
            (
                "verifier_id".to_string(),
                Value::String(self.verifier_id.clone()),
            ),
        ];

        if let Some(eph) = &self.eph_pub {
            obj.push((
                "eph_pub".to_string(),
                Value::String(eph.to_canonical_json()),
            ));
        }

        // Query DCQL: parseamos el canonical JSON de query para insertarlo ordenado
        let query_json = self.query.to_canonical_json();
        if let Ok(query_val) = parse_bytes(query_json.as_bytes(), &Limits::profile_default()) {
            obj.push(("query".to_string(), query_val));
        }

        obj.sort_by(|a, b| a.0.cmp(&b.0));
        to_canonical_json(&Value::Object(obj))
    }

    /// Serializa la solicitud a bytes JSON UTF-8 (`PROTOCOL.md §3.1`).
    ///
    /// # Errores
    /// Nunca falla en la implementación canónica.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, GidError> {
        Ok(self.to_canonical_json().into_bytes())
    }

    /// Parsea una solicitud de verificación desde bytes JSON.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedMessage`] si el JSON no es válido o falta algún campo obligatorio.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, GidError> {
        let val = parse_bytes(bytes, &Limits::profile_default()).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedMessage,
                format!("failed to parse verification request JSON: {e}"),
            )
        })?;

        let type_str = member_str(&val, "type").ok_or_else(|| {
            GidError::new(ErrorCode::MalformedMessage, "missing 'type' in request")
        })?;
        if type_str != VERIFICATION_REQUEST_TYPE {
            return Err(GidError::new(
                ErrorCode::UnsupportedProtocolVersion,
                format!(
                    "unsupported request type '{type_str}', expected '{VERIFICATION_REQUEST_TYPE}'"
                ),
            ));
        }

        let verifier_id = member_str(&val, "verifier_id").ok_or_else(|| {
            GidError::new(
                ErrorCode::MalformedMessage,
                "missing 'verifier_id' in request",
            )
        })?;

        let nonce = member_str(&val, "nonce").ok_or_else(|| {
            GidError::new(ErrorCode::MalformedMessage, "missing 'nonce' in request")
        })?;

        let audience = member_str(&val, "audience").ok_or_else(|| {
            GidError::new(ErrorCode::MalformedMessage, "missing 'audience' in request")
        })?;

        let issued_at = member_u64(&val, "issued_at")
            .map(UnixTime::from_seconds)
            .ok_or_else(|| {
                GidError::new(
                    ErrorCode::MalformedMessage,
                    "missing 'issued_at' in request",
                )
            })?;

        let expires_at = member_u64(&val, "expires_at")
            .map(UnixTime::from_seconds)
            .ok_or_else(|| {
                GidError::new(
                    ErrorCode::MalformedMessage,
                    "missing 'expires_at' in request",
                )
            })?;

        let query_val = val.member("query").ok_or_else(|| {
            GidError::new(ErrorCode::MalformedMessage, "missing 'query' in request")
        })?;
        let query_json = to_canonical_json(query_val);
        let query = DcqlQuery::from_json_bytes(query_json.as_bytes())?;

        let eph_pub = match member_str(&val, "eph_pub") {
            Some(s) => Some(JwkEcP256::parse(s)?),
            None => None,
        };

        Self::new(
            verifier_id,
            nonce,
            audience,
            issued_at,
            expires_at,
            query,
            eph_pub,
        )
    }
}
