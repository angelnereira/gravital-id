//! Modelo y serialización de credenciales almacenadas en la wallet del titular (REQ-KEY-008, REQ-STOR-001).
//!
//! Trazabilidad:
//! - `REQ-KEY-008`: El SDK y la wallet DEBEN asociar cada credencial emitida con la
//!   clave de titular correspondiente mediante un identificador local abstracto,
//!   sin almacenar la clave privada en la misma estructura ni permitir la sustitución
//!   no autenticada de claves.
//! - `REQ-STOR-001`: Cifrado de sobre DEK/KEK y datos asociados canónicos.
//! - `INV-02`: Sin PII en claro en el almacenamiento persistente ni en logs.
//! - `INV-03`: Ningún servicio custodia claves privadas; la clave del titular permanece en KeyStore.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use gravital_id_codec::json::{parse_bytes, Limits, Number, Value};
use gravital_id_credential::to_canonical_json;
use gravital_id_crypto::JwkEcP256;
use gravital_id_storage::RecordId;
use gravital_id_types::{ErrorCode, GidError, UnixTime, Vct};

/// Longitud máxima para un identificador de credencial local en la wallet.
pub const MAX_CREDENTIAL_ID_LEN: usize = 128;

/// Identificador único local abstracto de una credencial almacenada en la wallet (`REQ-KEY-008`).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialId(String);

impl CredentialId {
    /// Crea y valida un nuevo `CredentialId`.
    pub fn new(id: impl Into<String>) -> Result<Self, GidError> {
        let s = id.into();
        if s.is_empty() || s.len() > MAX_CREDENTIAL_ID_LEN {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                format!(
                    "credential id length must be between 1 and {MAX_CREDENTIAL_ID_LEN} bytes (got {})",
                    s.len()
                ),
            ));
        }

        for b in s.bytes() {
            if !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b':' || b == b'.') {
                return Err(GidError::new(
                    ErrorCode::MalformedMessage,
                    "credential id contains invalid characters (allowed: ASCII alphanumeric, '-', '_', ':', '.')",
                ));
            }
        }

        Ok(Self(s))
    }

    /// Retorna la referencia a la cadena del identificador.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convierte el `CredentialId` a un `RecordId` de `gravital-id-storage`.
    pub fn to_record_id(&self) -> Result<RecordId, GidError> {
        RecordId::new(&self.0)
    }
}

impl fmt::Display for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CredentialId(\"{}\")", self.0)
    }
}

/// Credencial verificable completa guardada en la wallet del titular.
#[derive(Debug, Clone, PartialEq)]
pub struct WalletCredential {
    /// Identificador local de la credencial en la wallet.
    pub id: CredentialId,
    /// Cadena compacta emitida SD-JWT original (incluyendo divulgaciones y finalizada en `~`).
    pub raw_sd_jwt: String,
    /// Tipo de credencial verificable (`vct`).
    pub vct: Vct,
    /// Identificador o URL del emisor que firmó la credencial (`iss`).
    pub issuer: String,
    /// Identificador abstracto de la clave privada del titular en el `KeyStore` (`REQ-KEY-008`).
    pub holder_binding_key_id: String,
    /// Clave pública JWK EC P-256 del titular vinculada en la credencial (`cnf.jwk`).
    pub holder_jwk: JwkEcP256,
    /// Momento de emisión (`iat`).
    pub issued_at: UnixTime,
    /// Momento a partir del cual es válida (`nbf`), si existe.
    pub not_before: Option<UnixTime>,
    /// Momento de expiración (`exp`), si existe.
    pub expires_at: Option<UnixTime>,
    /// Lista de nombres de claims disponibles para divulgación selectiva.
    pub available_claims: Vec<String>,
}

impl WalletCredential {
    /// Serializa la estructura de la credencial a JSON canónico para su almacenamiento cifrado.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut claims_arr = Vec::with_capacity(self.available_claims.len());
        for c in &self.available_claims {
            claims_arr.push(Value::String(c.clone()));
        }

        let mut obj = vec![
            ("available_claims".to_string(), Value::Array(claims_arr)),
            (
                "holder_binding_key_id".to_string(),
                Value::String(self.holder_binding_key_id.clone()),
            ),
            (
                "holder_jwk".to_string(),
                Value::String(self.holder_jwk.to_canonical_json()),
            ),
            (
                "id".to_string(),
                Value::String(self.id.as_str().to_string()),
            ),
            (
                "issued_at".to_string(),
                Value::Number(Number::PosInt(self.issued_at.as_seconds())),
            ),
            ("issuer".to_string(), Value::String(self.issuer.clone())),
            (
                "raw_sd_jwt".to_string(),
                Value::String(self.raw_sd_jwt.clone()),
            ),
            (
                "vct".to_string(),
                Value::String(self.vct.as_str().to_string()),
            ),
        ];

        if let Some(nbf) = self.not_before {
            obj.push((
                "not_before".to_string(),
                Value::Number(Number::PosInt(nbf.as_seconds())),
            ));
        }

        if let Some(exp) = self.expires_at {
            obj.push((
                "expires_at".to_string(),
                Value::Number(Number::PosInt(exp.as_seconds())),
            ));
        }

        obj.sort_by(|a, b| a.0.cmp(&b.0));
        to_canonical_json(&Value::Object(obj))
    }

    /// Deserializa una credencial guardada desde JSON canónico descifrado.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, GidError> {
        let val = parse_bytes(bytes, &Limits::profile_default()).map_err(|e| {
            GidError::new(
                ErrorCode::StorageReadFailed,
                format!("failed to parse wallet credential JSON: {e}"),
            )
        })?;

        let obj = match val {
            Value::Object(map) => map,
            _ => {
                return Err(GidError::new(
                    ErrorCode::StorageReadFailed,
                    "wallet credential JSON root must be an object",
                ))
            }
        };

        let mut id_str = None;
        let mut raw_sd_jwt = None;
        let mut vct_str = None;
        let mut issuer_str = None;
        let mut key_id = None;
        let mut holder_jwk_str = None;
        let mut issued_at = None;
        let mut not_before = None;
        let mut expires_at = None;
        let mut available_claims = Vec::new();

        for (k, v) in obj {
            match k.as_str() {
                "id" => {
                    if let Value::String(s) = v {
                        id_str = Some(s);
                    }
                }
                "raw_sd_jwt" => {
                    if let Value::String(s) = v {
                        raw_sd_jwt = Some(s);
                    }
                }
                "vct" => {
                    if let Value::String(s) = v {
                        vct_str = Some(s);
                    }
                }
                "issuer" => {
                    if let Value::String(s) = v {
                        issuer_str = Some(s);
                    }
                }
                "holder_binding_key_id" => {
                    if let Value::String(s) = v {
                        key_id = Some(s);
                    }
                }
                "holder_jwk" => {
                    if let Value::String(s) = v {
                        holder_jwk_str = Some(s);
                    }
                }
                "issued_at" => {
                    if let Value::Number(Number::PosInt(n)) = v {
                        issued_at = Some(UnixTime::from_seconds(n));
                    }
                }
                "not_before" => {
                    if let Value::Number(Number::PosInt(n)) = v {
                        not_before = Some(UnixTime::from_seconds(n));
                    }
                }
                "expires_at" => {
                    if let Value::Number(Number::PosInt(n)) = v {
                        expires_at = Some(UnixTime::from_seconds(n));
                    }
                }
                "available_claims" => {
                    if let Value::Array(arr) = v {
                        for item in arr {
                            if let Value::String(c) = item {
                                available_claims.push(c);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        let id_str = id_str.ok_or_else(|| {
            GidError::new(ErrorCode::StorageReadFailed, "missing 'id' in credential")
        })?;
        let id = CredentialId::new(id_str)?;

        let raw_sd_jwt = raw_sd_jwt.ok_or_else(|| {
            GidError::new(
                ErrorCode::StorageReadFailed,
                "missing 'raw_sd_jwt' in credential",
            )
        })?;

        let vct_str = vct_str.ok_or_else(|| {
            GidError::new(ErrorCode::StorageReadFailed, "missing 'vct' in credential")
        })?;
        let vct = Vct::parse(&vct_str)?;

        let issuer = issuer_str.ok_or_else(|| {
            GidError::new(
                ErrorCode::StorageReadFailed,
                "missing 'issuer' in credential",
            )
        })?;

        let holder_binding_key_id = key_id.ok_or_else(|| {
            GidError::new(
                ErrorCode::StorageReadFailed,
                "missing 'holder_binding_key_id' in credential",
            )
        })?;

        let holder_jwk_str = holder_jwk_str.ok_or_else(|| {
            GidError::new(
                ErrorCode::StorageReadFailed,
                "missing 'holder_jwk' in credential",
            )
        })?;
        let holder_jwk = JwkEcP256::parse(&holder_jwk_str)?;

        let issued_at = issued_at.ok_or_else(|| {
            GidError::new(
                ErrorCode::StorageReadFailed,
                "missing 'issued_at' in credential",
            )
        })?;

        Ok(Self {
            id,
            raw_sd_jwt,
            vct,
            issuer,
            holder_binding_key_id,
            holder_jwk,
            issued_at,
            not_before,
            expires_at,
            available_claims,
        })
    }

    /// Retorna un resumen ligero de la credencial para listados.
    #[must_use]
    pub fn summary(&self) -> WalletCredentialSummary {
        WalletCredentialSummary {
            id: self.id.clone(),
            vct: self.vct.clone(),
            issuer: self.issuer.clone(),
            holder_binding_key_id: self.holder_binding_key_id.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            available_claims: self.available_claims.clone(),
        }
    }
}

/// Resumen ligero de una credencial para consultas y vistas en UI de la wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletCredentialSummary {
    /// Identificador local único.
    pub id: CredentialId,
    /// Tipo de credencial (`vct`).
    pub vct: Vct,
    /// Emisor de la credencial (`iss`).
    pub issuer: String,
    /// Identificador abstracto de la clave de titular asociada.
    pub holder_binding_key_id: String,
    /// Momento de emisión.
    pub issued_at: UnixTime,
    /// Momento de expiración opcional.
    pub expires_at: Option<UnixTime>,
    /// Nombres de los claims que contiene la credencial.
    pub available_claims: Vec<String>,
}
