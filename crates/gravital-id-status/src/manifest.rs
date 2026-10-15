//! Manifiesto de estado del emisor (F4.T01, ADR-0017, REQ-STAT-008).
//!
//! Cada emisor publica un documento firmado que vincula las URI y los hashes de sus
//! Token Status Lists, desacoplando el estado de revocación de las actualizaciones del
//! trust bundle (`TRUST_BUNDLE.md` §7, REQ-TRUST-010):
//!
//! ```json
//! {
//!   "issuer_id": "iss-panama-tribunal-electoral",
//!   "manifest_version": 845,
//!   "issued_at": 1791633600,
//!   "valid_until": 1791720000,
//!   "status_lists": [
//!     { "status_list_id": "sl-1", "type": "TokenStatusList",
//!       "uri": "https://…/part1.jwt", "sha256": "8f4e2b…",
//!       "valid_until": 1791720000 }
//!   ]
//! }
//! ```
//!
//! Trazabilidad:
//! - **REQ-STAT-008:** manifiesto firmado con versión monotónica; el cliente rechaza
//!   versiones inferiores a la última aceptada de ese emisor.
//! - **REQ-STAT-004:** la frescura se comprueba con el `Clock` inyectado (INV-11).
//! - **INV-05:** ante cualquier incoherencia el manifiesto se rechaza completo.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use gravital_id_codec::base64url;
use gravital_id_codec::json::{parse_bytes, Limits as JsonLimits, Number, Value};
use gravital_id_crypto::{verify_es256_jwk, JwkEcP256, ES256_SIGNATURE_LEN};
use gravital_id_types::{ErrorCode, GidError, UnixTime};

/// Tamaño máximo del manifiesto (`TRUST_BUNDLE.md` §8, REQ-VER-008).
pub const DEFAULT_MANIFEST_MAX_BYTES: usize = 64 * 1024;

/// Tipo declarado por cada entrada de lista del manifiesto.
pub const MANIFEST_LIST_TYPE: &str = "TokenStatusList";

/// Una entrada de lista dentro del manifiesto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestListEntry {
    /// Identificador local de la lista.
    pub status_list_id: String,
    /// Tipo declarado (debe ser `TokenStatusList`).
    pub list_type: String,
    /// URI de la lista.
    pub uri: String,
    /// Hash SHA-256 esperado del JWT de la lista (hexadecimal en minúsculas).
    pub sha256: String,
    /// Instante hasta el que la entrada es válida.
    pub valid_until: Option<UnixTime>,
}

/// Manifiesto de estado de un emisor, ya parseado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerStatusManifest {
    issuer_id: String,
    manifest_version: u64,
    issued_at: Option<UnixTime>,
    valid_until: Option<UnixTime>,
    lists: Vec<ManifestListEntry>,
}

impl IssuerStatusManifest {
    /// Identificador del emisor.
    #[must_use]
    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    /// Versión del manifiesto (monótona por emisor).
    #[must_use]
    pub fn manifest_version(&self) -> u64 {
        self.manifest_version
    }

    /// Instante de emisión del manifiesto.
    #[must_use]
    pub fn issued_at(&self) -> Option<UnixTime> {
        self.issued_at
    }

    /// Instante hasta el que el manifiesto es válido.
    #[must_use]
    pub fn valid_until(&self) -> Option<UnixTime> {
        self.valid_until
    }

    /// Entradas de lista declaradas.
    #[must_use]
    pub fn lists(&self) -> &[ManifestListEntry] {
        &self.lists
    }

    /// Busca la entrada correspondiente a una URI de lista.
    #[must_use]
    pub fn entry_for_uri(&self, uri: &str) -> Option<&ManifestListEntry> {
        self.lists.iter().find(|entry| entry.uri == uri)
    }

    /// Comprueba la frescura del manifiesto contra el reloj inyectado (REQ-STAT-004).
    ///
    /// # Errores
    /// - [`ErrorCode::CredentialNotYetValid`] si `issued_at` es futuro.
    /// - [`ErrorCode::StatusListExpired`] si `valid_until` ya venció.
    pub fn check_freshness(&self, now: UnixTime) -> Result<(), GidError> {
        if let Some(issued_at) = self.issued_at {
            if issued_at.as_seconds() > now.as_seconds() {
                return Err(GidError::new(
                    ErrorCode::CredentialNotYetValid,
                    "status manifest 'issued_at' is in the future",
                ));
            }
        }
        if let Some(valid_until) = self.valid_until {
            if now.as_seconds() > valid_until.as_seconds() {
                return Err(GidError::new(
                    ErrorCode::StatusListExpired,
                    "status manifest has expired",
                ));
            }
        }
        Ok(())
    }

    /// Comprueba el anti-rollback por emisor (REQ-STAT-008).
    ///
    /// # Errores
    /// [`ErrorCode::MalformedStatusList`] si la versión no es estrictamente mayor que la
    /// última aceptada.
    pub fn check_monotonic_version(&self, last_accepted: Option<u64>) -> Result<(), GidError> {
        if let Some(last) = last_accepted {
            if self.manifest_version <= last {
                return Err(GidError::new(
                    ErrorCode::MalformedStatusList,
                    format!(
                        "status manifest version {} is not newer than the last accepted version {last}",
                        self.manifest_version
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// Verificador de manifiestos de estado.
pub struct StatusManifestVerifier;

impl StatusManifestVerifier {
    /// Parsea un manifiesto desde su payload JSON ya decodificado.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedStatusList`] si falta un campo obligatorio, si los tipos son
    /// incorrectos o si una entrada declara un tipo distinto de `TokenStatusList`.
    pub fn from_payload(payload: &Value) -> Result<IssuerStatusManifest, GidError> {
        let issuer_id = payload
            .member("issuer_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                GidError::new(
                    ErrorCode::MalformedStatusList,
                    "status manifest missing 'issuer_id'",
                )
            })?
            .to_string();
        if issuer_id.is_empty() {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "status manifest 'issuer_id' must not be empty",
            ));
        }

        let manifest_version = match payload.member("manifest_version") {
            Some(Value::Number(Number::PosInt(version))) => *version,
            _ => {
                return Err(GidError::new(
                    ErrorCode::MalformedStatusList,
                    "status manifest missing integer 'manifest_version'",
                ));
            }
        };

        let issued_at = match payload.member("issued_at") {
            Some(Value::Number(Number::PosInt(value))) => Some(UnixTime::from_seconds(*value)),
            Some(_) => {
                return Err(GidError::new(
                    ErrorCode::MalformedStatusList,
                    "status manifest 'issued_at' must be a positive integer",
                ));
            }
            None => None,
        };

        let valid_until = match payload.member("valid_until") {
            Some(Value::Number(Number::PosInt(value))) => Some(UnixTime::from_seconds(*value)),
            Some(_) => {
                return Err(GidError::new(
                    ErrorCode::MalformedStatusList,
                    "status manifest 'valid_until' must be a positive integer",
                ));
            }
            None => None,
        };

        let Some(Value::Array(raw_lists)) = payload.member("status_lists") else {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "status manifest missing the 'status_lists' array",
            ));
        };

        let mut lists = Vec::with_capacity(raw_lists.len());
        for entry in raw_lists {
            lists.push(Self::parse_entry(entry)?);
        }

        if let (Some(issued), Some(valid)) = (issued_at, valid_until) {
            if valid.as_seconds() < issued.as_seconds() {
                return Err(GidError::new(
                    ErrorCode::MalformedStatusList,
                    "status manifest 'valid_until' is before 'issued_at'",
                ));
            }
        }

        Ok(IssuerStatusManifest {
            issuer_id,
            manifest_version,
            issued_at,
            valid_until,
            lists,
        })
    }

    /// Parsea una entrada de lista del manifiesto.
    fn parse_entry(entry: &Value) -> Result<ManifestListEntry, GidError> {
        let status_list_id = entry
            .member("status_list_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                GidError::new(
                    ErrorCode::MalformedStatusList,
                    "status manifest entry missing 'status_list_id'",
                )
            })?
            .to_string();

        let list_type = entry
            .member("type")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                GidError::new(
                    ErrorCode::MalformedStatusList,
                    "status manifest entry missing 'type'",
                )
            })?
            .to_string();
        if list_type != MANIFEST_LIST_TYPE {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                format!(
                    "status manifest entry '{status_list_id}' has unsupported type '{list_type}'"
                ),
            ));
        }

        let uri = entry
            .member("uri")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                GidError::new(
                    ErrorCode::MalformedStatusList,
                    "status manifest entry missing 'uri'",
                )
            })?
            .to_string();

        let sha256 = entry
            .member("sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                GidError::new(
                    ErrorCode::MalformedStatusList,
                    "status manifest entry missing 'sha256'",
                )
            })?
            .to_string();
        if !is_sha256_hex(&sha256) {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "status manifest entry 'sha256' must be 64 hexadecimal characters",
            ));
        }

        let valid_until = match entry.member("valid_until") {
            Some(Value::Number(Number::PosInt(value))) => Some(UnixTime::from_seconds(*value)),
            Some(_) => {
                return Err(GidError::new(
                    ErrorCode::MalformedStatusList,
                    "status manifest entry 'valid_until' must be a positive integer",
                ));
            }
            None => None,
        };

        Ok(ManifestListEntry {
            status_list_id,
            list_type,
            uri,
            sha256,
            valid_until,
        })
    }

    /// Parsea el JWS completo del manifiesto (sin verificar la firma).
    ///
    /// # Errores
    /// [`ErrorCode::MalformedStatusList`] ante cualquier incumplimiento de formato o de
    /// tamaño (REQ-VER-008).
    pub fn parse(jwt: &str) -> Result<IssuerStatusManifest, GidError> {
        if jwt.len() > DEFAULT_MANIFEST_MAX_BYTES {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                format!(
                    "status manifest size {} exceeds the limit of {DEFAULT_MANIFEST_MAX_BYTES} bytes",
                    jwt.len()
                ),
            ));
        }

        let segments: Vec<&str> = jwt.split('.').collect();
        if segments.len() != 3 {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                format!(
                    "status manifest must have 3 dot-separated segments, got {}",
                    segments.len()
                ),
            ));
        }
        let Some(&payload_b64) = segments.get(1) else {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "missing status manifest payload",
            ));
        };

        let payload_bytes = base64url::decode(payload_b64).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedStatusList,
                format!("invalid base64url in status manifest payload: {e}"),
            )
        })?;
        let payload = parse_bytes(&payload_bytes, &JsonLimits::profile_default()).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedStatusList,
                format!("failed to parse status manifest payload: {e}"),
            )
        })?;

        Self::from_payload(&payload)
    }

    /// Verifica la firma JWS del manifiesto contra la clave de estado del emisor.
    ///
    /// # Errores
    /// [`ErrorCode::InvalidSignature`] si la firma no verifica o su longitud es inválida.
    pub fn verify_signature(jwt: &str, status_key: &JwkEcP256) -> Result<(), GidError> {
        let segments: Vec<&str> = jwt.split('.').collect();
        if segments.len() != 3 {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                format!(
                    "status manifest must have 3 dot-separated segments, got {}",
                    segments.len()
                ),
            ));
        }
        let Some(&header_b64) = segments.first() else {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "missing status manifest header",
            ));
        };
        let Some(&payload_b64) = segments.get(1) else {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "missing status manifest payload",
            ));
        };
        let Some(&sig_b64) = segments.get(2) else {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "missing status manifest signature",
            ));
        };

        let signature = base64url::decode(sig_b64).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedStatusList,
                format!("invalid base64url in status manifest signature: {e}"),
            )
        })?;
        if signature.len() != ES256_SIGNATURE_LEN {
            return Err(GidError::new(
                ErrorCode::InvalidSignature,
                format!(
                    "status manifest signature must be {} bytes, got {}",
                    ES256_SIGNATURE_LEN,
                    signature.len()
                ),
            ));
        }
        let mut signature_bytes = [0u8; ES256_SIGNATURE_LEN];
        if let Some(slot) = signature_bytes.get_mut(..signature.len()) {
            slot.copy_from_slice(&signature);
        }

        verify_es256_jwk(
            status_key,
            format!("{header_b64}.{payload_b64}").as_bytes(),
            &signature_bytes,
        )
    }

    /// Comprueba que el hash de una lista descargada coincide con el del manifiesto
    /// (`TRUST_BUNDLE.md` §7.2.3, REQ-SYNC-004).
    ///
    /// # Errores
    /// [`ErrorCode::StatusManifestMismatch`] si el hash no coincide o la URI no está
    /// declarada en el manifiesto.
    pub fn check_list_digest(
        manifest: &IssuerStatusManifest,
        uri: &str,
        sha256_hex: &str,
    ) -> Result<(), GidError> {
        let Some(entry) = manifest.entry_for_uri(uri) else {
            return Err(GidError::new(
                ErrorCode::StatusManifestMismatch,
                "status manifest has no entry for the referenced list uri",
            ));
        };
        if !entry.sha256.eq_ignore_ascii_case(sha256_hex) {
            return Err(GidError::new(
                ErrorCode::StatusManifestMismatch,
                "status list digest does not match the signed manifest entry",
            ));
        }
        Ok(())
    }
}

/// Comprueba que una cadena es un SHA-256 en hexadecimal (64 caracteres).
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
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
    use alloc::vec;

    fn manifest_payload(version: u64) -> Value {
        Value::Object(vec![
            (
                "issuer_id".to_string(),
                Value::String("iss-example".to_string()),
            ),
            (
                "manifest_version".to_string(),
                Value::Number(Number::PosInt(version)),
            ),
            (
                "issued_at".to_string(),
                Value::Number(Number::PosInt(1_700_000_000)),
            ),
            (
                "valid_until".to_string(),
                Value::Number(Number::PosInt(1_800_000_000)),
            ),
            (
                "status_lists".to_string(),
                Value::Array(vec![Value::Object(vec![
                    (
                        "status_list_id".to_string(),
                        Value::String("sl-1".to_string()),
                    ),
                    (
                        "type".to_string(),
                        Value::String(MANIFEST_LIST_TYPE.to_string()),
                    ),
                    (
                        "uri".to_string(),
                        Value::String("https://status.example.gov/l".to_string()),
                    ),
                    ("sha256".to_string(), Value::String("a".repeat(64))),
                ])]),
            ),
        ])
    }

    #[test]
    fn nominal_manifest_is_parsed() {
        let manifest =
            StatusManifestVerifier::from_payload(&manifest_payload(845)).expect("manifest");
        assert_eq!(manifest.issuer_id(), "iss-example");
        assert_eq!(manifest.manifest_version(), 845);
        assert_eq!(manifest.lists().len(), 1);
        assert!(manifest
            .entry_for_uri("https://status.example.gov/l")
            .is_some());
        assert!(manifest
            .entry_for_uri("https://otra.example.gov/l")
            .is_none());
    }

    #[test]
    fn freshness_and_monotonic_version_are_enforced() {
        let manifest = StatusManifestVerifier::from_payload(&manifest_payload(845)).unwrap();

        manifest
            .check_freshness(UnixTime::from_seconds(1_700_000_100))
            .expect("vigente");
        let error = manifest
            .check_freshness(UnixTime::from_seconds(1_800_000_100))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::StatusListExpired);

        // Anti-rollback.
        manifest
            .check_monotonic_version(Some(844))
            .expect("versión nueva");
        let error = manifest.check_monotonic_version(Some(845)).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedStatusList);
        let error = manifest.check_monotonic_version(Some(900)).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedStatusList);
        manifest
            .check_monotonic_version(None)
            .expect("primer manifiesto");
    }

    #[test]
    fn list_digest_is_checked_case_insensitively() {
        let manifest = StatusManifestVerifier::from_payload(&manifest_payload(1)).unwrap();
        StatusManifestVerifier::check_list_digest(
            &manifest,
            "https://status.example.gov/l",
            &"A".repeat(64),
        )
        .expect("hash coincide");

        let error = StatusManifestVerifier::check_list_digest(
            &manifest,
            "https://status.example.gov/l",
            &"b".repeat(64),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::StatusManifestMismatch);

        let error = StatusManifestVerifier::check_list_digest(
            &manifest,
            "https://desconocida.example.gov/l",
            &"a".repeat(64),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::StatusManifestMismatch);
    }

    #[test]
    fn malformed_entries_are_rejected() {
        // Tipo de entrada no soportado.
        let mut payload = manifest_payload(1);
        if let Value::Object(entries) = &mut payload {
            for (key, value) in entries.iter_mut() {
                if key == "status_lists" {
                    if let Value::Array(lists) = value {
                        if let Some(Value::Object(entry)) = lists.first_mut() {
                            for (k, v) in entry.iter_mut() {
                                if k == "type" {
                                    *v = Value::String("OtraCosa".to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        let error = StatusManifestVerifier::from_payload(&payload).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedStatusList);

        // sha256 que no es hexadecimal de 64 caracteres.
        let payload = Value::Object(vec![
            (
                "issuer_id".to_string(),
                Value::String("iss-example".to_string()),
            ),
            (
                "manifest_version".to_string(),
                Value::Number(Number::PosInt(1)),
            ),
            (
                "status_lists".to_string(),
                Value::Array(vec![Value::Object(vec![
                    (
                        "status_list_id".to_string(),
                        Value::String("sl-1".to_string()),
                    ),
                    (
                        "type".to_string(),
                        Value::String(MANIFEST_LIST_TYPE.to_string()),
                    ),
                    (
                        "uri".to_string(),
                        Value::String("https://s.example.gov/l".to_string()),
                    ),
                    ("sha256".to_string(), Value::String("zz".to_string())),
                ])]),
            ),
        ]);
        let error = StatusManifestVerifier::from_payload(&payload).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedStatusList);

        // Sin manifest_version.
        let payload = Value::Object(vec![(
            "issuer_id".to_string(),
            Value::String("iss-example".to_string()),
        )]);
        let error = StatusManifestVerifier::from_payload(&payload).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedStatusList);
    }

    #[test]
    fn manifest_size_limit_is_enforced() {
        let oversized = "a".repeat(DEFAULT_MANIFEST_MAX_BYTES.saturating_add(1));
        let error = StatusManifestVerifier::parse(&oversized).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedStatusList);
        assert!(error.message.contains("exceeds"));
    }
}
