//! Raíz de confianza (`TrustRoot`) y encadenamiento de raíces (F4.T03).
//!
//! La raíz fija qué claves pueden firmar la próxima raíz y qué operadores pueden
//! cofirmar bundles. Se distribuye como JWS multi-firma (RFC 7515 §7.2) y se encadena en
//! rotación: la raíz nueva exige el umbral de la anterior **y** el suyo propio
//! (`TRUST_BUNDLE.md` §2.3, REQ-TRUST-009).
//!
//! Trazabilidad:
//! - **REQ-TRUST-009:** cadena de raíces con doble umbral y `bundle_epoch` incremental.
//! - **INV-16:** ninguna clave única decide la confianza offline: siempre umbral k-de-n.
//! - **INV-05:** una raíz que no acumula firmas suficientes se rechaza completa.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use gravital_id_codec::json::{Number, Value};
use gravital_id_crypto::JwkEcP256;
use gravital_id_types::{ErrorCode, GidError, UnixTime};

use crate::jws_json::{JwsJsonParser, MultiSignedJws};

/// Número máximo de claves de raíz (`TRUST_BUNDLE.md` §2.2, REQ-VER-008).
pub const MAX_ROOT_KEYS: usize = 32;

/// Longitud máxima de `framework_id` (REQ-VER-008).
pub const MAX_FRAMEWORK_ID_BYTES: usize = 64;

/// Longitud máxima de `registry_address` (REQ-VER-008).
pub const MAX_REGISTRY_ADDRESS_BYTES: usize = 64;

/// Clave pública autorizada a firmar la siguiente raíz.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootKey {
    /// Identificador de la clave.
    pub kid: String,
    /// Clave pública EC P-256.
    pub jwk: JwkEcP256,
}

/// Operador autorizado a cofirmar bundles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSigner {
    /// Organización del operador.
    pub operator: String,
    /// Identificador de la clave del operador.
    pub kid: String,
    /// Clave pública del operador.
    pub jwk: JwkEcP256,
}

/// Raíz de confianza parseada.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustRoot {
    framework_id: String,
    root_version: u64,
    bundle_epoch: u64,
    issued_at: UnixTime,
    valid_until: UnixTime,
    chain_id: u64,
    registry_address: String,
    root_keys: Vec<RootKey>,
    root_threshold: u32,
    bundle_signers: Vec<BundleSigner>,
    bundle_threshold: u32,
}

impl TrustRoot {
    /// Identificador del marco de confianza.
    #[must_use]
    pub fn framework_id(&self) -> &str {
        &self.framework_id
    }

    /// Versión de la raíz (monótona dentro del marco).
    #[must_use]
    pub fn root_version(&self) -> u64 {
        self.root_version
    }

    /// Época de bundles vigente.
    #[must_use]
    pub fn bundle_epoch(&self) -> u64 {
        self.bundle_epoch
    }

    /// Instante de emisión de la raíz.
    #[must_use]
    pub fn issued_at(&self) -> UnixTime {
        self.issued_at
    }

    /// Instante de expiración de la raíz.
    #[must_use]
    pub fn valid_until(&self) -> UnixTime {
        self.valid_until
    }

    /// Cadena blockchain de origen (EIP-155).
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Dirección del contrato de registro.
    #[must_use]
    pub fn registry_address(&self) -> &str {
        &self.registry_address
    }

    /// Claves autorizadas a firmar la siguiente raíz.
    #[must_use]
    pub fn root_keys(&self) -> &[RootKey] {
        &self.root_keys
    }

    /// Umbral de firmas de raíz exigido para la rotación.
    #[must_use]
    pub fn root_threshold(&self) -> u32 {
        self.root_threshold
    }

    /// Operadores autorizados a cofirmar bundles.
    #[must_use]
    pub fn bundle_signers(&self) -> &[BundleSigner] {
        &self.bundle_signers
    }

    /// Umbral de firmantes distintos exigido a un bundle.
    #[must_use]
    pub fn bundle_threshold(&self) -> u32 {
        self.bundle_threshold
    }

    /// Clave de raíz por `kid`.
    #[must_use]
    pub fn root_key(&self, kid: &str) -> Option<&RootKey> {
        self.root_keys.iter().find(|key| key.kid == kid)
    }

    /// Firmante de bundle por `kid`.
    #[must_use]
    pub fn bundle_signer(&self, kid: &str) -> Option<&BundleSigner> {
        self.bundle_signers.iter().find(|signer| signer.kid == kid)
    }

    /// Ventana de vigencia de la raíz.
    #[must_use]
    pub fn contains(&self, now: UnixTime) -> bool {
        now.as_seconds() >= self.issued_at.as_seconds()
            && now.as_seconds() <= self.valid_until.as_seconds()
    }

    /// Construye la raíz a partir del payload JSON.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedSdJwt`] si falta un campo obligatorio, si los tipos son
    /// incorrectos o si los umbrales caen fuera de `1..=n` (INV-16, INV-05).
    pub fn from_payload(payload: &Value) -> Result<Self, GidError> {
        let framework_id = required_str(payload, "framework_id")?;
        if framework_id.is_empty() || framework_id.len() > MAX_FRAMEWORK_ID_BYTES {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "trust root 'framework_id' must be 1..=64 characters",
            ));
        }

        let root_version = required_u64(payload, "root_version")?;
        let bundle_epoch = required_u64(payload, "bundle_epoch")?;
        let issued_at = UnixTime::from_seconds(required_u64(payload, "issued_at")?);
        let valid_until = UnixTime::from_seconds(required_u64(payload, "valid_until")?);
        if valid_until.as_seconds() < issued_at.as_seconds() {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "trust root 'valid_until' is before 'issued_at'",
            ));
        }

        let chain_id = required_u64(payload, "chain_id")?;
        let registry_address = required_str(payload, "registry_address")?;
        if registry_address.len() > MAX_REGISTRY_ADDRESS_BYTES {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "trust root 'registry_address' is too long",
            ));
        }

        let root_keys = parse_root_keys(payload)?;
        let root_threshold = required_u32(payload, "root_threshold")?;
        validate_threshold("root", root_threshold, root_keys.len())?;

        let bundle_signers = parse_bundle_signers(payload)?;
        let bundle_threshold = required_u32(payload, "bundle_threshold")?;
        validate_threshold("bundle", bundle_threshold, bundle_signers.len())?;

        Ok(Self {
            framework_id: framework_id.to_string(),
            root_version,
            bundle_epoch,
            issued_at,
            valid_until,
            chain_id,
            registry_address: registry_address.to_string(),
            root_keys,
            root_threshold,
            bundle_signers,
            bundle_threshold,
        })
    }

    /// Parsea el documento JWS multi-firma de la raíz.
    pub fn parse(document: &str) -> Result<(Self, MultiSignedJws), GidError> {
        let jws = JwsJsonParser::parse(document)?;
        let root = Self::from_payload(&jws.payload)?;
        Ok((root, jws))
    }
}

/// Verificador de la cadena de raíces.
pub struct TrustRootVerifier;

impl TrustRootVerifier {
    /// Comprueba que una raíz candidata está correctamente encadenada sobre la anterior.
    ///
    /// Exige (`TRUST_BUNDLE.md` §2.3):
    /// 1. `root_version` creciente.
    /// 2. `framework_id` idéntico.
    /// 3. `bundle_epoch` no decreciente.
    /// 4. Al menos `current.root_threshold` firmas válidas de claves de `current`, sobre la
    ///    entrada firmada del **candidato** (es el documento que se acepta).
    /// 5. Al menos `candidate.root_threshold` firmas válidas de claves propias, sobre esa
    ///    misma entrada.
    ///
    /// # Errores
    /// - [`ErrorCode::TrustRootChainBroken`] si falla cualquier requisito.
    /// - [`ErrorCode::InsufficientBundleSignatures`] si un umbral no se alcanza.
    pub fn verify_chain(
        current: &TrustRoot,
        _current_jws: &MultiSignedJws,
        candidate: &TrustRoot,
        candidate_jws: &MultiSignedJws,
    ) -> Result<(), GidError> {
        if candidate.framework_id != current.framework_id {
            return Err(GidError::new(
                ErrorCode::TrustRootChainBroken,
                "trust root 'framework_id' does not match the installed root",
            ));
        }
        if candidate.root_version <= current.root_version {
            return Err(GidError::new(
                ErrorCode::TrustRootChainBroken,
                format!(
                    "trust root version {} is not newer than the installed version {}",
                    candidate.root_version, current.root_version
                ),
            ));
        }
        if candidate.bundle_epoch < current.bundle_epoch {
            return Err(GidError::new(
                ErrorCode::TrustRootChainBroken,
                "trust root 'bundle_epoch' cannot decrease",
            ));
        }

        // Ambos umbrales se comprueban sobre la entrada firmada del candidato: la raíz
        // anterior autoriza el documento nuevo firmándolo.
        let previous_kids = candidate_jws
            .verified_kids(|kid| current.root_key(kid).map(|key| key.jwk.clone()))
            .map_err(|e| {
                GidError::new(
                    ErrorCode::InsufficientBundleSignatures,
                    format!("invalid signature while verifying the previous root: {e}"),
                )
            })?;
        if (previous_kids.len() as u32) < current.root_threshold {
            return Err(GidError::new(
                ErrorCode::InsufficientBundleSignatures,
                format!(
                    "new root carries {} valid signatures from the installed root, {} required",
                    previous_kids.len(),
                    current.root_threshold
                ),
            ));
        }

        let own_kids = candidate_jws
            .verified_kids(|kid| candidate.root_key(kid).map(|key| key.jwk.clone()))
            .map_err(|e| {
                GidError::new(
                    ErrorCode::InsufficientBundleSignatures,
                    format!("invalid signature while verifying the new root: {e}"),
                )
            })?;
        if (own_kids.len() as u32) < candidate.root_threshold {
            return Err(GidError::new(
                ErrorCode::InsufficientBundleSignatures,
                format!(
                    "new root carries {} valid signatures of its own keys, {} required",
                    own_kids.len(),
                    candidate.root_threshold
                ),
            ));
        }

        Ok(())
    }

    /// Indica si el candidato fuerza una nueva época (recuperación de avance forzado).
    ///
    /// `TRUST_BUNDLE.md` §6: al incrementar `bundle_epoch` el cliente descarta el bundle
    /// activo y reinicia el contador de versión a 0.
    #[must_use]
    pub fn forces_new_epoch(current: &TrustRoot, candidate: &TrustRoot) -> bool {
        candidate.bundle_epoch > current.bundle_epoch
    }
}

/// Lee un campo de texto obligatorio.
fn required_str<'a>(payload: &'a Value, name: &str) -> Result<&'a str, GidError> {
    payload.member(name).and_then(Value::as_str).ok_or_else(|| {
        GidError::new(
            ErrorCode::MalformedSdJwt,
            format!("trust root missing string field '{name}'"),
        )
    })
}

/// Lee un campo entero sin signo obligatorio.
fn required_u64(payload: &Value, name: &str) -> Result<u64, GidError> {
    match payload.member(name) {
        Some(Value::Number(Number::PosInt(value))) => Ok(*value),
        _ => Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            format!("trust root missing integer field '{name}'"),
        )),
    }
}

/// Lee un campo entero de 32 bits obligatorio.
fn required_u32(payload: &Value, name: &str) -> Result<u32, GidError> {
    let value = required_u64(payload, name)?;
    u32::try_from(value).map_err(|_| {
        GidError::new(
            ErrorCode::MalformedSdJwt,
            format!("trust root field '{name}' does not fit in 32 bits"),
        )
    })
}

/// Parseo de las JWK de un array (acepta `{ "kid": …, "jwk": {…} }` o una JWK plana con `kid`).
fn parse_jwk_entry(entry: &Value, kind: &str) -> Result<(String, JwkEcP256), GidError> {
    let jwk_value = entry.member("jwk").unwrap_or(entry);
    let canonical = crate::to_canonical_json(jwk_value);
    let jwk = JwkEcP256::parse(&canonical).map_err(|e| {
        GidError::new(
            ErrorCode::InvalidKeyFormat,
            format!("invalid JWK in {kind}: {e}"),
        )
    })?;
    let kid = entry
        .member("kid")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| jwk.kid().map(ToString::to_string))
        .ok_or_else(|| {
            GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("{kind} entry missing 'kid'"),
            )
        })?;
    Ok((kid, jwk))
}

/// Parseo de `root_keys`.
fn parse_root_keys(payload: &Value) -> Result<Vec<RootKey>, GidError> {
    let Some(Value::Array(entries)) = payload.member("root_keys") else {
        return Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            "trust root missing the 'root_keys' array",
        ));
    };
    if entries.is_empty() || entries.len() > MAX_ROOT_KEYS {
        return Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            format!(
                "'root_keys' must contain 1..={MAX_ROOT_KEYS} entries, got {}",
                entries.len()
            ),
        ));
    }
    let mut keys = Vec::with_capacity(entries.len());
    let mut seen = Vec::new();
    for entry in entries {
        let (kid, jwk) = parse_jwk_entry(entry, "root_keys")?;
        if seen.contains(&kid) {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("duplicate root key kid '{kid}'"),
            ));
        }
        seen.push(kid.clone());
        keys.push(RootKey { kid, jwk });
    }
    Ok(keys)
}

/// Parseo de `bundle_signers`.
fn parse_bundle_signers(payload: &Value) -> Result<Vec<BundleSigner>, GidError> {
    let Some(Value::Array(entries)) = payload.member("bundle_signers") else {
        return Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            "trust root missing the 'bundle_signers' array",
        ));
    };
    if entries.is_empty() || entries.len() > MAX_ROOT_KEYS {
        return Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            format!(
                "'bundle_signers' must contain 1..={MAX_ROOT_KEYS} entries, got {}",
                entries.len()
            ),
        ));
    }
    let mut signers = Vec::with_capacity(entries.len());
    let mut seen = Vec::new();
    for entry in entries {
        let operator = entry
            .member("operator")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                GidError::new(
                    ErrorCode::MalformedSdJwt,
                    "bundle signer entry missing 'operator'",
                )
            })?
            .to_string();
        let (kid, jwk) = parse_jwk_entry(entry, "bundle_signers")?;
        if seen.contains(&kid) {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("duplicate bundle signer kid '{kid}'"),
            ));
        }
        seen.push(kid.clone());
        signers.push(BundleSigner { operator, kid, jwk });
    }
    Ok(signers)
}

/// Comprueba que un umbral esté en `1..=n` (INV-16).
fn validate_threshold(kind: &str, threshold: u32, keys: usize) -> Result<(), GidError> {
    if threshold == 0 || (threshold as usize) > keys {
        return Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            format!("{kind} threshold {threshold} is outside 1..={keys}"),
        ));
    }
    Ok(())
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
    use alloc::vec;
    use gravital_id_keys::{IssuerSigning, KeyStore, SoftwareKeyStore};
    use gravital_id_testkit::SeededRng;

    fn jwk_value(kid: &str, jwk: &JwkEcP256) -> Value {
        Value::Object(vec![
            ("kid".to_string(), Value::String(kid.to_string())),
            ("jwk".to_string(), crate::json_value_of(jwk)),
        ])
    }

    fn root_payload(version: u64, epoch: u64, threshold: u32) -> Value {
        let mut store = SoftwareKeyStore::new(SeededRng::new(1));
        let keys: Vec<Value> = (0..3)
            .map(|index| {
                let handle = store.generate_key::<IssuerSigning>().expect("key");
                let jwk = store.public_key(&handle).expect("jwk");
                jwk_value(&format!("root-{index}"), &jwk)
            })
            .collect();
        let signers: Vec<Value> = (0..3)
            .map(|index| {
                let handle = store.generate_key::<IssuerSigning>().expect("key");
                let jwk = store.public_key(&handle).expect("jwk");
                Value::Object(vec![
                    (
                        "operator".to_string(),
                        Value::String(format!("op-{index}.org")),
                    ),
                    ("kid".to_string(), Value::String(format!("signer-{index}"))),
                    ("jwk".to_string(), crate::json_value_of(&jwk)),
                ])
            })
            .collect();

        Value::Object(vec![
            (
                "framework_id".to_string(),
                Value::String("pip-global".to_string()),
            ),
            (
                "root_version".to_string(),
                Value::Number(Number::PosInt(version)),
            ),
            (
                "bundle_epoch".to_string(),
                Value::Number(Number::PosInt(epoch)),
            ),
            (
                "issued_at".to_string(),
                Value::Number(Number::PosInt(1_700_000_000)),
            ),
            (
                "valid_until".to_string(),
                Value::Number(Number::PosInt(1_900_000_000)),
            ),
            ("chain_id".to_string(), Value::Number(Number::PosInt(1))),
            (
                "registry_address".to_string(),
                Value::String("0x1234567890123456789012345678901234567890".to_string()),
            ),
            ("root_keys".to_string(), Value::Array(keys)),
            (
                "root_threshold".to_string(),
                Value::Number(Number::PosInt(u64::from(threshold))),
            ),
            ("bundle_signers".to_string(), Value::Array(signers)),
            (
                "bundle_threshold".to_string(),
                Value::Number(Number::PosInt(u64::from(threshold))),
            ),
        ])
    }

    #[test]
    fn nominal_root_is_parsed() {
        let root = TrustRoot::from_payload(&root_payload(1, 1, 2)).expect("root");
        assert_eq!(root.framework_id(), "pip-global");
        assert_eq!(root.root_keys().len(), 3);
        assert_eq!(root.bundle_signers().len(), 3);
        assert_eq!(root.root_threshold(), 2);
        assert!(root.contains(UnixTime::from_seconds(1_750_000_000)));
        assert!(!root.contains(UnixTime::from_seconds(1_699_000_000)));
    }

    #[test]
    fn thresholds_outside_one_to_n_are_rejected() {
        // Umbral 0.
        let mut payload = root_payload(1, 1, 2);
        if let Value::Object(entries) = &mut payload {
            for (key, value) in entries.iter_mut() {
                if key == "root_threshold" {
                    *value = Value::Number(Number::PosInt(0));
                }
            }
        }
        let error = TrustRoot::from_payload(&payload).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedSdJwt);

        // Umbral mayor que el número de claves.
        let mut payload = root_payload(1, 1, 2);
        if let Value::Object(entries) = &mut payload {
            for (key, value) in entries.iter_mut() {
                if key == "bundle_threshold" {
                    *value = Value::Number(Number::PosInt(4));
                }
            }
        }
        let error = TrustRoot::from_payload(&payload).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedSdJwt);
    }

    #[test]
    fn forces_new_epoch_detects_a_forced_recovery() {
        let current = TrustRoot::from_payload(&root_payload(1, 1, 2)).expect("root");
        let candidate = TrustRoot::from_payload(&root_payload(2, 2, 2)).expect("root");
        assert!(TrustRootVerifier::forces_new_epoch(&current, &candidate));

        let same_epoch = TrustRoot::from_payload(&root_payload(2, 1, 2)).expect("root");
        assert!(!TrustRootVerifier::forces_new_epoch(&current, &same_epoch));
    }
}
