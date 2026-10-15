//! Trust bundle multi-firma (F4.T03, `TRUST_BUNDLE.md` §3 y §5).
//!
//! El bundle es la proyección determinista del registro on-chain: qué emisores y claves
//! son válidos, con qué perfiles y `vct`, y en qué estado está cada clave. Se cofirma por
//! un umbral k-de-n de operadores distintos y el cliente lo acepta solo si supera el
//! anti-rollback por `(bundle_epoch, bundle_version)`.
//!
//! Trazabilidad:
//! - **REQ-TRUST-001:** cofirma k-de-n de firmantes distintos, versión monotónica y
//!   ventana de validez.
//! - **REQ-TRUST-002:** rechazo de `(bundle_epoch, bundle_version)` inferior al aceptado.
//! - **REQ-TRUST-010:** el bundle no contiene punteros ni hashes de listas de estado.
//! - **REQ-KEY-005 / REQ-KEY-006:** estados de clave de emisor y vigencia de credenciales
//!   emitidas antes del retiro.
//! - **INV-16:** umbral de firmantes distintos; nunca una clave única.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use gravital_id_codec::json::{Number, Value};
use gravital_id_crypto::JwkEcP256;
use gravital_id_types::{ErrorCode, GidError, Kid, UnixTime};

use crate::jws_json::{JwsJsonParser, MultiSignedJws};

/// Tamaño máximo del documento del bundle (`TRUST_BUNDLE.md` §8, REQ-VER-008).
pub const MAX_BUNDLE_BYTES: usize = 512 * 1024;

/// Número máximo de emisores por bundle (`TRUST_BUNDLE.md` §8).
pub const MAX_ISSUERS_PER_BUNDLE: usize = 1_000;

/// Número máximo de claves activas por emisor (`TRUST_BUNDLE.md` §8).
pub const MAX_KEYS_PER_ISSUER: usize = 16;

/// Estado administrativo de un emisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerState {
    /// Emisor plenamente autorizado.
    Active,
    /// Suspensión administrativa temporal.
    Suspended,
}

impl IssuerState {
    /// Interpreta el estado declarado en el bundle.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedSdJwt`] si el estado no es uno de los definidos.
    pub fn parse(value: &str) -> Result<Self, GidError> {
        match value {
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            other => Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("unknown issuer state '{other}'"),
            )),
        }
    }

    /// Nombre canónico del estado.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }

    /// Comprueba si el emisor está administrativamente activo.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Comprueba si el emisor está administrativamente suspendido.
    #[must_use]
    pub const fn is_suspended(&self) -> bool {
        matches!(self, Self::Suspended)
    }
}

/// Estado de una clave de emisor (`ARCHITECTURE.md §11.6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// Clave plenamente vigente.
    Active,
    /// Retirada ordenadamente desde `state_since`.
    Retired,
    /// En revisión técnica o presuntamente comprometida.
    Suspended,
    /// Comprometida de forma irrevocable.
    Compromised,
}

impl KeyState {
    /// Interpreta el estado declarado en el bundle.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedSdJwt`] si el estado no es uno de los definidos.
    pub fn parse(value: &str) -> Result<Self, GidError> {
        match value {
            "active" => Ok(Self::Active),
            "retired" => Ok(Self::Retired),
            "suspended" => Ok(Self::Suspended),
            "compromised" => Ok(Self::Compromised),
            other => Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("unknown key state '{other}'"),
            )),
        }
    }

    /// Nombre canónico del estado.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Suspended => "suspended",
            Self::Compromised => "compromised",
        }
    }

    /// Comprueba si la clave está activa.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Comprueba si la clave está retirada.
    #[must_use]
    pub const fn is_retired(&self) -> bool {
        matches!(self, Self::Retired)
    }

    /// Comprueba si la clave está suspendida.
    #[must_use]
    pub const fn is_suspended(&self) -> bool {
        matches!(self, Self::Suspended)
    }

    /// Comprueba si la clave está comprometida.
    #[must_use]
    pub const fn is_compromised(&self) -> bool {
        matches!(self, Self::Compromised)
    }
}

/// Clave de emisor declarada en el bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerKey {
    /// Identificador de la clave.
    pub kid: Kid,
    /// Clave pública.
    pub jwk: JwkEcP256,
    /// Estado de la clave.
    pub state: KeyState,
    /// Instante desde el que aplica el estado.
    pub state_since: UnixTime,
}

impl IssuerKey {
    /// Indica si la clave podía firmar válidamente en el instante dado.
    ///
    /// `Retired` solo admite credenciales emitidas antes del retiro (REQ-KEY-006);
    /// `Suspended` y `Compromised` nunca admiten firma válida nueva.
    #[must_use]
    pub fn could_sign_at(&self, at: UnixTime) -> bool {
        match self.state {
            KeyState::Active => true,
            KeyState::Retired => at.as_seconds() < self.state_since.as_seconds(),
            KeyState::Suspended | KeyState::Compromised => false,
        }
    }

    /// Comprueba si la clave está activa.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.state.is_active()
    }

    /// Comprueba si la clave está retirada.
    #[must_use]
    pub const fn is_retired(&self) -> bool {
        self.state.is_retired()
    }

    /// Comprueba si la clave está suspendida.
    #[must_use]
    pub const fn is_suspended(&self) -> bool {
        self.state.is_suspended()
    }

    /// Comprueba si la clave está comprometida.
    #[must_use]
    pub const fn is_compromised(&self) -> bool {
        self.state.is_compromised()
    }
}

/// Clave de estado de un emisor (firma sus listas y su manifiesto).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusKey {
    /// Identificador de la clave.
    pub kid: String,
    /// Clave pública.
    pub jwk: JwkEcP256,
}

/// Emisor registrado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerEntry {
    /// Identador del emisor.
    pub issuer_id: String,
    /// Perfiles que puede emitir.
    pub profiles: Vec<String>,
    /// Tipos de credencial que puede emitir.
    pub vcts: Vec<String>,
    /// Inicio de vigencia del registro.
    pub valid_from: UnixTime,
    /// Fin de vigencia del registro.
    pub valid_until: Option<UnixTime>,
    /// Estado administrativo.
    pub state: IssuerState,
    /// Claves de estado del emisor.
    pub status_keys: Vec<StatusKey>,
    /// Claves de firma del emisor.
    pub keys: Vec<IssuerKey>,
}

impl IssuerEntry {
    /// Busca una clave de firma del emisor por su `kid`.
    #[must_use]
    pub fn find_key(&self, kid: &str) -> Option<&IssuerKey> {
        self.keys.iter().find(|key| key.kid.as_str() == kid)
    }
}

/// Verificador registrado (opcional por perfil, REQ-TRUST-007).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierEntry {
    /// Identificador del verificador.
    pub verifier_id: String,
    /// Perfiles para los que está registrado.
    pub profiles: Vec<String>,
    /// Inicio de vigencia.
    pub valid_from: UnixTime,
    /// Fin de vigencia.
    pub valid_until: Option<UnixTime>,
}

/// Política de perfico referenciada por el bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEntry {
    /// Identificador del perfil.
    pub profile_id: String,
    /// Versión de la política.
    pub version: String,
    /// Hash de la política.
    pub policy_hash: String,
}

/// Trust bundle parseado.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustBundle {
    framework_id: String,
    bundle_epoch: u64,
    bundle_version: u64,
    chain_id: u64,
    registry_address: String,
    finalized_block_number: u64,
    finalized_block_hash: String,
    issued_at: UnixTime,
    valid_until: UnixTime,
    issuers: Vec<IssuerEntry>,
    verifiers: Vec<VerifierEntry>,
    policies: Vec<PolicyEntry>,
}

impl TrustBundle {
    /// Identificador del marco de confianza.
    #[must_use]
    pub fn framework_id(&self) -> &str {
        &self.framework_id
    }

    /// Época del bundle.
    #[must_use]
    pub fn bundle_epoch(&self) -> u64 {
        self.bundle_epoch
    }

    /// Versión del bundle (monótona dentro de la época).
    #[must_use]
    pub fn bundle_version(&self) -> u64 {
        self.bundle_version
    }

    /// Cadena blockchain de origen.
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Dirección del contrato de registro.
    #[must_use]
    pub fn registry_address(&self) -> &str {
        &self.registry_address
    }

    /// Número de bloque finalizado del que deriva.
    #[must_use]
    pub fn finalized_block_number(&self) -> u64 {
        self.finalized_block_number
    }

    /// Hash del bloque finalizado.
    #[must_use]
    pub fn finalized_block_hash(&self) -> &str {
        &self.finalized_block_hash
    }

    /// Instante de emisión del bundle.
    #[must_use]
    pub fn issued_at(&self) -> UnixTime {
        self.issued_at
    }

    /// Instante de expiración del bundle.
    #[must_use]
    pub fn valid_until(&self) -> UnixTime {
        self.valid_until
    }

    /// Emisores registrados.
    #[must_use]
    pub fn issuers(&self) -> &[IssuerEntry] {
        &self.issuers
    }

    /// Verificadores registrados.
    #[must_use]
    pub fn verifiers(&self) -> &[VerifierEntry] {
        &self.verifiers
    }

    /// Políticas referenciadas.
    #[must_use]
    pub fn policies(&self) -> &[PolicyEntry] {
        &self.policies
    }

    /// Busca un emisor por su identificador.
    #[must_use]
    pub fn issuer(&self, issuer_id: &str) -> Option<&IssuerEntry> {
        self.issuers
            .iter()
            .find(|issuer| issuer.issuer_id == issuer_id)
    }

    /// Busca una clave de emisor por su `kid`.
    #[must_use]
    pub fn issuer_key(&self, kid: &str) -> Option<(&IssuerEntry, &IssuerKey)> {
        self.issuers.iter().find_map(|issuer| {
            issuer
                .keys
                .iter()
                .find(|key| key.kid.as_str() == kid)
                .map(|key| (issuer, key))
        })
    }

    /// Ventana de vigencia del bundle.
    #[must_use]
    pub fn contains(&self, now: UnixTime) -> bool {
        now.as_seconds() >= self.issued_at.as_seconds()
            && now.as_seconds() <= self.valid_until.as_seconds()
    }

    /// Construye el bundle a partir del payload JSON.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedSdJwt`] ante cualquier incumplimiento de formato o de límites.
    pub fn from_payload(payload: &Value) -> Result<Self, GidError> {
        let framework_id = str_field(payload, "framework_id")?;
        let bundle_epoch = u64_field(payload, "bundle_epoch")?;
        let bundle_version = u64_field(payload, "bundle_version")?;
        let chain_id = u64_field(payload, "chain_id")?;
        let registry_address = str_field(payload, "registry_address")?;
        let finalized_block_number = u64_field(payload, "finalized_block_number")?;
        let finalized_block_hash = str_field(payload, "finalized_block_hash")?;
        let issued_at = UnixTime::from_seconds(u64_field(payload, "issued_at")?);
        let valid_until = UnixTime::from_seconds(u64_field(payload, "valid_until")?);
        if valid_until.as_seconds() < issued_at.as_seconds() {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "bundle 'valid_until' is before 'issued_at'",
            ));
        }

        let issuers = parse_issuers(payload)?;
        let verifiers = parse_verifiers(payload)?;
        let policies = parse_policies(payload)?;

        Ok(Self {
            framework_id: framework_id.to_string(),
            bundle_epoch,
            bundle_version,
            chain_id,
            registry_address: registry_address.to_string(),
            finalized_block_number,
            finalized_block_hash: finalized_block_hash.to_string(),
            issued_at,
            valid_until,
            issuers,
            verifiers,
            policies,
        })
    }

    /// Parsea el documento JWS multi-firma del bundle.
    pub fn parse(document: &str) -> Result<(Self, MultiSignedJws), GidError> {
        if document.len() > MAX_BUNDLE_BYTES {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!(
                    "bundle size {} exceeds the limit of {MAX_BUNDLE_BYTES} bytes",
                    document.len()
                ),
            ));
        }
        let jws = JwsJsonParser::parse(document)?;
        let bundle = Self::from_payload(&jws.payload)?;
        Ok((bundle, jws))
    }
}

/// Verificador del trust bundle (umbral, anti-rollback y vigencia).
pub struct TrustBundleVerifier;

/// Estado aceptado por el cliente, para el anti-rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedBundleState {
    /// Época aceptada.
    pub bundle_epoch: u64,
    /// Versión aceptada.
    pub bundle_version: u64,
}

impl TrustBundleVerifier {
    /// Verifica un bundle completo contra la raíz activa.
    ///
    /// Comprueba, en el orden de `TRUST_BUNDLE.md` §5: marco y época, anti-rollback,
    /// umbral k-de-n de firmantes distintos y ventana de validez.
    ///
    /// # Errores
    /// - [`ErrorCode::MalformedSdJwt`]: marco o época incompatibles.
    /// - [`ErrorCode::BundleVersionRollback`]: versión no creciente (REQ-TRUST-002).
    /// - [`ErrorCode::InsufficientBundleSignatures`]: umbral no alcanzado (INV-16).
    /// - [`ErrorCode::StatusListExpired`]: bundle fuera de vigencia.
    pub fn verify(
        bundle: &TrustBundle,
        jws: &MultiSignedJws,
        root: &crate::TrustRoot,
        accepted: Option<AcceptedBundleState>,
        now: UnixTime,
    ) -> Result<(), GidError> {
        // 2. Marco y época.
        if bundle.framework_id() != root.framework_id() {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "bundle 'framework_id' does not match the trust root",
            ));
        }
        if bundle.bundle_epoch() != root.bundle_epoch() {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!(
                    "bundle epoch {} does not match the active root epoch {}",
                    bundle.bundle_epoch(),
                    root.bundle_epoch()
                ),
            ));
        }

        // 3. Anti-rollback por (época, versión).
        if let Some(accepted) = accepted {
            if bundle.bundle_version() <= accepted.bundle_version {
                return Err(GidError::new(
                    ErrorCode::BundleVersionRollback,
                    format!(
                        "bundle version {} is not newer than the accepted version {}",
                        bundle.bundle_version(),
                        accepted.bundle_version
                    ),
                ));
            }
        }

        // 4. Umbral k-de-n de firmantes distintos.
        let verified = jws
            .verified_kids(|kid| root.bundle_signer(kid).map(|signer| signer.jwk.clone()))
            .map_err(|e| {
                GidError::new(
                    ErrorCode::InsufficientBundleSignatures,
                    format!("invalid signature in bundle: {e}"),
                )
            })?;
        let distinct_operators = count_distinct_operators(root, &verified);
        if distinct_operators < root.bundle_threshold() {
            return Err(GidError::new(
                ErrorCode::InsufficientBundleSignatures,
                format!(
                    "bundle carries {distinct_operators} valid signatures from distinct operators, {} required",
                    root.bundle_threshold()
                ),
            ));
        }

        // 5. Ventana de validez.
        if !bundle.contains(now) {
            return Err(GidError::new(
                ErrorCode::StatusListExpired,
                "bundle is outside its validity window",
            ));
        }

        Ok(())
    }

    /// Comprueba el anti-rollback de forma aislada (REQ-TRUST-002).
    ///
    /// # Errores
    /// [`ErrorCode::BundleVersionRollback`] si la versión no es estrictamente mayor.
    pub fn check_anti_rollback(
        bundle: &TrustBundle,
        accepted: Option<AcceptedBundleState>,
    ) -> Result<(), GidError> {
        if let Some(accepted) = accepted {
            if bundle.bundle_version() <= accepted.bundle_version {
                return Err(GidError::new(
                    ErrorCode::BundleVersionRollback,
                    format!(
                        "bundle version {} is not newer than the accepted version {}",
                        bundle.bundle_version(),
                        accepted.bundle_version
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// Cuenta firmantes distintos que han verificado (por `kid` único).
fn count_distinct_operators(root: &crate::TrustRoot, verified_kids: &[String]) -> u32 {
    let mut count = 0u32;
    for kid in verified_kids {
        if root.bundle_signer(kid).is_some() {
            count = count.saturating_add(1);
        }
    }
    count
}

/// Lee un campo de texto obligatorio.
fn str_field<'a>(payload: &'a Value, name: &str) -> Result<&'a str, GidError> {
    payload.member(name).and_then(Value::as_str).ok_or_else(|| {
        GidError::new(
            ErrorCode::MalformedSdJwt,
            format!("bundle missing string field '{name}'"),
        )
    })
}

/// Lee un campo entero sin signo obligatorio.
fn u64_field(payload: &Value, name: &str) -> Result<u64, GidError> {
    match payload.member(name) {
        Some(Value::Number(Number::PosInt(value))) => Ok(*value),
        _ => Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            format!("bundle missing integer field '{name}'"),
        )),
    }
}

/// Lee un campo entero opcional como instante.
fn optional_time(payload: &Value, name: &str) -> Result<Option<UnixTime>, GidError> {
    match payload.member(name) {
        Some(Value::Number(Number::PosInt(value))) => Ok(Some(UnixTime::from_seconds(*value))),
        Some(_) => Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            format!("bundle field '{name}' must be a positive integer"),
        )),
        None => Ok(None),
    }
}

/// Lee un array de textos obligatorio.
fn string_array(entry: &Value, name: &str) -> Result<Vec<String>, GidError> {
    match entry.member(name) {
        Some(Value::Array(values)) => {
            let mut out = Vec::with_capacity(values.len());
            for value in values {
                let text = value.as_str().ok_or_else(|| {
                    GidError::new(
                        ErrorCode::MalformedSdJwt,
                        format!("'{name}' must contain only strings"),
                    )
                })?;
                out.push(text.to_string());
            }
            Ok(out)
        }
        _ => Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            format!("missing string array '{name}'"),
        )),
    }
}

/// Parseo de `issuers`.
fn parse_issuers(payload: &Value) -> Result<Vec<IssuerEntry>, GidError> {
    let Some(Value::Array(entries)) = payload.member("issuers") else {
        return Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            "bundle missing the 'issuers' array",
        ));
    };
    if entries.len() > MAX_ISSUERS_PER_BUNDLE {
        return Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            format!(
                "bundle declares {} issuers, above the limit of {MAX_ISSUERS_PER_BUNDLE}",
                entries.len()
            ),
        ));
    }

    let mut issuers = Vec::with_capacity(entries.len());
    for entry in entries {
        let issuer_id = entry
            .member("issuer_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                GidError::new(
                    ErrorCode::MalformedSdJwt,
                    "issuer entry missing 'issuer_id'",
                )
            })?
            .to_string();
        let profiles = string_array(entry, "profiles")?;
        let vcts = string_array(entry, "vcts")?;
        let valid_from = UnixTime::from_seconds(u64_field(entry, "valid_from")?);
        let valid_until = optional_time(entry, "valid_until")?;
        let state = IssuerState::parse(entry.member("state").and_then(Value::as_str).ok_or_else(
            || {
                GidError::new(
                    ErrorCode::MalformedSdJwt,
                    format!("issuer '{issuer_id}' missing 'state'"),
                )
            },
        )?)?;

        let status_keys = parse_status_keys(entry)?;
        let keys = parse_issuer_keys(entry)?;
        if keys.is_empty() {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("issuer '{issuer_id}' declares no keys"),
            ));
        }

        issuers.push(IssuerEntry {
            issuer_id,
            profiles,
            vcts,
            valid_from,
            valid_until,
            state,
            status_keys,
            keys,
        });
    }
    Ok(issuers)
}

/// Parseo de `status_keys` de un emisor.
fn parse_status_keys(entry: &Value) -> Result<Vec<StatusKey>, GidError> {
    let Some(Value::Array(entries)) = entry.member("status_keys") else {
        return Ok(Vec::new());
    };
    let mut keys = Vec::with_capacity(entries.len());
    for key_entry in entries {
        let kid = key_entry
            .member("kid")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                GidError::new(ErrorCode::MalformedSdJwt, "status key entry missing 'kid'")
            })?
            .to_string();
        let jwk_value = key_entry.member("jwk").ok_or_else(|| {
            GidError::new(ErrorCode::MalformedSdJwt, "status key entry missing 'jwk'")
        })?;
        let jwk = JwkEcP256::parse(&crate::to_canonical_json(jwk_value)).map_err(|e| {
            GidError::new(
                ErrorCode::InvalidKeyFormat,
                format!("invalid status key jwk: {e}"),
            )
        })?;
        keys.push(StatusKey { kid, jwk });
    }
    Ok(keys)
}

/// Parseo de `keys` de un emisor.
fn parse_issuer_keys(entry: &Value) -> Result<Vec<IssuerKey>, GidError> {
    let Some(Value::Array(entries)) = entry.member("keys") else {
        return Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            "issuer entry missing the 'keys' array",
        ));
    };
    if entries.len() > MAX_KEYS_PER_ISSUER {
        return Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            format!(
                "issuer declares {} keys, above the limit of {MAX_KEYS_PER_ISSUER}",
                entries.len()
            ),
        ));
    }
    let mut keys = Vec::with_capacity(entries.len());
    let mut seen: Vec<String> = Vec::new();
    for key_entry in entries {
        let kid = key_entry
            .member("kid")
            .and_then(Value::as_str)
            .ok_or_else(|| GidError::new(ErrorCode::MalformedSdJwt, "issuer key missing 'kid'"))?;
        let kid = Kid::parse(kid).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("invalid issuer key kid: {e}"),
            )
        })?;
        if seen.iter().any(|other| other == kid.as_str()) {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("duplicate issuer key kid '{}'", kid.as_str()),
            ));
        }
        seen.push(kid.as_str().to_string());

        let jwk_value = key_entry.member("jwk").ok_or_else(|| {
            GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("issuer key '{}' missing 'jwk'", kid.as_str()),
            )
        })?;
        let jwk = JwkEcP256::parse(&crate::to_canonical_json(jwk_value)).map_err(|e| {
            GidError::new(
                ErrorCode::InvalidKeyFormat,
                format!("invalid issuer key jwk: {e}"),
            )
        })?;
        let state = KeyState::parse(
            key_entry
                .member("state")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    GidError::new(
                        ErrorCode::MalformedSdJwt,
                        format!("issuer key '{}' missing 'state'", kid.as_str()),
                    )
                })?,
        )?;
        let state_since = UnixTime::from_seconds(u64_field(key_entry, "state_since")?);

        keys.push(IssuerKey {
            kid,
            jwk,
            state,
            state_since,
        });
    }
    Ok(keys)
}

/// Parseo de `verifiers`.
fn parse_verifiers(payload: &Value) -> Result<Vec<VerifierEntry>, GidError> {
    let Some(Value::Array(entries)) = payload.member("verifiers") else {
        return Ok(Vec::new());
    };
    let mut verifiers = Vec::with_capacity(entries.len());
    for entry in entries {
        verifiers.push(VerifierEntry {
            verifier_id: entry
                .member("verifier_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    GidError::new(
                        ErrorCode::MalformedSdJwt,
                        "verifier entry missing 'verifier_id'",
                    )
                })?
                .to_string(),
            profiles: string_array(entry, "profiles")?,
            valid_from: UnixTime::from_seconds(u64_field(entry, "valid_from")?),
            valid_until: optional_time(entry, "valid_until")?,
        });
    }
    Ok(verifiers)
}

/// Parseo de `policies`.
fn parse_policies(payload: &Value) -> Result<Vec<PolicyEntry>, GidError> {
    let Some(Value::Array(entries)) = payload.member("policies") else {
        return Ok(Vec::new());
    };
    let mut policies = Vec::with_capacity(entries.len());
    for entry in entries {
        policies.push(PolicyEntry {
            profile_id: entry
                .member("profile_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    GidError::new(
                        ErrorCode::MalformedSdJwt,
                        "policy entry missing 'profile_id'",
                    )
                })?
                .to_string(),
            version: entry
                .member("version")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    GidError::new(ErrorCode::MalformedSdJwt, "policy entry missing 'version'")
                })?
                .to_string(),
            policy_hash: entry
                .member("policy_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    GidError::new(
                        ErrorCode::MalformedSdJwt,
                        "policy entry missing 'policy_hash'",
                    )
                })?
                .to_string(),
        });
    }
    Ok(policies)
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
    use gravital_id_keys::{IssuerSigning, KeyStore, SoftwareKeyStore};
    use gravital_id_testkit::SeededRng;

    fn jwk_value(
        store: &mut SoftwareKeyStore<SeededRng>,
        kid: &str,
        state: &str,
        since: u64,
    ) -> Value {
        let handle = store.generate_key::<IssuerSigning>().expect("key");
        let jwk = store.public_key(&handle).expect("jwk");
        Value::Object(vec![
            ("kid".to_string(), Value::String(kid.to_string())),
            ("jwk".to_string(), crate::json_value_of(&jwk)),
            ("state".to_string(), Value::String(state.to_string())),
            (
                "state_since".to_string(),
                Value::Number(Number::PosInt(since)),
            ),
        ])
    }

    fn bundle_payload(version: u64, epoch: u64) -> Value {
        let mut store = SoftwareKeyStore::new(SeededRng::new(5));
        let keys = vec![
            jwk_value(&mut store, "iss-key-1", "active", 0),
            jwk_value(&mut store, "iss-key-2", "retired", 1_800_000_000),
        ];
        let status_handle = store.generate_key::<IssuerSigning>().expect("status key");
        let status_jwk = store.public_key(&status_handle).expect("status jwk");
        let status_keys = Value::Array(vec![Value::Object(vec![
            ("kid".to_string(), Value::String("status-1".to_string())),
            ("jwk".to_string(), crate::json_value_of(&status_jwk)),
        ])]);

        Value::Object(vec![
            (
                "framework_id".to_string(),
                Value::String("pip-global".to_string()),
            ),
            (
                "bundle_epoch".to_string(),
                Value::Number(Number::PosInt(epoch)),
            ),
            (
                "bundle_version".to_string(),
                Value::Number(Number::PosInt(version)),
            ),
            ("chain_id".to_string(), Value::Number(Number::PosInt(1))),
            (
                "registry_address".to_string(),
                Value::String("0xabc".to_string()),
            ),
            (
                "finalized_block_number".to_string(),
                Value::Number(Number::PosInt(21_890_450)),
            ),
            (
                "finalized_block_hash".to_string(),
                Value::String("0x4a8f".to_string()),
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
                "issuers".to_string(),
                Value::Array(vec![Value::Object(vec![
                    (
                        "issuer_id".to_string(),
                        Value::String("iss-example".to_string()),
                    ),
                    (
                        "profiles".to_string(),
                        Value::Array(vec![Value::String("pip-personal-v1".to_string())]),
                    ),
                    (
                        "vcts".to_string(),
                        Value::Array(vec![Value::String(
                            "https://credentials.example/vct/1".to_string(),
                        )]),
                    ),
                    (
                        "valid_from".to_string(),
                        Value::Number(Number::PosInt(1_700_000_000)),
                    ),
                    ("state".to_string(), Value::String("active".to_string())),
                    ("status_keys".to_string(), status_keys),
                    ("keys".to_string(), Value::Array(keys)),
                ])]),
            ),
            ("verifiers".to_string(), Value::Array(vec![])),
            (
                "policies".to_string(),
                Value::Array(vec![Value::Object(vec![
                    (
                        "profile_id".to_string(),
                        Value::String("pip-personal-v1".to_string()),
                    ),
                    ("version".to_string(), Value::String("1.0.0".to_string())),
                    ("policy_hash".to_string(), Value::String("ab".to_string())),
                ])]),
            ),
        ])
    }

    #[test]
    fn nominal_bundle_is_parsed() {
        let bundle = TrustBundle::from_payload(&bundle_payload(1_420, 1)).expect("bundle");
        assert_eq!(bundle.issuers().len(), 1);
        let issuer = bundle.issuer("iss-example").expect("issuer");
        assert_eq!(issuer.keys.len(), 2);
        assert_eq!(issuer.keys[0].state, KeyState::Active);
        assert_eq!(issuer.keys[1].state, KeyState::Retired);
        assert_eq!(issuer.status_keys.len(), 1);

        // REQ-KEY-006: la clave retirada solo valida credenciales anteriores al retiro.
        assert!(issuer.keys[1].could_sign_at(UnixTime::from_seconds(1_700_000_000)));
        assert!(!issuer.keys[1].could_sign_at(UnixTime::from_seconds(1_800_000_001)));

        // Búsqueda por kid.
        assert!(bundle.issuer_key("iss-key-1").is_some());
        assert!(bundle.issuer_key("iss-key-9").is_none());
        assert_eq!(bundle.policies().len(), 1);
    }

    #[test]
    fn unknown_key_states_are_rejected() {
        let mut payload = bundle_payload(1, 1);
        if let Value::Object(entries) = &mut payload {
            for (key, value) in entries.iter_mut() {
                if key == "issuers" {
                    if let Value::Array(issuers) = value {
                        if let Some(Value::Object(issuer)) = issuers.first_mut() {
                            for (issuer_key, issuer_value) in issuer.iter_mut() {
                                if issuer_key == "keys" {
                                    if let Value::Array(keys) = issuer_value {
                                        if let Some(Value::Object(key_entry)) = keys.first_mut() {
                                            for (k, v) in key_entry.iter_mut() {
                                                if k == "state" {
                                                    *v = Value::String("revocado".to_string());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let error = TrustBundle::from_payload(&payload).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedSdJwt);
    }

    #[test]
    fn anti_rollback_requires_a_newer_version() {
        let bundle = TrustBundle::from_payload(&bundle_payload(10, 1)).expect("bundle");
        let accepted = AcceptedBundleState {
            bundle_epoch: 1,
            bundle_version: 10,
        };
        let error = TrustBundleVerifier::check_anti_rollback(&bundle, Some(accepted)).unwrap_err();
        assert_eq!(error.code, ErrorCode::BundleVersionRollback);

        let newer = TrustBundle::from_payload(&bundle_payload(11, 1)).expect("bundle");
        TrustBundleVerifier::check_anti_rollback(&newer, Some(accepted)).expect("versión nueva");
        TrustBundleVerifier::check_anti_rollback(&newer, None).expect("sin estado previo");
    }

    #[test]
    fn bundle_without_issuer_keys_is_rejected() {
        let mut payload = bundle_payload(1, 1);
        if let Value::Object(entries) = &mut payload {
            for (key, value) in entries.iter_mut() {
                if key == "issuers" {
                    if let Value::Array(issuers) = value {
                        if let Some(Value::Object(issuer)) = issuers.first_mut() {
                            for (issuer_key, issuer_value) in issuer.iter_mut() {
                                if issuer_key == "keys" {
                                    *issuer_value = Value::Array(vec![]);
                                }
                            }
                        }
                    }
                }
            }
        }
        let error = TrustBundle::from_payload(&payload).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedSdJwt);
    }

    #[test]
    fn bundle_contains_no_status_list_pointers() {
        // REQ-TRUST-010: el bundle no debe declarar listas de estado.
        let payload = bundle_payload(1, 1);
        let text = crate::to_canonical_json(&payload).to_lowercase();
        assert!(!text.contains("status_lists"));
        assert!(!text.contains("status_uri"));
        assert!(!text.contains("list_uri"));
    }

    #[test]
    fn key_state_semantics_all_variants_and_predicates() {
        // REQ-KEY-005, ARCHITECTURE.md §11.6
        let active = KeyState::parse("active").expect("active");
        assert_eq!(active, KeyState::Active);
        assert_eq!(active.as_str(), "active");
        assert!(active.is_active());
        assert!(!active.is_retired());
        assert!(!active.is_suspended());
        assert!(!active.is_compromised());

        let retired = KeyState::parse("retired").expect("retired");
        assert_eq!(retired, KeyState::Retired);
        assert_eq!(retired.as_str(), "retired");
        assert!(!retired.is_active());
        assert!(retired.is_retired());
        assert!(!retired.is_suspended());
        assert!(!retired.is_compromised());

        let suspended = KeyState::parse("suspended").expect("suspended");
        assert_eq!(suspended, KeyState::Suspended);
        assert_eq!(suspended.as_str(), "suspended");
        assert!(!suspended.is_active());
        assert!(!suspended.is_retired());
        assert!(suspended.is_suspended());
        assert!(!suspended.is_compromised());

        let compromised = KeyState::parse("compromised").expect("compromised");
        assert_eq!(compromised, KeyState::Compromised);
        assert_eq!(compromised.as_str(), "compromised");
        assert!(!compromised.is_active());
        assert!(!compromised.is_retired());
        assert!(!compromised.is_suspended());
        assert!(compromised.is_compromised());

        let err = KeyState::parse("invalid_state").unwrap_err();
        assert_eq!(err.code, ErrorCode::MalformedSdJwt);
    }

    #[test]
    fn issuer_state_semantics_and_predicates() {
        let active = IssuerState::parse("active").expect("active");
        assert_eq!(active, IssuerState::Active);
        assert_eq!(active.as_str(), "active");
        assert!(active.is_active());
        assert!(!active.is_suspended());

        let suspended = IssuerState::parse("suspended").expect("suspended");
        assert_eq!(suspended, IssuerState::Suspended);
        assert_eq!(suspended.as_str(), "suspended");
        assert!(!suspended.is_active());
        assert!(suspended.is_suspended());

        let err = IssuerState::parse("banned").unwrap_err();
        assert_eq!(err.code, ErrorCode::MalformedSdJwt);
    }

    #[test]
    fn issuer_key_could_sign_at_all_states() {
        // REQ-KEY-005, REQ-KEY-006:
        // - active: siempre true
        // - retired: true estrictamente si at < state_since
        // - suspended: siempre false
        // - compromised: siempre false
        let kid = Kid::parse("k1").expect("kid");
        let mut store = SoftwareKeyStore::new(SeededRng::new(42));
        let handle = store.generate_key::<IssuerSigning>().expect("key");
        let jwk = store.public_key(&handle).expect("jwk");
        let state_since = UnixTime::from_seconds(1_000_000);

        let active_key = IssuerKey {
            kid: kid.clone(),
            jwk: jwk.clone(),
            state: KeyState::Active,
            state_since,
        };
        assert!(active_key.is_active());
        assert!(active_key.could_sign_at(UnixTime::from_seconds(500_000)));
        assert!(active_key.could_sign_at(UnixTime::from_seconds(1_000_000)));
        assert!(active_key.could_sign_at(UnixTime::from_seconds(2_000_000)));

        let retired_key = IssuerKey {
            kid: kid.clone(),
            jwk: jwk.clone(),
            state: KeyState::Retired,
            state_since,
        };
        assert!(retired_key.is_retired());
        assert!(retired_key.could_sign_at(UnixTime::from_seconds(999_999)));
        assert!(!retired_key.could_sign_at(UnixTime::from_seconds(1_000_000)));
        assert!(!retired_key.could_sign_at(UnixTime::from_seconds(1_000_001)));

        let suspended_key = IssuerKey {
            kid: kid.clone(),
            jwk: jwk.clone(),
            state: KeyState::Suspended,
            state_since,
        };
        assert!(suspended_key.is_suspended());
        assert!(!suspended_key.could_sign_at(UnixTime::from_seconds(500_000)));
        assert!(!suspended_key.could_sign_at(UnixTime::from_seconds(1_000_000)));
        assert!(!suspended_key.could_sign_at(UnixTime::from_seconds(2_000_000)));

        let compromised_key = IssuerKey {
            kid,
            jwk,
            state: KeyState::Compromised,
            state_since,
        };
        assert!(compromised_key.is_compromised());
        assert!(!compromised_key.could_sign_at(UnixTime::from_seconds(500_000)));
        assert!(!compromised_key.could_sign_at(UnixTime::from_seconds(1_000_000)));
        assert!(!compromised_key.could_sign_at(UnixTime::from_seconds(2_000_000)));
    }
}
