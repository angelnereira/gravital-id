//! Capa SD-JWT VC según `draft-ietf-oauth-sd-jwt-vc-19` (F3.T05).
//!
//! Trazabilidad:
//! - **REQ-CRED-001:** El formato v1 DEBE ser SD-JWT VC sobre RFC 9901 con tipo `dc+sd-jwt`.
//! - **REQ-CRED-007:** Toda credencial DEBE incluir referencia de estado (`status`),
//!   salvo perfiles que lo excluyan explícitamente para credenciales de vida corta.
//! - **REQ-CRED-008:** Se DEBEN rechazar algoritmos fuera de la lista del perfil, incluido `none`.
//! - **REQ-VER-003:** Fail-closed ante cualquier error, dato faltante o ambigüedad.
//! - **INV-08:** Algoritmo ES256 obligatorio; `alg: none` siempre rechazado.
//! - **INV-11:** Verificación temporal con reloj inyectado (`UnixTime`).
//! - **ARCHITECTURE.md §8.2:** los claims `iss`, `vct`, `iat`, `nbf`, `exp`, `cnf` y `status`
//!   son siempre visibles; solo los atributos y predicados del perfil se divulgan selectivamente.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use gravital_id_codec::json::{parse_bytes, Limits as JsonLimits, Number, Value};
use gravital_id_crypto::{JwkEcP256, Rng};
use gravital_id_keys::{KeyHandle, KeyStore, SigningPurpose};
use gravital_id_types::{ErrorCode, GidError, Kid, ProfileId, UnixTime, Vct};

use crate::issuer::{IssuedSdJwt, JwsHeader, SdIssuer, SdObjectBuilder};
use crate::json_canonical::to_canonical_json;
use crate::profile::ProfileSchema;
use crate::salt::Salt;

/// Tipo de token normativo para SD-JWT VC (draft-ietf-oauth-sd-jwt-vc-19 §3.2.1, CRYPTO_PROFILES).
pub const SD_JWT_VC_TYP: &str = "dc+sd-jwt";

/// Algoritmo criptográfico normativo para SD-JWT VC (INV-08: ES256).
pub const SD_JWT_VC_DEFAULT_ALG: &str = "ES256";

/// Tolerancia por defecto de sesgo de reloj para validación temporal en segundos.
pub const DEFAULT_VC_CLOCK_SKEW_SECONDS: u64 = 60;

/// Esquema obligatorio del identificador de emisor (`iss`, ARCHITECTURE.md §3).
pub const VC_ISS_SCHEME: &str = "https://";

/// Longitud máxima en bytes del claim `iss` (REQ-VER-008).
pub const MAX_VC_ISS_BYTES: usize = 256;

/// Longitud máxima en bytes de la URI de una lista de estado (REQ-VER-008).
pub const MAX_STATUS_URI_BYTES: usize = 512;

/// Claims de nivel superior que DEBEN permanecer siempre visibles (ARCHITECTURE.md §8.2).
///
/// Un emisor no puede divulgarlos selectivamente: hacerlo los ocultaría del verificador
/// y rompería la verificación de vigencia, estado y vinculación (fail-closed, REQ-VER-003).
const ALWAYS_VISIBLE_CLAIMS: [&str; 7] = ["iss", "vct", "iat", "nbf", "exp", "cnf", "status"];

/// Comprueba si un nombre de claim es de nivel superior y por tanto siempre visible.
fn is_always_visible_claim(name: &str) -> bool {
    ALWAYS_VISIBLE_CLAIMS.contains(&name)
}

/// Valida el identificador de emisor (`iss`) como URL HTTPS sin espacios ni controles.
fn validate_issuer_uri(iss: &str) -> Result<(), GidError> {
    if iss.len() > MAX_VC_ISS_BYTES {
        return Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            format!("claim 'iss' exceeds maximum length of {MAX_VC_ISS_BYTES} bytes"),
        ));
    }
    if !iss.starts_with(VC_ISS_SCHEME) {
        return Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            format!("claim 'iss' must be an HTTPS URL starting with '{VC_ISS_SCHEME}'"),
        ));
    }
    for ch in iss.chars() {
        if ch.is_ascii_whitespace() || ch.is_control() {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "claim 'iss' contains whitespace or control characters",
            ));
        }
    }
    Ok(())
}

/// Lee un claim numérico entero sin signo de un objeto JSON.
fn member_u64(val: &Value, name: &str) -> Option<u64> {
    match val.member(name) {
        Some(Value::Number(Number::PosInt(n))) => Some(*n),
        _ => None,
    }
}

/// Referencia a una lista de estado de tokens (draft-ietf-oauth-status-list-21, REQ-CRED-007).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusListReference {
    /// Índice de la entrada dentro del status list (u64).
    pub idx: u64,
    /// URI de la lista de estado de tokens.
    pub uri: String,
}

impl StatusListReference {
    /// Construye una nueva referencia a lista de estado tras validar los parámetros.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedStatusList`] si la URI está vacía, supera el límite de longitud
    /// o contiene caracteres de control o espacios.
    pub fn new(idx: u64, uri: impl Into<String>) -> Result<Self, GidError> {
        let uri = uri.into();
        if uri.is_empty() {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "status list uri must not be empty",
            ));
        }
        if uri.len() > MAX_STATUS_URI_BYTES {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                format!("status list uri exceeds maximum length of {MAX_STATUS_URI_BYTES} bytes"),
            ));
        }
        for ch in uri.chars() {
            if ch.is_ascii_whitespace() || ch.is_control() {
                return Err(GidError::new(
                    ErrorCode::MalformedStatusList,
                    "status list uri contains whitespace or control characters",
                ));
            }
        }
        Ok(Self { idx, uri })
    }

    /// Convierte la referencia a [`Value`] JSON.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Object(vec![
            ("idx".to_string(), Value::Number(Number::PosInt(self.idx))),
            ("uri".to_string(), Value::String(self.uri.clone())),
        ])
    }

    /// Analiza y valida una referencia desde un [`Value`] JSON.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedStatusList`] si falta `idx` o `uri`, o tienen tipos incorrectos.
    pub fn from_value(val: &Value) -> Result<Self, GidError> {
        let idx = member_u64(val, "idx").ok_or_else(|| {
            GidError::new(
                ErrorCode::MalformedStatusList,
                "missing or invalid 'idx' in status_list reference",
            )
        })?;

        let uri = val.member("uri").and_then(Value::as_str).ok_or_else(|| {
            GidError::new(
                ErrorCode::MalformedStatusList,
                "missing or invalid 'uri' in status_list reference",
            )
        })?;

        Self::new(idx, uri)
    }
}

/// Claim normativo de referencia de estado de credencial (REQ-CRED-007).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusClaim {
    /// Referencia a la lista de estado Token Status List.
    pub status_list: StatusListReference,
}

impl StatusClaim {
    /// Crea un nuevo claim de estado a partir de su referencia.
    #[must_use]
    pub fn new(status_list: StatusListReference) -> Self {
        Self { status_list }
    }

    /// Convierte el claim de estado a [`Value`] JSON.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Object(vec![(
            "status_list".to_string(),
            self.status_list.to_value(),
        )])
    }

    /// Analiza un claim de estado desde un [`Value`] JSON.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedStatusList`] si no contiene el objeto `status_list`.
    pub fn from_value(val: &Value) -> Result<Self, GidError> {
        let sl_val = val.member("status_list").ok_or_else(|| {
            GidError::new(
                ErrorCode::MalformedStatusList,
                "status claim missing 'status_list' member",
            )
        })?;
        let status_list = StatusListReference::from_value(sl_val)?;
        Ok(Self { status_list })
    }
}

/// Claim `cnf` de confirmación de clave pública del titular (RFC 7800 / draft-19 §3.2.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmationClaim {
    /// Clave pública JWK EC P-256 del titular.
    pub jwk: JwkEcP256,
}

impl ConfirmationClaim {
    /// Construye una nueva confirmación de clave a partir de la clave pública del titular.
    #[must_use]
    pub fn new(jwk: JwkEcP256) -> Self {
        Self { jwk }
    }

    /// Convierte la confirmación a [`Value`] JSON.
    ///
    /// Serializa la clave pública con los miembros canónicos RFC 7638 (`crv`, `kty`, `x`, `y`),
    /// de modo que nunca se emiten componentes privados (INV-02, INV-03).
    ///
    /// # Errores
    /// [`ErrorCode::MalformedSdJwt`] si la clave pública no puede serializarse.
    pub fn to_value(&self) -> Result<Value, GidError> {
        let jwk_json = self.jwk.to_canonical_json();
        let jwk_val =
            parse_bytes(jwk_json.as_bytes(), &JsonLimits::profile_default()).map_err(|e| {
                GidError::new(
                    ErrorCode::MalformedSdJwt,
                    format!("failed to serialize holder confirmation key: {e}"),
                )
            })?;
        Ok(Value::Object(vec![("jwk".to_string(), jwk_val)]))
    }

    /// Analiza la confirmación desde un [`Value`] JSON, validando que el JWK no contenga
    /// miembros de clave privada (INV-02, INV-03).
    ///
    /// # Errores
    /// [`ErrorCode::MalformedSdJwt`] si falta `jwk` o [`ErrorCode::InvalidKeyFormat`] si es inválido.
    pub fn from_value(val: &Value) -> Result<Self, GidError> {
        let jwk_val = val.member("jwk").ok_or_else(|| {
            GidError::new(
                ErrorCode::MalformedSdJwt,
                "confirmation claim 'cnf' missing 'jwk' member",
            )
        })?;
        let canonical_str = to_canonical_json(jwk_val);
        let jwk = JwkEcP256::parse(&canonical_str)?;
        Ok(Self { jwk })
    }
}

/// Claims normativos de nivel superior de una credencial SD-JWT VC (draft-19, ARCHITECTURE §8.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdJwtVcClaims {
    /// Identificador del emisor (`iss`).
    pub iss: String,
    /// Identificador del tipo de credencial verificable (`vct`).
    pub vct: Vct,
    /// Instante de emisión (`iat`).
    pub iat: UnixTime,
    /// Instante de inicio de vigencia (`nbf`), opcional.
    pub nbf: Option<UnixTime>,
    /// Instante de expiración (`exp`), opcional.
    pub exp: Option<UnixTime>,
    /// Confirmación de clave pública de titular (`cnf`), opcional.
    pub cnf: Option<ConfirmationClaim>,
    /// Referencia de estado de revocación/suspensión (`status`), opcional según perfil (REQ-CRED-007).
    pub status: Option<StatusClaim>,
}

/// Política de verificación de credenciales SD-JWT VC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VcValidityPolicy {
    /// Tolerancia máxima de sesgo de reloj en segundos (por defecto 60).
    pub clock_skew_seconds: u64,
    /// Si es `true`, exige que la credencial contenga el claim `status` (REQ-CRED-007). Por defecto `true`.
    pub require_status: bool,
    /// Si es `true`, exige que la credencial contenga el claim `exp`. Por defecto `false`.
    pub require_exp: bool,
    /// Si es `true`, exige que la credencial contenga el claim `cnf` para holder binding. Por defecto `false`.
    pub require_cnf: bool,
    /// Lista de algoritmos criptográficos autorizados (REQ-CRED-008). Por defecto `["ES256"]`.
    pub allowed_algorithms: Vec<String>,
    /// Perfil cuyos esquemas se validan en verificación (REQ-CRED-004). Por defecto `None`.
    ///
    /// Si está presente, `verify_vc` exige que el `vct` de la credencial coincida con el
    /// del esquema y valida los atributos divulgados contra él. Si el perfil no tiene
    /// esquema registrado en compilación, la verificación falla (fail-closed, INV-05).
    pub profile: Option<ProfileId>,
}

impl Default for VcValidityPolicy {
    fn default() -> Self {
        Self {
            clock_skew_seconds: DEFAULT_VC_CLOCK_SKEW_SECONDS,
            require_status: true,
            require_exp: false,
            require_cnf: false,
            allowed_algorithms: vec![SD_JWT_VC_DEFAULT_ALG.to_string()],
            profile: None,
        }
    }
}

impl VcValidityPolicy {
    /// Configura la tolerancia de sesgo de reloj en segundos.
    #[must_use]
    pub fn with_clock_skew_seconds(mut self, seconds: u64) -> Self {
        self.clock_skew_seconds = seconds;
        self
    }

    /// Exige (o no) el claim `status` (REQ-CRED-007).
    #[must_use]
    pub fn with_require_status(mut self, require: bool) -> Self {
        self.require_status = require;
        self
    }

    /// Exige (o no) el claim `exp`.
    #[must_use]
    pub fn with_require_exp(mut self, require: bool) -> Self {
        self.require_exp = require;
        self
    }

    /// Exige (o no) el claim `cnf`.
    #[must_use]
    pub fn with_require_cnf(mut self, require: bool) -> Self {
        self.require_cnf = require;
        self
    }

    /// Sustituye la lista de algoritmos autorizados (REQ-CRED-008).
    #[must_use]
    pub fn with_allowed_algorithms(mut self, algorithms: Vec<String>) -> Self {
        self.allowed_algorithms = algorithms;
        self
    }

    /// Fija el perfil cuyos esquemas se validan en verificación (REQ-CRED-004).
    #[must_use]
    pub fn with_profile(mut self, profile_id: ProfileId) -> Self {
        self.profile = Some(profile_id);
        self
    }

    /// Elimina la validación de esquemas de perfil de la política.
    #[must_use]
    pub fn without_profile(mut self) -> Self {
        self.profile = None;
        self
    }

    /// Comprueba si un algoritmo está autorizado por la política.
    #[must_use]
    pub fn is_algorithm_allowed(&self, alg: &str) -> bool {
        self.allowed_algorithms.iter().any(|a| a == alg)
    }
}

/// Verificador fail-closed de la capa SD-JWT VC (REQ-CRED-001, REQ-CRED-007, REQ-CRED-008).
pub struct SdJwtVcVerifier;

impl SdJwtVcVerifier {
    /// Extrae de un objeto de claims los atributos válidos para el esquema del perfil,
    /// descartando los metadatos siempre visibles de la capa VC (REQ-CRED-004).
    #[must_use]
    pub fn profile_attributes(claims: &Value) -> Value {
        let Value::Object(entries) = claims else {
            return Value::Object(Vec::new());
        };
        Value::Object(
            entries
                .iter()
                .filter(|(k, _)| !is_always_visible_claim(k))
                .cloned()
                .collect(),
        )
    }

    /// Resuelve el esquema declarado por la política (fail-closed si no está registrado).
    fn resolve_schema(profile: &ProfileId) -> Result<&'static ProfileSchema, GidError> {
        ProfileSchema::lookup(profile).ok_or_else(|| {
            GidError::new(
                ErrorCode::SchemaValidationFailed,
                format!("no compile-time schema registered for profile '{profile}'"),
            )
        })
    }

    /// Valida los claims de la capa VC contra el esquema del perfil de la política
    /// (REQ-CRED-004).
    ///
    /// `claims` es el objeto de claims reconstruidos (metadatos siempre visibles más
    /// atributos divulgados ya verificados por digest). Se validan los **tipos** de los
    /// atributos divulgados y se comprueba que el `vct` de la credencial coincide con el
    /// del esquema. Los claims `required` del esquema son una obligación del emisor
    /// (se comprueban en la emisión): una presentación puede divulgar un subconjunto de
    /// atributos (la minimización de presentaciones se exige en la fase F5), de modo que
    /// exigirlos aquí impediría la
    /// minimización.
    ///
    /// # Errores
    /// [`ErrorCode::SchemaValidationFailed`] (`PIP-E3004`) si el perfil no tiene esquema,
    /// si el `vct` no coincide o si algún claim divulgado incumple el esquema.
    pub fn verify_profile_claims(
        claims: &Value,
        vct: &Vct,
        policy: &VcValidityPolicy,
    ) -> Result<(), GidError> {
        let Some(profile) = policy.profile.as_ref() else {
            return Ok(());
        };
        let schema = Self::resolve_schema(profile)?;

        if vct.as_str() != schema.vct {
            return Err(GidError::new(
                ErrorCode::SchemaValidationFailed,
                format!("credential vct '{vct}' does not match the vct of profile '{profile}'"),
            ));
        }

        schema.validate_disclosed(&Self::profile_attributes(claims))
    }

    /// Valida la cabecera del SD-JWT contra la política del perfil VC.
    ///
    /// # Errores
    /// - [`ErrorCode::MalformedSdJwt`] si falta `typ` o no es `"dc+sd-jwt"`.
    /// - [`ErrorCode::UnsupportedAlgorithm`] si `alg` es `"none"` o no está permitido por la política.
    pub fn verify_header(header: &Value, policy: &VcValidityPolicy) -> Result<(), GidError> {
        // 1. typ DEBE ser "dc+sd-jwt"
        let typ = header
            .member("typ")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                GidError::new(
                    ErrorCode::MalformedSdJwt,
                    "missing 'typ' header in SD-JWT VC",
                )
            })?;
        if typ != SD_JWT_VC_TYP {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("unsupported 'typ' header '{typ}', expected '{SD_JWT_VC_TYP}'"),
            ));
        }

        // 2. alg DEBE estar en la lista de permitidos y NUNCA "none" (REQ-CRED-008, INV-08)
        let alg = header
            .member("alg")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                GidError::new(
                    ErrorCode::UnsupportedAlgorithm,
                    "missing 'alg' header in SD-JWT VC",
                )
            })?;
        if alg.eq_ignore_ascii_case("none") {
            return Err(GidError::new(
                ErrorCode::UnsupportedAlgorithm,
                "algorithm 'none' is strictly prohibited (INV-08, REQ-CRED-008)",
            ));
        }
        if !policy.is_algorithm_allowed(alg) {
            return Err(GidError::new(
                ErrorCode::UnsupportedAlgorithm,
                format!("algorithm '{alg}' is not allowed by VC policy (REQ-CRED-008)"),
            ));
        }

        Ok(())
    }

    /// Valida los claims normativos de nivel superior del SD-JWT VC.
    ///
    /// Debe invocarse sobre el **payload firmado por el emisor**, donde estos claims son
    /// siempre visibles (ARCHITECTURE §8.2). Verificarlos sobre una reconstrucción permitiría
    /// que un emisor los ocultase tras divulgación selectiva.
    ///
    /// # Errores
    /// - [`ErrorCode::MissingRequiredClaim`] si falta `iss`, `vct`, `iat`, o `status`/`exp`/`cnf` cuando la política lo exige.
    /// - [`ErrorCode::MalformedSdJwt`] si los claims tienen tipos erróneos o contradicciones lógicas.
    /// - [`ErrorCode::CredentialNotYetValid`] si `iat` o `nbf` están en el futuro.
    /// - [`ErrorCode::CredentialExpired`] si `exp` ha vencido.
    /// - [`ErrorCode::MalformedStatusList`] si la estructura de `status` es inválida.
    pub fn verify_claims(
        claims_val: &Value,
        now: UnixTime,
        policy: &VcValidityPolicy,
    ) -> Result<SdJwtVcClaims, GidError> {
        // 1. Claim 'iss' obligatorio (URL HTTPS del emisor, ARCHITECTURE §3)
        let iss = claims_val
            .member("iss")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                GidError::new(
                    ErrorCode::MissingRequiredClaim,
                    "missing required claim 'iss'",
                )
            })?;
        validate_issuer_uri(iss)?;
        let iss = iss.to_string();

        // 2. Claim 'vct' obligatorio
        let vct_str = claims_val
            .member("vct")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                GidError::new(
                    ErrorCode::MissingRequiredClaim,
                    "missing required claim 'vct'",
                )
            })?;
        let vct = Vct::parse(vct_str).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("invalid 'vct' claim: {e}"),
            )
        })?;

        // 3. Claim 'iat' obligatorio
        let iat_sec = member_u64(claims_val, "iat").ok_or_else(|| {
            GidError::new(
                ErrorCode::MissingRequiredClaim,
                "missing required claim 'iat'",
            )
        })?;
        let iat = UnixTime::from_seconds(iat_sec);

        let now_sec = now.as_seconds();
        let skew = policy.clock_skew_seconds;

        // Comprobación de iat no futuro con tolerancia de reloj
        if iat_sec > now_sec.saturating_add(skew) {
            return Err(GidError::new(
                ErrorCode::CredentialNotYetValid,
                "credential 'iat' is in the future",
            ));
        }

        // 4. Claim 'nbf' opcional
        let nbf = if let Some(nbf_val) = claims_val.member("nbf") {
            let nbf_sec = match nbf_val {
                Value::Number(Number::PosInt(n)) => *n,
                _ => {
                    return Err(GidError::new(
                        ErrorCode::MalformedSdJwt,
                        "claim 'nbf' must be a positive integer",
                    ))
                }
            };
            if now_sec.saturating_add(skew) < nbf_sec {
                return Err(GidError::new(
                    ErrorCode::CredentialNotYetValid,
                    "credential 'nbf' is in the future",
                ));
            }
            if nbf_sec < iat_sec {
                return Err(GidError::new(
                    ErrorCode::MalformedSdJwt,
                    "credential 'nbf' is before 'iat'",
                ));
            }
            Some(UnixTime::from_seconds(nbf_sec))
        } else {
            None
        };

        // 5. Claim 'exp' opcional o requerido
        let exp = if let Some(exp_val) = claims_val.member("exp") {
            let exp_sec = match exp_val {
                Value::Number(Number::PosInt(n)) => *n,
                _ => {
                    return Err(GidError::new(
                        ErrorCode::MalformedSdJwt,
                        "claim 'exp' must be a positive integer",
                    ))
                }
            };
            if now_sec > exp_sec.saturating_add(skew) {
                return Err(GidError::new(
                    ErrorCode::CredentialExpired,
                    "credential 'exp' has expired",
                ));
            }
            if exp_sec < iat_sec {
                return Err(GidError::new(
                    ErrorCode::MalformedSdJwt,
                    "credential 'exp' is before 'iat'",
                ));
            }
            if let Some(nbf_time) = nbf {
                if exp_sec < nbf_time.as_seconds() {
                    return Err(GidError::new(
                        ErrorCode::MalformedSdJwt,
                        "credential 'exp' is before 'nbf'",
                    ));
                }
            }
            Some(UnixTime::from_seconds(exp_sec))
        } else if policy.require_exp {
            return Err(GidError::new(
                ErrorCode::MissingRequiredClaim,
                "missing required claim 'exp'",
            ));
        } else {
            None
        };

        // 6. Claim 'cnf' opcional o requerido
        let cnf = if let Some(cnf_val) = claims_val.member("cnf") {
            let claim = ConfirmationClaim::from_value(cnf_val)?;
            Some(claim)
        } else if policy.require_cnf {
            return Err(GidError::new(
                ErrorCode::MissingRequiredClaim,
                "missing required claim 'cnf'",
            ));
        } else {
            None
        };

        // 7. Claim 'status' requerido por defecto (REQ-CRED-007)
        let status = if let Some(status_val) = claims_val.member("status") {
            let claim = StatusClaim::from_value(status_val)?;
            Some(claim)
        } else if policy.require_status {
            return Err(GidError::new(
                ErrorCode::MissingRequiredClaim,
                "missing required status reference claim 'status' (REQ-CRED-007)",
            ));
        } else {
            None
        };

        Ok(SdJwtVcClaims {
            iss,
            vct,
            iat,
            nbf,
            exp,
            cnf,
            status,
        })
    }
}

/// Constructor de credenciales SD-JWT VC conformes con draft-19 (REQ-CRED-001).
///
/// No implementa `Clone`: delega en [`SdObjectBuilder`], que consume sus claims.
pub struct SdJwtVcBuilder {
    iss: String,
    vct: Vct,
    iat: UnixTime,
    nbf: Option<UnixTime>,
    exp: Option<UnixTime>,
    cnf: Option<ConfirmationClaim>,
    status: Option<StatusClaim>,
    sd_builder: SdObjectBuilder,
    plain_names: Vec<String>,
    sd_names: Vec<String>,
    attributes: Vec<(String, Value)>,
    profile: Option<ProfileId>,
}

impl fmt::Debug for SdJwtVcBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SdJwtVcBuilder")
            .field("iss", &self.iss)
            .field("vct", &self.vct)
            .field("iat", &self.iat)
            .field("nbf", &self.nbf)
            .field("exp", &self.exp)
            .field("has_cnf", &self.cnf.is_some())
            .field("has_status", &self.status.is_some())
            .field("plain_claims", &self.plain_names.len())
            .field("sd_claims", &self.sd_names.len())
            .field("profile", &self.profile)
            .finish()
    }
}

impl SdJwtVcBuilder {
    /// Inicializa un constructor con los claims obligatorios básicos.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedSdJwt`] si `iss` no es una URL HTTPS válida.
    pub fn new(iss: impl Into<String>, vct: Vct, iat: UnixTime) -> Result<Self, GidError> {
        let iss = iss.into();
        validate_issuer_uri(&iss)?;
        Ok(Self {
            iss,
            vct,
            iat,
            nbf: None,
            exp: None,
            cnf: None,
            status: None,
            sd_builder: SdObjectBuilder::new(),
            plain_names: Vec::new(),
            sd_names: Vec::new(),
            attributes: Vec::new(),
            profile: None,
        })
    }

    /// Configura el instante de inicio de vigencia (`nbf`).
    #[must_use]
    pub fn nbf(mut self, nbf: UnixTime) -> Self {
        self.nbf = Some(nbf);
        self
    }

    /// Configura el instante de expiración (`exp`).
    #[must_use]
    pub fn exp(mut self, exp: UnixTime) -> Self {
        self.exp = Some(exp);
        self
    }

    /// Configura la clave pública del titular (`cnf.jwk`).
    #[must_use]
    pub fn cnf_jwk(mut self, jwk: JwkEcP256) -> Self {
        self.cnf = Some(ConfirmationClaim::new(jwk));
        self
    }

    /// Configura el claim de confirmación completo (`cnf`).
    #[must_use]
    pub fn cnf(mut self, cnf: ConfirmationClaim) -> Self {
        self.cnf = Some(cnf);
        self
    }

    /// Configura la referencia de estado (`status`, REQ-CRED-007).
    #[must_use]
    pub fn status(mut self, status: StatusClaim) -> Self {
        self.status = Some(status);
        self
    }

    /// Helper para configurar la referencia de status list (`status.status_list`).
    pub fn status_list(mut self, idx: u64, uri: impl Into<String>) -> Result<Self, GidError> {
        let reference = StatusListReference::new(idx, uri)?;
        self.status = Some(StatusClaim::new(reference));
        Ok(self)
    }

    /// Añade un claim visible llano (sin divulgación selectiva).
    #[must_use]
    pub fn add_plain_claim(mut self, name: impl Into<String>, value: Value) -> Self {
        let name = name.into();
        self.plain_names.push(name.clone());
        self.attributes.push((name.clone(), value.clone()));
        self.sd_builder = self.sd_builder.add_plain_claim(name, value);
        self
    }

    /// Añade un claim selectivamente divulgable (`_sd`).
    #[must_use]
    pub fn add_sd_claim(mut self, name: impl Into<String>, value: Value) -> Self {
        let name = name.into();
        self.sd_names.push(name.clone());
        self.attributes.push((name.clone(), value.clone()));
        self.sd_builder = self.sd_builder.add_sd_claim(name, value);
        self
    }

    /// Añade un claim selectivamente divulgable con una sal específica.
    #[must_use]
    pub fn add_sd_claim_with_salt(
        mut self,
        name: impl Into<String>,
        value: Value,
        salt: Salt,
    ) -> Self {
        let name = name.into();
        self.sd_names.push(name.clone());
        self.attributes.push((name.clone(), value.clone()));
        self.sd_builder = self.sd_builder.add_sd_claim_with_salt(name, value, salt);
        self
    }

    /// Fija el perfil cuyos esquemas se validan **en emisión** (REQ-CRED-004).
    ///
    /// El perfil determina el `vct` esperado y el conjunto de claims obligatorios con
    /// sus tipos; la credencial se rechaza antes de firmarse si no los cumple.
    #[must_use]
    pub fn profile(mut self, profile_id: ProfileId) -> Self {
        self.profile = Some(profile_id);
        self
    }

    /// Configura la cantidad de digests señuelo (decoys, REQ-CRED-003).
    #[must_use]
    pub fn set_decoys(mut self, count: usize) -> Self {
        self.sd_builder = self.sd_builder.set_decoys(count);
        self
    }

    /// Comprueba que ningún claim de nivel superior se oculte ni se duplique (ARCHITECTURE §8.2).
    fn validate_attribute_names(&self) -> Result<(), GidError> {
        for name in self.plain_names.iter().chain(self.sd_names.iter()) {
            if is_always_visible_claim(name) {
                return Err(GidError::new(
                    ErrorCode::MalformedSdJwt,
                    format!(
                        "claim '{name}' is always visible in an SD-JWT VC and must not be added as an attribute"
                    ),
                ));
            }
            if self.plain_names.contains(name) && self.sd_names.contains(name) {
                return Err(GidError::new(
                    ErrorCode::MalformedSdJwt,
                    format!("claim '{name}' is declared both plain and selectively disclosable"),
                ));
            }
        }
        Ok(())
    }

    /// Compila los claims de nivel superior de SD-JWT VC en el [`SdObjectBuilder`].
    pub fn build(self) -> Result<SdObjectBuilder, GidError> {
        self.validate_attribute_names()?;

        // Validaciones de consistencia temporal
        if let Some(nbf) = self.nbf {
            if nbf.as_seconds() < self.iat.as_seconds() {
                return Err(GidError::new(
                    ErrorCode::MalformedSdJwt,
                    "credential 'nbf' cannot be before 'iat'",
                ));
            }
        }
        if let Some(exp) = self.exp {
            if exp.as_seconds() < self.iat.as_seconds() {
                return Err(GidError::new(
                    ErrorCode::MalformedSdJwt,
                    "credential 'exp' cannot be before 'iat'",
                ));
            }
            if let Some(nbf) = self.nbf {
                if exp.as_seconds() < nbf.as_seconds() {
                    return Err(GidError::new(
                        ErrorCode::MalformedSdJwt,
                        "credential 'exp' cannot be before 'nbf'",
                    ));
                }
            }
        }

        // REQ-CRED-004: validación de los atributos contra el esquema del perfil en emisión.
        if let Some(profile) = self.profile.as_ref() {
            let schema = ProfileSchema::lookup(profile).ok_or_else(|| {
                GidError::new(
                    ErrorCode::SchemaValidationFailed,
                    format!("no compile-time schema registered for profile '{profile}'"),
                )
            })?;
            if self.vct.as_str() != schema.vct {
                return Err(GidError::new(
                    ErrorCode::SchemaValidationFailed,
                    format!(
                        "credential vct '{}' does not match the vct of profile '{profile}'",
                        self.vct
                    ),
                ));
            }
            schema.validate(&Value::Object(self.attributes.clone()))?;
        }

        let mut builder = self.sd_builder;

        builder = builder
            .add_plain_claim("iss", Value::String(self.iss))
            .add_plain_claim("vct", Value::String(self.vct.as_str().to_string()))
            .add_plain_claim("iat", Value::Number(Number::PosInt(self.iat.as_seconds())));

        if let Some(nbf) = self.nbf {
            builder =
                builder.add_plain_claim("nbf", Value::Number(Number::PosInt(nbf.as_seconds())));
        }

        if let Some(exp) = self.exp {
            builder =
                builder.add_plain_claim("exp", Value::Number(Number::PosInt(exp.as_seconds())));
        }

        if let Some(cnf) = self.cnf {
            builder = builder.add_plain_claim("cnf", cnf.to_value()?);
        }

        if let Some(status) = self.status {
            builder = builder.add_plain_claim("status", status.to_value());
        }

        Ok(builder)
    }

    /// Emite y firma la credencial SD-JWT VC con cabecera `typ: dc+sd-jwt` y algoritmo `ES256`.
    ///
    /// La firma se delega al [`KeyStore`] del emisor sin extraer material privado (INV-03).
    pub fn issue_signed<S: KeyStore, P: SigningPurpose, R: Rng>(
        self,
        key_store: &S,
        handle: &KeyHandle<P>,
        kid: Option<Kid>,
        rng: &R,
    ) -> Result<IssuedSdJwt, GidError> {
        let builder = self.build()?;
        let header = JwsHeader {
            alg: SD_JWT_VC_DEFAULT_ALG.to_string(),
            typ: SD_JWT_VC_TYP.to_string(),
            kid,
        };
        SdIssuer::issue_signed(builder, key_store, handle, header, rng)
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
    use gravital_id_keys::{IssuerSigning, KeyHandle, SoftwareKeyStore};
    use gravital_id_testkit::SeededRng;

    fn issue_vc(
        builder: SdJwtVcBuilder,
        key_store: &SoftwareKeyStore<impl Rng>,
        handle: &KeyHandle<IssuerSigning>,
    ) -> IssuedSdJwt {
        let rng_emit = SeededRng::new(102);
        builder
            .issue_signed(key_store, handle, None, &rng_emit)
            .expect("issue")
    }

    #[test]
    fn nominal_vc_builder_and_verification() {
        let rng = SeededRng::new(101);
        let mut key_store = SoftwareKeyStore::new(rng);
        let issuer_handle = key_store
            .generate_key::<IssuerSigning>()
            .expect("issuer key");
        let issuer_jwk = key_store.public_key(&issuer_handle).expect("issuer jwk");

        let vct = Vct::parse("https://credentials.gravital.io/vct/personal/id-v1").expect("vct");
        let now = UnixTime::from_seconds(1_700_000_000);
        let exp = UnixTime::from_seconds(1_700_003_600);

        let issued = issue_vc(
            SdJwtVcBuilder::new("https://issuer.example.com", vct.clone(), now)
                .expect("builder")
                .exp(exp)
                .status_list(42, "https://status.example.com/status-list-1")
                .expect("status_list")
                .add_sd_claim("given_name", Value::String("Alice".to_string()))
                .set_decoys(2),
            &key_store,
            &issuer_handle,
        );

        let parsed =
            crate::parser::ParsedSdJwt::parse(issued.to_compact_serialization()).expect("parse");
        parsed
            .verify_issuer_signature(&issuer_jwk)
            .expect("signature");

        let policy = VcValidityPolicy::default();
        let vc_claims = parsed.verify_vc(now, &policy).expect("verify vc");

        assert_eq!(vc_claims.iss, "https://issuer.example.com");
        assert_eq!(vc_claims.vct, vct);
        assert_eq!(vc_claims.iat, now);
        assert_eq!(vc_claims.exp, Some(exp));
        assert!(vc_claims.status.is_some());
        let st = vc_claims.status.expect("status");
        assert_eq!(st.status_list.idx, 42);
        assert_eq!(
            st.status_list.uri,
            "https://status.example.com/status-list-1"
        );
    }

    #[test]
    fn rejection_of_non_https_issuer_identifier() {
        let vct = Vct::parse("https://example.com/vct").expect("vct");
        let now = UnixTime::from_seconds(1_700_000_000);

        // HTTP no es HTTPS: ARCHITECTURE §3 fija 'iss' como URL HTTPS.
        let err = SdJwtVcBuilder::new("http://issuer.example.com", vct, now).unwrap_err();
        assert_eq!(err.code, ErrorCode::MalformedSdJwt);
    }

    #[test]
    fn rejection_of_always_visible_claim_as_selectively_disclosable() {
        let vct = Vct::parse("https://example.com/vct").expect("vct");
        let now = UnixTime::from_seconds(1_700_000_000);

        let rng = SeededRng::new(303);
        let mut key_store = SoftwareKeyStore::new(rng);
        let issuer_handle = key_store
            .generate_key::<IssuerSigning>()
            .expect("issuer key");

        let builder = SdJwtVcBuilder::new("https://issuer.example.com", vct, now)
            .expect("builder")
            .add_sd_claim("iss", Value::String("https://other.example.com".into()));
        let err = builder
            .issue_signed(&key_store, &issuer_handle, None, &SeededRng::new(304))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::MalformedSdJwt);
        assert!(err.message.contains("always visible"));
    }

    #[test]
    fn rejection_of_missing_status_when_policy_requires_it() {
        let vct = Vct::parse("https://example.com/vct").expect("vct");
        let now = UnixTime::from_seconds(1_700_000_000);

        let claims = Value::Object(vec![
            (
                "iss".to_string(),
                Value::String("https://issuer.com".to_string()),
            ),
            ("vct".to_string(), Value::String(vct.as_str().to_string())),
            (
                "iat".to_string(),
                Value::Number(Number::PosInt(now.as_seconds())),
            ),
        ]);

        let policy = VcValidityPolicy {
            require_status: true,
            ..Default::default()
        };

        let err = SdJwtVcVerifier::verify_claims(&claims, now, &policy).unwrap_err();
        assert_eq!(err.code, ErrorCode::MissingRequiredClaim);
        assert!(err.message.contains("status"));
    }

    #[test]
    fn rejection_of_expired_vc() {
        let vct = Vct::parse("https://example.com/vct").expect("vct");
        let iat = UnixTime::from_seconds(1_700_000_000);
        let exp = UnixTime::from_seconds(1_700_001_000);
        let now = UnixTime::from_seconds(1_700_002_000); // Expirado por 1000s

        let claims = Value::Object(vec![
            (
                "iss".to_string(),
                Value::String("https://issuer.com".to_string()),
            ),
            ("vct".to_string(), Value::String(vct.as_str().to_string())),
            (
                "iat".to_string(),
                Value::Number(Number::PosInt(iat.as_seconds())),
            ),
            (
                "exp".to_string(),
                Value::Number(Number::PosInt(exp.as_seconds())),
            ),
            (
                "status".to_string(),
                Value::Object(vec![(
                    "status_list".to_string(),
                    Value::Object(vec![
                        ("idx".to_string(), Value::Number(Number::PosInt(0))),
                        (
                            "uri".to_string(),
                            Value::String("https://status.com".to_string()),
                        ),
                    ]),
                )]),
            ),
        ]);

        let policy = VcValidityPolicy::default();
        let err = SdJwtVcVerifier::verify_claims(&claims, now, &policy).unwrap_err();
        assert_eq!(err.code, ErrorCode::CredentialExpired);
    }

    #[test]
    fn rejection_of_future_iat_or_nbf() {
        let vct = Vct::parse("https://example.com/vct").expect("vct");
        let now = UnixTime::from_seconds(1_700_000_000);
        let future_iat = UnixTime::from_seconds(1_700_001_000); // 1000s en el futuro

        let claims = Value::Object(vec![
            (
                "iss".to_string(),
                Value::String("https://issuer.com".to_string()),
            ),
            ("vct".to_string(), Value::String(vct.as_str().to_string())),
            (
                "iat".to_string(),
                Value::Number(Number::PosInt(future_iat.as_seconds())),
            ),
            (
                "status".to_string(),
                Value::Object(vec![(
                    "status_list".to_string(),
                    Value::Object(vec![
                        ("idx".to_string(), Value::Number(Number::PosInt(0))),
                        (
                            "uri".to_string(),
                            Value::String("https://status.com".to_string()),
                        ),
                    ]),
                )]),
            ),
        ]);

        let policy = VcValidityPolicy::default();
        let err = SdJwtVcVerifier::verify_claims(&claims, now, &policy).unwrap_err();
        assert_eq!(err.code, ErrorCode::CredentialNotYetValid);
        assert!(err.message.contains("iat"));
    }

    #[test]
    fn rejection_of_invalid_typ_or_alg_none() {
        let policy = VcValidityPolicy::default();

        // typ inválido ("JWT" en vez de "dc+sd-jwt")
        let bad_typ_header = Value::Object(vec![
            ("typ".to_string(), Value::String("JWT".to_string())),
            ("alg".to_string(), Value::String("ES256".to_string())),
        ]);
        let err = SdJwtVcVerifier::verify_header(&bad_typ_header, &policy).unwrap_err();
        assert_eq!(err.code, ErrorCode::MalformedSdJwt);

        // alg: none
        let alg_none_header = Value::Object(vec![
            ("typ".to_string(), Value::String(SD_JWT_VC_TYP.to_string())),
            ("alg".to_string(), Value::String("none".to_string())),
        ]);
        let err_none = SdJwtVcVerifier::verify_header(&alg_none_header, &policy).unwrap_err();
        assert_eq!(err_none.code, ErrorCode::UnsupportedAlgorithm);
    }

    #[test]
    fn rejection_of_algorithm_not_in_profile_list() {
        let policy = VcValidityPolicy::default().with_allowed_algorithms(vec!["ES384".to_string()]);
        let header = Value::Object(vec![
            ("typ".to_string(), Value::String(SD_JWT_VC_TYP.to_string())),
            ("alg".to_string(), Value::String("ES256".to_string())),
        ]);
        let err = SdJwtVcVerifier::verify_header(&header, &policy).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedAlgorithm);
    }

    #[test]
    fn rejection_of_malformed_status_reference() {
        let vct = Vct::parse("https://example.com/vct").expect("vct");
        let now = UnixTime::from_seconds(1_700_000_000);

        // 'uri' ausente en status_list
        let claims = Value::Object(vec![
            (
                "iss".to_string(),
                Value::String("https://issuer.com".to_string()),
            ),
            ("vct".to_string(), Value::String(vct.as_str().to_string())),
            (
                "iat".to_string(),
                Value::Number(Number::PosInt(now.as_seconds())),
            ),
            (
                "status".to_string(),
                Value::Object(vec![(
                    "status_list".to_string(),
                    Value::Object(vec![("idx".to_string(), Value::Number(Number::PosInt(0)))]),
                )]),
            ),
        ]);

        let policy = VcValidityPolicy::default();
        let err = SdJwtVcVerifier::verify_claims(&claims, now, &policy).unwrap_err();
        assert_eq!(err.code, ErrorCode::MalformedStatusList);
    }

    #[test]
    fn rejection_of_cnf_with_private_key_material() {
        let vct = Vct::parse("https://example.com/vct").expect("vct");
        let now = UnixTime::from_seconds(1_700_000_000);

        // 'cnf.jwk' contiene el parámetro privado 'd'
        let claims = Value::Object(vec![
            (
                "iss".to_string(),
                Value::String("https://issuer.com".to_string()),
            ),
            ("vct".to_string(), Value::String(vct.as_str().to_string())),
            (
                "iat".to_string(),
                Value::Number(Number::PosInt(now.as_seconds())),
            ),
            (
                "status".to_string(),
                Value::Object(vec![(
                    "status_list".to_string(),
                    Value::Object(vec![
                        ("idx".to_string(), Value::Number(Number::PosInt(0))),
                        (
                            "uri".to_string(),
                            Value::String("https://status.com".to_string()),
                        ),
                    ]),
                )]),
            ),
            (
                "cnf".to_string(),
                Value::Object(vec![(
                    "jwk".to_string(),
                    Value::Object(vec![
                        ("kty".to_string(), Value::String("EC".to_string())),
                        ("crv".to_string(), Value::String("P-256".to_string())),
                        (
                            "x".to_string(),
                            Value::String(
                                "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU".to_string(),
                            ),
                        ),
                        (
                            "y".to_string(),
                            Value::String(
                                "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0".to_string(),
                            ),
                        ),
                        (
                            "d".to_string(),
                            Value::String(
                                "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI".to_string(),
                            ),
                        ),
                    ]),
                )]),
            ),
        ]);

        let policy = VcValidityPolicy::default();
        let err = SdJwtVcVerifier::verify_claims(&claims, now, &policy).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidKeyFormat);
    }

    #[test]
    fn default_policy_requires_status_and_allows_only_es256() {
        let policy = VcValidityPolicy::default();
        assert!(policy.require_status);
        assert!(policy.is_algorithm_allowed("ES256"));
        assert!(!policy.is_algorithm_allowed("none"));
        assert!(!policy.is_algorithm_allowed("RS256"));
        assert_eq!(
            policy.allowed_algorithms,
            vec![SD_JWT_VC_DEFAULT_ALG.to_string()]
        );
    }
}
