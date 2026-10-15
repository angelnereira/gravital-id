//! Modelo normativo de resultado de verificación y evidencia de comprobaciones (F4.T06).
//!
//! Trazabilidad:
//! - **REQ-VER-002:** El resultado DEBE ser uno de `Valid`, `ValidWithStaleStatus`,
//!   `Unverifiable`, `Invalid`, con lista de comprobaciones y evidencia.
//! - **REQ-VER-010:** Precedencia de estados: `Invalid` > `Unverifiable` > `ValidWithStaleStatus` > `Valid`.
//! - **REQ-VER-012:** Las comprobaciones que dependen de datos no autenticados quedan `Skipped`;
//!   `Valid` es inconstruible sin que todas las comprobaciones obligatorias hayan pasado.
//! - **INV-04:** Cuatro estados cerrados con evidencia; nunca se reduce a booleano.
//! - **INV-05:** Fail-closed ante cualquier error, dato faltante o ambigüedad.

use alloc::string::String;
use alloc::vec::Vec;

use gravital_id_codec::json::Value;
use gravital_id_types::ErrorCode;

/// Estado de la verificación según el modelo de cuatro estados cerrados (INV-04, REQ-VER-002).
///
/// Precedencia estricta (REQ-VER-010):
/// `Invalid` > `Unverifiable` > `ValidWithStaleStatus` > `Valid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerificationStatus {
    /// Todo es correcto y el estado de revocación está dentro de la frescura exigida.
    Valid,
    /// Todo lo criptográfico es correcto, pero el estado supera la frescura máxima exigida.
    ValidWithStaleStatus,
    /// No se puede verificar con certeza (falta dato, emisor/clave suspendidos, reloj no confiable).
    Unverifiable,
    /// Violación de regla de integridad, firma inválida, expirado, revocado o no autorizado.
    Invalid,
}

impl VerificationStatus {
    /// Indica si el estado corresponde a un éxito de verificación (`Valid` o `ValidWithStaleStatus`).
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Valid | Self::ValidWithStaleStatus)
    }

    /// Nombre canónico del estado.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Valid => "Valid",
            Self::ValidWithStaleStatus => "ValidWithStaleStatus",
            Self::Unverifiable => "Unverifiable",
            Self::Invalid => "Invalid",
        }
    }
}

/// Identificador de una de las 11 comprobaciones ordenadas del pipeline (ROADMAP F4.T06).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CheckKind {
    /// 1. Estructura sintáctica del SD-JWT / SD-JWT VC (`typ: dc+sd-jwt`, cabeceras, límites).
    Structure,
    /// 2. Emisor registrado y autorizado en el TrustBundle / selección de emisores.
    IssuerAuthorized,
    /// 3. Estado de la clave del emisor (`active`, `retired` admisible, rechazo de `suspended`/`compromised`).
    KeyState,
    /// 4. Firma criptográfica JWS del emisor con la clave del TrustBundle.
    Signature,
    /// 5. Vigencia temporal de la credencial (`iat`, `nbf`, `exp` con sesgo de reloj).
    Validity,
    /// 6. Integridad de divulgaciones (digests SHA-256 en `_sd`/`...`, sin duplicados ni huérfanos).
    Disclosures,
    /// 7. Esquema y claims requeridos por el perfil y tipo de credencial (`vct`).
    Schema,
    /// 8. Vinculación de titular (Key Binding JWT: `typ: kb+jwt`, `sd_hash`, firma titular con `cnf.jwk`).
    KeyBinding,
    /// 9. Comprobación y consumo de nonce anti-replay en `VerifierStateStore`.
    Nonce,
    /// 10. Estado de revocación en Token Status List (activo / revocado / suspendido).
    Status,
    /// 11. Cumplimiento de la política del integrador (`OperationClass`, frescura, selección).
    Policy,
}

impl CheckKind {
    /// Nombre descriptivo de la comprobación.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Structure => "structure",
            Self::IssuerAuthorized => "issuer_authorized",
            Self::KeyState => "key_state",
            Self::Signature => "signature",
            Self::Validity => "validity",
            Self::Disclosures => "disclosures",
            Self::Schema => "schema",
            Self::KeyBinding => "key_binding",
            Self::Nonce => "nonce",
            Self::Status => "status",
            Self::Policy => "policy",
        }
    }
}

/// Resultado individual de una comprobación del pipeline (ADR-0020, REQ-VER-012).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CheckStatus {
    /// Comprobación evaluada satisfactoriamente.
    Passed,
    /// Comprobación evaluada con fallo normativo (conduce a `Invalid`).
    Failed,
    /// Comprobación no concluyente por falta de datos o estado no concluyente (conduce a `Unverifiable`).
    Indeterminate,
    /// Comprobación no evaluada porque depende de datos no autenticados o un paso previo falló (REQ-VER-012).
    Skipped,
}

/// Evidencia individual de una comprobación evaluada u omitida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckEvidence {
    /// Tipo de comprobación.
    pub kind: CheckKind,
    /// Resultado de la comprobación.
    pub status: CheckStatus,
    /// Código de error si la comprobación falló o quedó indeterminada.
    pub error_code: Option<ErrorCode>,
    /// Mensaje explicativo de la evidencia.
    pub message: String,
}

impl CheckEvidence {
    /// Crea evidencia de comprobación superada.
    #[must_use]
    pub fn passed(kind: CheckKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            status: CheckStatus::Passed,
            error_code: None,
            message: message.into(),
        }
    }

    /// Crea evidencia de comprobación fallida.
    #[must_use]
    pub fn failed(kind: CheckKind, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            kind,
            status: CheckStatus::Failed,
            error_code: Some(code),
            message: message.into(),
        }
    }

    /// Crea evidencia de comprobación indeterminada.
    #[must_use]
    pub fn indeterminate(kind: CheckKind, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            kind,
            status: CheckStatus::Indeterminate,
            error_code: Some(code),
            message: message.into(),
        }
    }

    /// Crea evidencia de comprobación omitida (REQ-VER-012).
    #[must_use]
    pub fn skipped(kind: CheckKind, reason: impl Into<String>) -> Self {
        Self {
            kind,
            status: CheckStatus::Skipped,
            error_code: None,
            message: reason.into(),
        }
    }
}

/// Testigo del sistema de tipos que acredita que todas las comprobaciones obligatorias pasaron (REQ-VER-012).
///
/// Este tipo no puede construirse fuera del pipeline de verificación, lo que hace
/// que sea imposible forjar un resultado `Valid` eludiendo las comprobaciones (prueba trybuild).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllMandatoryPassed {
    pub(crate) _private: (),
}

impl AllMandatoryPassed {
    /// Crea el testigo de que todas las comprobaciones obligatorias pasaron.
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }
}

/// Resultado inmutable y exhaustivo de la verificación offline (INV-04, REQ-VER-002).
#[derive(Debug, Clone, PartialEq)]
pub struct VerificationResult {
    status: VerificationStatus,
    checks: Vec<CheckEvidence>,
    issuer_id: Option<String>,
    kid_used: Option<String>,
    vct: Option<String>,
    verified_claims: Option<Value>,
    status_age_seconds: Option<u64>,
}

impl VerificationResult {
    /// Construye un resultado `Valid` únicamente si se aporta el testigo `AllMandatoryPassed` (REQ-VER-012).
    #[must_use]
    pub fn new_valid(
        _witness: AllMandatoryPassed,
        checks: Vec<CheckEvidence>,
        issuer_id: String,
        kid_used: String,
        vct: String,
        verified_claims: Value,
        status_age_seconds: Option<u64>,
    ) -> Self {
        Self {
            status: VerificationStatus::Valid,
            checks,
            issuer_id: Some(issuer_id),
            kid_used: Some(kid_used),
            vct: Some(vct),
            verified_claims: Some(verified_claims),
            status_age_seconds,
        }
    }

    /// Construye un resultado `ValidWithStaleStatus`.
    #[must_use]
    pub fn new_valid_with_stale_status(
        checks: Vec<CheckEvidence>,
        issuer_id: String,
        kid_used: String,
        vct: String,
        verified_claims: Value,
        status_age_seconds: u64,
    ) -> Self {
        Self {
            status: VerificationStatus::ValidWithStaleStatus,
            checks,
            issuer_id: Some(issuer_id),
            kid_used: Some(kid_used),
            vct: Some(vct),
            verified_claims: Some(verified_claims),
            status_age_seconds: Some(status_age_seconds),
        }
    }

    /// Construye un resultado `Unverifiable`.
    #[must_use]
    pub fn new_unverifiable(
        checks: Vec<CheckEvidence>,
        issuer_id: Option<String>,
        kid_used: Option<String>,
        vct: Option<String>,
    ) -> Self {
        Self {
            status: VerificationStatus::Unverifiable,
            checks,
            issuer_id,
            kid_used,
            vct,
            verified_claims: None,
            status_age_seconds: None,
        }
    }

    /// Construye un resultado `Invalid`.
    #[must_use]
    pub fn new_invalid(
        checks: Vec<CheckEvidence>,
        issuer_id: Option<String>,
        kid_used: Option<String>,
        vct: Option<String>,
    ) -> Self {
        Self {
            status: VerificationStatus::Invalid,
            checks,
            issuer_id,
            kid_used,
            vct,
            verified_claims: None,
            status_age_seconds: None,
        }
    }

    /// Estado global de la verificación.
    #[must_use]
    pub fn status(&self) -> VerificationStatus {
        self.status
    }

    /// Indica si el resultado es estrictamente `Valid`.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.status == VerificationStatus::Valid
    }

    /// Indica si el resultado es exitoso (`Valid` o `ValidWithStaleStatus`).
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// Lista ordenada de evidencias de cada comprobación del pipeline.
    #[must_use]
    pub fn checks(&self) -> &[CheckEvidence] {
        &self.checks
    }

    /// Busca la evidencia de una comprobación concreta.
    #[must_use]
    pub fn check(&self, kind: CheckKind) -> Option<&CheckEvidence> {
        self.checks.iter().find(|c| c.kind == kind)
    }

    /// Identificador del emisor verificado, si pudo determinarse.
    #[must_use]
    pub fn issuer_id(&self) -> Option<&str> {
        self.issuer_id.as_deref()
    }

    /// Identificador de la clave usada para la firma, si se resolvió.
    #[must_use]
    pub fn kid_used(&self) -> Option<&str> {
        self.kid_used.as_deref()
    }

    /// Tipo de credencial verificable (`vct`), si pudo determinarse.
    #[must_use]
    pub fn vct(&self) -> Option<&str> {
        self.vct.as_deref()
    }

    /// Claims verificados y reconstruidos de la credencial (solo presentes si la firma es válida).
    #[must_use]
    pub fn verified_claims(&self) -> Option<&Value> {
        self.verified_claims.as_ref()
    }

    /// Antigüedad en segundos del snapshot de estado utilizado, si aplica.
    #[must_use]
    pub fn status_age_seconds(&self) -> Option<u64> {
        self.status_age_seconds
    }
}
