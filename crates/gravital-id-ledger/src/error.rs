//! Tipos de error para el adaptador de ledger y reconstrucción de estado (F6.T08).
//!
//! Trazabilidad:
//! - **REQ-LEDG-002:** Abstracción mediante `LedgerAdapter`.
//! - **REQ-TRUST-008:** Reconstrucción pura y determinista.

use core::fmt;
use gravital_id_types::{ErrorCode, GidError};

use crate::event::EventCoordinate;

/// Resultado de operaciones en `gravital-id-ledger`.
pub type LedgerResult<T> = Result<T, LedgerError>;

/// Catálogo de errores del motor de ledger y reconstrucción de estado.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LedgerError {
    /// La coordenada del evento no es estrictamente creciente respecto al último procesado.
    NonMonotonicEventCoordinate {
        /// Última coordenada registrada.
        last: EventCoordinate,
        /// Coordenada recibida fuera de orden o duplicada.
        received: EventCoordinate,
    },
    /// El emisor indicado ya existe en el estado.
    IssuerAlreadyExists([u8; 32]),
    /// El emisor indicado no existe en el estado.
    IssuerNotFound([u8; 32]),
    /// El emisor no se encuentra en estado operativo activo.
    IssuerNotActive([u8; 32]),
    /// La clave de emisor ya existe para este emisor.
    KeyAlreadyExists {
        /// Identificador del emisor.
        issuer_id: [u8; 32],
        /// Identificador de la clave (thumbprint SHA-256).
        kid: [u8; 32],
    },
    /// La clave de emisor no existe.
    KeyNotFound {
        /// Identificador del emisor.
        issuer_id: [u8; 32],
        /// Identificador de la clave.
        kid: [u8; 32],
    },
    /// La clave ya se encuentra en estado terminal comprometido.
    KeyAlreadyCompromised {
        /// Identificador del emisor.
        issuer_id: [u8; 32],
        /// Identificador de la clave.
        kid: [u8; 32],
    },
    /// Transición de ciclo de vida de clave no permitida por las reglas de seguridad.
    InvalidKeyTransition {
        /// Estado actual.
        from: &'static str,
        /// Estado destino intentado.
        to: &'static str,
        /// Causa de la invalidez.
        reason: &'static str,
    },
    /// Clave pública P-256 malformada o inválida.
    InvalidPublicKey(String),
    /// Rango temporal de vigencia inválido (`valid_from >= valid_until`).
    InvalidTimestamps {
        /// Inicio de vigencia.
        valid_from: u64,
        /// Fin de vigencia.
        valid_until: u64,
    },
    /// Prohibición de auto-renovación de suspensión preventiva de emergencia (REQ-LEDG-004).
    EmergencyRenewalForbidden {
        /// Identificador de la clave o emisor.
        target_id: [u8; 32],
    },
    /// Versión de la raíz de confianza no monotónica.
    NonMonotonicRootVersion {
        /// Versión vigente en el estado.
        current: u64,
        /// Versión propuesta.
        proposed: u64,
    },
    /// Versión del manifiesto de estado no monotónica para el emisor.
    NonMonotonicManifestVersion {
        /// Identificador del emisor.
        issuer_id: [u8; 32],
        /// Versión actual registrada.
        current: u64,
        /// Versión propuesta no monótona.
        proposed: u64,
    },
    /// Hash de manifiesto inválido (cero bytes).
    InvalidManifestHash([u8; 32]),
    /// Verificador ya registrado.
    VerifierAlreadyExists([u8; 32]),
    /// Verificador no localizado.
    VerifierNotFound([u8; 32]),
    /// Error en la serialización canónica o formateo JSON.
    Serialization(String),
    /// Error de validación o construcción del trust bundle derivado.
    BundleError(String),
    /// Error devuelto por la implementación concreta del adaptador de ledger.
    Adapter(String),
    /// Política de verificación completa inválida (ej. min_sources < 2).
    InvalidPolicy(&'static str),
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonMonotonicEventCoordinate { last, received } => write!(
                f,
                "non-monotonic event coordinate: received ({received:?}) must be > last ({last:?})"
            ),
            Self::IssuerAlreadyExists(id) => write!(f, "issuer already exists: {id:?}"),
            Self::IssuerNotFound(id) => write!(f, "issuer not found: {id:?}"),
            Self::IssuerNotActive(id) => write!(f, "issuer is not active: {id:?}"),
            Self::KeyAlreadyExists { issuer_id, kid } => {
                write!(f, "key {kid:?} already exists for issuer {issuer_id:?}")
            }
            Self::KeyNotFound { issuer_id, kid } => {
                write!(f, "key {kid:?} not found for issuer {issuer_id:?}")
            }
            Self::KeyAlreadyCompromised { issuer_id, kid } => {
                write!(
                    f,
                    "key {kid:?} is permanently compromised for issuer {issuer_id:?}"
                )
            }
            Self::InvalidKeyTransition { from, to, reason } => {
                write!(
                    f,
                    "invalid key state transition from {from} to {to}: {reason}"
                )
            }
            Self::InvalidPublicKey(msg) => write!(f, "invalid public key: {msg}"),
            Self::InvalidTimestamps {
                valid_from,
                valid_until,
            } => {
                write!(
                    f,
                    "invalid timestamps: valid_from ({valid_from}) >= valid_until ({valid_until})"
                )
            }
            Self::EmergencyRenewalForbidden { target_id } => {
                write!(
                    f,
                    "emergency suspension cannot be renewed while active for target {target_id:?}"
                )
            }
            Self::NonMonotonicRootVersion { current, proposed } => {
                write!(
                    f,
                    "non-monotonic trust root version: current {current}, proposed {proposed}"
                )
            }
            Self::NonMonotonicManifestVersion {
                issuer_id,
                current,
                proposed,
            } => {
                write!(
                    f,
                    "non-monotonic manifest version for issuer {issuer_id:?}: current {current}, proposed {proposed}"
                )
            }
            Self::InvalidManifestHash(hash) => write!(f, "manifest hash cannot be zero: {hash:?}"),
            Self::VerifierAlreadyExists(id) => write!(f, "verifier already exists: {id:?}"),
            Self::VerifierNotFound(id) => write!(f, "verifier not found: {id:?}"),
            Self::Serialization(msg) => write!(f, "serialization error: {msg}"),
            Self::BundleError(msg) => write!(f, "bundle error: {msg}"),
            Self::Adapter(msg) => write!(f, "ledger adapter error: {msg}"),
            Self::InvalidPolicy(msg) => write!(f, "invalid policy: {msg}"),
        }
    }
}

impl std::error::Error for LedgerError {}

impl From<LedgerError> for GidError {
    fn from(err: LedgerError) -> Self {
        let code = match &err {
            LedgerError::NonMonotonicEventCoordinate { .. } => ErrorCode::MalformedMessage,
            LedgerError::IssuerAlreadyExists(_) => ErrorCode::MalformedMessage,
            LedgerError::IssuerNotFound(_) => ErrorCode::UntrustedIssuer,
            LedgerError::IssuerNotActive(_) => ErrorCode::IssuerSuspended,
            LedgerError::KeyAlreadyExists { .. } => ErrorCode::MalformedMessage,
            LedgerError::KeyNotFound { .. } => ErrorCode::KeyNotFound,
            LedgerError::KeyAlreadyCompromised { .. } => ErrorCode::IssuerKeyCompromised,
            LedgerError::InvalidKeyTransition { .. } => ErrorCode::MalformedMessage,
            LedgerError::InvalidPublicKey(_) => ErrorCode::InvalidKeyFormat,
            LedgerError::InvalidTimestamps { .. } => ErrorCode::MalformedMessage,
            LedgerError::EmergencyRenewalForbidden { .. } => ErrorCode::MalformedMessage,
            LedgerError::NonMonotonicRootVersion { .. } => ErrorCode::TrustRootChainBroken,
            LedgerError::NonMonotonicManifestVersion { .. } => ErrorCode::MalformedStatusList,
            LedgerError::InvalidManifestHash(_) => ErrorCode::MalformedStatusList,
            LedgerError::VerifierAlreadyExists(_) => ErrorCode::MalformedMessage,
            LedgerError::VerifierNotFound(_) => ErrorCode::MalformedMessage,
            LedgerError::Serialization(_) => ErrorCode::MalformedSdJwt,
            LedgerError::BundleError(_) => ErrorCode::MalformedSdJwt,
            LedgerError::Adapter(_) => ErrorCode::MalformedMessage,
            LedgerError::InvalidPolicy(_) => ErrorCode::MalformedMessage,
        };
        GidError::new(code, err.to_string())
    }
}
