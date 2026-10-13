//! Propósitos de clave (`KeyPurpose`) y handles tipados (`KeyHandle`).
//!
//! Trazabilidad:
//! - **REQ-KEY-001:** Separación de claves por propósito y prevención en el sistema de tipos.
//! - **REQ-KEY-009:** Claves de acuerdo (HPKE) con propósito propio separado de firma.
//! - **ARCHITECTURE.md §12:** Tabla de gestión de claves y separación tipada.

use alloc::string::String;
use core::fmt;
use core::marker::PhantomData;

/// Propósito asignado a una clave criptográfica en el protocolo Gravital ID.
///
/// La asignación de propósito es inmutable durante el ciclo de vida de la clave
/// y se refleja tanto a nivel de tipos (`KeyHandle<P>`) como en tiempo de ejecución.
///
/// Trazabilidad: `REQ-KEY-001`, `REQ-KEY-009`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum KeyPurpose {
    /// Clave de vinculación del titular (firma del KB-JWT en presentaciones).
    HolderBinding,
    /// Clave para firmar solicitudes de verificación (OID4VP / DCQL).
    VerifierRequest,
    /// Clave de recuperación del titular específica por emisor.
    HolderRecovery,
    /// Clave de firma de credenciales del emisor (SD-JWT VC).
    IssuerSigning,
    /// Clave de firma de listas de revocación y estado de tokens (Token Status List).
    StatusListSigning,
    /// Clave para recepción y acuerdo de claves HPKE (DHKEM P-256, RFC 9180).
    HpkeKeyAgreement,
    /// Clave de la raíz de confianza multisig / ceremonia TFA.
    TrustRoot,
    /// Clave de operador independiente para firma de trust bundle.
    TrustBundle,
}

impl KeyPurpose {
    /// Representación textual canónica del propósito.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HolderBinding => "holder-binding",
            Self::VerifierRequest => "verifier-request",
            Self::HolderRecovery => "holder-recovery",
            Self::IssuerSigning => "issuer-signing",
            Self::StatusListSigning => "status-list-signing",
            Self::HpkeKeyAgreement => "hpke-key-agreement",
            Self::TrustRoot => "trust-root",
            Self::TrustBundle => "trust-bundle",
        }
    }

    /// Determina si este propósito autoriza operaciones de firma digital ECDSA.
    ///
    /// Una clave de acuerdo HPKE nunca autoriza operaciones de firma (REQ-KEY-009).
    #[must_use]
    pub const fn allows_signing(self) -> bool {
        match self {
            Self::HolderBinding
            | Self::VerifierRequest
            | Self::HolderRecovery
            | Self::IssuerSigning
            | Self::StatusListSigning
            | Self::TrustRoot
            | Self::TrustBundle => true,
            Self::HpkeKeyAgreement => false,
        }
    }

    /// Determina si este propósito autoriza operaciones de acuerdo de claves (ECDH / HPKE).
    ///
    /// Una clave de firma nunca autoriza operaciones de acuerdo de claves (REQ-KEY-009).
    #[must_use]
    pub const fn allows_key_agreement(self) -> bool {
        match self {
            Self::HpkeKeyAgreement => true,
            Self::HolderBinding
            | Self::VerifierRequest
            | Self::HolderRecovery
            | Self::IssuerSigning
            | Self::StatusListSigning
            | Self::TrustRoot
            | Self::TrustBundle => false,
        }
    }
}

impl fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Marcador a nivel de tipo para propósitos de clave.
pub trait KeyPurposeMarker:
    'static + Send + Sync + fmt::Debug + Clone + Copy + PartialEq + Eq
{
    /// Constante del propósito en tiempo de ejecución.
    const PURPOSE: KeyPurpose;
}

/// Marcador que habilita operaciones de firma digital para una clave.
///
/// Implementado únicamente por propósitos de firma; excluye explícitamente
/// propósitos de acuerdo de claves (REQ-KEY-001, REQ-KEY-009).
pub trait SigningPurpose: KeyPurposeMarker {}

/// Marcador que habilita operaciones de acuerdo de claves (HPKE / ECDH).
///
/// Implementado únicamente por [`HpkeKeyAgreement`]; excluye explícitamente
/// propósitos de firma digital (REQ-KEY-001, REQ-KEY-009).
pub trait KeyAgreementPurpose: KeyPurposeMarker {}

/// Marcador para claves de vinculación del titular.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HolderBinding;
impl KeyPurposeMarker for HolderBinding {
    const PURPOSE: KeyPurpose = KeyPurpose::HolderBinding;
}
impl SigningPurpose for HolderBinding {}

/// Marcador para claves de solicitud del verificador.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerifierRequest;
impl KeyPurposeMarker for VerifierRequest {
    const PURPOSE: KeyPurpose = KeyPurpose::VerifierRequest;
}
impl SigningPurpose for VerifierRequest {}

/// Marcador para claves de recuperación del titular.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HolderRecovery;
impl KeyPurposeMarker for HolderRecovery {
    const PURPOSE: KeyPurpose = KeyPurpose::HolderRecovery;
}
impl SigningPurpose for HolderRecovery {}

/// Marcador para claves de firma del emisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IssuerSigning;
impl KeyPurposeMarker for IssuerSigning {
    const PURPOSE: KeyPurpose = KeyPurpose::IssuerSigning;
}
impl SigningPurpose for IssuerSigning {}

/// Marcador para claves de firma de listas de estado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StatusListSigning;
impl KeyPurposeMarker for StatusListSigning {
    const PURPOSE: KeyPurpose = KeyPurpose::StatusListSigning;
}
impl SigningPurpose for StatusListSigning {}

/// Marcador para la clave raíz de confianza.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustRoot;
impl KeyPurposeMarker for TrustRoot {
    const PURPOSE: KeyPurpose = KeyPurpose::TrustRoot;
}
impl SigningPurpose for TrustRoot {}

/// Marcador para la clave de firma del trust bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustBundle;
impl KeyPurposeMarker for TrustBundle {
    const PURPOSE: KeyPurpose = KeyPurpose::TrustBundle;
}
impl SigningPurpose for TrustBundle {}

/// Marcador para claves de acuerdo HPKE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HpkeKeyAgreement;
impl KeyPurposeMarker for HpkeKeyAgreement {
    const PURPOSE: KeyPurpose = KeyPurpose::HpkeKeyAgreement;
}
impl KeyAgreementPurpose for HpkeKeyAgreement {}

/// Identificador de clave gestionado por un almacén seguro, tipado por su propósito `P`.
///
/// La presencia del parámetro `P` garantiza en tiempo de compilación que esta clave
/// solo pueda pasarse a funciones y métodos que admitan dicho propósito (REQ-KEY-001).
///
/// No contiene material de clave privada (INV-02, INV-03).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyHandle<P> {
    id: String,
    _marker: PhantomData<P>,
}

impl<P: KeyPurposeMarker> KeyHandle<P> {
    /// Crea un nuevo handle tipado con el identificador dado (típicamente JWK thumbprint).
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            _marker: PhantomData,
        }
    }

    /// Identificador de la clave en el almacén (`kid`).
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Propósito asociado a esta clave.
    #[must_use]
    pub const fn purpose(&self) -> KeyPurpose {
        P::PURPOSE
    }
}

impl<P: KeyPurposeMarker> fmt::Debug for KeyHandle<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyHandle")
            .field("id", &self.id)
            .field("purpose", &P::PURPOSE)
            .finish()
    }
}

impl<P: KeyPurposeMarker> fmt::Display for KeyHandle<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", P::PURPOSE, self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn purpose_signing_permissions() {
        assert!(KeyPurpose::HolderBinding.allows_signing());
        assert!(KeyPurpose::VerifierRequest.allows_signing());
        assert!(KeyPurpose::HolderRecovery.allows_signing());
        assert!(KeyPurpose::IssuerSigning.allows_signing());
        assert!(KeyPurpose::StatusListSigning.allows_signing());
        assert!(KeyPurpose::TrustRoot.allows_signing());
        assert!(KeyPurpose::TrustBundle.allows_signing());
        assert!(!KeyPurpose::HpkeKeyAgreement.allows_signing());
    }

    #[test]
    fn purpose_key_agreement_permissions() {
        assert!(KeyPurpose::HpkeKeyAgreement.allows_key_agreement());
        assert!(!KeyPurpose::HolderBinding.allows_key_agreement());
        assert!(!KeyPurpose::IssuerSigning.allows_key_agreement());
    }

    #[test]
    fn key_handle_construction_and_display() {
        let handle = KeyHandle::<HolderBinding>::new("test-key-1");
        assert_eq!(handle.id(), "test-key-1");
        assert_eq!(handle.purpose(), KeyPurpose::HolderBinding);
        assert_eq!(format!("{handle}"), "holder-binding:test-key-1");
    }
}
