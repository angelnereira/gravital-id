//! Tipos de eventos y coordenadas de ordenación determinista para el ledger (F6.T08).
//!
//! Trazabilidad:
//! - **REQ-LEDG-002:** Tipos de eventos para `TrustRegistry` y `StatusAnchor`.
//! - **REQ-TRUST-008:** Secuenciación determinista por `(block_number, tx_index, log_index)`.
//! - **REQ-LEDG-001 / INV-02:** Cero datos personales en parámetros y eventos.

use core::cmp::Ordering;
use core::fmt;

/// Coordenada determinista de ordenación de un evento finalizado en el ledger (`CONTRACTS.md §6`).
///
/// Los eventos en el ledger forman una secuencia monotónica y estrictamente ordenada por la tupla:
/// `(block_number, tx_index, log_index)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventCoordinate {
    /// Altura del bloque finalizado en el que se incluyó el evento.
    pub block_number: u64,
    /// Índice de la transacción dentro del bloque.
    pub tx_index: u32,
    /// Índice del registro de log dentro de la transacción / bloque.
    pub log_index: u32,
    /// Marca de tiempo Unix (en segundos) del bloque.
    pub block_timestamp: u64,
}

impl EventCoordinate {
    /// Crea una nueva coordenada de evento.
    #[must_use]
    pub const fn new(
        block_number: u64,
        tx_index: u32,
        log_index: u32,
        block_timestamp: u64,
    ) -> Self {
        Self {
            block_number,
            tx_index,
            log_index,
            block_timestamp,
        }
    }
}

impl PartialOrd for EventCoordinate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EventCoordinate {
    fn cmp(&self, other: &Self) -> Ordering {
        self.block_number
            .cmp(&other.block_number)
            .then_with(|| self.tx_index.cmp(&other.tx_index))
            .then_with(|| self.log_index.cmp(&other.log_index))
    }
}

impl fmt::Display for EventCoordinate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "b{}:tx{}:log{}@{}",
            self.block_number, self.tx_index, self.log_index, self.block_timestamp
        )
    }
}

/// Evento de registro de nuevo emisor institucional (`ITrustRegistry.IssuerRegistered`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerRegisteredEvent {
    /// Identificador opaco de 32 bytes del emisor (`bytes32`).
    pub issuer_id: [u8; 32],
    /// URI HTTPS canónica del emisor (o seudónimo opaco, REQ-LEDG-007).
    pub uri: String,
    /// Identificadores de perfiles autorizados (ej. `pip-personal-v1`).
    pub profiles: Vec<String>,
    /// Identificadores o hashes de VCTs autorizados.
    pub vcts: Vec<String>,
    /// Inicio de vigencia de la autorización (Unix timestamp).
    pub valid_from: u64,
    /// Fin de vigencia de la autorización (Unix timestamp).
    pub valid_until: u64,
}

/// Evento de suspensión administrativa de un emisor (`ITrustRegistry.IssuerSuspended`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerSuspendedEvent {
    /// Identificador del emisor suspendido.
    pub issuer_id: [u8; 32],
    /// Instante Unix en que expira la suspensión automática (TTL).
    pub expires_at: u64,
    /// Dirección del iniciador de la suspensión.
    pub initiated_by: [u8; 20],
}

/// Evento de rehabilitación o reactivación de un emisor (`ITrustRegistry.IssuerReinstated`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerReinstatedEvent {
    /// Identificador del emisor rehabilitado.
    pub issuer_id: [u8; 32],
}

/// Evento de baja definitiva de un emisor (`ITrustRegistry.IssuerDeregistered`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerDeregisteredEvent {
    /// Identificador del emisor dado de baja.
    pub issuer_id: [u8; 32],
}

/// Evento de adición de clave pública de emisor (`ITrustRegistry.KeyAdded`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAddedEvent {
    /// Identificador del emisor al que pertenece la clave.
    pub issuer_id: [u8; 32],
    /// Identificador canónico de la clave (thumbprint SHA-256 RFC 7638).
    pub kid: [u8; 32],
    /// Clave pública P-256 en formato SEC-1 (33 bytes comprimida o 65 bytes no comprimida).
    pub public_key: Vec<u8>,
}

/// Evento de retiro ordenado de clave pública (`ITrustRegistry.KeyRetired`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRetiredEvent {
    /// Identificador del emisor.
    pub issuer_id: [u8; 32],
    /// Identificador de la clave retirada.
    pub kid: [u8; 32],
    /// Instante Unix a partir del cual la clave quedó retirada.
    pub state_since: u64,
}

/// Evento de suspensión preventiva de clave pública (`ITrustRegistry.KeySuspended`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySuspendedEvent {
    /// Identificador del emisor.
    pub issuer_id: [u8; 32],
    /// Identificador de la clave suspendida.
    pub kid: [u8; 32],
    /// Instante Unix de caducidad automática de la suspensión.
    pub expires_at: u64,
    /// Dirección que ejecutó la suspensión.
    pub initiated_by: [u8; 20],
}

/// Evento de compromiso irrevocable de clave pública (`ITrustRegistry.KeyCompromised`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCompromisedEvent {
    /// Identificador del emisor.
    pub issuer_id: [u8; 32],
    /// Identificador de la clave comprometida.
    pub kid: [u8; 32],
    /// Instante Unix de registro del compromiso.
    pub state_since: u64,
}

/// Evento de registro de verificador autorizado (`ITrustRegistry.VerifierRegistered`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierRegisteredEvent {
    /// Identificador del verificador (`bytes32`).
    pub verifier_id: [u8; 32],
    /// URI del verificador.
    pub uri: String,
    /// Perfiles para los que está autorizado.
    pub profiles: Vec<String>,
    /// Clave pública P-256 SEC-1 opcional para firmas de solicitud offline.
    pub public_key: Vec<u8>,
    /// Inicio de vigencia.
    pub valid_from: u64,
    /// Fin de vigencia.
    pub valid_until: u64,
}

/// Evento de baja de verificador (`ITrustRegistry.VerifierDeregistered`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierDeregisteredEvent {
    /// Identificador del verificador.
    pub verifier_id: [u8; 32],
}

/// Evento de actualización de la raíz de confianza (`ITrustRegistry.TrustRootUpdated`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRootUpdatedEvent {
    /// Hash SHA-256 del documento TrustRoot canónico.
    pub root_hash: [u8; 32],
    /// Versión monotónica incremental de la raíz.
    pub root_version: u64,
    /// Instante Unix de la actualización.
    pub updated_at: u64,
}

/// Evento de actualización de operador firmante de bundle (`ITrustRegistry.BundleSignerUpdated`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSignerUpdatedEvent {
    /// Dirección Ethereum del firmante.
    pub signer_address: [u8; 20],
    /// Identificador de clave del firmante.
    pub kid: [u8; 32],
    /// Clave pública P-256 SEC-1.
    pub public_key: Vec<u8>,
    /// Estado de autorización (true = activo, false = revocado).
    pub authorized: bool,
}

/// Evento de anclaje de manifiesto de estado (`IStatusAnchor.StatusManifestAnchored`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusManifestAnchoredEvent {
    /// Identificador del emisor que ancla su estado.
    pub issuer_id: [u8; 32],
    /// Versión monotónica incremental del manifiesto.
    pub manifest_version: u64,
    /// Hash SHA-256 del IssuerStatusManifest canónico.
    pub manifest_hash: [u8; 32],
    /// Sugerencia de ubicación URI para recuperación de listas.
    pub uri_hint: String,
}

/// Unión de todos los eventos del ledger admitidos por el protocolo.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LedgerEvent {
    /// Emisor registrado.
    IssuerRegistered(IssuerRegisteredEvent),
    /// Emisor suspendido.
    IssuerSuspended(IssuerSuspendedEvent),
    /// Emisor rehabilitado.
    IssuerReinstated(IssuerReinstatedEvent),
    /// Emisor dado de baja.
    IssuerDeregistered(IssuerDeregisteredEvent),
    /// Clave de emisor añadida.
    KeyAdded(KeyAddedEvent),
    /// Clave de emisor retirada.
    KeyRetired(KeyRetiredEvent),
    /// Clave de emisor suspendida.
    KeySuspended(KeySuspendedEvent),
    /// Clave de emisor comprometida.
    KeyCompromised(KeyCompromisedEvent),
    /// Verificador registrado.
    VerifierRegistered(VerifierRegisteredEvent),
    /// Verificador dado de baja.
    VerifierDeregistered(VerifierDeregisteredEvent),
    /// Raíz de confianza actualizada.
    TrustRootUpdated(TrustRootUpdatedEvent),
    /// Firmante de trust bundle actualizado.
    BundleSignerUpdated(BundleSignerUpdatedEvent),
    /// Compromiso de manifiesto de estado anclado.
    StatusManifestAnchored(StatusManifestAnchoredEvent),
}

/// Evento secuenciado con su coordenada temporal y de bloque en el ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencedLedgerEvent {
    /// Coordenada determinista de secuenciación.
    pub coordinate: EventCoordinate,
    /// Carga útil del evento.
    pub event: LedgerEvent,
}

impl SequencedLedgerEvent {
    /// Construye un nuevo evento secuenciado.
    #[must_use]
    pub const fn new(coordinate: EventCoordinate, event: LedgerEvent) -> Self {
        Self { coordinate, event }
    }
}
