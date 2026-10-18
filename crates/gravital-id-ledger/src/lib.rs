//! # `gravital-id-ledger`
//!
//! Trait de adaptador de ledger, secuenciación de eventos, reconstrucción pura del estado
//! y derivación determinista del trust bundle para Gravital ID (F6.T08).
//!
//! - **Capa arquitectónica:** L4 (sans-I/O)
//! - **Garantía no_std:** No (utiliza `alloc` / `std` para BTreeMap y serialización, pero es 100% sans-I/O sin red)
//!
//! Trazabilidad:
//! - **REQ-LEDG-002:** El acceso al ledger DEBE abstraerse con `LedgerAdapter`.
//! - **REQ-TRUST-004:** El modo de verificación completa DEBE contrastar el bundle con $\ge 2$ fuentes de ledger independientes (F7.T08).
//! - **REQ-TRUST-008:** El bundle DEBE derivarse de forma determinista del estado finalizado
//!   (payload canónico), de modo que operadores independientes obtengan bytes idénticos.
//! - **REQ-LEDG-004:** Control de ciclo de vida, estados irreversibles y retardo de timelock.
//! - **REQ-LEDG-001 / REQ-LEDG-007 / INV-02:** Cero datos personales en tipos y eventos del ledger.
//! - **INV-01:** Verificación y lógica de núcleo sans-I/O sin llamadas de red.
//! - **INV-16:** Prohibición absoluta de confiar en una sola fuente en modo de verificación completa.

#![forbid(unsafe_code)]

extern crate alloc;

pub mod adapter;
pub mod derivation;
pub mod diff;
pub mod error;
pub mod event;
pub mod full_verification;
pub mod state;

pub use adapter::{BlockHeader, InMemoryLedgerAdapter, LedgerAdapter, StatusCommitmentRecord};
pub use derivation::{derive_trust_bundle, hex_string, BundleDerivationParams, DerivedBundle};
pub use diff::{compare_bundle_with_state, BundleDiffReport, BundleStateDivergence};
pub use error::{LedgerError, LedgerResult};
pub use event::{
    BundleSignerUpdatedEvent, EventCoordinate, IssuerDeregisteredEvent, IssuerRegisteredEvent,
    IssuerReinstatedEvent, IssuerSuspendedEvent, KeyAddedEvent, KeyCompromisedEvent,
    KeyRetiredEvent, KeySuspendedEvent, LedgerEvent, SequencedLedgerEvent,
    StatusManifestAnchoredEvent, TrustRootUpdatedEvent, VerifierDeregisteredEvent,
    VerifierRegisteredEvent,
};
pub use full_verification::{
    BundleDivergenceAlarm, CrossLedgerDivergenceAlarm, FullVerificationEngine,
    FullVerificationOutcome, FullVerificationPolicy, SourceCheckpoint,
};
pub use state::{
    BundleSignerStateRecord, IssuerLifecycleState, IssuerStateRecord, KeyLifecycleState,
    KeyStateRecord, LedgerState, TrustRootRecord, VerifierStateRecord,
};

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
