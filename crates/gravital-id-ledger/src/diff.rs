//! Comparación y reconciliación pura entre TrustBundle y LedgerState (F6.T08).
//!
//! Trazabilidad:
//! - **REQ-TRUST-008:** Contraste determinista bundle ↔ estado del ledger.
//! - **REQ-TRUST-004:** Modo de verificación completa con fuentes del ledger.
//! - **REQ-LEDG-002:** Detección de compromisos, retiros o discrepancias.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use gravital_id_trust::{IssuerState, KeyState, TrustBundle};

use crate::derivation::hex_string;
use crate::state::LedgerState;

/// Tipo de discrepancia detectada entre un `TrustBundle` y el `LedgerState`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleStateDivergence {
    /// Incompatibilidad en el ID de la cadena blockchain.
    ChainIdMismatch {
        /// Chain ID declarado en el bundle.
        bundle: u64,
        /// Chain ID del estado del ledger.
        ledger: u64,
    },
    /// Incompatibilidad en la dirección del contrato `TrustRegistry`.
    RegistryAddressMismatch {
        /// Dirección en el bundle.
        bundle: String,
        /// Dirección en el ledger.
        ledger: String,
    },
    /// El bloque finalizado del bundle es superior al estado finalizado observado en el ledger.
    FinalizedBlockAheadOfLedger {
        /// Bloque del bundle.
        bundle_block: u64,
        /// Último bloque procesado en el ledger.
        ledger_block: u64,
    },
    /// Emisor presente en el bundle pero ausente en el ledger.
    IssuerMissingInLedger(String),
    /// Emisor activo en el ledger ausente en el bundle.
    ActiveIssuerMissingInBundle(String),
    /// Discrepancia en el estado administrativo del emisor.
    IssuerStateMismatch {
        /// Identificador del emisor.
        issuer_id: String,
        /// Estado declarado en el bundle.
        bundle_state: IssuerState,
        /// Estado efectivo en el ledger.
        ledger_state: IssuerState,
    },
    /// Clave de emisor declarada en el bundle que no existe en el ledger.
    KeyMissingInLedger {
        /// Identificador del emisor.
        issuer_id: String,
        /// Identificador de la clave (`kid`).
        kid: String,
    },
    /// Clave activa en el ledger que falta en el bundle.
    ActiveKeyMissingInBundle {
        /// Identificador del emisor.
        issuer_id: String,
        /// Identificador de la clave (`kid`).
        kid: String,
    },
    /// Discrepancia en el estado de una clave de emisor.
    KeyStateMismatch {
        /// Identificador del emisor.
        issuer_id: String,
        /// Identificador de la clave (`kid`).
        kid: String,
        /// Estado declarado en el bundle.
        bundle_state: KeyState,
        /// Estado efectivo en el ledger.
        ledger_state: KeyState,
    },
    /// ALERTA CRÍTICA DE SEGURIDAD: Una clave figura comprometida en el ledger pero no en el bundle.
    CompromisedKeyNotReflected {
        /// Identificador del emisor.
        issuer_id: String,
        /// Identificador de la clave comprometida.
        kid: String,
    },
    /// Verificador declarado en el bundle no presente o no activo en el ledger.
    VerifierMissingOrInactiveInLedger(String),
}

/// Informe detallado de comparación entre un TrustBundle y el LedgerState.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleDiffReport {
    /// Lista de discrepancias observadas.
    pub divergences: Vec<BundleStateDivergence>,
}

impl BundleDiffReport {
    /// Comprueba si el bundle y el estado son 100% consistentes (0 discrepancias).
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        self.divergences.is_empty()
    }

    /// Comprueba si existe alguna discrepancia crítica de seguridad (ej. claves comprometidas no reflejadas).
    #[must_use]
    pub fn has_critical_security_divergence(&self) -> bool {
        self.divergences.iter().any(|d| {
            matches!(
                d,
                BundleStateDivergence::CompromisedKeyNotReflected { .. }
                    | BundleStateDivergence::ChainIdMismatch { .. }
                    | BundleStateDivergence::RegistryAddressMismatch { .. }
            )
        })
    }
}

/// Realiza una comparación pura entre un `TrustBundle` y el `LedgerState` en el instante indicado.
#[must_use]
pub fn compare_bundle_with_state(
    bundle: &TrustBundle,
    state: &LedgerState,
    at_timestamp: u64,
) -> BundleDiffReport {
    let mut divergences = Vec::new();

    // 1. Validar metadatos de red y contrato
    if bundle.chain_id() != state.chain_id() {
        divergences.push(BundleStateDivergence::ChainIdMismatch {
            bundle: bundle.chain_id(),
            ledger: state.chain_id(),
        });
    }

    if !addresses_equal(bundle.registry_address(), state.registry_address()) {
        divergences.push(BundleStateDivergence::RegistryAddressMismatch {
            bundle: bundle.registry_address().to_string(),
            ledger: state.registry_address().to_string(),
        });
    }

    if let Some(last_coord) = state.last_coordinate() {
        if bundle.finalized_block_number() > last_coord.block_number {
            divergences.push(BundleStateDivergence::FinalizedBlockAheadOfLedger {
                bundle_block: bundle.finalized_block_number(),
                ledger_block: last_coord.block_number,
            });
        }
    }

    // 2. Comparar emisores y claves presentes en el bundle contra el ledger
    for bundle_issuer in bundle.issuers() {
        // Localizar emisor en el ledger
        let ledger_issuer = state.issuers().values().find(|i| {
            (!i.uri.is_empty() && i.uri == bundle_issuer.issuer_id)
                || hex_string(&i.issuer_id) == bundle_issuer.issuer_id
                || format!("0x{}", hex_string(&i.issuer_id)) == bundle_issuer.issuer_id
        });

        let Some(ledger_issuer) = ledger_issuer else {
            divergences.push(BundleStateDivergence::IssuerMissingInLedger(
                bundle_issuer.issuer_id.clone(),
            ));
            continue;
        };

        // Comparar estado efectivo del emisor
        if let Some(effective_state) =
            state.effective_issuer_state(&ledger_issuer.issuer_id, at_timestamp)
        {
            if bundle_issuer.state != effective_state {
                divergences.push(BundleStateDivergence::IssuerStateMismatch {
                    issuer_id: bundle_issuer.issuer_id.clone(),
                    bundle_state: bundle_issuer.state,
                    ledger_state: effective_state,
                });
            }
        }

        // Comparar claves del emisor
        for bundle_key in &bundle_issuer.keys {
            let ledger_key = ledger_issuer.keys.values().find(|k| {
                format!("0x{}", hex_string(&k.kid)) == bundle_key.kid.as_str()
                    || hex_string(&k.kid) == bundle_key.kid.as_str()
            });

            let Some(ledger_key) = ledger_key else {
                divergences.push(BundleStateDivergence::KeyMissingInLedger {
                    issuer_id: bundle_issuer.issuer_id.clone(),
                    kid: bundle_key.kid.as_str().to_string(),
                });
                continue;
            };

            let Some(effective_key_state) =
                state.effective_key_state(&ledger_issuer.issuer_id, &ledger_key.kid, at_timestamp)
            else {
                continue;
            };

            // Detección crítica de clave comprometida
            if effective_key_state == KeyState::Compromised
                && bundle_key.state != KeyState::Compromised
            {
                divergences.push(BundleStateDivergence::CompromisedKeyNotReflected {
                    issuer_id: bundle_issuer.issuer_id.clone(),
                    kid: bundle_key.kid.as_str().to_string(),
                });
            } else if bundle_key.state != effective_key_state {
                divergences.push(BundleStateDivergence::KeyStateMismatch {
                    issuer_id: bundle_issuer.issuer_id.clone(),
                    kid: bundle_key.kid.as_str().to_string(),
                    bundle_state: bundle_key.state,
                    ledger_state: effective_key_state,
                });
            }
        }
    }

    // 3. Detectar emisores o claves activas en el ledger omitidas en el bundle
    for (issuer_id_bytes, ledger_issuer) in state.issuers() {
        let Some(effective_issuer_state) =
            state.effective_issuer_state(issuer_id_bytes, at_timestamp)
        else {
            continue;
        };

        if effective_issuer_state != IssuerState::Active {
            continue;
        }

        // Emisores sin claves activas se omiten del bundle según TRUST_BUNDLE.md §8
        let has_active_keys = ledger_issuer.keys.keys().any(|kid_bytes| {
            state.effective_key_state(issuer_id_bytes, kid_bytes, at_timestamp)
                == Some(KeyState::Active)
        });
        if !has_active_keys {
            continue;
        }

        let bundle_issuer = bundle.issuers().iter().find(|i| {
            (!ledger_issuer.uri.is_empty() && i.issuer_id == ledger_issuer.uri)
                || i.issuer_id == hex_string(issuer_id_bytes)
                || i.issuer_id == format!("0x{}", hex_string(issuer_id_bytes))
        });

        let Some(bundle_issuer) = bundle_issuer else {
            divergences.push(BundleStateDivergence::ActiveIssuerMissingInBundle(
                if ledger_issuer.uri.is_empty() {
                    hex_string(issuer_id_bytes)
                } else {
                    ledger_issuer.uri.clone()
                },
            ));
            continue;
        };

        for kid_bytes in ledger_issuer.keys.keys() {
            let Some(effective_key_state) =
                state.effective_key_state(issuer_id_bytes, kid_bytes, at_timestamp)
            else {
                continue;
            };

            if effective_key_state != KeyState::Active {
                continue;
            }

            let key_in_bundle = bundle_issuer.keys.iter().any(|k| {
                k.kid.as_str() == hex_string(kid_bytes)
                    || k.kid.as_str() == format!("0x{}", hex_string(kid_bytes))
            });

            if !key_in_bundle {
                divergences.push(BundleStateDivergence::ActiveKeyMissingInBundle {
                    issuer_id: bundle_issuer.issuer_id.clone(),
                    kid: hex_string(kid_bytes),
                });
            }
        }
    }

    // 4. Comparar verificadores
    for bundle_verifier in bundle.verifiers() {
        let ledger_verifier = state.verifiers().values().find(|v| {
            (!v.uri.is_empty() && v.uri == bundle_verifier.verifier_id)
                || hex_string(&v.verifier_id) == bundle_verifier.verifier_id
                || format!("0x{}", hex_string(&v.verifier_id)) == bundle_verifier.verifier_id
        });

        if let Some(v) = ledger_verifier {
            if !v.active {
                divergences.push(BundleStateDivergence::VerifierMissingOrInactiveInLedger(
                    bundle_verifier.verifier_id.clone(),
                ));
            }
        } else {
            divergences.push(BundleStateDivergence::VerifierMissingOrInactiveInLedger(
                bundle_verifier.verifier_id.clone(),
            ));
        }
    }

    BundleDiffReport { divergences }
}

fn addresses_equal(a: &str, b: &str) -> bool {
    let clean_a = a.strip_prefix("0x").unwrap_or(a);
    let clean_b = b.strip_prefix("0x").unwrap_or(b);
    clean_a.eq_ignore_ascii_case(clean_b)
}
