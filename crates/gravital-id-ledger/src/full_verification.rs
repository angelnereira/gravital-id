//! Modo de verificación completa multi-fuente de TrustBundle (F7.T08).
//!
//! Trazabilidad:
//! - **REQ-TRUST-004:** El modo de verificación completa DEBE contrastar el bundle con $\ge 2$ fuentes de ledger independientes.
//! - **P-10:** Resiliencia y descentralización de la confianza.
//! - **INV-01:** Capa L4 sans-I/O: la orquestación y contraste de fuentes es determinista y no realiza I/O directo.
//! - **INV-02:** Cero datos personales o identificadores de titulares en alarmas y diagnósticos.
//! - **INV-04:** Modelo estructurado con diagnósticos y evidencia (nunca un booleano plano).
//! - **INV-05:** Fail-closed ante cualquier discrepancia, fallo de fuente o ambigüedad.
//! - **INV-11:** Marca temporal inyectada deterministamente.
//! - **INV-16:** Prohibición absoluta de confiar en una sola fuente en modo de verificación completa.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use gravital_id_trust::TrustBundle;

use crate::adapter::{BlockHeader, LedgerAdapter};
use crate::diff::{compare_bundle_with_state, BundleDiffReport, BundleStateDivergence};
use crate::error::{LedgerError, LedgerResult};
use crate::state::LedgerState;

/// Política de configuración del modo de verificación completa (REQ-TRUST-004).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullVerificationPolicy {
    /// Número mínimo de fuentes independientes de ledger requeridas (DEBE ser $\ge 2$).
    min_sources: usize,
    /// Desviación máxima tolerada de bloques finalizados entre fuentes (drift).
    max_allowed_block_drift: u64,
    /// Si es `true`, todas las fuentes deben haber finalizado al menos el bloque del bundle.
    require_bundle_block_covered: bool,
}

impl FullVerificationPolicy {
    /// Crea una nueva política de verificación completa validando que `min_sources >= 2`.
    ///
    /// # Errores
    /// [`LedgerError::InvalidPolicy`] si `min_sources < 2` (REQ-TRUST-004, INV-16).
    pub fn new(min_sources: usize, max_allowed_block_drift: u64) -> LedgerResult<Self> {
        if min_sources < 2 {
            return Err(LedgerError::InvalidPolicy(
                "min_sources must be >= 2 for full verification mode (REQ-TRUST-004, INV-16)",
            ));
        }
        Ok(Self {
            min_sources,
            max_allowed_block_drift,
            require_bundle_block_covered: true,
        })
    }

    /// Retorna la política estándar recomendada: mínimo 2 fuentes y 100 bloques de drift.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            min_sources: 2,
            max_allowed_block_drift: 100,
            require_bundle_block_covered: true,
        }
    }

    /// Retorna el número mínimo de fuentes requeridas.
    #[must_use]
    pub const fn min_sources(&self) -> usize {
        self.min_sources
    }

    /// Retorna el drift máximo de bloques tolerado entre fuentes.
    #[must_use]
    pub const fn max_allowed_block_drift(&self) -> u64 {
        self.max_allowed_block_drift
    }

    /// Configura si se requiere que todas las fuentes cubran el bloque finalizado del bundle.
    #[must_use]
    pub const fn with_require_bundle_block_covered(mut self, require: bool) -> Self {
        self.require_bundle_block_covered = require;
        self
    }
}

/// Punto de control de bloque finalizado y métricas de una fuente de ledger individual.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCheckpoint {
    /// Identificador descriptivo de la fuente (ej. `"rpc-node-1"`, `"alchemy-mainnet"`).
    pub source_id: String,
    /// Identificador de la red blockchain (EIP-155).
    pub chain_id: u64,
    /// Cabecera del bloque finalizado más reciente reportado por la fuente.
    pub finalized_head: BlockHeader,
    /// Total de eventos aplicados para reconstruir el estado.
    pub events_count: usize,
}

/// Alarma estructurada cuando el trust bundle diverge de una o más fuentes del ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleDivergenceAlarm {
    /// Época del bundle examinado.
    pub bundle_epoch: u64,
    /// Versión del bundle examinado.
    pub bundle_version: u64,
    /// Bloque finalizado declarado en el bundle.
    pub bundle_finalized_block: u64,
    /// Discrepancias observadas indexadas por el identificador de la fuente.
    pub divergences_by_source: BTreeMap<String, Vec<BundleStateDivergence>>,
    /// Indica si al menos una discrepancia es crítica de seguridad (ej. clave comprometida no reflejada).
    pub has_critical_security_divergence: bool,
    /// Marca de tiempo de emisión de la alarma.
    pub at_timestamp: u64,
}

/// Alarma estructurada cuando las propias fuentes del ledger difieren entre sí (bifurcación o RPC manipulado).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossLedgerDivergenceAlarm {
    /// Descripción técnica de la discrepancia inter-ledger detectada.
    pub reason: String,
    /// Fuentes involucradas en la discrepancia.
    pub sources_involved: Vec<String>,
    /// Marca de tiempo de emisión de la alarma.
    pub at_timestamp: u64,
}

/// Resultado de la verificación completa multi-fuente de un TrustBundle (REQ-TRUST-004).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FullVerificationOutcome {
    /// El TrustBundle es plenamente consistente con $\ge 2$ fuentes de ledger independientes.
    Verified {
        /// Lista de identificadores de las fuentes que confirmaron consistencia.
        sources_verified: Vec<String>,
        /// Checkpoints de los bloques finalizados en cada fuente.
        checkpoints: Vec<SourceCheckpoint>,
        /// Marca de tiempo de la verificación.
        at_timestamp: u64,
    },
    /// Rechazo: El bundle diverge del estado del ledger en una o más fuentes.
    BundleDivergence(BundleDivergenceAlarm),
    /// Rechazo: Las propias fuentes del ledger divergen entre sí (bifurcación de red o proveedor corrupto).
    CrossLedgerDivergence(CrossLedgerDivergenceAlarm),
    /// Rechazo: Menos de 2 fuentes independientes disponibles o respondiendo adecuadamente (fail-closed, INV-05).
    InsufficientSources {
        /// Fuentes requeridas por política ($\ge 2$).
        required: usize,
        /// Fuentes saludables obtenidas.
        available: usize,
        /// Detalle de fuentes que fallaron o no respondieron.
        failed_sources: Vec<(String, String)>,
    },
}

impl FullVerificationOutcome {
    /// Retorna `true` si el resultado es `Verified`.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }
}

/// Motor del modo de verificación completa multi-fuente de TrustBundle (REQ-TRUST-004).
#[derive(Debug, Clone)]
pub struct FullVerificationEngine {
    policy: FullVerificationPolicy,
}

impl FullVerificationEngine {
    /// Construye un nuevo motor con la política provista.
    #[must_use]
    pub const fn new(policy: FullVerificationPolicy) -> Self {
        Self { policy }
    }

    /// Construye un nuevo motor con la política estándar por defecto.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            policy: FullVerificationPolicy::standard(),
        }
    }

    /// Retorna una referencia a la política configurada.
    #[must_use]
    pub const fn policy(&self) -> &FullVerificationPolicy {
        &self.policy
    }

    /// Ejecuta el contraste multi-fuente de `bundle` contra $\ge 2$ fuentes de ledger (REQ-TRUST-004).
    ///
    /// # Flujo de verificación:
    /// 1. Consulta la cabecera finalizada y los eventos de cada fuente provista.
    /// 2. Valida que al menos `policy.min_sources` ($\ge 2$) fuentes hayan respondido exitosamente.
    /// 3. Reconstruye el `LedgerState` de cada fuente deterministamente.
    /// 4. Contrasta la consistencia entre las fuentes (mismo `chain_id`, drift de bloques $\le$ umbral).
    /// 5. Contrasta el `bundle` contra el estado de cada fuente usando [`compare_bundle_with_state`].
    /// 6. Ante cualquier discrepancia, emite alarma estructurada y rechaza de forma fail-closed (`INV-05`).
    pub fn verify_bundle(
        &self,
        bundle: &TrustBundle,
        sources: &[(&str, &dyn LedgerAdapter)],
        now_timestamp: u64,
    ) -> FullVerificationOutcome {
        let mut healthy_sources = Vec::new();
        let mut failed_sources = Vec::new();

        // 1. Consultar cabeceras y eventos de cada fuente
        for &(source_id, adapter) in sources {
            let head = match adapter.finalized_head() {
                Ok(h) => h,
                Err(e) => {
                    failed_sources.push((source_id.to_string(), e.to_string()));
                    continue;
                }
            };

            // Validar si cubre el bloque del bundle en caso de exigirse
            if self.policy.require_bundle_block_covered
                && head.block_number < bundle.finalized_block_number()
            {
                failed_sources.push((
                    source_id.to_string(),
                    format!(
                        "finalized block {} is behind bundle finalized block {}",
                        head.block_number,
                        bundle.finalized_block_number()
                    ),
                ));
                continue;
            }

            // Consultar eventos finalizados hasta la cabecera
            let events = match adapter.fetch_events(0, head.block_number) {
                Ok(evs) => evs,
                Err(e) => {
                    failed_sources.push((source_id.to_string(), e.to_string()));
                    continue;
                }
            };

            // Reconstruir estado determinista de la fuente
            let mut state =
                LedgerState::new(adapter.chain_id(), bundle.registry_address().to_string());

            let mut apply_error = None;
            for ev in &events {
                if let Err(e) = state.apply_event(ev) {
                    apply_error = Some(e);
                    break;
                }
            }

            if let Some(err) = apply_error {
                failed_sources.push((
                    source_id.to_string(),
                    format!("failed to reconstruct state from events: {err}"),
                ));
                continue;
            }

            let checkpoint = SourceCheckpoint {
                source_id: source_id.to_string(),
                chain_id: adapter.chain_id(),
                finalized_head: head,
                events_count: events.len(),
            };

            healthy_sources.push((source_id.to_string(), checkpoint, state));
        }

        // 2. Verificar cota mínima de fuentes saludables (fail-closed si < min_sources)
        if healthy_sources.len() < self.policy.min_sources {
            return FullVerificationOutcome::InsufficientSources {
                required: self.policy.min_sources,
                available: healthy_sources.len(),
                failed_sources,
            };
        }

        // 3. Contraste cruzado inter-ledger (Cross-Ledger Consistency)
        if let Some(cross_alarm) =
            self.check_cross_ledger_consistency(&healthy_sources, now_timestamp)
        {
            return FullVerificationOutcome::CrossLedgerDivergence(cross_alarm);
        }

        // 4. Contraste de cada fuente contra el TrustBundle
        let mut divergences_by_source = BTreeMap::new();
        let mut has_critical_security = false;
        let mut sources_verified = Vec::new();
        let mut checkpoints = Vec::new();

        for (source_id, checkpoint, state) in healthy_sources {
            let diff_report: BundleDiffReport =
                compare_bundle_with_state(bundle, &state, now_timestamp);

            if !diff_report.is_consistent() {
                if diff_report.has_critical_security_divergence() {
                    has_critical_security = true;
                }
                divergences_by_source.insert(source_id.clone(), diff_report.divergences);
            } else {
                sources_verified.push(source_id);
                checkpoints.push(checkpoint);
            }
        }

        // 5. Evaluar resultado y emitir alarma ante cualquier divergencia
        if !divergences_by_source.is_empty() {
            return FullVerificationOutcome::BundleDivergence(BundleDivergenceAlarm {
                bundle_epoch: bundle.bundle_epoch(),
                bundle_version: bundle.bundle_version(),
                bundle_finalized_block: bundle.finalized_block_number(),
                divergences_by_source,
                has_critical_security_divergence: has_critical_security,
                at_timestamp: now_timestamp,
            });
        }

        FullVerificationOutcome::Verified {
            sources_verified,
            checkpoints,
            at_timestamp: now_timestamp,
        }
    }

    /// Verifica que todas las fuentes de ledger coincidan en red, contrato y drift acotado.
    fn check_cross_ledger_consistency(
        &self,
        sources: &[(String, SourceCheckpoint, LedgerState)],
        now_timestamp: u64,
    ) -> Option<CrossLedgerDivergenceAlarm> {
        let first = sources.first()?;
        let expected_chain_id = first.1.chain_id;

        let mut min_block = first.1.finalized_head.block_number;
        let mut max_block = first.1.finalized_head.block_number;
        let mut min_source = &first.0;
        let mut max_source = &first.0;

        for (id, cp, _) in sources {
            // Mismo chain_id
            if cp.chain_id != expected_chain_id {
                return Some(CrossLedgerDivergenceAlarm {
                    reason: format!(
                        "sources disagree on chain_id: '{}' has {} while '{}' has {}",
                        first.0, expected_chain_id, id, cp.chain_id
                    ),
                    sources_involved: alloc::vec![first.0.clone(), id.clone()],
                    at_timestamp: now_timestamp,
                });
            }

            // Seguimiento de drift de bloques
            if cp.finalized_head.block_number < min_block {
                min_block = cp.finalized_head.block_number;
                min_source = id;
            }
            if cp.finalized_head.block_number > max_block {
                max_block = cp.finalized_head.block_number;
                max_source = id;
            }
        }

        let drift = max_block.saturating_sub(min_block);
        if drift > self.policy.max_allowed_block_drift {
            return Some(CrossLedgerDivergenceAlarm {
                reason: format!(
                    "block drift between sources exceeds policy limit: source '{}' (block {}) vs source '{}' (block {}) has drift {} > max allowed {}",
                    min_source, min_block, max_source, max_block, drift, self.policy.max_allowed_block_drift
                ),
                sources_involved: alloc::vec![min_source.clone(), max_source.clone()],
                at_timestamp: now_timestamp,
            });
        }

        None
    }
}
