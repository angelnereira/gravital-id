//! Motor orquestador de derivación, cofirma y publicación de Trust Bundles (F7.T04).

use crate::aggregator::UntrustedBundleAggregator;
use crate::config::TrustServiceConfig;
use crate::error::TrustServiceError;
use crate::health::LastAggregationStatus;
use crate::operator::TrustOperatorNode;
use crate::publisher::{BundlePublisher, PublishedBundleRecord};
use gravital_id_crypto::jwk::JwkEcP256;
use gravital_id_ledger::adapter::BlockHeader;
use gravital_id_ledger::BundleDerivationParams;
use gravital_id_trust::PolicyEntry;
use gravital_id_types::Clock;
use pip_service_common::shutdown::ShutdownCoordinator;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Motor central de `pip-trust-service`.
pub struct TrustServiceEngine {
    primary_node: Arc<TrustOperatorNode>,
    operator_nodes: Vec<Arc<TrustOperatorNode>>,
    aggregator: UntrustedBundleAggregator,
    publisher: Arc<dyn BundlePublisher>,
    clock: Arc<dyn Clock + Send + Sync>,
    config: TrustServiceConfig,
    shutdown: ShutdownCoordinator,
    status: Arc<Mutex<Option<LastAggregationStatus>>>,
}

/// Dependencias operativas requeridas para inicializar [`TrustServiceEngine`].
pub struct TrustEngineDeps {
    /// Nodo operador primario local.
    pub primary_node: Arc<TrustOperatorNode>,
    /// Lista de nodos operadores institucionales remotos o pares.
    pub operator_nodes: Vec<Arc<TrustOperatorNode>>,
    /// Agregador no confiable de firmas JWS.
    pub aggregator: UntrustedBundleAggregator,
    /// Publicador en almacenamiento de artefactos (S3 / disco / memoria).
    pub publisher: Arc<dyn BundlePublisher>,
    /// Reloj determinista inyectado (INV-11).
    pub clock: Arc<dyn Clock + Send + Sync>,
    /// Coordinador de parada ordenada.
    pub shutdown: ShutdownCoordinator,
    /// Estado compartido de observabilidad.
    pub status: Arc<Mutex<Option<LastAggregationStatus>>>,
}

impl TrustServiceEngine {
    /// Construye una nueva instancia del motor de confianza.
    #[must_use]
    pub fn new(config: TrustServiceConfig, deps: TrustEngineDeps) -> Self {
        Self {
            primary_node: deps.primary_node,
            operator_nodes: deps.operator_nodes,
            aggregator: deps.aggregator,
            publisher: deps.publisher,
            clock: deps.clock,
            config,
            shutdown: deps.shutdown,
            status: deps.status,
        }
    }

    /// Retorna una copia del último estado de agregación si existe.
    #[must_use]
    pub fn current_status(&self) -> Option<LastAggregationStatus> {
        self.status.lock().ok().and_then(|g| g.clone())
    }

    /// Ejecuta un ciclo de derivación, recolección de firmas, agregación y publicación.
    ///
    /// # Errores
    /// Devuelve [`TrustServiceError`] ante fallos de derivación, insuficiencia de firmas o error de I/O.
    pub fn step(
        &self,
        finalized_block: BlockHeader,
        policies: Vec<PolicyEntry>,
    ) -> Result<PublishedBundleRecord, TrustServiceError> {
        let now = self.clock.now_seconds();
        let params = BundleDerivationParams::new(
            self.config.framework_id.clone(),
            self.config.bundle_epoch,
            self.config.bundle_version,
            finalized_block,
            self.config.validity_duration_seconds,
            policies,
        );

        // 1. Derivar el bundle canónico de referencia desde el propio indexador (REQ-TRUST-003, REQ-TRUST-008)
        let reference_bundle = match self.primary_node.derive_local_bundle(&params) {
            Ok(b) => b,
            Err(e) => {
                self.record_failure(now, &e.to_string());
                return Err(e);
            }
        };

        // 2. Recopilar firmas de todos los operadores participantes
        let mut responses = Vec::new();
        let mut keys_by_kid: BTreeMap<String, JwkEcP256> = BTreeMap::new();

        // 2a. Operador primario local
        match self.primary_node.evaluate_and_sign(&params) {
            Ok(resp) => {
                keys_by_kid.insert(
                    self.primary_node.kid().to_string(),
                    self.primary_node.signer().public_key().clone(),
                );
                responses.push(resp);
            }
            Err(e) => {
                tracing::warn!(
                    operator = %self.primary_node.operator_id(),
                    error = %e,
                    "Fallo al firmar con operador primario"
                );
            }
        }

        // 2b. Operadores adicionales (independientes)
        for op in &self.operator_nodes {
            keys_by_kid.insert(op.kid().to_string(), op.signer().public_key().clone());
            match op.evaluate_and_sign(&params) {
                Ok(resp) => responses.push(resp),
                Err(e) => {
                    tracing::warn!(
                        operator = %op.operator_id(),
                        error = %e,
                        "Fallo al firmar con operador institucional"
                    );
                }
            }
        }

        // 3. Agregación no confiable: detección de divergencia y verificación de umbral k-de-n
        let aggregated =
            match self
                .aggregator
                .aggregate(&reference_bundle, &responses, &keys_by_kid)
            {
                Ok(agg) => agg,
                Err(e) => {
                    self.record_failure(now, &e.to_string());
                    return Err(e);
                }
            };

        tracing::info!(
            epoch = self.config.bundle_epoch,
            version = self.config.bundle_version,
            distinct_operators = aggregated.distinct_operators,
            divergent_count = aggregated.divergent_operators.len(),
            "Trust Bundle cofirmado exitosamente con quórum"
        );

        // 4. Publicación en almacenamiento de objetos / CDN
        let record = match self.publisher.publish_bundle(
            self.config.bundle_epoch,
            self.config.bundle_version,
            &aggregated.jws_json,
            &aggregated.canonical_digest,
            now,
        ) {
            Ok(rec) => rec,
            Err(e) => {
                self.record_failure(now, &e.to_string());
                return Err(e);
            }
        };

        // 5. Registrar éxito en estado
        if let Ok(mut guard) = self.status.lock() {
            *guard = Some(LastAggregationStatus {
                timestamp: now,
                success: true,
                last_bundle: Some(aggregated),
                error_message: None,
            });
        }

        Ok(record)
    }

    /// Ejecuta el bucle de servicio respetando señales de terminación limpia.
    pub fn run_loop<F>(&self, mut header_supplier: F)
    where
        F: FnMut() -> Option<(BlockHeader, Vec<PolicyEntry>)>,
    {
        let poll_duration = Duration::from_millis(self.config.poll_interval_millis);

        tracing::info!(
            service = "pip-trust-service",
            poll_interval_ms = self.config.poll_interval_millis,
            "Iniciando bucle de servicio de confianza"
        );

        while !self.shutdown.is_shutting_down() {
            if let Some((header, policies)) = header_supplier() {
                if let Err(e) = self.step(header, policies) {
                    tracing::error!(error = %e, "Error durante ciclo de cofirma");
                }
            }
            thread::sleep(poll_duration);
        }

        tracing::info!("Bucle de pip-trust-service finalizado ordenadamente");
    }

    fn record_failure(&self, timestamp: u64, message: &str) {
        if let Ok(mut guard) = self.status.lock() {
            *guard = Some(LastAggregationStatus {
                timestamp,
                success: false,
                last_bundle: None,
                error_message: Some(message.to_string()),
            });
        }
    }
}
