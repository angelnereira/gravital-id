//! Motor central de indexación determinista de eventos finalizados (F7.T03, REQ-LEDG-005).

use crate::config::IndexerConfig;
use crate::error::IndexerError;
use crate::metrics::LagMetrics;
use crate::storage::IndexerStorage;
use gravital_id_ledger::LedgerAdapter;
use gravital_id_types::Clock;
use pip_service_common::shutdown::ShutdownCoordinator;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Motor de indexación que orquesta el consumo de bloques finalizados del ledger y su persistencia.
pub struct IndexerEngine {
    adapter: Arc<dyn LedgerAdapter + Send + Sync>,
    storage: Arc<dyn IndexerStorage>,
    clock: Arc<dyn Clock + Send + Sync>,
    config: IndexerConfig,
    shutdown: ShutdownCoordinator,
    metrics: Arc<Mutex<Option<LagMetrics>>>,
}

impl IndexerEngine {
    /// Construye una nueva instancia del motor de indexación con inyección de reloj y dependencias.
    #[must_use]
    pub fn new(
        adapter: Arc<dyn LedgerAdapter + Send + Sync>,
        storage: Arc<dyn IndexerStorage>,
        clock: Arc<dyn Clock + Send + Sync>,
        config: IndexerConfig,
        shutdown: ShutdownCoordinator,
        metrics: Arc<Mutex<Option<LagMetrics>>>,
    ) -> Self {
        Self {
            adapter,
            storage,
            clock,
            config,
            shutdown,
            metrics,
        }
    }

    /// Retorna una copia de las últimas métricas de retraso calculadas, si existen.
    #[must_use]
    pub fn current_metrics(&self) -> Option<LagMetrics> {
        self.metrics.lock().ok().and_then(|g| *g)
    }

    /// Ejecuta un paso individual de indexación.
    ///
    /// # Flujo:
    /// 1. Lee la última altura de bloque procesada desde el almacenamiento (o `start_block`).
    /// 2. Consulta la cabeza finalizada (`finalized_head`) del adaptador del ledger (**REQ-LEDG-005**).
    /// 3. Actualiza las métricas de retraso (`LagMetrics`).
    /// 4. Si la cabeza finalizada es menor que el cursor guardado (reorganización que afectó la frontera),
    ///    rebobina de forma segura el cursor a la altura finalizada actual.
    /// 5. Si hay bloques finalizados pendientes, calcula la ventana `[from_block, to_block]` acotada
    ///    por `chunk_size_blocks`.
    /// 6. Recupera los eventos del rango, los persiste de forma idempotente (`store_events`) y actualiza
    ///    el punto de control (`save_checkpoint`).
    ///
    /// # Errores
    /// Devuelve [`IndexerError`] si la consulta al ledger o la persistencia en base de datos fallan.
    pub fn step(&self) -> Result<Option<u64>, IndexerError> {
        let chain_id = self.config.chain_id;
        let last_checkpoint = self.storage.get_checkpoint(chain_id)?;

        let finalized_header = self
            .adapter
            .finalized_head()
            .map_err(|e| IndexerError::Ledger(format!("Error consultando finalized_head: {e}")))?;
        let finalized_head = finalized_header.block_number;

        let now = self.clock.now_seconds();

        // 1. Manejo de reorg o retroceso de bloque finalizado
        if let Some(processed) = last_checkpoint {
            if finalized_head < processed {
                tracing::warn!(
                    chain_id = chain_id,
                    finalized_head = finalized_head,
                    processed = processed,
                    "Reorganización detectada en frontera finalizada: rebobinando cursor"
                );
                self.storage
                    .rewind_to_block(chain_id, finalized_head, now)?;
                self.update_metrics(finalized_head, finalized_head, now);
                return Ok(Some(finalized_head));
            }
        }

        let current_cursor = last_checkpoint.unwrap_or(self.config.start_block);
        self.update_metrics(finalized_head, current_cursor, now);

        // 2. Si ya estamos al día con la cabeza finalizada, no hay nada que procesar
        if last_checkpoint.is_some() && current_cursor >= finalized_head {
            return Ok(None);
        }

        // 3. Determinar el rango a escanear
        let from_block = if last_checkpoint.is_none() {
            self.config.start_block
        } else {
            current_cursor.saturating_add(1)
        };

        if from_block > finalized_head {
            return Ok(None);
        }

        let max_chunk = self.config.chunk_size_blocks.saturating_sub(1);
        let to_block = from_block.saturating_add(max_chunk).min(finalized_head);

        tracing::info!(
            chain_id = chain_id,
            from_block = from_block,
            to_block = to_block,
            finalized_head = finalized_head,
            "Indexando rango de bloques finalizados"
        );

        // 4. Ingesta acotada estrictamente a bloques finalizados (REQ-LEDG-005)
        let events = self
            .adapter
            .fetch_events(from_block, to_block)
            .map_err(|e| IndexerError::Ledger(format!("Error en fetch_events: {e}")))?;

        let inserted = self.storage.store_events(chain_id, &events)?;

        self.storage
            .save_checkpoint(chain_id, to_block, None, now)?;

        self.update_metrics(finalized_head, to_block, now);

        tracing::info!(
            chain_id = chain_id,
            to_block = to_block,
            events_count = events.len(),
            newly_inserted = inserted,
            "Lote de eventos procesado y checkpoint actualizado"
        );

        Ok(Some(to_block))
    }

    /// Rebobina el índice a una altura de bloque anterior para forzar el reprocesamiento histórico.
    ///
    /// # Errores
    /// Devuelve [`IndexerError`] si la operación en el almacenamiento falla.
    pub fn reprocess_from_block(&self, target_block: u64) -> Result<(), IndexerError> {
        let chain_id = self.config.chain_id;
        tracing::info!(
            chain_id = chain_id,
            target_block = target_block,
            "Solicitado reprocesamiento histórico desde altura"
        );

        let now = self.clock.now_seconds();
        self.storage.rewind_to_block(chain_id, target_block, now)?;

        let finalized_head = self
            .adapter
            .finalized_head()
            .map(|h| h.block_number)
            .unwrap_or(target_block);
        self.update_metrics(finalized_head, target_block, now);

        Ok(())
    }

    /// Ejecuta el bucle continuo del indexador respetando las señales de parada limpia.
    pub fn run_loop(&self) {
        let poll_duration = Duration::from_millis(self.config.poll_interval_millis);

        tracing::info!(
            chain_id = self.config.chain_id,
            poll_interval_ms = self.config.poll_interval_millis,
            "Iniciando bucle continuo de pip-indexer"
        );

        while !self.shutdown.is_shutting_down() {
            match self.step() {
                Ok(Some(_)) => {
                    // Si se procesó un lote y aún puede haber más bloques, no esperamos el intervalo completo
                }
                Ok(None) => {
                    // Al día con la cabeza finalizada: esperar intervalo de sondeo
                    thread::sleep(poll_duration);
                }
                Err(e) => {
                    tracing::error!(error = %e, "Error durante paso de indexación; reintentando");
                    thread::sleep(poll_duration);
                }
            }
        }

        tracing::info!("Bucle de indexación finalizado ordenadamente");
    }

    fn update_metrics(&self, finalized_head: u64, indexed_head: u64, timestamp: u64) {
        if let Ok(mut guard) = self.metrics.lock() {
            *guard = Some(LagMetrics::compute(finalized_head, indexed_head, timestamp));
        }
    }
}
