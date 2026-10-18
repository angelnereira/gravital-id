//! Motor de sincronización sans-I/O para Gravital ID (F7.T07).
//!
//! Trazabilidad:
//! - **REQ-SYNC-001:** Cola de salida cifrada con claves de idempotencia.
//! - **REQ-SYNC-002:** Entrega al-menos-una-vez con deduplicación en el destinatario.
//! - **REQ-SYNC-003:** Backoff exponencial con jitter.
//! - **REQ-SYNC-004:** Verificación estricta de hash de todo contenido recibido.
//! - **REQ-SYNC-005:** Descargas públicas anónimas sin identificadores.
//! - **REQ-SYNC-006:** Sobres cifrados con HPKE.
//! - **REQ-SYNC-007:** Pool de relays con failover automático.
//! - **INV-01:** Sans-I/O estricto en capa L4.
//! - **INV-02:** Cero datos personales en logs, métricas o errores.
//! - **INV-11:** Inyección de reloj y semilla de aleatoriedad.

use gravital_id_types::{Clock, UnixTime};

use crate::backoff::RetryPolicy;
use crate::dedup::InboundDeduplicationFilter;
use crate::error::SyncError;
use crate::hpke_envelope::HpkeEnvelope;
use crate::model::{DeliveredMessage, MailboxId, OperationId, SyncOperation};
use crate::queue::EncryptedOutboxQueue;
use crate::relay_pool::RelayPool;
use crate::transport::Transport;
use crate::verifier::ContentVerifier;

/// Resultado de una iteración de procesamiento de la cola de salida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboxStepResult {
    /// No había operaciones listas para despachar en la cola.
    Idle,
    /// Operación despachada y confirmada por el relay con éxito.
    Delivered {
        /// Clave de idempotencia de la operación entregada.
        operation_id: OperationId,
        /// URL del relay que confirmó la recepción.
        relay_url: String,
    },
    /// Intento fallido; operación reprogramada con backoff y jitter.
    RetryScheduled {
        /// Clave de idempotencia de la operación.
        operation_id: OperationId,
        /// Instante programado para el siguiente intento.
        next_attempt: UnixTime,
        /// Conteo de reintentos acumulados.
        retry_count: u32,
        /// URL del relay donde ocurrió el fallo.
        relay_url: String,
    },
    /// Operación falló definitivamente tras agotar los reintentos permitidos.
    PermanentlyFailed {
        /// Clave de idempotencia de la operación.
        operation_id: OperationId,
        /// Número total de reintentos agotados.
        retries_exhausted: u32,
    },
}

/// Motor integral sans-I/O de sincronización de operaciones y datos públicos (F7.T07).
pub struct SyncEngine {
    relay_pool: RelayPool,
    outbox: EncryptedOutboxQueue,
    dedup: InboundDeduplicationFilter,
    retry_policy: RetryPolicy,
}

impl SyncEngine {
    /// Construye una nueva instancia del motor de sincronización.
    #[must_use]
    pub fn new(
        relay_pool: RelayPool,
        outbox: EncryptedOutboxQueue,
        dedup: InboundDeduplicationFilter,
        retry_policy: RetryPolicy,
    ) -> Self {
        Self {
            relay_pool,
            outbox,
            dedup,
            retry_policy,
        }
    }

    /// Encola una nueva operación saliente cifrada con su clave de idempotencia (REQ-SYNC-001).
    pub fn enqueue_operation(
        &mut self,
        id: OperationId,
        target_mailbox: MailboxId,
        payload_ciphertext: Vec<u8>,
        now: UnixTime,
        ttl_secs: Option<u64>,
    ) -> Result<(), SyncError> {
        let op = SyncOperation::new(id, target_mailbox, payload_ciphertext, now, ttl_secs);
        self.outbox.enqueue(op)
    }

    /// Ejecuta un paso del ciclo de despacho de la cola de salida (REQ-SYNC-001, REQ-SYNC-003, REQ-SYNC-007).
    ///
    /// # Flujo sans-I/O
    /// 1. Busca la primera operación pendiente cuya hora de intento sea $\le \text{now}$.
    /// 2. Selecciona el relay saludable activo del pool (o conmuta a otro si está penalizado).
    /// 3. Envía el sobre mediante `transport.post_envelope`.
    /// 4. Si el envío es exitoso, marca la operación como `Delivered` y limpia el error del relay.
    /// 5. Si el envío falla, penaliza al relay, calcula el siguiente intento con backoff exponencial
    ///    y jitter simétrico determinista, y reprograma la operación o la marca como fallida definitiva.
    pub fn step_outbox(
        &mut self,
        transport: &dyn Transport,
        clock: &dyn Clock,
        jitter_seed: u64,
    ) -> Result<OutboxStepResult, SyncError> {
        let now = UnixTime::from_seconds(clock.now_seconds());

        let due_id = match self.outbox.peek_due(now) {
            Some(op) => op.id.clone(),
            None => return Ok(OutboxStepResult::Idle),
        };

        let relay_url = self.relay_pool.select_active_relay(now)?.to_string();

        let op = self
            .outbox
            .get(&due_id)
            .ok_or_else(|| SyncError::OperationNotFound(due_id.to_string()))?
            .clone();

        self.outbox.mark_in_flight(&due_id)?;

        match transport.post_envelope(
            &relay_url,
            op.target_mailbox.as_str(),
            op.id.as_str(),
            &op.payload_ciphertext,
            op.ttl_secs,
        ) {
            Ok(()) => {
                self.relay_pool.record_success(&relay_url);
                self.outbox.mark_delivered(&due_id)?;
                Ok(OutboxStepResult::Delivered {
                    operation_id: due_id,
                    relay_url,
                })
            }
            Err(_transport_err) => {
                self.relay_pool.record_failure(&relay_url, now);
                let current_retries = op.retry_count.saturating_add(1);
                let next_attempt =
                    self.retry_policy
                        .compute_next_attempt(current_retries, now, jitter_seed);

                let is_permanent = self.outbox.mark_attempt_failed(
                    &due_id,
                    next_attempt,
                    self.retry_policy.max_retries,
                )?;

                if is_permanent {
                    Ok(OutboxStepResult::PermanentlyFailed {
                        operation_id: due_id,
                        retries_exhausted: current_retries,
                    })
                } else {
                    Ok(OutboxStepResult::RetryScheduled {
                        operation_id: due_id,
                        next_attempt,
                        retry_count: current_retries,
                        relay_url,
                    })
                }
            }
        }
    }

    /// Consulta un buzón de relay, deduplica y descifra los sobres recibidos (REQ-SYNC-002, REQ-SYNC-006).
    pub fn poll_inbox(
        &mut self,
        transport: &dyn Transport,
        mailbox_id: &MailboxId,
        recipient_secret: &[u8; 32],
        aad: &[u8],
        clock: &dyn Clock,
        since: Option<UnixTime>,
    ) -> Result<Vec<DeliveredMessage>, SyncError> {
        let now = UnixTime::from_seconds(clock.now_seconds());
        let relay_url = self.relay_pool.select_active_relay(now)?.to_string();

        let envelopes = match transport.fetch_envelopes(&relay_url, mailbox_id.as_str(), since) {
            Ok(envs) => {
                self.relay_pool.record_success(&relay_url);
                envs
            }
            Err(e) => {
                self.relay_pool.record_failure(&relay_url, now);
                return Err(e);
            }
        };

        let mut delivered = Vec::new();

        for env in envelopes {
            // Deduplicación en el receptor (REQ-SYNC-002)
            if !self.dedup.check_and_record(&env.envelope_id, now) {
                // Sobre duplicado: confirmar en el relay para evitar reentregas futuras y saltar
                let _ = transport.ack_envelope(&relay_url, mailbox_id.as_str(), &env.envelope_id);
                continue;
            }

            // Descifrado HPKE (REQ-SYNC-006)
            let plaintext = HpkeEnvelope::open(recipient_secret, &env.payload, aad)?;

            // Confirmar recepción en el relay
            let _ = transport.ack_envelope(&relay_url, mailbox_id.as_str(), &env.envelope_id);

            delivered.push(DeliveredMessage {
                envelope_id: env.envelope_id,
                mailbox_id: mailbox_id.clone(),
                plaintext_payload: plaintext,
                received_at: now,
            });
        }

        Ok(delivered)
    }

    /// Descarga un objeto público verificando su integridad sin transmitir identificadores (REQ-SYNC-004, REQ-SYNC-005).
    pub fn download_public_object(
        &mut self,
        transport: &dyn Transport,
        sha256_hex: &str,
        clock: &dyn Clock,
    ) -> Result<Vec<u8>, SyncError> {
        let now = UnixTime::from_seconds(clock.now_seconds());
        let relay_url = self.relay_pool.select_active_relay(now)?.to_string();

        ContentVerifier::assert_anonymous_public_request(sha256_hex)?;

        let data = match transport.get_object(&relay_url, sha256_hex) {
            Ok(bytes) => {
                self.relay_pool.record_success(&relay_url);
                bytes
            }
            Err(e) => {
                self.relay_pool.record_failure(&relay_url, now);
                return Err(e);
            }
        };

        // Verificación estricta de hash (REQ-SYNC-004, INV-05)
        ContentVerifier::verify_object_sha256(&data, sha256_hex)?;

        Ok(data)
    }

    /// Referencia a la cola de salida para inspección de métricas.
    #[must_use]
    pub fn outbox(&self) -> &EncryptedOutboxQueue {
        &self.outbox
    }

    /// Referencia mutable a la cola de salida.
    pub fn outbox_mut(&mut self) -> &mut EncryptedOutboxQueue {
        &mut self.outbox
    }

    /// Referencia al filtro de deduplicación.
    #[must_use]
    pub fn dedup(&self) -> &InboundDeduplicationFilter {
        &self.dedup
    }

    /// Referencia al pool de relays.
    #[must_use]
    pub fn relay_pool(&self) -> &RelayPool {
        &self.relay_pool
    }
}
