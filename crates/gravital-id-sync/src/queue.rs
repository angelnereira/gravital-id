//! Cola de salida de operaciones pendientes con clave de idempotencia (REQ-SYNC-001).
//!
//! Trazabilidad:
//! - **REQ-SYNC-001:** Las operaciones pendientes DEBEN guardarse en una cola cifrada con claves de idempotencia.
//! - **INV-01:** Sans-I/O: la cola es pura en memoria y serializable para persistencia cifrada.
//! - **INV-05:** Fail-closed ante duplicidad de claves o transiciones inválidas.

use gravital_id_types::UnixTime;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::error::SyncError;
use crate::model::{OperationId, OperationStatus, SyncOperation};

/// Límite por defecto de operaciones pendientes en la cola de salida.
pub const DEFAULT_MAX_QUEUE_CAPACITY: usize = 1_000;

/// Cola de salida de operaciones de sincronización pendientes (REQ-SYNC-001).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedOutboxQueue {
    max_capacity: usize,
    operations: BTreeMap<OperationId, SyncOperation>,
}

impl Default for EncryptedOutboxQueue {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_QUEUE_CAPACITY)
    }
}

impl EncryptedOutboxQueue {
    /// Crea una nueva cola con la capacidad máxima indicada.
    #[must_use]
    pub fn new(max_capacity: usize) -> Self {
        Self {
            max_capacity: if max_capacity == 0 { 1 } else { max_capacity },
            operations: BTreeMap::new(),
        }
    }

    /// Encola una nueva operación saliente garantizando unicidad de idempotencia (REQ-SYNC-001).
    ///
    /// # Errores
    /// - [`SyncError::DuplicateOperationId`] si la clave de idempotencia ya está en cola.
    /// - [`SyncError::StorageError`] si la cola ha alcanzado su capacidad máxima.
    pub fn enqueue(&mut self, op: SyncOperation) -> Result<(), SyncError> {
        if self.operations.contains_key(&op.id) {
            return Err(SyncError::DuplicateOperationId(op.id.to_string()));
        }

        if self.operations.len() >= self.max_capacity {
            return Err(SyncError::StorageError(format!(
                "outbox queue capacity exceeded (max: {})",
                self.max_capacity
            )));
        }

        self.operations.insert(op.id.clone(), op);
        Ok(())
    }

    /// Retorna la primera operación lista para despachar (`status == Pending` y `now >= next_attempt`).
    #[must_use]
    pub fn peek_due(&self, now: UnixTime) -> Option<&SyncOperation> {
        self.operations.values().find(|op| {
            op.status == OperationStatus::Pending
                && op.next_attempt.as_seconds() <= now.as_seconds()
        })
    }

    /// Obtiene una referencia a una operación por su clave de idempotencia.
    #[must_use]
    pub fn get(&self, id: &OperationId) -> Option<&SyncOperation> {
        self.operations.get(id)
    }

    /// Marca una operación como en tránsito (`InFlight`).
    ///
    /// # Errores
    /// - [`SyncError::OperationNotFound`] si el id no existe.
    /// - [`SyncError::InvalidOperationState`] si no estaba en estado `Pending`.
    pub fn mark_in_flight(&mut self, id: &OperationId) -> Result<(), SyncError> {
        let op = self
            .operations
            .get_mut(id)
            .ok_or_else(|| SyncError::OperationNotFound(id.to_string()))?;

        if op.status != OperationStatus::Pending {
            return Err(SyncError::InvalidOperationState {
                id: id.to_string(),
                expected: "Pending",
                actual: match op.status {
                    OperationStatus::Pending => "Pending",
                    OperationStatus::InFlight => "InFlight",
                    OperationStatus::Delivered => "Delivered",
                    OperationStatus::FailedPermanent => "FailedPermanent",
                },
            });
        }

        op.status = OperationStatus::InFlight;
        Ok(())
    }

    /// Marca una operación como entregada satisfactoriamente (`Delivered`).
    ///
    /// # Errores
    /// [`SyncError::OperationNotFound`] si el id no existe.
    pub fn mark_delivered(&mut self, id: &OperationId) -> Result<(), SyncError> {
        let op = self
            .operations
            .get_mut(id)
            .ok_or_else(|| SyncError::OperationNotFound(id.to_string()))?;

        op.status = OperationStatus::Delivered;
        Ok(())
    }

    /// Registra un intento fallido y programa el siguiente reintento o marca como fallo definitivo.
    ///
    /// Retorna `true` si la operación pasó a `FailedPermanent` tras superar `max_retries`.
    ///
    /// # Errores
    /// [`SyncError::OperationNotFound`] si el id no existe.
    pub fn mark_attempt_failed(
        &mut self,
        id: &OperationId,
        next_attempt: UnixTime,
        max_retries: u32,
    ) -> Result<bool, SyncError> {
        let op = self
            .operations
            .get_mut(id)
            .ok_or_else(|| SyncError::OperationNotFound(id.to_string()))?;

        op.retry_count = op.retry_count.saturating_add(1);

        if op.retry_count >= max_retries {
            op.status = OperationStatus::FailedPermanent;
            Ok(true)
        } else {
            op.status = OperationStatus::Pending;
            op.next_attempt = next_attempt;
            Ok(false)
        }
    }

    /// Elimina una operación completada o descartada de la cola.
    pub fn remove(&mut self, id: &OperationId) -> Option<SyncOperation> {
        self.operations.remove(id)
    }

    /// Retorna el número total de operaciones registradas en cola.
    #[must_use]
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Indica si la cola está completamente vacía.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Retorna el número de operaciones en estado `Pending`.
    #[must_use]
    pub fn count_pending(&self) -> usize {
        self.operations
            .values()
            .filter(|op| op.status == OperationStatus::Pending)
            .count()
    }

    /// Retorna el número de operaciones en estado `InFlight`.
    #[must_use]
    pub fn count_in_flight(&self) -> usize {
        self.operations
            .values()
            .filter(|op| op.status == OperationStatus::InFlight)
            .count()
    }

    /// Retorna el número de operaciones en estado `Delivered`.
    #[must_use]
    pub fn count_delivered(&self) -> usize {
        self.operations
            .values()
            .filter(|op| op.status == OperationStatus::Delivered)
            .count()
    }

    /// Retorna el número de operaciones en estado `FailedPermanent`.
    #[must_use]
    pub fn count_failed(&self) -> usize {
        self.operations
            .values()
            .filter(|op| op.status == OperationStatus::FailedPermanent)
            .count()
    }
}
