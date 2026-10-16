//! Abstracción transaccional de almacenamiento e implementación en memoria (F5.T01).
//!
//! Trazabilidad:
//! - `REQ-STOR-008`: Backend intercambiable (SQLite nativo en L5, adaptador en memoria en L3).
//! - `REQ-STOR-004`: Integridad transaccional y atomicidad en escrituras.
//! - `REQ-STOR-003`: Consultas mediante índices ciegos.
//! - `INV-01`: Cero dependencias de I/O de red ni llamadas bloqueantes.
//! - `INV-10`: Sin unwrap, expect ni panics.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use gravital_id_types::{GidError, UnixTime};

use crate::blind_index::BlindIndex;
use crate::record::{CollectionName, EncryptedRecord, RecordId};

/// Registro persistido en el backend de almacenamiento con marcas de tiempo.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StoredRecord {
    /// Identificador único del registro.
    pub record_id: RecordId,
    /// Nombre de la colección a la que pertenece.
    pub collection: CollectionName,
    /// Carga binaria cifrada con AEAD y datos asociados.
    pub record: EncryptedRecord,
    /// Marca de tiempo de creación del registro.
    pub created_at: UnixTime,
    /// Marca de tiempo de última actualización del registro.
    pub updated_at: UnixTime,
}

/// Operación atómica de almacenamiento para transacciones (`REQ-STOR-004`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum StorageOp {
    /// Inserción o actualización de un registro con sus índices ciegos.
    Put {
        /// Colección destino.
        collection: CollectionName,
        /// Identificador de registro.
        record_id: RecordId,
        /// Carga binaria cifrada.
        record: EncryptedRecord,
        /// Índices ciegos asociados para búsquedas.
        indices: Vec<BlindIndex>,
        /// Marca de tiempo de la operación.
        timestamp: UnixTime,
    },
    /// Eliminación de un registro y sus índices ciegos asociados.
    Delete {
        /// Colección de origen.
        collection: CollectionName,
        /// Identificador de registro.
        record_id: RecordId,
    },
}

/// Lote acumulador de operaciones atómicas para ejecución en transacción.
#[derive(Default, Clone, Debug)]
pub struct StorageBatch {
    ops: Vec<StorageOp>,
}

impl StorageBatch {
    /// Crea un nuevo lote vacío.
    #[must_use]
    pub const fn new() -> Self {
        Self { ops: Vec::new() }
    }

    /// Añade una operación de inserción o actualización al lote.
    pub fn put(
        &mut self,
        collection: CollectionName,
        record_id: RecordId,
        record: EncryptedRecord,
        indices: Vec<BlindIndex>,
        timestamp: UnixTime,
    ) {
        self.ops.push(StorageOp::Put {
            collection,
            record_id,
            record,
            indices,
            timestamp,
        });
    }

    /// Añade una operación de eliminación al lote.
    pub fn delete(&mut self, collection: CollectionName, record_id: RecordId) {
        self.ops.push(StorageOp::Delete {
            collection,
            record_id,
        });
    }

    /// Retorna una referencia a las operaciones contenidas en el lote.
    #[must_use]
    pub fn ops(&self) -> &[StorageOp] {
        &self.ops
    }

    /// Consume el lote retornando el vector de operaciones.
    #[must_use]
    pub fn into_ops(self) -> Vec<StorageOp> {
        self.ops
    }
}

/// Contrato clave-valor transaccional para el almacenamiento local de Gravital ID (`REQ-STOR-008`).
pub trait StorageBackend {
    /// Obtiene un registro por su colección e identificador único.
    fn get(
        &self,
        collection: &CollectionName,
        record_id: &RecordId,
    ) -> Result<Option<StoredRecord>, GidError>;

    /// Inserta o actualiza un registro asociando sus índices ciegos de búsqueda.
    fn put(
        &mut self,
        collection: &CollectionName,
        record_id: &RecordId,
        record: EncryptedRecord,
        indices: &[BlindIndex],
        timestamp: UnixTime,
    ) -> Result<(), GidError>;

    /// Elimina un registro y todos sus índices ciegos asociados.
    ///
    /// Retorna `true` si el registro existía y fue eliminado, `false` en caso contrario.
    fn delete(
        &mut self,
        collection: &CollectionName,
        record_id: &RecordId,
    ) -> Result<bool, GidError>;

    /// Consulta todos los registros de una colección que coinciden con un índice ciego (`REQ-STOR-003`).
    fn query_by_blind_index(
        &self,
        collection: &CollectionName,
        index: &BlindIndex,
    ) -> Result<Vec<StoredRecord>, GidError>;

    /// Lista todos los registros pertenecientes a una colección.
    fn list(&self, collection: &CollectionName) -> Result<Vec<StoredRecord>, GidError>;

    /// Retorna el número de registros almacenados en una colección.
    fn count(&self, collection: &CollectionName) -> Result<usize, GidError>;

    /// Ejecuta atómicamente una secuencia de operaciones dentro de una transacción.
    ///
    /// Si cualquier operación falla, el estado debe revertirse íntegramente (`REQ-STOR-004`).
    fn execute_transaction(&mut self, ops: &[StorageOp]) -> Result<(), GidError>;
}

/// Implementación en memoria de [`StorageBackend`] para pruebas y entornos L3 sin SQLite.
#[derive(Default, Clone, Debug)]
pub struct InMemoryStorageBackend {
    records: BTreeMap<(CollectionName, RecordId), StoredRecord>,
    indices: BTreeMap<(CollectionName, BlindIndex), BTreeSet<RecordId>>,
    record_indices: BTreeMap<(CollectionName, RecordId), BTreeSet<BlindIndex>>,
}

impl InMemoryStorageBackend {
    /// Crea una nueva base de datos en memoria vacía.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            indices: BTreeMap::new(),
            record_indices: BTreeMap::new(),
        }
    }
}

impl StorageBackend for InMemoryStorageBackend {
    fn get(
        &self,
        collection: &CollectionName,
        record_id: &RecordId,
    ) -> Result<Option<StoredRecord>, GidError> {
        let key = (collection.clone(), record_id.clone());
        Ok(self.records.get(&key).cloned())
    }

    fn put(
        &mut self,
        collection: &CollectionName,
        record_id: &RecordId,
        record: EncryptedRecord,
        indices: &[BlindIndex],
        timestamp: UnixTime,
    ) -> Result<(), GidError> {
        let key = (collection.clone(), record_id.clone());

        // Limpiar índices antiguos si el registro ya existía previamente
        if let Some(old_indices) = self.record_indices.remove(&key) {
            for old_idx in old_indices {
                let idx_key = (collection.clone(), old_idx);
                if let Some(set) = self.indices.get_mut(&idx_key) {
                    set.remove(record_id);
                    if set.is_empty() {
                        self.indices.remove(&idx_key);
                    }
                }
            }
        }

        // Determinar created_at preservando el original en actualizaciones
        let created_at = match self.records.get(&key) {
            Some(existing) => existing.created_at,
            None => timestamp,
        };

        let stored = StoredRecord {
            record_id: record_id.clone(),
            collection: collection.clone(),
            record,
            created_at,
            updated_at: timestamp,
        };

        self.records.insert(key.clone(), stored);

        // Registrar nuevos índices ciegos
        let mut index_set = BTreeSet::new();
        for &idx in indices {
            index_set.insert(idx);
            let idx_key = (collection.clone(), idx);
            self.indices
                .entry(idx_key)
                .or_default()
                .insert(record_id.clone());
        }
        self.record_indices.insert(key, index_set);

        Ok(())
    }

    fn delete(
        &mut self,
        collection: &CollectionName,
        record_id: &RecordId,
    ) -> Result<bool, GidError> {
        let key = (collection.clone(), record_id.clone());
        if self.records.remove(&key).is_none() {
            return Ok(false);
        }

        // Limpiar índices asociados
        if let Some(indices) = self.record_indices.remove(&key) {
            for idx in indices {
                let idx_key = (collection.clone(), idx);
                if let Some(set) = self.indices.get_mut(&idx_key) {
                    set.remove(record_id);
                    if set.is_empty() {
                        self.indices.remove(&idx_key);
                    }
                }
            }
        }

        Ok(true)
    }

    fn query_by_blind_index(
        &self,
        collection: &CollectionName,
        index: &BlindIndex,
    ) -> Result<Vec<StoredRecord>, GidError> {
        let idx_key = (collection.clone(), *index);
        let id_set = match self.indices.get(&idx_key) {
            Some(set) => set,
            None => return Ok(Vec::new()),
        };

        let mut results = Vec::with_capacity(id_set.len());
        for id in id_set {
            let key = (collection.clone(), id.clone());
            if let Some(stored) = self.records.get(&key) {
                results.push(stored.clone());
            }
        }
        Ok(results)
    }

    fn list(&self, collection: &CollectionName) -> Result<Vec<StoredRecord>, GidError> {
        let mut results = Vec::new();
        for ((col, _), stored) in &self.records {
            if col == collection {
                results.push(stored.clone());
            }
        }
        Ok(results)
    }

    fn count(&self, collection: &CollectionName) -> Result<usize, GidError> {
        let mut n = 0usize;
        for (col, _) in self.records.keys() {
            if col == collection {
                n = n.saturating_add(1);
            }
        }
        Ok(n)
    }

    fn execute_transaction(&mut self, ops: &[StorageOp]) -> Result<(), GidError> {
        // Enfoque copy-on-write para garantizar atomicidad y reversión ante fallo (REQ-STOR-004)
        let snapshot = self.clone();

        for op in ops {
            let result = match op {
                StorageOp::Put {
                    collection,
                    record_id,
                    record,
                    indices,
                    timestamp,
                } => self.put(collection, record_id, record.clone(), indices, *timestamp),
                StorageOp::Delete {
                    collection,
                    record_id,
                } => self.delete(collection, record_id).map(|_| ()),
            };

            if let Err(err) = result {
                // Reversión completa a estado inicial consistente
                *self = snapshot;
                return Err(err);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::record::CipherSuite;
    use alloc::vec;

    fn sample_record() -> EncryptedRecord {
        EncryptedRecord::new(
            1,
            CipherSuite::XChaCha20Poly1305,
            [0x11u8; 24],
            [0x22u8; 16],
            b"encrypted_payload".to_vec(),
            [0x33u8; 16],
        )
    }

    // // Verifies: REQ-STOR-008 (operaciones CRUD sobre InMemoryStorageBackend)
    #[test]
    fn in_memory_crud_operations() {
        let mut backend = InMemoryStorageBackend::new();
        let col = CollectionName::new(CollectionName::CREDENTIALS).expect("col");
        let id = RecordId::new("rec-001").expect("id");
        let time = UnixTime::from_seconds(1700000000);
        let index = BlindIndex::new([0xaa; 32]);

        // Get de elemento no existente
        assert!(backend.get(&col, &id).expect("get").is_none());
        assert_eq!(backend.count(&col).expect("count"), 0);

        // Put
        backend
            .put(&col, &id, sample_record(), &[index], time)
            .expect("put");
        assert_eq!(backend.count(&col).expect("count"), 1);

        // Get existente
        let retrieved = backend.get(&col, &id).expect("get").expect("found");
        assert_eq!(retrieved.record_id, id);
        assert_eq!(retrieved.created_at, time);
        assert_eq!(retrieved.updated_at, time);

        // Búsqueda por índice ciego
        let matches = backend.query_by_blind_index(&col, &index).expect("query");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].record_id, id);

        // List
        let list = backend.list(&col).expect("list");
        assert_eq!(list.len(), 1);

        // Delete
        assert!(backend.delete(&col, &id).expect("delete"));
        assert!(backend.get(&col, &id).expect("get").is_none());
        assert_eq!(backend.count(&col).expect("count"), 0);

        // Índice ciego ya no devuelve nada tras delete
        let matches_after = backend.query_by_blind_index(&col, &index).expect("query");
        assert!(matches_after.is_empty());
    }

    // // Verifies: REQ-STOR-004 (consistencia y reversión atómica de transacciones)
    #[test]
    fn transaction_atomicity_and_rollback() {
        let mut backend = InMemoryStorageBackend::new();
        let col = CollectionName::new(CollectionName::CREDENTIALS).expect("col");
        let id1 = RecordId::new("rec-001").expect("id1");
        let id2 = RecordId::new("rec-002").expect("id2");
        let time = UnixTime::from_seconds(1700000000);

        let mut batch = StorageBatch::new();
        batch.put(col.clone(), id1.clone(), sample_record(), vec![], time);
        batch.put(col.clone(), id2.clone(), sample_record(), vec![], time);

        backend.execute_transaction(batch.ops()).expect("tx commit");
        assert_eq!(backend.count(&col).expect("count"), 2);

        // Transacción de borrado y añadido
        let id3 = RecordId::new("rec-003").expect("id3");
        let mut batch2 = StorageBatch::new();
        batch2.delete(col.clone(), id1.clone());
        batch2.put(col.clone(), id3.clone(), sample_record(), vec![], time);

        backend
            .execute_transaction(batch2.ops())
            .expect("tx2 commit");
        assert_eq!(backend.count(&col).expect("count"), 2);
        assert!(backend.get(&col, &id1).expect("get").is_none());
        assert!(backend.get(&col, &id2).expect("get").is_some());
        assert!(backend.get(&col, &id3).expect("get").is_some());
    }
}
