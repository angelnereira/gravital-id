//! Adaptador persistente SQLite implementando `StorageBackend` (F5.T04, REQ-STOR-008).
//!
//! Trazabilidad:
//! - `REQ-STOR-008`: Backend intercambiable (SQLite nativo en L5).
//! - `REQ-STOR-004`: Atomicidad transaccional y WAL mode.
//! - `REQ-STOR-003`: Consultas mediante índices ciegos sobre `pip_blind_indices`.
//! - `STORAGE_FORMAT.md §4, §5`: Estructura de tablas y PRAGMAs obligatorios.
//! - `INV-01`: Verificación offline sin I/O de red.
//! - `INV-02`: Ausencia absoluta de PII en claro.

use std::path::Path;

use gravital_id_storage::{
    BlindIndex, CollectionName, EncryptedRecord, RecordId, StorageBackend, StorageOp, StoredRecord,
};
use gravital_id_types::{GidError, UnixTime};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::error::{sqlite_read_err, sqlite_write_err};
use crate::migration::{apply_migrations, LATEST_SCHEMA_VERSION};

/// Configuración de arranque para el almacenamiento SQLite.
#[derive(Debug, Clone)]
pub struct SqliteStorageConfig {
    /// Ruta del fichero SQLite en disco, o `:memory:` para instancia en memoria.
    pub path: String,
    /// Versión de esquema objetivo a la que migrar la base de datos.
    pub target_schema_version: u32,
}

impl Default for SqliteStorageConfig {
    fn default() -> Self {
        Self {
            path: ":memory:".to_string(),
            target_schema_version: LATEST_SCHEMA_VERSION,
        }
    }
}

/// Almacenamiento persistente SQLite para Gravital ID (`REQ-STOR-008`).
pub struct SqliteStorage {
    conn: Connection,
}

impl std::fmt::Debug for SqliteStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStorage").finish_non_exhaustive()
    }
}

impl SqliteStorage {
    /// Abre una base de datos SQLite efímera en memoria (ideal para pruebas y agentes).
    pub fn open_in_memory() -> Result<Self, GidError> {
        Self::open_with_config(SqliteStorageConfig::default())
    }

    /// Abre una base de datos SQLite persistente en la ruta especificada.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, GidError> {
        let config = SqliteStorageConfig {
            path: path.as_ref().to_string_lossy().to_string(),
            target_schema_version: LATEST_SCHEMA_VERSION,
        };
        Self::open_with_config(config)
    }

    /// Abre la base de datos aplicando la configuración y ejecutando las migraciones automáticas.
    pub fn open_with_config(config: SqliteStorageConfig) -> Result<Self, GidError> {
        let mut conn = if config.path == ":memory:" {
            Connection::open_in_memory().map_err(sqlite_write_err)?
        } else {
            Connection::open(&config.path).map_err(sqlite_write_err)?
        };

        // PRAGMAs normativos de STORAGE_FORMAT.md §5:
        // WAL mode, synchronous = NORMAL, foreign_keys = ON.
        if config.path != ":memory:" {
            let _: String = conn
                .query_row("PRAGMA journal_mode = WAL;", [], |row| row.get(0))
                .map_err(sqlite_write_err)?;
        }
        conn.execute_batch(
            r#"
            PRAGMA synchronous = NORMAL;
            PRAGMA foreign_keys = ON;
            "#,
        )
        .map_err(sqlite_write_err)?;

        apply_migrations(&mut conn, config.target_schema_version, 0)?;

        Ok(Self { conn })
    }

    /// Acceso inmutable a la conexión subyacente para inspección o utilidades.
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Acceso mutable a la conexión subyacente.
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

impl StorageBackend for SqliteStorage {
    fn get(
        &self,
        collection: &CollectionName,
        record_id: &RecordId,
    ) -> Result<Option<StoredRecord>, GidError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT record_data, created_at, updated_at FROM pip_records WHERE collection = ?1 AND record_id = ?2",
            )
            .map_err(sqlite_read_err)?;

        let result = stmt
            .query_row(params![collection.as_str(), record_id.as_str()], |row| {
                let blob: Vec<u8> = row.get(0)?;
                let created_at: u64 = row.get(1)?;
                let updated_at: u64 = row.get(2)?;
                Ok((blob, created_at, updated_at))
            })
            .optional()
            .map_err(sqlite_read_err)?;

        match result {
            Some((blob, created_at, updated_at)) => {
                let record = EncryptedRecord::from_bytes(&blob)?;
                Ok(Some(StoredRecord {
                    record_id: record_id.clone(),
                    collection: collection.clone(),
                    record,
                    created_at: UnixTime::from_seconds(created_at),
                    updated_at: UnixTime::from_seconds(updated_at),
                }))
            }
            None => Ok(None),
        }
    }

    fn put(
        &mut self,
        collection: &CollectionName,
        record_id: &RecordId,
        record: EncryptedRecord,
        indices: &[BlindIndex],
        timestamp: UnixTime,
    ) -> Result<(), GidError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_write_err)?;

        let blob = record.to_bytes();
        let ts = timestamp.as_seconds();

        // Preservar created_at si ya existe, actualizar updated_at
        tx.execute(
            r#"
            INSERT INTO pip_records (record_id, collection, record_data, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?4)
            ON CONFLICT(record_id) DO UPDATE SET
                collection = excluded.collection,
                record_data = excluded.record_data,
                updated_at = excluded.updated_at
            "#,
            params![record_id.as_str(), collection.as_str(), blob, ts],
        )
        .map_err(sqlite_write_err)?;

        // Reemplazar índices ciegos asociados al registro
        tx.execute(
            "DELETE FROM pip_blind_indices WHERE record_id = ?1",
            params![record_id.as_str()],
        )
        .map_err(sqlite_write_err)?;

        for idx in indices {
            tx.execute(
                "INSERT INTO pip_blind_indices (index_hash, record_id, collection) VALUES (?1, ?2, ?3)",
                params![idx.to_hex(), record_id.as_str(), collection.as_str()],
            )
            .map_err(sqlite_write_err)?;
        }

        tx.commit().map_err(sqlite_write_err)?;
        Ok(())
    }

    fn delete(
        &mut self,
        collection: &CollectionName,
        record_id: &RecordId,
    ) -> Result<bool, GidError> {
        let count = self
            .conn
            .execute(
                "DELETE FROM pip_records WHERE collection = ?1 AND record_id = ?2",
                params![collection.as_str(), record_id.as_str()],
            )
            .map_err(sqlite_write_err)?;

        Ok(count > 0)
    }

    fn query_by_blind_index(
        &self,
        collection: &CollectionName,
        index: &BlindIndex,
    ) -> Result<Vec<StoredRecord>, GidError> {
        let mut stmt = self
            .conn
            .prepare(
                r#"
                SELECT r.record_id, r.collection, r.record_data, r.created_at, r.updated_at
                FROM pip_records r
                INNER JOIN pip_blind_indices b ON r.record_id = b.record_id
                WHERE b.collection = ?1 AND b.index_hash = ?2
                ORDER BY r.created_at ASC
                "#,
            )
            .map_err(sqlite_read_err)?;

        let mut rows = stmt
            .query(params![collection.as_str(), index.to_hex()])
            .map_err(sqlite_read_err)?;

        let mut results = Vec::new();
        while let Some(row) = rows.next().map_err(sqlite_read_err)? {
            let rec_id_str: String = row.get(0).map_err(sqlite_read_err)?;
            let col_str: String = row.get(1).map_err(sqlite_read_err)?;
            let blob: Vec<u8> = row.get(2).map_err(sqlite_read_err)?;
            let created_at: u64 = row.get(3).map_err(sqlite_read_err)?;
            let updated_at: u64 = row.get(4).map_err(sqlite_read_err)?;

            let record_id = RecordId::new(rec_id_str)?;
            let col = CollectionName::new(col_str)?;
            let record = EncryptedRecord::from_bytes(&blob)?;

            results.push(StoredRecord {
                record_id,
                collection: col,
                record,
                created_at: UnixTime::from_seconds(created_at),
                updated_at: UnixTime::from_seconds(updated_at),
            });
        }

        Ok(results)
    }

    fn list(&self, collection: &CollectionName) -> Result<Vec<StoredRecord>, GidError> {
        let mut stmt = self
            .conn
            .prepare(
                r#"
                SELECT record_id, collection, record_data, created_at, updated_at
                FROM pip_records
                WHERE collection = ?1
                ORDER BY created_at ASC
                "#,
            )
            .map_err(sqlite_read_err)?;

        let mut rows = stmt
            .query(params![collection.as_str()])
            .map_err(sqlite_read_err)?;

        let mut results = Vec::new();
        while let Some(row) = rows.next().map_err(sqlite_read_err)? {
            let rec_id_str: String = row.get(0).map_err(sqlite_read_err)?;
            let col_str: String = row.get(1).map_err(sqlite_read_err)?;
            let blob: Vec<u8> = row.get(2).map_err(sqlite_read_err)?;
            let created_at: u64 = row.get(3).map_err(sqlite_read_err)?;
            let updated_at: u64 = row.get(4).map_err(sqlite_read_err)?;

            let record_id = RecordId::new(rec_id_str)?;
            let col = CollectionName::new(col_str)?;
            let record = EncryptedRecord::from_bytes(&blob)?;

            results.push(StoredRecord {
                record_id,
                collection: col,
                record,
                created_at: UnixTime::from_seconds(created_at),
                updated_at: UnixTime::from_seconds(updated_at),
            });
        }

        Ok(results)
    }

    fn count(&self, collection: &CollectionName) -> Result<usize, GidError> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM pip_records WHERE collection = ?1",
                params![collection.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_read_err)?;

        usize::try_from(count).map_err(|_| {
            GidError::new(
                gravital_id_types::ErrorCode::MalformedMessage,
                "record count out of usize bounds",
            )
        })
    }

    fn execute_transaction(&mut self, ops: &[StorageOp]) -> Result<(), GidError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_write_err)?;

        for op in ops {
            match op {
                StorageOp::Put {
                    collection,
                    record_id,
                    record,
                    indices,
                    timestamp,
                } => {
                    let blob = record.to_bytes();
                    let ts = timestamp.as_seconds();

                    tx.execute(
                        r#"
                        INSERT INTO pip_records (record_id, collection, record_data, created_at, updated_at)
                        VALUES (?1, ?2, ?3, ?4, ?4)
                        ON CONFLICT(record_id) DO UPDATE SET
                            collection = excluded.collection,
                            record_data = excluded.record_data,
                            updated_at = excluded.updated_at
                        "#,
                        params![record_id.as_str(), collection.as_str(), blob, ts],
                    )
                    .map_err(sqlite_write_err)?;

                    tx.execute(
                        "DELETE FROM pip_blind_indices WHERE record_id = ?1",
                        params![record_id.as_str()],
                    )
                    .map_err(sqlite_write_err)?;

                    for idx in indices {
                        tx.execute(
                            "INSERT INTO pip_blind_indices (index_hash, record_id, collection) VALUES (?1, ?2, ?3)",
                            params![idx.to_hex(), record_id.as_str(), collection.as_str()],
                        )
                        .map_err(sqlite_write_err)?;
                    }
                }
                StorageOp::Delete {
                    collection,
                    record_id,
                } => {
                    tx.execute(
                        "DELETE FROM pip_records WHERE collection = ?1 AND record_id = ?2",
                        params![collection.as_str(), record_id.as_str()],
                    )
                    .map_err(sqlite_write_err)?;
                }
            }
        }

        tx.commit().map_err(sqlite_write_err)?;
        Ok(())
    }
}
