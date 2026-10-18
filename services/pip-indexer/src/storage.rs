//! Capa de almacenamiento y persistencia para pip-indexer (F7.T03, REQ-LEDG-005, INV-02).

use crate::error::IndexerError;
use gravital_id_ledger::{
    BundleSignerUpdatedEvent, EventCoordinate, IssuerDeregisteredEvent, IssuerRegisteredEvent,
    IssuerReinstatedEvent, IssuerSuspendedEvent, KeyAddedEvent, KeyCompromisedEvent,
    KeyRetiredEvent, KeySuspendedEvent, LedgerEvent, LedgerState, SequencedLedgerEvent,
    StatusManifestAnchoredEvent, TrustRootUpdatedEvent, VerifierDeregisteredEvent,
    VerifierRegisteredEvent,
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

/// Trait abstracto de persistencia para el indexador.
pub trait IndexerStorage: Send + Sync {
    /// Obtiene la última altura de bloque procesada para una cadena, o `None` si nunca se ha procesado.
    fn get_checkpoint(&self, chain_id: u64) -> Result<Option<u64>, IndexerError>;

    /// Actualiza el checkpoint de bloque procesado para una cadena.
    fn save_checkpoint(
        &self,
        chain_id: u64,
        block_number: u64,
        block_hash: Option<&str>,
        timestamp: u64,
    ) -> Result<(), IndexerError>;

    /// Guarda una lista de eventos finalizados de forma idempotente.
    ///
    /// Devuelve el número de nuevos eventos efectivamente insertados (omitiendo duplicados).
    fn store_events(
        &self,
        chain_id: u64,
        events: &[SequencedLedgerEvent],
    ) -> Result<usize, IndexerError>;

    /// Consulta eventos en un rango de bloques `[from_block, to_block]` ordenados canónicamente.
    fn get_events(
        &self,
        chain_id: u64,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<SequencedLedgerEvent>, IndexerError>;

    /// Rebobina el estado a una altura de bloque anterior (eliminando eventos posteriores y actualizando el cursor).
    fn rewind_to_block(
        &self,
        chain_id: u64,
        target_block: u64,
        timestamp: u64,
    ) -> Result<(), IndexerError>;

    /// Devuelve el total de eventos indexados para la cadena.
    fn count_events(&self, chain_id: u64) -> Result<usize, IndexerError>;

    /// Construye y proyecta el estado puro del ledger aplicando todos los eventos históricos en orden.
    fn build_ledger_state(&self, chain_id: u64) -> Result<LedgerState, IndexerError>;
}

// -------------------------------------------------------------------------------------------------
// Implementación en memoria (InMemoryIndexerStorage)
// -------------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct InMemoryData {
    checkpoints: BTreeMap<u64, (u64, Option<String>)>,
    events: BTreeMap<(u64, EventCoordinate), SequencedLedgerEvent>,
}

/// Almacenamiento determinista en memoria, útil para pruebas de integración y simulación de fallos.
#[derive(Debug, Default, Clone)]
pub struct InMemoryIndexerStorage {
    data: Arc<Mutex<InMemoryData>>,
}

impl InMemoryIndexerStorage {
    /// Crea un nuevo almacenamiento en memoria.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl IndexerStorage for InMemoryIndexerStorage {
    fn get_checkpoint(&self, chain_id: u64) -> Result<Option<u64>, IndexerError> {
        let guard = self
            .data
            .lock()
            .map_err(|e| IndexerError::Database(format!("Error adquiriendo lock: {e}")))?;
        Ok(guard.checkpoints.get(&chain_id).map(|(block, _)| *block))
    }

    fn save_checkpoint(
        &self,
        chain_id: u64,
        block_number: u64,
        block_hash: Option<&str>,
        _timestamp: u64,
    ) -> Result<(), IndexerError> {
        let mut guard = self
            .data
            .lock()
            .map_err(|e| IndexerError::Database(format!("Error adquiriendo lock: {e}")))?;
        guard
            .checkpoints
            .insert(chain_id, (block_number, block_hash.map(str::to_string)));
        Ok(())
    }

    fn store_events(
        &self,
        chain_id: u64,
        events: &[SequencedLedgerEvent],
    ) -> Result<usize, IndexerError> {
        let mut guard = self
            .data
            .lock()
            .map_err(|e| IndexerError::Database(format!("Error adquiriendo lock: {e}")))?;

        let mut inserted: usize = 0;
        for ev in events {
            let key = (chain_id, ev.coordinate);
            if let std::collections::btree_map::Entry::Vacant(e) = guard.events.entry(key) {
                e.insert(ev.clone());
                inserted = inserted.saturating_add(1);
            }
        }
        Ok(inserted)
    }

    fn get_events(
        &self,
        chain_id: u64,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<SequencedLedgerEvent>, IndexerError> {
        let guard = self
            .data
            .lock()
            .map_err(|e| IndexerError::Database(format!("Error adquiriendo lock: {e}")))?;

        let mut res = Vec::new();
        for ((c_id, coord), ev) in &guard.events {
            if *c_id == chain_id
                && coord.block_number >= from_block
                && coord.block_number <= to_block
            {
                res.push(ev.clone());
            }
        }
        res.sort_by_key(|e| e.coordinate);
        Ok(res)
    }

    fn rewind_to_block(
        &self,
        chain_id: u64,
        target_block: u64,
        _timestamp: u64,
    ) -> Result<(), IndexerError> {
        let mut guard = self
            .data
            .lock()
            .map_err(|e| IndexerError::Database(format!("Error adquiriendo lock: {e}")))?;

        guard
            .events
            .retain(|(c_id, coord), _| !(*c_id == chain_id && coord.block_number > target_block));

        let current_hash = guard
            .checkpoints
            .get(&chain_id)
            .and_then(|(_, h)| h.clone());
        guard
            .checkpoints
            .insert(chain_id, (target_block, current_hash));
        Ok(())
    }

    fn count_events(&self, chain_id: u64) -> Result<usize, IndexerError> {
        let guard = self
            .data
            .lock()
            .map_err(|e| IndexerError::Database(format!("Error adquiriendo lock: {e}")))?;
        let count = guard
            .events
            .keys()
            .filter(|(c_id, _)| *c_id == chain_id)
            .count();
        Ok(count)
    }

    fn build_ledger_state(&self, chain_id: u64) -> Result<LedgerState, IndexerError> {
        let guard = self
            .data
            .lock()
            .map_err(|e| IndexerError::Database(format!("Error adquiriendo lock: {e}")))?;

        let mut events: Vec<_> = guard
            .events
            .iter()
            .filter(|((c_id, _), _)| *c_id == chain_id)
            .map(|(_, ev)| ev.clone())
            .collect();
        events.sort_by_key(|e| e.coordinate);

        let mut state = LedgerState::new(chain_id, format!("0x{chain_id:040x}"));
        for ev in &events {
            state
                .apply_event(ev)
                .map_err(|e| IndexerError::Ledger(format!("Error aplicando evento: {e}")))?;
        }
        Ok(state)
    }
}

// -------------------------------------------------------------------------------------------------
// Implementación Relacional SQLite (SqliteIndexerStorage)
// -------------------------------------------------------------------------------------------------

/// Almacenamiento relacional SQLite transaccional e idempotente.
pub struct SqliteIndexerStorage {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteIndexerStorage {
    /// Inicializa una base de datos SQLite en memoria.
    ///
    /// # Errores
    /// Devuelve [`IndexerError::Database`] si falla la creación de tablas o la conexión.
    pub fn new_in_memory() -> Result<Self, IndexerError> {
        let conn = Connection::open_in_memory().map_err(|e| {
            IndexerError::Database(format!("Error abriendo SQLite en memoria: {e}"))
        })?;
        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        storage.init_tables()?;
        Ok(storage)
    }

    /// Inicializa una base de datos SQLite en la ruta de archivo especificada.
    ///
    /// # Errores
    /// Devuelve [`IndexerError::Database`] si falla la apertura o inicialización del esquema.
    pub fn new_from_path(path: &str) -> Result<Self, IndexerError> {
        let conn = Connection::open(path).map_err(|e| {
            IndexerError::Database(format!("Error abriendo SQLite en '{path}': {e}"))
        })?;
        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        storage.init_tables()?;
        Ok(storage)
    }

    fn init_tables(&self) -> Result<(), IndexerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| IndexerError::Database(format!("Error adquiriendo lock: {e}")))?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS indexer_checkpoints (
                chain_id INTEGER NOT NULL PRIMARY KEY,
                last_processed_block INTEGER NOT NULL,
                last_block_hash TEXT,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS indexed_events (
                chain_id INTEGER NOT NULL,
                block_number INTEGER NOT NULL,
                tx_index INTEGER NOT NULL,
                log_index INTEGER NOT NULL,
                block_timestamp INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                event_payload TEXT NOT NULL,
                PRIMARY KEY (chain_id, block_number, tx_index, log_index)
            );

            CREATE INDEX IF NOT EXISTS idx_indexed_events_range 
                ON indexed_events (chain_id, block_number);
            ",
        )
        .map_err(|e| {
            IndexerError::Database(format!("Error inicializando tablas DDL SQLite: {e}"))
        })?;

        Ok(())
    }
}

impl IndexerStorage for SqliteIndexerStorage {
    fn get_checkpoint(&self, chain_id: u64) -> Result<Option<u64>, IndexerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| IndexerError::Database(format!("Error adquiriendo lock: {e}")))?;

        let mut stmt = conn
            .prepare(
                "SELECT last_processed_block FROM indexer_checkpoints WHERE chain_id = ?1 LIMIT 1;",
            )
            .map_err(|e| IndexerError::Database(format!("Error preparando SELECT: {e}")))?;

        let mut rows = stmt
            .query(params![chain_id as i64])
            .map_err(|e| IndexerError::Database(format!("Error consultando checkpoint: {e}")))?;

        if let Some(row) = rows
            .next()
            .map_err(|e| IndexerError::Database(format!("Error leyendo fila checkpoint: {e}")))?
        {
            let block: i64 = row
                .get(0)
                .map_err(|e| IndexerError::Database(format!("Error extrayendo bloque: {e}")))?;
            #[allow(clippy::cast_sign_loss)]
            Ok(Some(block as u64))
        } else {
            Ok(None)
        }
    }

    fn save_checkpoint(
        &self,
        chain_id: u64,
        block_number: u64,
        block_hash: Option<&str>,
        timestamp: u64,
    ) -> Result<(), IndexerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| IndexerError::Database(format!("Error adquiriendo lock: {e}")))?;

        conn.execute(
            "
            INSERT INTO indexer_checkpoints (chain_id, last_processed_block, last_block_hash, updated_at)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT (chain_id) DO UPDATE SET
                last_processed_block = excluded.last_processed_block,
                last_block_hash = excluded.last_block_hash,
                updated_at = excluded.updated_at;
            ",
            params![chain_id as i64, block_number as i64, block_hash, timestamp as i64],
        )
        .map_err(|e| IndexerError::Database(format!("Error upsert checkpoint SQLite: {e}")))?;

        Ok(())
    }

    fn store_events(
        &self,
        chain_id: u64,
        events: &[SequencedLedgerEvent],
    ) -> Result<usize, IndexerError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| IndexerError::Database(format!("Error adquiriendo lock: {e}")))?;

        let tx = conn
            .transaction()
            .map_err(|e| IndexerError::Database(format!("Error iniciando transacción: {e}")))?;

        let mut inserted: usize = 0;
        {
            let mut stmt = tx
                .prepare(
                    "
                    INSERT OR IGNORE INTO indexed_events 
                    (chain_id, block_number, tx_index, log_index, block_timestamp, event_type, event_payload)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);
                    ",
                )
                .map_err(|e| IndexerError::Database(format!("Error preparando INSERT: {e}")))?;

            for ev in events {
                let (event_type, payload_json) = serialize_ledger_event(&ev.event)?;
                let rows_affected = stmt
                    .execute(params![
                        chain_id as i64,
                        ev.coordinate.block_number as i64,
                        i64::from(ev.coordinate.tx_index),
                        i64::from(ev.coordinate.log_index),
                        ev.coordinate.block_timestamp as i64,
                        event_type,
                        payload_json,
                    ])
                    .map_err(|e| IndexerError::Database(format!("Error insertando evento: {e}")))?;

                inserted = inserted.saturating_add(rows_affected);
            }
        }

        tx.commit()
            .map_err(|e| IndexerError::Database(format!("Error confirmando transacción: {e}")))?;

        Ok(inserted)
    }

    fn get_events(
        &self,
        chain_id: u64,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<SequencedLedgerEvent>, IndexerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| IndexerError::Database(format!("Error adquiriendo lock: {e}")))?;

        let mut stmt = conn
            .prepare(
                "
                SELECT block_number, tx_index, log_index, block_timestamp, event_payload
                FROM indexed_events
                WHERE chain_id = ?1 AND block_number >= ?2 AND block_number <= ?3
                ORDER BY block_number ASC, tx_index ASC, log_index ASC;
                ",
            )
            .map_err(|e| IndexerError::Database(format!("Error preparando consulta: {e}")))?;

        let rows = stmt
            .query_map(
                params![chain_id as i64, from_block as i64, to_block as i64],
                |row| {
                    let b_num: i64 = row.get(0)?;
                    let tx_idx: i64 = row.get(1)?;
                    let log_idx: i64 = row.get(2)?;
                    let b_ts: i64 = row.get(3)?;
                    let payload: String = row.get(4)?;
                    Ok((b_num, tx_idx, log_idx, b_ts, payload))
                },
            )
            .map_err(|e| IndexerError::Database(format!("Error ejecutando consulta: {e}")))?;

        let mut result = Vec::new();
        for item in rows {
            let (b_num, tx_idx, log_idx, b_ts, payload) =
                item.map_err(|e| IndexerError::Database(format!("Error leyendo fila: {e}")))?;

            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            let coord =
                EventCoordinate::new(b_num as u64, tx_idx as u32, log_idx as u32, b_ts as u64);

            let event = deserialize_ledger_event(&payload)?;
            result.push(SequencedLedgerEvent::new(coord, event));
        }

        Ok(result)
    }

    fn rewind_to_block(
        &self,
        chain_id: u64,
        target_block: u64,
        timestamp: u64,
    ) -> Result<(), IndexerError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| IndexerError::Database(format!("Error adquiriendo lock: {e}")))?;

        let tx = conn
            .transaction()
            .map_err(|e| IndexerError::Database(format!("Error iniciando transacción: {e}")))?;

        tx.execute(
            "DELETE FROM indexed_events WHERE chain_id = ?1 AND block_number > ?2;",
            params![chain_id as i64, target_block as i64],
        )
        .map_err(|e| IndexerError::Database(format!("Error eliminando eventos en rewind: {e}")))?;

        tx.execute(
            "
            INSERT INTO indexer_checkpoints (chain_id, last_processed_block, last_block_hash, updated_at)
            VALUES (?1, ?2, NULL, ?3)
            ON CONFLICT (chain_id) DO UPDATE SET
                last_processed_block = excluded.last_processed_block,
                updated_at = excluded.updated_at;
            ",
            params![chain_id as i64, target_block as i64, timestamp as i64],
        )
        .map_err(|e| IndexerError::Database(format!("Error actualizando checkpoint rewind: {e}")))?;

        tx.commit()
            .map_err(|e| IndexerError::Database(format!("Error confirmando rewind: {e}")))?;

        Ok(())
    }

    fn count_events(&self, chain_id: u64) -> Result<usize, IndexerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| IndexerError::Database(format!("Error adquiriendo lock: {e}")))?;

        let mut stmt = conn
            .prepare("SELECT COUNT(*) FROM indexed_events WHERE chain_id = ?1;")
            .map_err(|e| IndexerError::Database(format!("Error preparando conteo: {e}")))?;

        let count: i64 = stmt
            .query_row(params![chain_id as i64], |row| row.get(0))
            .map_err(|e| IndexerError::Database(format!("Error ejecutando conteo: {e}")))?;

        #[allow(clippy::cast_sign_loss)]
        Ok(count as usize)
    }

    fn build_ledger_state(&self, chain_id: u64) -> Result<LedgerState, IndexerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| IndexerError::Database(format!("Error adquiriendo lock: {e}")))?;

        let mut stmt = conn
            .prepare(
                "
                SELECT block_number, tx_index, log_index, block_timestamp, event_payload
                FROM indexed_events
                WHERE chain_id = ?1
                ORDER BY block_number ASC, tx_index ASC, log_index ASC;
                ",
            )
            .map_err(|e| IndexerError::Database(format!("Error preparando lectura: {e}")))?;

        let rows = stmt
            .query_map(params![chain_id as i64], |row| {
                let b_num: i64 = row.get(0)?;
                let tx_idx: i64 = row.get(1)?;
                let log_idx: i64 = row.get(2)?;
                let b_ts: i64 = row.get(3)?;
                let payload: String = row.get(4)?;
                Ok((b_num, tx_idx, log_idx, b_ts, payload))
            })
            .map_err(|e| IndexerError::Database(format!("Error ejecutando lectura: {e}")))?;

        let mut state = LedgerState::new(chain_id, format!("0x{chain_id:040x}"));
        for item in rows {
            let (b_num, tx_idx, log_idx, b_ts, payload) =
                item.map_err(|e| IndexerError::Database(format!("Error leyendo fila: {e}")))?;

            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            let coord =
                EventCoordinate::new(b_num as u64, tx_idx as u32, log_idx as u32, b_ts as u64);

            let event = deserialize_ledger_event(&payload)?;
            let sequenced = SequencedLedgerEvent::new(coord, event);
            state.apply_event(&sequenced).map_err(|e| {
                IndexerError::Ledger(format!("Error aplicando evento al estado: {e}"))
            })?;
        }

        Ok(state)
    }
}

// -------------------------------------------------------------------------------------------------
// Serialización y Deserialización JSON de eventos
// -------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
enum SerializedEvent {
    IssuerRegistered {
        issuer_id: String,
        uri: String,
        profiles: Vec<String>,
        vcts: Vec<String>,
        valid_from: u64,
        valid_until: u64,
    },
    IssuerSuspended {
        issuer_id: String,
        expires_at: u64,
        initiated_by: String,
    },
    IssuerReinstated {
        issuer_id: String,
    },
    IssuerDeregistered {
        issuer_id: String,
    },
    KeyAdded {
        issuer_id: String,
        kid: String,
        public_key: String,
    },
    KeyRetired {
        issuer_id: String,
        kid: String,
        state_since: u64,
    },
    KeySuspended {
        issuer_id: String,
        kid: String,
        expires_at: u64,
        initiated_by: String,
    },
    KeyCompromised {
        issuer_id: String,
        kid: String,
        state_since: u64,
    },
    VerifierRegistered {
        verifier_id: String,
        uri: String,
        profiles: Vec<String>,
        public_key: String,
        valid_from: u64,
        valid_until: u64,
    },
    VerifierDeregistered {
        verifier_id: String,
    },
    TrustRootUpdated {
        root_hash: String,
        root_version: u64,
        updated_at: u64,
    },
    BundleSignerUpdated {
        signer_address: String,
        kid: String,
        public_key: String,
        authorized: bool,
    },
    StatusManifestAnchored {
        issuer_id: String,
        manifest_version: u64,
        manifest_hash: String,
        uri_hint: String,
    },
}

/// Serializa un [`LedgerEvent`] a un par `(nombre_tipo, json)`.
///
/// # Errores
/// Devuelve [`IndexerError::Serialization`] si la codificación JSON falla.
pub fn serialize_ledger_event(event: &LedgerEvent) -> Result<(&'static str, String), IndexerError> {
    let (event_name, ser) = match event {
        LedgerEvent::IssuerRegistered(e) => (
            "IssuerRegistered",
            SerializedEvent::IssuerRegistered {
                issuer_id: hex_encode(&e.issuer_id),
                uri: e.uri.clone(),
                profiles: e.profiles.clone(),
                vcts: e.vcts.clone(),
                valid_from: e.valid_from,
                valid_until: e.valid_until,
            },
        ),
        LedgerEvent::IssuerSuspended(e) => (
            "IssuerSuspended",
            SerializedEvent::IssuerSuspended {
                issuer_id: hex_encode(&e.issuer_id),
                expires_at: e.expires_at,
                initiated_by: hex_encode(&e.initiated_by),
            },
        ),
        LedgerEvent::IssuerReinstated(e) => (
            "IssuerReinstated",
            SerializedEvent::IssuerReinstated {
                issuer_id: hex_encode(&e.issuer_id),
            },
        ),
        LedgerEvent::IssuerDeregistered(e) => (
            "IssuerDeregistered",
            SerializedEvent::IssuerDeregistered {
                issuer_id: hex_encode(&e.issuer_id),
            },
        ),
        LedgerEvent::KeyAdded(e) => (
            "KeyAdded",
            SerializedEvent::KeyAdded {
                issuer_id: hex_encode(&e.issuer_id),
                kid: hex_encode(&e.kid),
                public_key: hex_encode(&e.public_key),
            },
        ),
        LedgerEvent::KeyRetired(e) => (
            "KeyRetired",
            SerializedEvent::KeyRetired {
                issuer_id: hex_encode(&e.issuer_id),
                kid: hex_encode(&e.kid),
                state_since: e.state_since,
            },
        ),
        LedgerEvent::KeySuspended(e) => (
            "KeySuspended",
            SerializedEvent::KeySuspended {
                issuer_id: hex_encode(&e.issuer_id),
                kid: hex_encode(&e.kid),
                expires_at: e.expires_at,
                initiated_by: hex_encode(&e.initiated_by),
            },
        ),
        LedgerEvent::KeyCompromised(e) => (
            "KeyCompromised",
            SerializedEvent::KeyCompromised {
                issuer_id: hex_encode(&e.issuer_id),
                kid: hex_encode(&e.kid),
                state_since: e.state_since,
            },
        ),
        LedgerEvent::VerifierRegistered(e) => (
            "VerifierRegistered",
            SerializedEvent::VerifierRegistered {
                verifier_id: hex_encode(&e.verifier_id),
                uri: e.uri.clone(),
                profiles: e.profiles.clone(),
                public_key: hex_encode(&e.public_key),
                valid_from: e.valid_from,
                valid_until: e.valid_until,
            },
        ),
        LedgerEvent::VerifierDeregistered(e) => (
            "VerifierDeregistered",
            SerializedEvent::VerifierDeregistered {
                verifier_id: hex_encode(&e.verifier_id),
            },
        ),
        LedgerEvent::TrustRootUpdated(e) => (
            "TrustRootUpdated",
            SerializedEvent::TrustRootUpdated {
                root_hash: hex_encode(&e.root_hash),
                root_version: e.root_version,
                updated_at: e.updated_at,
            },
        ),
        LedgerEvent::BundleSignerUpdated(e) => (
            "BundleSignerUpdated",
            SerializedEvent::BundleSignerUpdated {
                signer_address: hex_encode(&e.signer_address),
                kid: hex_encode(&e.kid),
                public_key: hex_encode(&e.public_key),
                authorized: e.authorized,
            },
        ),
        LedgerEvent::StatusManifestAnchored(e) => (
            "StatusManifestAnchored",
            SerializedEvent::StatusManifestAnchored {
                issuer_id: hex_encode(&e.issuer_id),
                manifest_version: e.manifest_version,
                manifest_hash: hex_encode(&e.manifest_hash),
                uri_hint: e.uri_hint.clone(),
            },
        ),
        _ => {
            return Err(IndexerError::Serialization(
                "Variante de evento no soportada".to_string(),
            ));
        }
    };

    let json = serde_json::to_string(&ser)
        .map_err(|e| IndexerError::Serialization(format!("Error serializando evento: {e}")))?;
    Ok((event_name, json))
}

/// Deserializa una cadena JSON a un [`LedgerEvent`].
///
/// # Errores
/// Devuelve [`IndexerError::Serialization`] si el JSON es inválido o no coincide con ninguna variante.
pub fn deserialize_ledger_event(json_str: &str) -> Result<LedgerEvent, IndexerError> {
    let ser: SerializedEvent = serde_json::from_str(json_str)
        .map_err(|e| IndexerError::Serialization(format!("JSON inválido para evento: {e}")))?;

    match ser {
        SerializedEvent::IssuerRegistered {
            issuer_id,
            uri,
            profiles,
            vcts,
            valid_from,
            valid_until,
        } => Ok(LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
            issuer_id: to_bytes32(&issuer_id)?,
            uri,
            profiles,
            vcts,
            valid_from,
            valid_until,
        })),
        SerializedEvent::IssuerSuspended {
            issuer_id,
            expires_at,
            initiated_by,
        } => Ok(LedgerEvent::IssuerSuspended(IssuerSuspendedEvent {
            issuer_id: to_bytes32(&issuer_id)?,
            expires_at,
            initiated_by: to_bytes20(&initiated_by)?,
        })),
        SerializedEvent::IssuerReinstated { issuer_id } => {
            Ok(LedgerEvent::IssuerReinstated(IssuerReinstatedEvent {
                issuer_id: to_bytes32(&issuer_id)?,
            }))
        }
        SerializedEvent::IssuerDeregistered { issuer_id } => {
            Ok(LedgerEvent::IssuerDeregistered(IssuerDeregisteredEvent {
                issuer_id: to_bytes32(&issuer_id)?,
            }))
        }
        SerializedEvent::KeyAdded {
            issuer_id,
            kid,
            public_key,
        } => Ok(LedgerEvent::KeyAdded(KeyAddedEvent {
            issuer_id: to_bytes32(&issuer_id)?,
            kid: to_bytes32(&kid)?,
            public_key: hex_decode(&public_key)?,
        })),
        SerializedEvent::KeyRetired {
            issuer_id,
            kid,
            state_since,
        } => Ok(LedgerEvent::KeyRetired(KeyRetiredEvent {
            issuer_id: to_bytes32(&issuer_id)?,
            kid: to_bytes32(&kid)?,
            state_since,
        })),
        SerializedEvent::KeySuspended {
            issuer_id,
            kid,
            expires_at,
            initiated_by,
        } => Ok(LedgerEvent::KeySuspended(KeySuspendedEvent {
            issuer_id: to_bytes32(&issuer_id)?,
            kid: to_bytes32(&kid)?,
            expires_at,
            initiated_by: to_bytes20(&initiated_by)?,
        })),
        SerializedEvent::KeyCompromised {
            issuer_id,
            kid,
            state_since,
        } => Ok(LedgerEvent::KeyCompromised(KeyCompromisedEvent {
            issuer_id: to_bytes32(&issuer_id)?,
            kid: to_bytes32(&kid)?,
            state_since,
        })),
        SerializedEvent::VerifierRegistered {
            verifier_id,
            uri,
            profiles,
            public_key,
            valid_from,
            valid_until,
        } => Ok(LedgerEvent::VerifierRegistered(VerifierRegisteredEvent {
            verifier_id: to_bytes32(&verifier_id)?,
            uri,
            profiles,
            public_key: hex_decode(&public_key)?,
            valid_from,
            valid_until,
        })),
        SerializedEvent::VerifierDeregistered { verifier_id } => Ok(
            LedgerEvent::VerifierDeregistered(VerifierDeregisteredEvent {
                verifier_id: to_bytes32(&verifier_id)?,
            }),
        ),
        SerializedEvent::TrustRootUpdated {
            root_hash,
            root_version,
            updated_at,
        } => Ok(LedgerEvent::TrustRootUpdated(TrustRootUpdatedEvent {
            root_hash: to_bytes32(&root_hash)?,
            root_version,
            updated_at,
        })),
        SerializedEvent::BundleSignerUpdated {
            signer_address,
            kid,
            public_key,
            authorized,
        } => Ok(LedgerEvent::BundleSignerUpdated(BundleSignerUpdatedEvent {
            signer_address: to_bytes20(&signer_address)?,
            kid: to_bytes32(&kid)?,
            public_key: hex_decode(&public_key)?,
            authorized,
        })),
        SerializedEvent::StatusManifestAnchored {
            issuer_id,
            manifest_version,
            manifest_hash,
            uri_hint,
        } => Ok(LedgerEvent::StatusManifestAnchored(
            StatusManifestAnchoredEvent {
                issuer_id: to_bytes32(&issuer_id)?,
                manifest_version,
                manifest_hash: to_bytes32(&manifest_hash)?,
                uri_hint,
            },
        )),
    }
}

/// Codifica bytes a una representación hexadecimal sin prefijo.
#[must_use]
pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len().saturating_mul(2));
    for byte in data {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// Decodifica una cadena hexadecimal a bytes.
///
/// # Errores
/// Devuelve [`IndexerError::Serialization`] si la longitud es impar o contiene caracteres no válidos.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, IndexerError> {
    let clean = s.strip_prefix("0x").unwrap_or(s);
    if !clean.len().is_multiple_of(2) {
        return Err(IndexerError::Serialization(
            "Longitud hexadecimal impar".to_string(),
        ));
    }
    let mut bytes = Vec::with_capacity(clean.len() / 2);
    for chunk in clean.as_bytes().chunks(2) {
        let chunk_str =
            std::str::from_utf8(chunk).map_err(|e| IndexerError::Serialization(e.to_string()))?;
        let byte = u8::from_str_radix(chunk_str, 16)
            .map_err(|e| IndexerError::Serialization(e.to_string()))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn to_bytes32(s: &str) -> Result<[u8; 32], IndexerError> {
    let b = hex_decode(s)?;
    if b.len() != 32 {
        return Err(IndexerError::Serialization(format!(
            "Se esperaban 32 bytes para campo hash/id, pero se obtuvieron {}",
            b.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&b);
    Ok(arr)
}

fn to_bytes20(s: &str) -> Result<[u8; 20], IndexerError> {
    let b = hex_decode(s)?;
    if b.len() != 20 {
        return Err(IndexerError::Serialization(format!(
            "Se esperaban 20 bytes para dirección Ethereum, pero se obtuvieron {}",
            b.len()
        )));
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&b);
    Ok(arr)
}
