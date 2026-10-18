//! Definiciones de esquema y sentencias SQL para PostgreSQL 16 (F7.T03, ADR-0013).

/// Nombre de la tabla de puntos de control de indexación.
pub const TABLE_INDEXER_CHECKPOINTS: &str = "indexer_checkpoints";

/// Nombre de la tabla de eventos indexados.
pub const TABLE_INDEXED_EVENTS: &str = "indexed_events";

/// Nombre de la tabla de proyección de emisores.
pub const TABLE_ISSUERS_PROJECTION: &str = "issuers_projection";

/// Nombre de la tabla de proyección de claves criptográficas.
pub const TABLE_KEYS_PROJECTION: &str = "keys_projection";

/// Nombre de la tabla de proyección de anclajes de estado.
pub const TABLE_STATUS_ANCHORS_PROJECTION: &str = "status_anchors_projection";

/// Nombre de la tabla de proyección de firmantes de trust bundle.
pub const TABLE_BUNDLE_SIGNERS_PROJECTION: &str = "bundle_signers_projection";

/// Contenido DDL normativo para PostgreSQL 16 embebido en compilación.
pub const POSTGRES_SCHEMA_V1_SQL: &str = include_str!("../schema/V1__indexer_schema.sql");

/// Sentencia de inserción idempotente para eventos indexados en PostgreSQL.
pub const SQL_POSTGRES_INSERT_EVENT_IDEMPOTENT: &str = "\
INSERT INTO indexed_events (chain_id, block_number, tx_index, log_index, block_timestamp, event_type, event_payload) \
VALUES ($1, $2, $3, $4, $5, $6, $7) \
ON CONFLICT (chain_id, block_number, tx_index, log_index) DO NOTHING;";

/// Sentencia de actualización de checkpoint atómico en PostgreSQL.
pub const SQL_POSTGRES_UPSERT_CHECKPOINT: &str = "\
INSERT INTO indexer_checkpoints (chain_id, last_processed_block, last_block_hash, updated_at) \
VALUES ($1, $2, $3, NOW()) \
ON CONFLICT (chain_id) DO UPDATE \
SET last_processed_block = EXCLUDED.last_processed_block, \
    last_block_hash = EXCLUDED.last_block_hash, \
    updated_at = NOW();";

/// Sentencia de consulta de checkpoint para una cadena.
pub const SQL_POSTGRES_SELECT_CHECKPOINT: &str = "\
SELECT last_processed_block, last_block_hash \
FROM indexer_checkpoints \
WHERE chain_id = $1;";

/// Sentencia para rebobinar el cursor a una altura anterior tras un reorg.
pub const SQL_POSTGRES_REWIND_EVENTS: &str = "\
DELETE FROM indexed_events \
WHERE chain_id = $1 AND block_number > $2;";
