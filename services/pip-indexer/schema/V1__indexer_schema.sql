-- V1__indexer_schema.sql — Esquema relacional oficial para pip-indexer (PostgreSQL 16)
-- Trazabilidad: REQ-LEDG-005, ADR-0013, INV-02 (Cero datos personales en almacenamiento de eventos o proyecciones)

-- 1. Checkpoint de cursor de indexación por cadena
CREATE TABLE IF NOT EXISTS indexer_checkpoints (
    chain_id BIGINT NOT NULL,
    last_processed_block BIGINT NOT NULL,
    last_block_hash VARCHAR(66),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (chain_id)
);

-- 2. Registro canónico de eventos ordenados e indexados
CREATE TABLE IF NOT EXISTS indexed_events (
    chain_id BIGINT NOT NULL,
    block_number BIGINT NOT NULL,
    tx_index INT NOT NULL,
    log_index INT NOT NULL,
    block_timestamp BIGINT NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    event_payload JSONB NOT NULL,
    indexed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (chain_id, block_number, tx_index, log_index)
);

CREATE INDEX IF NOT EXISTS idx_indexed_events_block_range
    ON indexed_events (chain_id, block_number);

CREATE INDEX IF NOT EXISTS idx_indexed_events_type
    ON indexed_events (chain_id, event_type);

-- 3. Proyección de emisores institucionales
CREATE TABLE IF NOT EXISTS issuers_projection (
    chain_id BIGINT NOT NULL,
    issuer_id VARCHAR(66) NOT NULL,
    uri TEXT NOT NULL,
    profiles JSONB NOT NULL DEFAULT '[]'::jsonb,
    vcts JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(32) NOT NULL,
    valid_from BIGINT NOT NULL,
    valid_until BIGINT NOT NULL,
    suspended_until BIGINT,
    updated_at_block BIGINT NOT NULL,
    PRIMARY KEY (chain_id, issuer_id)
);

-- 4. Proyección de claves de emisores
CREATE TABLE IF NOT EXISTS keys_projection (
    chain_id BIGINT NOT NULL,
    kid VARCHAR(66) NOT NULL,
    issuer_id VARCHAR(66) NOT NULL,
    public_key_sec1 TEXT NOT NULL,
    status VARCHAR(32) NOT NULL,
    suspended_until BIGINT,
    updated_at_block BIGINT NOT NULL,
    PRIMARY KEY (chain_id, kid)
);

CREATE INDEX IF NOT EXISTS idx_keys_projection_issuer
    ON keys_projection (chain_id, issuer_id);

-- 5. Proyección de anclajes de manifiestos de estado
CREATE TABLE IF NOT EXISTS status_anchors_projection (
    chain_id BIGINT NOT NULL,
    issuer_id VARCHAR(66) NOT NULL,
    manifest_version BIGINT NOT NULL,
    manifest_hash VARCHAR(66) NOT NULL,
    uri_hint TEXT NOT NULL,
    updated_at_block BIGINT NOT NULL,
    PRIMARY KEY (chain_id, issuer_id, manifest_version)
);

-- 6. Proyección de firmantes de trust bundle
CREATE TABLE IF NOT EXISTS bundle_signers_projection (
    chain_id BIGINT NOT NULL,
    signer_address VARCHAR(42) NOT NULL,
    kid VARCHAR(66) NOT NULL,
    public_key_sec1 TEXT NOT NULL,
    authorized BOOLEAN NOT NULL,
    updated_at_block BIGINT NOT NULL,
    PRIMARY KEY (chain_id, signer_address)
);
