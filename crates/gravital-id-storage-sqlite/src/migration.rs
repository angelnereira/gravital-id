//! Motor de migraciones versionadas de esquema para SQLite (F5.T05, REQ-STOR-005).
//!
//! Trazabilidad:
//! - `REQ-STOR-005`: Versionado obligatorio y migraciones atómicas y probadas con esquemas anteriores.
//! - `STORAGE_FORMAT.md §6`: Procedimiento paso a paso $N \to N+1 \dots \to M$.
//! - `INV-04`, `INV-05`: Fail-closed ante fallos de migración.

use gravital_id_types::{ErrorCode, GidError};
use rusqlite::{params, Connection};

use crate::error::migration_err;

/// Versión actual más reciente del esquema de almacenamiento SQLite.
pub const LATEST_SCHEMA_VERSION: u32 = 2;

/// Definición de una migración de esquema paso a paso.
pub struct Migration {
    /// Número de versión que introduce esta migración.
    pub version: u32,
    /// Descripción técnica de los cambios.
    pub description: &'static str,
    /// Script SQL a ejecutar dentro de una transacción atómica.
    pub sql: &'static str,
}

/// Lista ordenada de todas las migraciones publicadas.
pub static MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        description: "Esquema inicial v1: tablas de registros, índices ciegos y estado de verificador",
        sql: r#"
            CREATE TABLE IF NOT EXISTS pip_records (
                record_id TEXT PRIMARY KEY,
                collection TEXT NOT NULL,
                record_data BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pip_blind_indices (
                index_hash TEXT NOT NULL,
                record_id TEXT NOT NULL,
                collection TEXT NOT NULL,
                PRIMARY KEY (index_hash, record_id),
                FOREIGN KEY (record_id) REFERENCES pip_records(record_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_pip_blind_lookup ON pip_blind_indices(collection, index_hash);
            CREATE INDEX IF NOT EXISTS idx_pip_records_collection ON pip_records(collection);

            CREATE TABLE IF NOT EXISTS pip_verifier_state (
                key TEXT PRIMARY KEY,
                value_int INTEGER,
                value_text TEXT,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pip_verifier_nonces (
                nonce TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_pip_nonces_expiry ON pip_verifier_nonces(expires_at);
        "#,
    },
    Migration {
        version: 2,
        description: "Esquema v2: índice sobre updated_at para depuración y retención de eventos (REQ-STOR-006)",
        sql: r#"
            CREATE INDEX IF NOT EXISTS idx_pip_records_updated_at ON pip_records(updated_at);
        "#,
    },
];

/// Inicializa la tabla de control de versiones de esquema `pip_schema_migrations`.
pub fn init_migrations_table(conn: &Connection) -> Result<(), GidError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS pip_schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at INTEGER NOT NULL
        );
        "#,
    )
    .map_err(migration_err)
}

/// Obtiene la versión actual de esquema registrada en la base de datos.
///
/// Si la tabla aún no existe o no tiene registros, devuelve 0.
pub fn get_current_version(conn: &Connection) -> Result<u32, GidError> {
    init_migrations_table(conn)?;
    let mut stmt = conn
        .prepare("SELECT COALESCE(MAX(version), 0) FROM pip_schema_migrations")
        .map_err(migration_err)?;
    let version: u32 = stmt
        .query_row([], |row| row.get(0))
        .map_err(migration_err)?;
    Ok(version)
}

/// Aplica todas las migraciones pendientes hasta `target_version` de forma atómica paso a paso.
///
/// Cada paso de migración se ejecuta dentro de su propia transacción inmediata (`REQ-STOR-004`).
///
/// # Errores
/// [`ErrorCode::SchemaMigrationFailed`] si alguna migración falla o si `target_version` es menor
/// que la versión actual registrada en disco (anti-downgrade).
pub fn apply_migrations(
    conn: &mut Connection,
    target_version: u32,
    now_secs: u64,
) -> Result<u32, GidError> {
    let current = get_current_version(conn)?;

    if current > target_version {
        return Err(GidError::new(
            ErrorCode::SchemaMigrationFailed,
            format!(
                "Database schema version ({current}) is newer than supported binary target ({target_version})"
            ),
        ));
    }

    if current == target_version {
        return Ok(current);
    }

    for migration in MIGRATIONS {
        if migration.version > current && migration.version <= target_version {
            let tx = conn.transaction().map_err(migration_err)?;
            tx.execute_batch(migration.sql).map_err(migration_err)?;
            tx.execute(
                "INSERT INTO pip_schema_migrations (version, applied_at) VALUES (?1, ?2)",
                params![migration.version, now_secs],
            )
            .map_err(migration_err)?;
            tx.commit().map_err(migration_err)?;
        }
    }

    get_current_version(conn)
}
