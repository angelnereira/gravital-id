//! Implementación de `VerifierStateStore` sobre SQLite (F5.T04, REQ-VER-006, REQ-VER-011).
//!
//! Trazabilidad:
//! - `REQ-VER-006`: Piso de tiempo monotónico en almacenamiento confiable.
//! - `REQ-VER-011`: Detección de corrupción o rollback y reinicialización explícita (`reset`).
//! - `REQ-PRES-004`: Caché persistente de nonces anti-replay.
//! - `REQ-TRUST-009`: Anti-rollback del trust bundle (`AcceptedBundleState`).
//! - `INV-01`: Cero llamadas a red durante la verificación.

use gravital_id_trust::AcceptedBundleState;
use gravital_id_types::{GidError, UnixTime};
use gravital_id_verifier::state::VerifierStateStore;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::error::{sqlite_read_err, sqlite_write_err, verifier_state_corrupted};
use crate::storage::SqliteStorage;

impl VerifierStateStore for SqliteStorage {
    fn time_floor(&self) -> Result<Option<UnixTime>, GidError> {
        let mut stmt = self
            .connection()
            .prepare("SELECT value_int FROM pip_verifier_state WHERE key = 'time_floor'")
            .map_err(sqlite_read_err)?;

        let result: Option<i64> = stmt
            .query_row([], |row| row.get(0))
            .optional()
            .map_err(sqlite_read_err)?;

        match result {
            Some(secs) => {
                let u = u64::try_from(secs)
                    .map_err(|_| verifier_state_corrupted("negative timestamp in time_floor"))?;
                Ok(Some(UnixTime::from_seconds(u)))
            }
            None => Ok(None),
        }
    }

    fn raise_time_floor(&mut self, floor: UnixTime) -> Result<(), GidError> {
        let secs = i64::try_from(floor.as_seconds())
            .map_err(|_| verifier_state_corrupted("time_floor seconds out of i64 range"))?;

        self.connection_mut()
            .execute(
                r#"
                INSERT INTO pip_verifier_state (key, value_int, updated_at)
                VALUES ('time_floor', ?1, ?1)
                ON CONFLICT(key) DO UPDATE SET
                    value_int = MAX(value_int, excluded.value_int),
                    updated_at = excluded.updated_at
                "#,
                params![secs],
            )
            .map_err(sqlite_write_err)?;

        Ok(())
    }

    fn accepted_bundle(&self) -> Result<Option<AcceptedBundleState>, GidError> {
        let mut stmt = self
            .connection()
            .prepare("SELECT value_int, value_text FROM pip_verifier_state WHERE key = 'accepted_bundle'")
            .map_err(sqlite_read_err)?;

        let result = stmt
            .query_row([], |row| {
                let epoch: i64 = row.get(0)?;
                let version_str: String = row.get(1)?;
                Ok((epoch, version_str))
            })
            .optional()
            .map_err(sqlite_read_err)?;

        match result {
            Some((epoch_i64, version_str)) => {
                let bundle_epoch = u64::try_from(epoch_i64)
                    .map_err(|_| verifier_state_corrupted("negative bundle_epoch"))?;
                let bundle_version = version_str
                    .parse::<u64>()
                    .map_err(|_| verifier_state_corrupted("invalid bundle_version format"))?;
                Ok(Some(AcceptedBundleState {
                    bundle_epoch,
                    bundle_version,
                }))
            }
            None => Ok(None),
        }
    }

    fn record_accepted_bundle(&mut self, state: AcceptedBundleState) -> Result<(), GidError> {
        let epoch_i64 = i64::try_from(state.bundle_epoch)
            .map_err(|_| verifier_state_corrupted("bundle_epoch out of i64 range"))?;
        let version_str = state.bundle_version.to_string();
        let version_i64 = i64::try_from(state.bundle_version).unwrap_or(0);

        self.connection_mut()
            .execute(
                r#"
                INSERT INTO pip_verifier_state (key, value_int, value_text, updated_at)
                VALUES ('accepted_bundle', ?1, ?2, ?3)
                ON CONFLICT(key) DO UPDATE SET
                    value_int = excluded.value_int,
                    value_text = excluded.value_text,
                    updated_at = excluded.updated_at
                "#,
                params![epoch_i64, version_str, version_i64],
            )
            .map_err(sqlite_write_err)?;

        Ok(())
    }

    fn nonce_seen(&self, nonce: &str, now: UnixTime) -> Result<bool, GidError> {
        let now_i64 = i64::try_from(now.as_seconds())
            .map_err(|_| verifier_state_corrupted("timestamp out of i64 range"))?;

        let mut stmt = self
            .connection()
            .prepare("SELECT 1 FROM pip_verifier_nonces WHERE nonce = ?1 AND expires_at >= ?2")
            .map_err(sqlite_read_err)?;

        let exists = stmt
            .query_row(params![nonce, now_i64], |_| Ok(()))
            .optional()
            .map_err(sqlite_read_err)?;

        Ok(exists.is_some())
    }

    fn remember_nonce(&mut self, nonce: &str, expires_at: UnixTime) -> Result<(), GidError> {
        let exp_i64 = i64::try_from(expires_at.as_seconds())
            .map_err(|_| verifier_state_corrupted("expires_at out of i64 range"))?;

        self.connection_mut()
            .execute(
                "INSERT INTO pip_verifier_nonces (nonce, expires_at) VALUES (?1, ?2) ON CONFLICT(nonce) DO UPDATE SET expires_at = excluded.expires_at",
                params![nonce, exp_i64],
            )
            .map_err(sqlite_write_err)?;

        Ok(())
    }

    fn check_and_consume_nonce(
        &mut self,
        nonce: &str,
        expires_at: UnixTime,
        now: UnixTime,
    ) -> Result<bool, GidError> {
        let now_i64 = i64::try_from(now.as_seconds())
            .map_err(|_| verifier_state_corrupted("timestamp out of i64 range"))?;
        let exp_i64 = i64::try_from(expires_at.as_seconds())
            .map_err(|_| verifier_state_corrupted("expires_at out of i64 range"))?;

        let tx = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_write_err)?;

        // Purgar nonces expirados periódicamente
        let _ = tx.execute(
            "DELETE FROM pip_verifier_nonces WHERE expires_at < ?1",
            params![now_i64],
        );

        let mut stmt = tx
            .prepare("SELECT 1 FROM pip_verifier_nonces WHERE nonce = ?1 AND expires_at >= ?2")
            .map_err(sqlite_read_err)?;

        let seen = stmt
            .query_row(params![nonce, now_i64], |_| Ok(()))
            .optional()
            .map_err(sqlite_read_err)?;

        if seen.is_some() {
            return Ok(false);
        }

        drop(stmt);

        tx.execute(
            "INSERT INTO pip_verifier_nonces (nonce, expires_at) VALUES (?1, ?2)",
            params![nonce, exp_i64],
        )
        .map_err(sqlite_write_err)?;

        tx.commit().map_err(sqlite_write_err)?;
        Ok(true)
    }

    fn integrity_check(&self) -> Result<(), GidError> {
        // Verifica que la tabla esté operativa y accesible
        let _ = self.time_floor()?;
        let _ = self.accepted_bundle()?;
        Ok(())
    }

    fn reset(&mut self) {
        let _ = self.connection_mut().execute_batch(
            r#"
            DELETE FROM pip_verifier_state;
            DELETE FROM pip_verifier_nonces;
            "#,
        );
    }
}
