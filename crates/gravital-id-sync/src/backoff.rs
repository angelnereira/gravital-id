//! Política de reintentos con backoff exponencial y jitter (REQ-SYNC-003).
//!
//! Trazabilidad:
//! - **REQ-SYNC-003:** Los reintentos DEBEN usar backoff exponencial con jitter.
//! - **INV-11:** Determinismo estricto: el jitter se calcula a partir de un valor semilla inyectado.

use gravital_id_types::UnixTime;
use serde::{Deserialize, Serialize};

/// Parámetros de la política de reintentos para operaciones de sincronización.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Retardo base inicial en segundos para el primer reintento (por defecto: 1 s).
    pub initial_delay_secs: u64,
    /// Retardo máximo en segundos para limitar el crecimiento exponencial (por defecto: 300 s / 5 min).
    pub max_delay_secs: u64,
    /// Número máximo de reintentos antes de marcar como fallo definitivo (por defecto: 8).
    pub max_retries: u32,
    /// Porcentaje de variación para el jitter simétrico (por defecto: 25 %).
    pub jitter_percentage: u8,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial_delay_secs: 1,
            max_delay_secs: 300,
            max_retries: 8,
            jitter_percentage: 25,
        }
    }
}

impl RetryPolicy {
    /// Crea una nueva política validando límites de seguridad.
    #[must_use]
    pub fn new(
        initial_delay_secs: u64,
        max_delay_secs: u64,
        max_retries: u32,
        jitter_percentage: u8,
    ) -> Self {
        Self {
            initial_delay_secs: initial_delay_secs.max(1),
            max_delay_secs: max_delay_secs.max(initial_delay_secs),
            max_retries: max_retries.max(1),
            jitter_percentage: jitter_percentage.min(100),
        }
    }

    /// Calcula el retardo determinista con backoff exponencial y jitter (REQ-SYNC-003).
    ///
    /// # Fórmula
    /// $$\text{base} = \min\bigl(\text{max\_delay}, \text{initial\_delay} \cdot 2^{\min(\text{retry\_count}, 16)}\bigr)$$
    /// $$\text{jitter} = (\text{jitter\_seed} \pmod{2 \cdot \text{max\_jitter} + 1}) - \text{max\_jitter}$$
    ///
    /// # Determinismo
    /// La variación de jitter se deriva puramente de `jitter_seed` (INV-11).
    #[must_use]
    pub fn compute_delay_secs(&self, retry_count: u32, jitter_seed: u64) -> u64 {
        let capped_shift = retry_count.min(16);
        let factor = 1u64.checked_shl(capped_shift).unwrap_or(u64::MAX);

        let exponential = self
            .initial_delay_secs
            .saturating_mul(factor)
            .min(self.max_delay_secs);

        let max_jitter = exponential
            .saturating_mul(u64::from(self.jitter_percentage))
            .checked_div(100)
            .unwrap_or(0);

        if max_jitter == 0 {
            exponential
        } else {
            let span = max_jitter.saturating_mul(2).saturating_add(1);
            let offset = jitter_seed.checked_rem(span).unwrap_or(0);
            if offset >= max_jitter {
                let add = offset.saturating_sub(max_jitter);
                exponential.saturating_add(add).min(self.max_delay_secs)
            } else {
                let sub = max_jitter.saturating_sub(offset);
                exponential.saturating_sub(sub).max(1)
            }
        }
    }

    /// Calcula el instante del próximo intento sumando el retardo calculado a `now`.
    #[must_use]
    pub fn compute_next_attempt(
        &self,
        retry_count: u32,
        now: UnixTime,
        jitter_seed: u64,
    ) -> UnixTime {
        let delay = self.compute_delay_secs(retry_count, jitter_seed);
        UnixTime::from_seconds(now.as_seconds().saturating_add(delay))
    }
}
