//! Limitador de tasa (Rate Limiter) en memoria para pip-relay (F7.T06).
//!
//! Implementa el algoritmo Token Bucket por cliente (IP o token de acceso) mediante
//! aritmética de enteros estricta en milisegundos (`-D clippy::float-arithmetic`).
//! Cumple con `INV-02` (cero registro de IPs o identificadores en texto claro en logs).

use std::collections::HashMap;
use std::sync::Mutex;

use gravital_id_types::{Clock, UnixTime};

use crate::error::RelayError;

/// Unidades de militokens por token completo para aritmética entera de alta precisión.
const MILLI_TOKENS_PER_TOKEN: u64 = 1_000;

/// Cubeta de tokens para un cliente individual.
#[derive(Debug, Clone)]
struct ClientBucket {
    tokens_milli: u64,
    last_update: UnixTime,
}

/// Limitador de tasa en memoria basado en Token Bucket con aritmética entera sin punto flotante.
pub struct RateLimiter<C: Clock + Send + Sync + 'static> {
    clock: C,
    milli_tokens_per_sec: u64,
    burst_capacity_milli: u64,
    buckets: Mutex<HashMap<String, ClientBucket>>,
}

impl<C: Clock + Send + Sync + 'static> RateLimiter<C> {
    /// Construye un limitador de tasa con las cuotas indicadas y el reloj inyectado.
    pub fn new(requests_per_minute: u32, burst: u32, clock: C) -> Self {
        let rpm = (requests_per_minute as u64).max(1);
        let milli_tokens_per_sec = rpm.saturating_mul(MILLI_TOKENS_PER_TOKEN).div_ceil(60);
        let burst_capacity_milli = (burst as u64).max(1).saturating_mul(MILLI_TOKENS_PER_TOKEN);

        Self {
            clock,
            milli_tokens_per_sec,
            burst_capacity_milli,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    #[inline]
    fn now(&self) -> UnixTime {
        UnixTime::from_seconds(self.clock.now_seconds())
    }

    /// Verifica si la petición del cliente está dentro de la cuota permitida y consume un token.
    ///
    /// # Errores
    /// [`RelayError::RateLimitExceeded`] si la cubeta no dispone de tokens suficientes.
    pub fn check_rate_limit(&self, client_id: &str) -> Result<(), RelayError> {
        let now = self.now();
        let mut lock = self
            .buckets
            .lock()
            .map_err(|_| RelayError::Internal("poisoned rate limiter lock".into()))?;

        // Limpieza periódica si la tabla de clientes es grande
        if lock.len() > 10_000 {
            let cutoff = UnixTime::from_seconds(now.as_seconds().saturating_sub(300));
            lock.retain(|_, b| b.last_update > cutoff);
        }

        let burst_cap = self.burst_capacity_milli;
        let bucket = lock
            .entry(client_id.to_string())
            .or_insert_with(|| ClientBucket {
                tokens_milli: burst_cap,
                last_update: now,
            });

        // Rellenar tokens según los segundos enteros transcurridos
        let elapsed_secs = now
            .as_seconds()
            .saturating_sub(bucket.last_update.as_seconds());
        if elapsed_secs > 0 {
            let added = elapsed_secs.saturating_mul(self.milli_tokens_per_sec);
            bucket.tokens_milli = bucket.tokens_milli.saturating_add(added).min(burst_cap);
            bucket.last_update = now;
        }

        if bucket.tokens_milli >= MILLI_TOKENS_PER_TOKEN {
            bucket.tokens_milli = bucket.tokens_milli.saturating_sub(MILLI_TOKENS_PER_TOKEN);
            Ok(())
        } else {
            Err(RelayError::RateLimitExceeded)
        }
    }

    /// Retorna el número de clientes rastreados actualmente en el limitador.
    pub fn tracked_clients_count(&self) -> usize {
        self.buckets.lock().map(|b| b.len()).unwrap_or(0)
    }
}
