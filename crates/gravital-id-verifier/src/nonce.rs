//! Caché de nonces anti-replay con expiración y capacidad acotada (F4.T07, REQ-PRES-004, REQ-VER-008).
//!
//! El verificador offline genera un desafío de sesión aleatorio (nonce $\ge 128$ bits)
//! y debe recordar los nonces utilizados hasta su expiración temporal para rechazar
//! cualquier intento de reutilización (ataque de repetición).
//!
//! Trazabilidad:
//! - **REQ-PRES-004:** El verificador DEBE mantener una caché de nonces con expiración y
//!   rechazar nonces desconocidos o reutilizados.
//! - **REQ-VER-008:** Límites de memoria y cotas de entrada estrictas (`DEFAULT_MAX_NONCES`).
//! - **INV-01:** Sin I/O de red (`no_std` + `alloc`).
//! - **INV-05:** Fail-closed determinista ante reutilización de nonces (detección de replay).
//! - **INV-11:** El tiempo de caducidad se evalúa contra el reloj inyectado (`UnixTime`).

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

use gravital_id_types::{GidError, UnixTime};

pub use crate::state::{RememberedNonce, DEFAULT_MAX_NONCES};

/// Contrato abstracto para la caché de nonces anti-replay (REQ-PRES-004).
///
/// El verificador interactivo necesita recordar nonces de sesión para evitar ataques de replay.
/// Este trait define las operaciones mínimas necesarias para comprobar, recordar y purgar
/// nonces con expiración sin requerir acceso al sistema operativo ni I/O de red.
pub trait NonceCache {
    /// Comprueba si un nonce ya fue registrado y sigue vigente según el instante dado.
    ///
    /// # Errores
    /// Devuelve [`GidError`] si el almacén subyacente presenta inconsistencias o corrupción.
    fn is_seen(&self, nonce: &str, now: UnixTime) -> Result<bool, GidError>;

    /// Recuerda un nonce hasta su instante de expiración.
    ///
    /// Si la caché alcanza su capacidad máxima, desaloja primero las entradas expiradas.
    /// Si no hay expiradas, desaloja la entrada con la expiración más temprana (FIFO por expiración).
    ///
    /// # Errores
    /// Devuelve [`GidError`] si el registro no puede completarse.
    fn remember(&mut self, nonce: &str, expires_at: UnixTime) -> Result<(), GidError>;

    /// Comprueba atómicamente si el nonce fue visto; si es fresco, lo registra de inmediato.
    ///
    /// Devuelve `Ok(true)` si el nonce era fresco y fue registrado.
    /// Devuelve `Ok(false)` si el nonce ya existía y aún no ha expirado (replay detectado).
    ///
    /// # Errores
    /// Devuelve [`GidError`] ante fallos de lectura o escritura del almacén.
    fn check_and_consume(
        &mut self,
        nonce: &str,
        expires_at: UnixTime,
        now: UnixTime,
    ) -> Result<bool, GidError> {
        if self.is_seen(nonce, now)? {
            return Ok(false);
        }
        self.remember(nonce, expires_at)?;
        Ok(true)
    }

    /// Purga las entradas expiradas antes o en el instante `now`.
    fn purge_expired(&mut self, now: UnixTime);

    /// Número de entradas actualmente en la caché.
    fn len(&self) -> usize;

    /// Indica si la caché está vacía.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Capacidad máxima configurada para la caché.
    fn capacity(&self) -> usize;

    /// Limpia todas las entradas de la caché.
    fn clear(&mut self);
}

/// Implementación en memoria de la caché de nonces anti-replay (`no_std` + `alloc`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InMemoryNonceCache {
    entries: BTreeMap<String, RememberedNonce>,
    capacity: usize,
}

impl InMemoryNonceCache {
    /// Capacidad por defecto (4.096 nonces, REQ-VER-008).
    pub const DEFAULT_CAPACITY: usize = DEFAULT_MAX_NONCES;

    /// Crea una nueva caché en memoria con la capacidad por defecto.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }

    /// Crea una nueva caché en memoria con la capacidad especificada.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity: if capacity == 0 { 1 } else { capacity },
        }
    }

    /// Iterador ordenado sobre los nonces almacenados.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &RememberedNonce)> {
        self.entries.iter()
    }
}

impl Default for InMemoryNonceCache {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceCache for InMemoryNonceCache {
    fn is_seen(&self, nonce: &str, now: UnixTime) -> Result<bool, GidError> {
        match self.entries.get(nonce) {
            Some(entry) if entry.expires_at.as_seconds() >= now.as_seconds() => Ok(true),
            _ => Ok(false),
        }
    }

    fn remember(&mut self, nonce: &str, expires_at: UnixTime) -> Result<(), GidError> {
        if self.entries.contains_key(nonce) {
            if let Some(entry) = self.entries.get_mut(nonce) {
                if expires_at.as_seconds() > entry.expires_at.as_seconds() {
                    entry.expires_at = expires_at;
                }
            }
            return Ok(());
        }

        // Si alcanzamos la capacidad máxima, desalojamos la entrada que expira antes (FIFO por expiración)
        if self.entries.len() >= self.capacity {
            let mut earliest_victim: Option<(UnixTime, String)> = None;
            for (candidate, entry) in self.entries.iter() {
                match &earliest_victim {
                    Some((earliest_exp, _)) if earliest_exp <= &entry.expires_at => {}
                    _ => earliest_victim = Some((entry.expires_at, candidate.clone())),
                }
            }
            if let Some((_, victim)) = earliest_victim {
                self.entries.remove(&victim);
            }
        }

        self.entries
            .insert(nonce.to_string(), RememberedNonce { expires_at });
        Ok(())
    }

    fn purge_expired(&mut self, now: UnixTime) {
        self.entries
            .retain(|_, entry| entry.expires_at.as_seconds() > now.as_seconds());
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn capacity(&self) -> usize {
        self.capacity
    }

    fn clear(&mut self) {
        self.entries.clear();
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

    // Verifies: REQ-PRES-004
    #[test]
    fn check_and_consume_prevents_replay() {
        let mut cache = InMemoryNonceCache::new();
        let now = UnixTime::from_seconds(1_000);
        let expires_at = UnixTime::from_seconds(1_300);

        // Primer consumo: éxito
        assert!(cache
            .check_and_consume("nonce-1", expires_at, now)
            .expect("consume"));
        assert_eq!(cache.len(), 1);

        // Segundo consumo: detecta replay y devuelve false
        assert!(!cache
            .check_and_consume("nonce-1", expires_at, now)
            .expect("consume"));

        // Otro nonce fresco se admite
        assert!(cache
            .check_and_consume("nonce-2", expires_at, now)
            .expect("consume"));
        assert_eq!(cache.len(), 2);
    }

    // Verifies: REQ-PRES-004, INV-11
    #[test]
    fn expired_nonce_can_be_reused_after_expiry() {
        let mut cache = InMemoryNonceCache::new();
        let now = UnixTime::from_seconds(1_000);
        let expires_at = UnixTime::from_seconds(1_050);

        cache.remember("nonce-temp", expires_at).expect("remember");
        assert!(cache.is_seen("nonce-temp", now).expect("seen"));

        // En o después de expires_at, ya no bloquea
        let after = UnixTime::from_seconds(1_051);
        assert!(!cache.is_seen("nonce-temp", after).expect("seen"));

        // Puede ser registrado de nuevo
        let new_expires_at = UnixTime::from_seconds(1_200);
        assert!(cache
            .check_and_consume("nonce-temp", new_expires_at, after)
            .expect("consume"));
    }

    // Verifies: REQ-VER-008
    #[test]
    fn capacity_is_strictly_bounded_and_evicts_earliest_expiring() {
        let mut cache = InMemoryNonceCache::with_capacity(3);
        let now = UnixTime::from_seconds(1_000);

        cache
            .remember("nonce-exp-300", UnixTime::from_seconds(1_300))
            .expect("remember");
        cache
            .remember("nonce-exp-100", UnixTime::from_seconds(1_100))
            .expect("remember");
        cache
            .remember("nonce-exp-200", UnixTime::from_seconds(1_200))
            .expect("remember");
        assert_eq!(cache.len(), 3);

        // Al insertar un 4º nonce fresco, el que expira antes (nonce-exp-100) es desalojado
        cache
            .remember("nonce-exp-400", UnixTime::from_seconds(1_400))
            .expect("remember");
        assert_eq!(cache.len(), 3);

        assert!(!cache.is_seen("nonce-exp-100", now).expect("seen"));
        assert!(cache.is_seen("nonce-exp-200", now).expect("seen"));
        assert!(cache.is_seen("nonce-exp-300", now).expect("seen"));
        assert!(cache.is_seen("nonce-exp-400", now).expect("seen"));
    }

    // Verifies: REQ-PRES-004
    #[test]
    fn purge_expired_removes_only_expired_entries() {
        let mut cache = InMemoryNonceCache::new();
        cache
            .remember("active-1", UnixTime::from_seconds(1_500))
            .expect("rem");
        cache
            .remember("expired-1", UnixTime::from_seconds(1_000))
            .expect("rem");
        cache
            .remember("expired-2", UnixTime::from_seconds(1_050))
            .expect("rem");
        cache
            .remember("active-2", UnixTime::from_seconds(1_600))
            .expect("rem");

        assert_eq!(cache.len(), 4);
        cache.purge_expired(UnixTime::from_seconds(1_100));

        assert_eq!(cache.len(), 2);
        let now = UnixTime::from_seconds(1_100);
        assert!(cache.is_seen("active-1", now).expect("seen"));
        assert!(cache.is_seen("active-2", now).expect("seen"));
    }
}
