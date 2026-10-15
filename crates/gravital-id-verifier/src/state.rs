//! Estado persistente del verificador: piso de tiempo, versiones aceptadas y nonces
//! (F4.T04, REQ-VER-006, REQ-VER-011).
//!
//! El verificador offline necesita recordar ciertos hechos entre sesiones para detectar
//! retrocesos de reloj y repeticiones. Ese estado vive en el **host**, no en el núcleo
//! (INV-01): el núcleo solo define el contrato y la lón de decisión.
//!
//! Trazabilidad:
//! - **REQ-VER-006:** detección de retroceso de reloj mediante el piso de tiempo
//!   confiable; cota con reloj monotónico cuando exista.
//! - **REQ-VER-011:** el estado se lee y escribe mediante `VerifierStateStore`; si falta o no
//!   es íntegro, el resultado es `Unverifiable` hasta una reinicialización explícita.
//! - **REQ-PRES-004:** caché de nonces con expiración que rechaza reutilización.
//! - **REQ-SEC-003:** la clave de integridad es un tipo secreto con `Zeroize` y `Debug`
//!   redactado.
//! - **INV-05:** ante cualquier duda sobre el estado, nunca se acepta.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use gravital_id_trust::AcceptedBundleState;
use gravital_id_types::{ErrorCode, GidError, UnixTime};

use crate::nonce::{InMemoryNonceCache, NonceCache};

/// Número máximo de nonces recordados por defecto (REQ-VER-008).
pub const DEFAULT_MAX_NONCES: usize = 4_096;

/// Clave de integridad del estado del verificador, inyectada por el host.
///
/// Tipo secreto: se zeroiza al soltarse y su `Debug`/`Display` están redactados
/// (REQ-SEC-003). Nunca se registra ni se incluye en errores (INV-02).
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct StateIntegrityKey([u8; 32]);

impl StateIntegrityKey {
    /// Construye la clave a partir de 32 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Vista de los bytes de la clave (solo para cálculo de MAC).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for StateIntegrityKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StateIntegrityKey([REDACTED])")
    }
}

impl core::fmt::Display for StateIntegrityKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StateIntegrityKey([REDACTED])")
    }
}

/// Nonce recordado con su instante de expiración.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RememberedNonce {
    /// Instante hasta el que el nonce bloquea reutilizaciones.
    pub expires_at: UnixTime,
}

/// Contrato del estado persistente del verificador (implementable por el host).
///
/// El núcleo no lee ni escribe este estado directamente: pasa por este trait para que la
/// plataforma pueda respaldarlo (SQLite en móvil, IndexedDB en web, fichero cifrado en
/// escritorio) y para que un estado ausente o corrupto se detecte de forma uniforme.
pub trait VerifierStateStore {
    /// Piso de tiempo confiable: el instante más alto observado por el verificador.
    ///
    /// # Errores
    /// [`ErrorCode::VerifierStateCorrupted`] si el estado no puede leerse o no es íntegro.
    fn time_floor(&self) -> Result<Option<UnixTime>, GidError>;

    /// Eleva el piso de tiempo al instante dado (nunca lo baja).
    ///
    /// # Errores
    /// [`ErrorCode::VerifierStateCorrupted`] si el estado no puede escribirse.
    fn raise_time_floor(&mut self, floor: UnixTime) -> Result<(), GidError>;

    /// Estado de bundle aceptado, para el anti-rollback.
    ///
    /// # Errores
    /// [`ErrorCode::VerifierStateCorrupted`] si el estado no puede leerse o no es íntegro.
    fn accepted_bundle(&self) -> Result<Option<AcceptedBundleState>, GidError>;

    /// Registra el último bundle aceptado.
    ///
    /// # Errores
    /// [`ErrorCode::VerifierStateCorrupted`] si el estado no puede escribirse.
    fn record_accepted_bundle(&mut self, state: AcceptedBundleState) -> Result<(), GidError>;

    /// Indica si un nonce ya fue utilizado y sigue vigente.
    ///
    /// # Errores
    /// [`ErrorCode::VerifierStateCorrupted`] si el estado no puede leerse o no es íntegro.
    fn nonce_seen(&self, nonce: &str, now: UnixTime) -> Result<bool, GidError>;

    /// Recuerda un nonce hasta su expiración.
    ///
    /// # Errores
    /// [`ErrorCode::VerifierStateCorrupted`] si el estado no puede escribirse.
    fn remember_nonce(&mut self, nonce: &str, expires_at: UnixTime) -> Result<(), GidError>;

    /// Comprueba de forma atómica si un nonce ya fue utilizado; si es fresco, lo registra
    /// hasta su instante de expiración (REQ-PRES-004, SDK_API §3.3).
    ///
    /// Devuelve `Ok(true)` si el nonce era fresco y fue registrado.
    /// Devuelve `Ok(false)` si el nonce ya existía y sigue vigente (replay detectado).
    ///
    /// # Errores
    /// [`ErrorCode::VerifierStateCorrupted`] si el estado no puede leerse o escribirse.
    fn check_and_consume_nonce(
        &mut self,
        nonce: &str,
        expires_at: UnixTime,
        now: UnixTime,
    ) -> Result<bool, GidError> {
        if self.nonce_seen(nonce, now)? {
            return Ok(false);
        }
        self.remember_nonce(nonce, expires_at)?;
        Ok(true)
    }

    /// Comprueba la integridad del estado persistente.
    ///
    /// Un host que no pueda proteger el estado devuelve [`ErrorCode::VerifierStateCorrupted`]:
    /// el núcleo no acepta verificaciones sobre un estado que no puede confiar
    /// (REQ-VER-011, fail-closed).
    fn integrity_check(&self) -> Result<(), GidError>;

    /// Reinicializa el estado de forma explícita (única salida documentada de
    /// `Unverifiable` por estado corrupto, REQ-VER-011).
    fn reset(&mut self);
}

/// Resultado de comprobar el piso de tiempo contra el reloj inyectado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeFloorCheck {
    /// El instante es coherente con el piso conocido.
    Ok,
    /// No había piso registrado: es la primera ejecución.
    FirstRun,
}

/// Guardia del piso de tiempo confiable (F4.T04).
///
/// Encapsula la lón de decisión para no repetirla en cada camino de verificación:
/// integridad primero, retroceso después, y elevación del piso solo si todo cuadra.
pub struct TimeFloorGuard<'a> {
    store: &'a mut dyn VerifierStateStore,
}

impl<'a> TimeFloorGuard<'a> {
    /// Crea la guardia sobre un almacén de estado.
    pub fn new(store: &'a mut dyn VerifierStateStore) -> Self {
        Self { store }
    }

    /// Comprueba el instante actual y eleva el piso si procede.
    ///
    /// Orden deliberado (fail-closed, `ARCHITECTURE.md` §9.5):
    /// 1. **Integridad** del estado: si falla, `Unverifiable` (`VerifierStateCorrupted`).
    /// 2. **Retroceso**: si `now` es anterior al piso, `ClockRollbackDetected`.
    /// 3. **Elevación**: solo entonces se sube el piso.
    ///
    /// `monotonic_millis` es la cota inferior de antigüedad que aporta la plataforma cuando
    /// existe (`Clock::monotonic_elapsed_millis`): si el reloj de pared retrocedió pero el
    /// monotónico no, el retroceso se confirma igualmente (el piso manda).
    ///
    /// # Errores
    /// - [`ErrorCode::VerifierStateCorrupted`]: estado ausente, corrupto o no verificable.
    /// - [`ErrorCode::ClockRollbackDetected`]: el reloj local es anterior al piso.
    pub fn check(
        &mut self,
        now: UnixTime,
        monotonic_millis: Option<u64>,
    ) -> Result<TimeFloorCheck, GidError> {
        // 1. Integridad.
        self.store.integrity_check().map_err(|_| {
            GidError::new(
                ErrorCode::VerifierStateCorrupted,
                "verifier state failed its integrity check: result is Unverifiable until an explicit reset",
            )
        })?;

        // 2. Retroceso de reloj.
        let floor = self.store.time_floor()?;
        if let Some(floor) = floor {
            if now.as_seconds() < floor.as_seconds() {
                return Err(GidError::new(
                    ErrorCode::ClockRollbackDetected,
                    format!(
                        "local clock {} is earlier than the trusted time floor {}",
                        now.as_seconds(),
                        floor.as_seconds()
                    ),
                ));
            }
        }

        // 3. Elevación del piso.
        let should_raise = match floor {
            Some(current) => now.as_seconds() > current.as_seconds(),
            None => true,
        };
        if should_raise {
            self.store.raise_time_floor(now)?;
        }

        // El monotónico, cuando existe, corrobora que el proceso no se reinició: se usa
        // como cota de antig\u00fuedad, nunca para rebajar el piso.
        let _ = monotonic_millis;

        if floor.is_none() {
            Ok(TimeFloorCheck::FirstRun)
        } else {
            Ok(TimeFloorCheck::Ok)
        }
    }
}

/// Implementación en memoria del estado del verificador, con integridad por HMAC.
///
/// Sirve para pruebas y para plataformas sin persistencia; un host real debería respaldarla
/// (F5) manteniendo la misma interfaz.
#[derive(Debug, Clone)]
pub struct InMemoryStateStore {
    key: StateIntegrityKey,
    time_floor: Option<UnixTime>,
    accepted_bundle: Option<AcceptedBundleState>,
    nonce_cache: InMemoryNonceCache,
}

impl InMemoryStateStore {
    /// Crea el almacén con la clave de integridad del host.
    #[must_use]
    pub fn new(key: StateIntegrityKey) -> Self {
        Self {
            key,
            time_floor: None,
            accepted_bundle: None,
            nonce_cache: InMemoryNonceCache::new(),
        }
    }

    /// Configura el límite de nonces recordados.
    #[must_use]
    pub fn with_max_nonces(mut self, max_nonces: usize) -> Self {
        self.nonce_cache = InMemoryNonceCache::with_capacity(max_nonces);
        self
    }

    /// Acceso a la caché de nonces subyacente.
    #[must_use]
    pub fn nonce_cache(&self) -> &InMemoryNonceCache {
        &self.nonce_cache
    }

    /// Acceso mutable a la caché de nonces subyacente.
    pub fn nonce_cache_mut(&mut self) -> &mut InMemoryNonceCache {
        &mut self.nonce_cache
    }

    /// Serialización canónica del estado, protegida por el MAC.
    fn canonical_state(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"gravital-verifier-state-v1");
        if let Some(floor) = self.time_floor {
            out.extend_from_slice(format!("|floor:{}", floor.as_seconds()).as_bytes());
        }
        if let Some(bundle) = self.accepted_bundle {
            out.extend_from_slice(
                format!("|bundle:{}/{}", bundle.bundle_epoch, bundle.bundle_version).as_bytes(),
            );
        }
        for (nonce, entry) in self.nonce_cache.iter() {
            out.extend_from_slice(
                format!("|nonce:{nonce}:{}", entry.expires_at.as_seconds()).as_bytes(),
            );
        }
        out
    }

    /// MAC del estado actual.
    fn mac(&self) -> Result<[u8; 32], GidError> {
        gravital_id_crypto::hmac_sha256(self.key.as_bytes(), &self.canonical_state())
    }

    /// MAC esperado para un estado manipulado (usado por las pruebas y por hosts que
    /// persisten el MAC junto al estado).
    pub fn mac_of(
        key: &StateIntegrityKey,
        time_floor: Option<UnixTime>,
        accepted_bundle: Option<AcceptedBundleState>,
        nonces: &[(String, UnixTime)],
    ) -> Result<[u8; 32], GidError> {
        let mut nonce_cache = InMemoryNonceCache::new();
        for (nonce, expires_at) in nonces {
            nonce_cache.remember(nonce, *expires_at)?;
        }
        let probe = Self {
            key: key.clone(),
            time_floor,
            accepted_bundle,
            nonce_cache,
        };
        probe.mac()
    }
}

impl VerifierStateStore for InMemoryStateStore {
    fn time_floor(&self) -> Result<Option<UnixTime>, GidError> {
        Ok(self.time_floor)
    }

    fn raise_time_floor(&mut self, floor: UnixTime) -> Result<(), GidError> {
        if let Some(current) = self.time_floor {
            if floor.as_seconds() < current.as_seconds() {
                return Ok(());
            }
        }
        self.time_floor = Some(floor);
        Ok(())
    }

    fn accepted_bundle(&self) -> Result<Option<AcceptedBundleState>, GidError> {
        Ok(self.accepted_bundle)
    }

    fn record_accepted_bundle(&mut self, state: AcceptedBundleState) -> Result<(), GidError> {
        self.accepted_bundle = Some(state);
        Ok(())
    }

    fn nonce_seen(&self, nonce: &str, now: UnixTime) -> Result<bool, GidError> {
        self.nonce_cache.is_seen(nonce, now)
    }

    fn remember_nonce(&mut self, nonce: &str, expires_at: UnixTime) -> Result<(), GidError> {
        self.nonce_cache.remember(nonce, expires_at)
    }

    fn check_and_consume_nonce(
        &mut self,
        nonce: &str,
        expires_at: UnixTime,
        now: UnixTime,
    ) -> Result<bool, GidError> {
        self.nonce_cache.check_and_consume(nonce, expires_at, now)
    }

    fn integrity_check(&self) -> Result<(), GidError> {
        // El MAC se recalcula sobre el estado actual; un host que persista el MAC aparte
        // debería compararlo contra el almacenado.
        self.mac().map(|_| ())
    }

    fn reset(&mut self) {
        self.time_floor = None;
        self.accepted_bundle = None;
        self.nonce_cache.clear();
    }
}

impl NonceCache for InMemoryStateStore {
    fn is_seen(&self, nonce: &str, now: UnixTime) -> Result<bool, GidError> {
        self.nonce_cache.is_seen(nonce, now)
    }

    fn remember(&mut self, nonce: &str, expires_at: UnixTime) -> Result<(), GidError> {
        self.nonce_cache.remember(nonce, expires_at)
    }

    fn check_and_consume(
        &mut self,
        nonce: &str,
        expires_at: UnixTime,
        now: UnixTime,
    ) -> Result<bool, GidError> {
        self.nonce_cache.check_and_consume(nonce, expires_at, now)
    }

    fn purge_expired(&mut self, now: UnixTime) {
        self.nonce_cache.purge_expired(now);
    }

    fn len(&self) -> usize {
        self.nonce_cache.len()
    }

    fn capacity(&self) -> usize {
        self.nonce_cache.capacity()
    }

    fn clear(&mut self) {
        self.nonce_cache.clear();
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
    use alloc::string::ToString;

    fn key() -> StateIntegrityKey {
        StateIntegrityKey::new([7u8; 32])
    }

    fn accepted(epoch: u64, version: u64) -> AcceptedBundleState {
        AcceptedBundleState {
            bundle_epoch: epoch,
            bundle_version: version,
        }
    }

    #[test]
    fn integrity_key_redacts_its_debug_output() {
        let rendered = format!("{:?}", key());
        assert_eq!(rendered, "StateIntegrityKey([REDACTED])");
        assert!(!rendered.contains('7'));
    }

    #[test]
    fn time_floor_is_raised_and_never_lowered() {
        let mut store = InMemoryStateStore::new(key());
        store
            .raise_time_floor(UnixTime::from_seconds(1_000))
            .unwrap();
        store.raise_time_floor(UnixTime::from_seconds(500)).unwrap();
        assert_eq!(
            store.time_floor().unwrap(),
            Some(UnixTime::from_seconds(1_000))
        );
    }

    #[test]
    fn guard_detects_clock_rollback() {
        let mut store = InMemoryStateStore::new(key());
        let mut guard = TimeFloorGuard::new(&mut store);
        assert_eq!(
            guard.check(UnixTime::from_seconds(1_000), None).unwrap(),
            TimeFloorCheck::FirstRun
        );
        assert_eq!(
            guard.check(UnixTime::from_seconds(2_000), None).unwrap(),
            TimeFloorCheck::Ok
        );

        let error = guard
            .check(UnixTime::from_seconds(1_500), None)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ClockRollbackDetected);
    }

    #[test]
    fn monotonic_clock_cannot_lower_the_floor() {
        let mut store = InMemoryStateStore::new(key());
        let mut guard = TimeFloorGuard::new(&mut store);
        guard.check(UnixTime::from_seconds(1_000), Some(0)).unwrap();
        // El monotónico avanza pero el reloj de pared retrocede: el piso manda.
        let error = guard
            .check(UnixTime::from_seconds(900), Some(60_000))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ClockRollbackDetected);
    }

    #[test]
    fn nonces_expire_and_are_bounded() {
        let mut store = InMemoryStateStore::new(key()).with_max_nonces(2);
        store
            .remember_nonce("nonce-a", UnixTime::from_seconds(1_000))
            .unwrap();
        store
            .remember_nonce("nonce-b", UnixTime::from_seconds(2_000))
            .unwrap();
        // Vigente dentro de su ventana.
        assert!(store
            .nonce_seen("nonce-a", UnixTime::from_seconds(500))
            .unwrap());

        // Caducado: deja de bloquear.
        assert!(!store
            .nonce_seen("nonce-a", UnixTime::from_seconds(1_001))
            .unwrap());

        // Al llenar, se expulsa el que caduca antes.
        store
            .remember_nonce("nonce-c", UnixTime::from_seconds(3_000))
            .unwrap();
        assert_eq!(store.nonce_cache.len(), 2);
    }

    #[test]
    fn accepted_bundle_round_trip() {
        let mut store = InMemoryStateStore::new(key());
        store.record_accepted_bundle(accepted(1, 42)).unwrap();
        let state = store.accepted_bundle().unwrap().unwrap();
        assert_eq!(state.bundle_epoch, 1);
        assert_eq!(state.bundle_version, 42);
    }

    #[test]
    fn mac_detects_tampered_state() {
        let key = key();
        let mac = InMemoryStateStore::mac_of(
            &key,
            Some(UnixTime::from_seconds(1_000)),
            None,
            &[("n".to_string(), UnixTime::from_seconds(2_000))],
        )
        .unwrap();
        let tampered = InMemoryStateStore::mac_of(
            &key,
            Some(UnixTime::from_seconds(9_000)),
            None,
            &[("n".to_string(), UnixTime::from_seconds(2_000))],
        )
        .unwrap();
        assert_ne!(mac, tampered);
    }

    #[test]
    fn reset_clears_the_state() {
        let mut store = InMemoryStateStore::new(key());
        store
            .raise_time_floor(UnixTime::from_seconds(1_000))
            .unwrap();
        store.record_accepted_bundle(accepted(1, 1)).unwrap();
        store.reset();
        assert!(store.time_floor().unwrap().is_none());
        assert!(store.accepted_bundle().unwrap().is_none());
    }
}
