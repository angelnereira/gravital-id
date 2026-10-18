//! Inyección de reloj del sistema para pip-indexer (INV-11).

use gravital_id_types::Clock;

/// Implementación de [`Clock`] basada en el reloj del sistema operativo para servicios en capa L5.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_seconds(&self) -> u64 {
        // En capa L5 de servicios, el host inyecta el tiempo del sistema operativo conforme a INV-11.
        #[allow(clippy::disallowed_methods)]
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn monotonic_elapsed_millis(&self) -> Option<u64> {
        None
    }
}
