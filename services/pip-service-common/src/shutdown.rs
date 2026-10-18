//! Gestión de apagado ordenado (*graceful shutdown*) para servicios backend (F7.T02, REQ-REL-001).
//!
//! Permite que los servicios finalicen transacciones en curso antes de liberar recursos.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Coordinador de señal de apagado ordenado.
#[derive(Debug, Clone)]
pub struct ShutdownCoordinator {
    is_shutting_down: Arc<AtomicBool>,
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownCoordinator {
    /// Crea un nuevo coordinador de apagado.
    #[must_use]
    pub fn new() -> Self {
        Self {
            is_shutting_down: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Dispara la señal de apagado ordenado.
    pub fn trigger_shutdown(&self) {
        self.is_shutting_down.store(true, Ordering::SeqCst);
    }

    /// Comprueba si se ha iniciado la fase de apagado.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.is_shutting_down.load(Ordering::SeqCst)
    }

    /// Espera bloqueando hasta que se solicite el apagado o se alcance el timeout.
    pub fn wait_for_signal(&self, timeout: Duration) -> bool {
        let start = Instant::now();
        while !self.is_shutting_down() {
            if start.elapsed() >= timeout {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        true
    }
}
