//! Inyección de tiempo en el núcleo (`Clock`, `SDK_API.md §3.2`).
//!
//! El núcleo nunca lee el reloj del sistema (INV-11): el host inyecta una
//! implementación de `Clock` y las pruebas usan `gravital-id-testkit::FixedClock`.
//! Trazabilidad: `REQ-VER-009`, `ADR-0019`.

/// Contrato de reloj inyectado por el host.
///
/// Invariantes:
/// - La implementación del host devuelve el tiempo **real** del sistema; las
///   pruebas deben usar `FixedClock` para ser deterministas (INV-11).
/// - `now_seconds` NO debe retroceder entre llamadas consecutivas salvo
///   manipulación del dispositivo; el núcleo detecta el retroceso mediante el
///   piso de tiempo confiable (`ARCHITECTURE.md §9.5`).
pub trait Clock {
    /// Instante Unix actual en segundos.
    fn now_seconds(&self) -> u64;

    /// Tiempo monotónico transcurrido desde un origen arbitrario, en milisegundos.
    ///
    /// `None` cuando la plataforma no expone un reloj monotónico. El núcleo lo
    /// usa como cota inferior de la antigüedad del estado cuando existe
    /// (`ARCHITECTURE.md §9.5`).
    fn monotonic_elapsed_millis(&self) -> Option<u64>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reloj de prueba que verifica que el trait es implementable externamente.
    struct TestClock(u64);

    impl Clock for TestClock {
        fn now_seconds(&self) -> u64 {
            self.0
        }

        fn monotonic_elapsed_millis(&self) -> Option<u64> {
            None
        }
    }

    // // Verifies: REQ-VER-009
    #[test]
    fn injected_clock_returns_fixed_values_deterministically() {
        let clock = TestClock(1_700_000_000);
        assert_eq!(clock.now_seconds(), 1_700_000_000);
        assert_eq!(clock.monotonic_elapsed_millis(), None);
        // Determinismo: mismas entradas => mismo resultado.
        assert_eq!(clock.now_seconds(), 1_700_000_000);
    }
}
