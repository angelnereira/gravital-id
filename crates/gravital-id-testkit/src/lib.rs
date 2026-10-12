//! # `gravital-id-testkit`
//!
//! Utilidades de prueba, relojes fijos y datos deterministas para Gravital ID.
//!
//! - **Capa arquitectónica:** Dev (solo `[dev-dependencies]`)
//! - **Garantía no_std:** No
//!
//! Provee las implementaciones deterministas de los traits de inyección del
//! núcleo (`Clock`, `Rng`) exigidas por `TEST_STRATEGY.md §3` e INV-11:
//! ninguna prueba usa reloj real ni aleatoriedad sin sembrar.
//!
//! Las utilidades de aserción de `VerificationResult` (cuatro estados, ADR-0020)
//! se añaden junto al tipo en F4.T06; hasta entonces este crate expone solo el
//! determinismo base que F1 requiere (`ROADMAP.md` F1.T07).

#![forbid(unsafe_code)]

use std::cell::Cell;

pub use gravital_id_crypto::Rng;
pub use gravital_id_types::Clock;

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Reloj determinista controlado por la prueba (`Clock` inyectado).
///
/// Avanza solo cuando la prueba lo indica, de modo que los resultados sean
/// reproducibles byte a byte (INV-11, REQ-VER-009).
#[derive(Debug, Clone)]
pub struct FixedClock {
    now: Cell<u64>,
    elapsed_ms: Cell<u64>,
}

impl FixedClock {
    /// Crea un reloj fijo en el instante Unix dado.
    #[must_use]
    pub fn new(now_seconds: u64) -> Self {
        Self {
            now: Cell::new(now_seconds),
            elapsed_ms: Cell::new(0),
        }
    }

    /// Instante actual configurado por la prueba.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.now.get()
    }

    /// Fija el instante Unix sin tocar el monotónico.
    pub fn set(&self, now_seconds: u64) {
        self.now.set(now_seconds);
    }

    /// Adelanta el reloj de pared `seconds`.
    pub fn advance_seconds(&self, seconds: u64) {
        self.now.set(self.now.get().saturating_add(seconds));
        self.elapsed_ms.set(
            self.elapsed_ms
                .get()
                .saturating_add(seconds.saturating_mul(1_000)),
        );
    }

    /// Adelanta el reloj de pared `millis` (redondeo hacia abajo en segundos).
    pub fn advance_millis(&self, millis: u64) {
        let now = self.now.get().saturating_add(millis / 1_000);
        self.now.set(now);
        self.elapsed_ms
            .set(self.elapsed_ms.get().saturating_add(millis));
    }
}

impl Clock for FixedClock {
    fn now_seconds(&self) -> u64 {
        self.now.get()
    }

    fn monotonic_elapsed_millis(&self) -> Option<u64> {
        Some(self.elapsed_ms.get())
    }
}

/// Semilla por defecto reproducible para `SeededRng`.
pub const DEFAULT_TEST_SEED: u64 = 0x0050_4950_5445_5354; // "PIPTESTS" en ASCII LE

/// Generador determinista xoshiro256** sembrado explícitamente (`Rng` inyectado).
///
/// No es criptográfico: existe para que las pruebas produzcan siempre la misma
/// secuencia. El código de producción recibe el CSPRNG del host.
#[derive(Debug, Clone)]
pub struct SeededRng {
    state: Cell<[u64; 4]>,
}

impl SeededRng {
    /// Crea el generador a partir de una semilla de 64 bits (SplitMix64 de siembra).
    #[must_use]
    pub fn new(seed: u64) -> Self {
        let mut sm = SplitMix64 { state: seed };
        let mut s = [0u64; 4];
        for slot in &mut s {
            *slot = sm.next_u64();
        }
        // xoshiro256** exige estado no todo ceros.
        if s == [0u64; 4] {
            s = [DEFAULT_TEST_SEED; 4];
        }
        Self {
            state: Cell::new(s),
        }
    }

    /// Siguiente palabra de 64 bits del flujo.
    pub fn next_u64(&self) -> u64 {
        let mut s = self.state.get();
        let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        self.state.set(s);
        result
    }

    /// Rellena `dest` con bytes deterministas.
    pub fn fill(&self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            if let Some(src) = bytes.get(..chunk.len()) {
                chunk.copy_from_slice(src);
            }
        }
    }
}

impl Rng for SeededRng {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), gravital_id_types::GidError> {
        self.fill(dest);
        Ok(())
    }
}

/// Siembrador SplitMix64 para expandir una semilla de 64 bits al estado xoshiro.
#[derive(Debug, Clone)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)] // Las pruebas del testkit pueden usar expect/unwrap: toda condición es local y determinista (PROJECT_STRUCTURE.md §5.1).
mod tests {
    use super::*;

    // // Verifies: REQ-VER-009 (determinismo del reloj inyectado)
    #[test]
    fn fixed_clock_advances_only_when_test_says_so() {
        let clock = FixedClock::new(1_700_000_000);
        assert_eq!(clock.now_seconds(), 1_700_000_000);
        assert_eq!(clock.monotonic_elapsed_millis(), Some(0));

        clock.advance_seconds(30);
        assert_eq!(clock.now_seconds(), 1_700_000_030);
        assert_eq!(clock.monotonic_elapsed_millis(), Some(30_000));

        clock.advance_millis(500);
        assert_eq!(clock.now_seconds(), 1_700_000_030);
        assert_eq!(clock.monotonic_elapsed_millis(), Some(30_500));

        clock.set(1_800_000_000);
        assert_eq!(clock.now_seconds(), 1_800_000_000);
        assert_eq!(clock.monotonic_elapsed_millis(), Some(30_500));
    }

    // // Verifies: REQ-VER-009 (determinismo del RNG sembrado)
    #[test]
    fn seeded_rng_same_seed_produces_same_stream() {
        let a = SeededRng::new(42);
        let b = SeededRng::new(42);
        let mut buf_a = [0u8; 32];
        let mut buf_b = [0u8; 32];
        a.fill(&mut buf_a);
        b.fill(&mut buf_b);
        assert_eq!(buf_a, buf_b);
    }

    // // Verifies: REQ-VER-009 (semillas distintas producen flujos distintos)
    #[test]
    fn seeded_rng_different_seeds_produce_different_streams() {
        let a = SeededRng::new(1);
        let b = SeededRng::new(2);
        let mut buf_a = [0u8; 32];
        let mut buf_b = [0u8; 32];
        a.fill(&mut buf_a);
        b.fill(&mut buf_b);
        assert_ne!(buf_a, buf_b);
    }

    // // Verifies: REQ-VER-009 (fill_32_bytes del trait Rng es determinista)
    #[test]
    fn seeded_rng_satisfies_rng_trait_deterministically() {
        let a = SeededRng::new(DEFAULT_TEST_SEED);
        let b = SeededRng::new(DEFAULT_TEST_SEED);
        let first = a.fill_32_bytes().expect("seeded rng never fails");
        let second = b.fill_32_bytes().expect("seeded rng never fails");
        assert_eq!(first, second);
    }

    // // Verifies: REQ-VER-009 (sin estado degenerado)
    #[test]
    fn seeded_rng_zero_seed_is_not_degenerate() {
        let rng = SeededRng::new(0);
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }
}
