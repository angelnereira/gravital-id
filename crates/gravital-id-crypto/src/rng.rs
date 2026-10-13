//! Inyección de aleatoriedad criptográfica en el núcleo (`Rng`).
//!
//! El núcleo nunca obtiene entropía del sistema (INV-11): el host inyecta un
//! CSPRNG y las pruebas usan `gravital-id-testkit::SeededRng`.
//! Trazabilidad: `REQ-SEC-002`, `ADR-0019`, `CRYPTO_PROFILES.md`.

use gravital_id_types::GidError;

/// Contrato de generador criptográfico inyectado por el host.
///
/// Invariantes:
/// - La implementación de producción DEBE respaldar el generador en el CSPRNG
///   del sistema operativo o del hardware (`CRYPTO_PROFILES.md`).
/// - Un fallo de entropía DEBE reportarse como error (`InsufficientEntropy`);
///   nunca se devuelve material parcial ni se reintenta en silencio (INV-05).
/// - La salida destinada a seguridad (sales de divulgación ≥ 128 bits, nonces,
///   claves efímeras) proviene exclusivamente de esta fuente.
pub trait Rng {
    /// Rellena `dest` con bytes aleatorios criptográficos.
    ///
    /// # Errores
    /// [`ErrorCode::InsufficientEntropy`](gravital_id_types::ErrorCode::InsufficientEntropy) si la fuente no puede producir la
    /// cantidad solicitada; en ese caso `dest` queda indeterminado.
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), GidError>;

    /// Genera exactamente 32 bytes (256 bits) de material aleatorio.
    ///
    /// # Errores
    /// [`ErrorCode::InsufficientEntropy`](gravital_id_types::ErrorCode::InsufficientEntropy) si la fuente falla.
    fn fill_32_bytes(&self) -> Result<[u8; 32], GidError> {
        let mut out = [0u8; 32];
        self.fill_bytes(&mut out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RNG de prueba determinista (xorshift) para verificar el contrato.
    struct XorShiftRng(core::cell::Cell<u64>);

    impl Rng for XorShiftRng {
        fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), GidError> {
            for chunk in dest.chunks_mut(8) {
                let mut x = self.0.get();
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0.set(x);
                let bytes = x.to_le_bytes();
                if let Some(src) = bytes.get(..chunk.len()) {
                    chunk.copy_from_slice(src);
                }
            }
            Ok(())
        }
    }

    #[test]
    fn fill_bytes_covers_buffer_exactly() {
        let rng = XorShiftRng(core::cell::Cell::new(0x2545_F491_4F6C_DD1D));
        let mut buf = [0u8; 40];
        assert!(rng.fill_bytes(&mut buf).is_ok());
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn empty_buffer_is_accepted() {
        let rng = XorShiftRng(core::cell::Cell::new(1));
        let mut buf = [];
        assert!(rng.fill_bytes(&mut buf).is_ok());
    }
}
