//! Resumen criptográfico SHA-256 (F2.T06, REQ-SEC-002).
//!
//! Backend RustCrypto (`sha2`, ADR-0007). SHA-256 se usa para hashes de
//! divulgación SD-JWT, thumbprints RFC 7638 y compromisos del ledger.

use sha2::{Digest, Sha256};

/// Longitud del resumen SHA-256 en bytes.
pub const SHA256_OUTPUT_LEN: usize = 32;

/// Resumen SHA-256 de `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; SHA256_OUTPUT_LEN] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; SHA256_OUTPUT_LEN];
    if let Some(slice) = out.get_mut(..digest.len()) {
        slice.copy_from_slice(&digest);
    }
    out
}

/// SHA-256 incremental (para flujos).
#[derive(Debug, Clone)]
pub struct Sha256Hasher(Sha256);

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Hasher {
    /// Nuevo acumulador vacío.
    #[must_use]
    pub fn new() -> Self {
        Self(Sha256::new())
    }

    /// Absorbe más datos.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Consume el acumulador y devuelve el resumen.
    #[must_use]
    pub fn finalize(self) -> [u8; SHA256_OUTPUT_LEN] {
        let digest = self.0.finalize();
        let mut out = [0u8; SHA256_OUTPUT_LEN];
        if let Some(slice) = out.get_mut(..digest.len()) {
            slice.copy_from_slice(&digest);
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).
mod tests {
    use super::*;
    use alloc::vec;

    // // Verifies: REQ-SEC-002 (vectores NIST/FIPS 180-4)
    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            sha256(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
        // Vector de 56 bytes (dos bloques).
        assert_eq!(
            sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            [
                0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
                0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
                0x19, 0xdb, 0x06, 0xc1
            ]
        );
    }

    // // Verifies: REQ-SEC-002 (el acumulador incremental coincide con el directo)
    #[test]
    fn incremental_matches_oneshot() {
        let data = vec![0x5Au8; 10_000];
        let mut hasher = Sha256Hasher::new();
        for chunk in data.chunks(1000) {
            hasher.update(chunk);
        }
        assert_eq!(hasher.finalize(), sha256(&data));
    }
}
