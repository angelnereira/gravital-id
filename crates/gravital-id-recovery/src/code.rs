//! Código de recuperación de alta entropía (`RecoveryCode`).
//!
//! Trazabilidad:
//! - `REQ-REC-002`: El respaldo cifrado DEBE protegerse con un código de recuperación generado de ≥ 128 bits.
//! - `pip-personal-v1.md §5`: Código mnemónico BIP-39 de 12 palabras (128 bits de entropía).
//! - `INV-02`: Sin exposición de datos personales ni secretos en `Debug`.
//! - `INV-05`: Fail-closed ante cualquier checksum erróneo o palabra desconocida.
//! - `INV-11`: Inyección determinista de aleatoriedad (`Rng`).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use gravital_id_crypto::secret::SecretBytes;
use gravital_id_crypto::{sha256, Rng};
use zeroize::Zeroize;

use crate::error::RecoveryError;
use crate::wordlist::{find_word_index, get_word};

/// Longitud en bytes de la entropía del código de recuperación normativo (128 bits).
pub const RECOVERY_ENTROPY_LEN: usize = 16;

/// Cantidad exacta de palabras en un mnemónico BIP-39 de 128 bits.
pub const BIP39_WORD_COUNT: usize = 12;

/// Alfabeto canónico de Crockford Base32 (excluye I, L, O, U para evitar ambigüedades visuales).
const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Código de recuperación generado con ≥ 128 bits de entropía criptográfica y suma de verificación.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryCode {
    entropy: SecretBytes<RECOVERY_ENTROPY_LEN>,
}

impl RecoveryCode {
    /// Genera un nuevo código de recuperación con 128 bits de entropía usando el generador inyectado (`INV-11`).
    ///
    /// # Errores
    /// Retorna [`RecoveryError::InsufficientEntropy`] si la fuente de aleatoriedad inyectada falla.
    pub fn generate<R: Rng>(rng: &R) -> Result<Self, RecoveryError> {
        let mut bytes = [0u8; RECOVERY_ENTROPY_LEN];
        rng.fill_bytes(&mut bytes)
            .map_err(|_| RecoveryError::InsufficientEntropy)?;
        let res = Self::from_entropy(bytes);
        bytes.zeroize();
        Ok(res)
    }

    /// Construye una instancia a partir de 16 bytes exactos (128 bits) de entropía.
    #[must_use]
    pub fn from_entropy(entropy: [u8; RECOVERY_ENTROPY_LEN]) -> Self {
        Self {
            entropy: SecretBytes::new(entropy),
        }
    }

    /// Retorna los bytes de entropía protegidos.
    #[must_use]
    pub fn entropy(&self) -> &[u8; RECOVERY_ENTROPY_LEN] {
        self.entropy.expose_secret()
    }

    /// Codifica el código de recuperación en un mnemónico BIP-39 estándar de 12 palabras.
    ///
    /// Algoritmo BIP-39:
    /// - Entropía: 128 bits.
    /// - Checksum: primeros 4 bits de SHA-256(entropía).
    /// - Longitud total: 132 bits divididos en 12 índices de 11 bits (0..2047).
    #[must_use]
    pub fn to_mnemonic(&self) -> String {
        let ent = self.entropy.expose_secret();
        let digest = sha256(ent);
        let checksum = digest.first().copied().unwrap_or(0) >> 4; // 4 bits

        // Expandir a 17 bytes temporales (16 bytes de entropía + 1 byte con checksum en bits superiores)
        let mut bits132 = [0u8; 17];
        bits132[..16].copy_from_slice(ent);
        if let Some(last) = bits132.get_mut(16) {
            *last = checksum << 4;
        }

        let mut words: Vec<&'static str> = Vec::with_capacity(BIP39_WORD_COUNT);
        for i in 0..BIP39_WORD_COUNT {
            let bit_start = i.saturating_mul(11);
            let byte_start = bit_start / 8;
            let bit_offset = bit_start % 8;

            let b0 = bits132.get(byte_start).copied().unwrap_or(0) as u32;
            let b1 = bits132
                .get(byte_start.saturating_add(1))
                .copied()
                .unwrap_or(0) as u32;
            let b2 = bits132
                .get(byte_start.saturating_add(2))
                .copied()
                .unwrap_or(0) as u32;

            let chunk = (b0 << 16) | (b1 << 8) | b2;
            let shift = 24u32.saturating_sub(11).saturating_sub(bit_offset as u32);
            let index = ((chunk >> shift) & 0x07FF) as usize;

            let word = get_word(index).unwrap_or("abandon");
            words.push(word);
        }

        words.join(" ")
    }

    /// Parsea y valida un mnemónico BIP-39 de 12 palabras, verificando rigurosamente su checksum.
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self, RecoveryError> {
        let tokens: Vec<&str> = mnemonic.split_whitespace().collect();
        if tokens.len() != BIP39_WORD_COUNT {
            return Err(RecoveryError::InvalidRecoveryCode(
                "el mnemónico debe contener exactamente 12 palabras",
            ));
        }

        let mut indices = [0u16; BIP39_WORD_COUNT];
        for (i, token) in tokens.iter().enumerate() {
            let word = token.trim();
            let idx = find_word_index(word).ok_or(RecoveryError::InvalidRecoveryCode(
                "palabra desconocida en el diccionario BIP-39",
            ))?;
            if let Some(target) = indices.get_mut(i) {
                *target = idx as u16;
            }
        }

        // Reconstruir los 132 bits
        let mut bits132 = [0u8; 17];
        for (i, &idx) in indices.iter().enumerate() {
            let bit_start = i.saturating_mul(11);
            for bit_pos in 0..11 {
                let bit_val = ((idx >> (10u32.saturating_sub(bit_pos as u32))) & 1) as u8;
                let target_bit = bit_start.saturating_add(bit_pos);
                let byte_idx = target_bit / 8;
                let bit_in_byte = target_bit % 8;
                if let Some(byte) = bits132.get_mut(byte_idx) {
                    *byte |= bit_val << (7u32.saturating_sub(bit_in_byte as u32));
                }
            }
        }

        let mut entropy = [0u8; RECOVERY_ENTROPY_LEN];
        entropy.copy_from_slice(&bits132[..RECOVERY_ENTROPY_LEN]);
        let extracted_checksum = bits132.get(16).copied().unwrap_or(0) >> 4;

        // Verificar suma de comprobación SHA-256
        let digest = sha256(&entropy);
        let expected_checksum = digest.first().copied().unwrap_or(0) >> 4;

        if extracted_checksum != expected_checksum {
            entropy.zeroize();
            return Err(RecoveryError::InvalidChecksum);
        }

        let res = Ok(Self::from_entropy(entropy));
        entropy.zeroize();
        res
    }

    /// Codifica el código de recuperación en una representación alfanumérica compacta Crockford Base32
    /// con suma de verificación (26 caracteres de datos + 1 dígito de control en 6 bloques).
    #[must_use]
    pub fn to_compact_code(&self) -> String {
        let ent = self.entropy.expose_secret();
        let digest = sha256(ent);
        // Dígito de control: primer byte del digest mapeado a [0..32)
        let check_val = (digest.first().copied().unwrap_or(0) % 32) as usize;

        // Codificar 128 bits en 26 caracteres Base32 (5 bits cada uno)
        let mut chars = Vec::with_capacity(27);
        for i in 0..26usize {
            let bit_start = i.saturating_mul(5);
            let byte_start = bit_start / 8;
            let bit_offset = bit_start % 8;

            let b0 = ent.get(byte_start).copied().unwrap_or(0) as u32;
            let b1 = ent.get(byte_start.saturating_add(1)).copied().unwrap_or(0) as u32;

            let chunk = (b0 << 8) | b1;
            let shift = 16u32.saturating_sub(5).saturating_sub(bit_offset as u32);
            let val = ((chunk >> shift) & 0x1F) as usize;
            let c = CROCKFORD_ALPHABET.get(val).copied().unwrap_or(b'0');
            chars.push(c as char);
        }

        let check_char = CROCKFORD_ALPHABET.get(check_val).copied().unwrap_or(b'0') as char;
        chars.push(check_char);

        // Agrupar en formato: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XX
        let mut formatted = String::with_capacity(32);
        for (i, c) in chars.iter().enumerate() {
            if i > 0 && i % 4 == 0 {
                formatted.push('-');
            }
            formatted.push(*c);
        }
        formatted
    }

    /// Parsea un código compacto Crockford Base32 verificando su dígito de control.
    pub fn from_compact_code(code: &str) -> Result<Self, RecoveryError> {
        let mut clean = Vec::new();
        for ch in code.chars() {
            if ch == '-' || ch.is_whitespace() {
                continue;
            }
            let normalized = match ch.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                c => c,
            };
            clean.push(normalized);
        }

        if clean.len() != 27 {
            return Err(RecoveryError::InvalidRecoveryCode(
                "longitud inválida para código compacto Crockford (se requieren 27 caracteres)",
            ));
        }

        let mut vals = Vec::with_capacity(27);
        for &c in &clean {
            let val = CROCKFORD_ALPHABET
                .iter()
                .position(|&b| b == c as u8)
                .ok_or(RecoveryError::InvalidRecoveryCode(
                    "carácter no permitido en alfabeto Crockford Base32",
                ))?;
            vals.push(val as u8);
        }

        let extracted_check = vals.pop().unwrap_or(0) as usize;

        // Reconstruir los 128 bits desde los 26 valores de 5 bits
        let mut ent = [0u8; RECOVERY_ENTROPY_LEN];
        for (i, &val) in vals.iter().enumerate() {
            let bit_start = i.saturating_mul(5);
            for bit_pos in 0..5 {
                let target_bit = bit_start.saturating_add(bit_pos);
                if target_bit >= 128 {
                    continue; // 2 bits de relleno final descartados
                }
                let bit_val = (val >> (4u32.saturating_sub(bit_pos as u32))) & 1;
                let byte_idx = target_bit / 8;
                let bit_in_byte = target_bit % 8;
                if let Some(byte) = ent.get_mut(byte_idx) {
                    *byte |= bit_val << (7u32.saturating_sub(bit_in_byte as u32));
                }
            }
        }

        // Verificar suma de comprobación
        let digest = sha256(&ent);
        let expected_check = (digest.first().copied().unwrap_or(0) % 32) as usize;

        if extracted_check != expected_check {
            ent.zeroize();
            return Err(RecoveryError::InvalidChecksum);
        }

        let res = Ok(Self::from_entropy(ent));
        ent.zeroize();
        res
    }
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecoveryCode(***REDACTED***)")
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
    use alloc::format;
    use alloc::vec::Vec;
    use gravital_id_testkit::SeededRng;

    #[test]
    fn test_recovery_code_generation_and_mnemonic_roundtrip() {
        let rng = SeededRng::new(0x4242);
        for _ in 0..10 {
            let code = RecoveryCode::generate(&rng).expect("generate recovery code");
            let mnemonic = code.to_mnemonic();
            let words: Vec<&str> = mnemonic.split_whitespace().collect();
            assert_eq!(words.len(), 12);

            let parsed = RecoveryCode::from_mnemonic(&mnemonic).expect("parse mnemonic");
            assert_eq!(code.entropy(), parsed.entropy());
        }
    }

    #[test]
    fn test_recovery_code_compact_roundtrip() {
        let rng = SeededRng::new(0x7777);
        for _ in 0..10 {
            let code = RecoveryCode::generate(&rng).expect("generate recovery code");
            let compact = code.to_compact_code();
            let parsed = RecoveryCode::from_compact_code(&compact).expect("parse compact");
            assert_eq!(code.entropy(), parsed.entropy());
        }
    }

    #[test]
    fn test_recovery_code_invalid_checksum_rejected() {
        let rng = SeededRng::new(0x8888);
        let code = RecoveryCode::generate(&rng).expect("generate recovery code");
        let mnemonic = code.to_mnemonic();
        let mut words: Vec<&str> = mnemonic.split_whitespace().collect();

        // Alterar la última palabra (que contiene el checksum)
        words[11] = if words[11] == "abandon" {
            "zoo"
        } else {
            "abandon"
        };
        let mutated = words.join(" ");

        let res = RecoveryCode::from_mnemonic(&mutated);
        assert!(
            matches!(res, Err(RecoveryError::InvalidChecksum)),
            "Checksum manipulado debe fallar con InvalidChecksum"
        );
    }

    #[test]
    fn test_recovery_code_invalid_word_count() {
        let res = RecoveryCode::from_mnemonic("abandon ability able");
        assert!(matches!(res, Err(RecoveryError::InvalidRecoveryCode(_))));
    }

    #[test]
    fn test_recovery_code_unknown_word() {
        let words =
            "abandon ability able about above absent absorb abstract absurd abuse access gravital";
        let res = RecoveryCode::from_mnemonic(words);
        assert!(matches!(res, Err(RecoveryError::InvalidRecoveryCode(_))));
    }

    #[test]
    fn test_recovery_code_debug_redacted() {
        let rng = SeededRng::new(0x9999);
        let code = RecoveryCode::generate(&rng).expect("generate recovery code");
        let debug_str = format!("{code:?}");
        assert_eq!(debug_str, "RecoveryCode(***REDACTED***)");
    }
}
