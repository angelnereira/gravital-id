//! Partición secreta de Shamir ($k$-de-$n$) sobre $GF(2^8)$ para recuperación social (`SPEC-PIP-SHAMIR-001`).
//!
//! Permite fragmentar el material secreto del titular (código de recuperación o secreto maestro)
//! entre $n$ guardianes, requiriendo un quórum de al menos $k$ fragmentos para la reconstrucción.
//!
//! Trazabilidad:
//! - `REQ-REC-003`: Recuperación social Shamir (k-de-n).
//! - `P-10`: Resiliencia ante fallos sin punto único de compromiso.
//! - `INV-01`: Cero dependencias de red en capa L3 (`no_std` + `alloc`).
//! - `INV-02`: Ausencia de datos personales o identificadores de titular.
//! - `INV-05`: Fail-closed ante quórum insuficiente, índices duplicados o fragmentos alterados.
//! - `INV-09`: `#![forbid(unsafe_code)]`.
//! - `INV-10`: Sin unwraps ni panics en código de biblioteca.
//! - `INV-11`: RNG inyectado explícitamente para generación determinista de polinomios.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use gravital_id_crypto::sha::sha256;
use gravital_id_crypto::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::code::{RecoveryCode, CROCKFORD_ALPHABET, RECOVERY_ENTROPY_LEN};
use crate::error::RecoveryError;
use crate::gf256::{gf256_add, gf256_eval_poly, gf256_inv, gf256_mul};

/// Constante mágica de cabecera binaria para fragmentos Shamir (`GIDS` - Gravital ID Shamir).
pub const SHAMIR_MAGIC_GIDS: [u8; 4] = *b"GIDS";

/// Versión del formato canónico de fragmento Shamir (`SPEC-PIP-SHAMIR-001`).
pub const SHAMIR_FORMAT_VERSION: u8 = 1;

/// Umbral mínimo permitido de guardianes ($k \ge 2$).
pub const SHAMIR_MIN_THRESHOLD: u8 = 2;

/// Longitud de la cabecera fija de un fragmento binario (13 bytes).
pub const SHAMIR_HEADER_LEN: usize = 13;

/// Longitud de la suma de comprobación SHA-256 de integridad del fragmento (4 bytes).
pub const SHAMIR_CHECKSUM_LEN: usize = 4;

/// Límite máximo de bytes del secreto a dividir (1 KiB para prevenir DoS).
pub const MAX_SHAMIR_SECRET_LEN: usize = 1024;

/// Fragmento individual de recuperación Shamir $k$-de-$n$.
#[derive(Clone, PartialEq, Eq)]
pub struct ShamirShare {
    /// Umbral mínimo de fragmentos necesarios para la reconstrucción ($k$).
    pub threshold: u8,
    /// Total de fragmentos emitidos ($n$).
    pub total_shares: u8,
    /// Coordenada $x \in [1, 255]$ no nula correspondiente a este fragmento.
    pub share_index: u8,
    /// Identificador de 4 bytes del secreto derivado de `sha256(secret)[..4]`.
    pub secret_id: [u8; 4],
    /// Evaluación $f(x)$ protegida en memoria con [`ZeroizeOnDrop`].
    share_value: Vec<u8>,
}

impl ShamirShare {
    /// Construye una nueva instancia de fragmento con los metadatos y valor especificados.
    #[must_use]
    pub fn new(
        threshold: u8,
        total_shares: u8,
        share_index: u8,
        secret_id: [u8; 4],
        share_value: Vec<u8>,
    ) -> Self {
        Self {
            threshold,
            total_shares,
            share_index,
            secret_id,
            share_value,
        }
    }

    /// Retorna una referencia de solo lectura a los bytes del fragmento evaluado.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.share_value
    }

    /// Serializa el fragmento al formato binario canónico con suma de verificación SHA-256.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let val_len = self.share_value.len();
        let total_len = SHAMIR_HEADER_LEN
            .saturating_add(val_len)
            .saturating_add(SHAMIR_CHECKSUM_LEN);
        let mut out = Vec::with_capacity(total_len);

        // Cabecera (13 bytes)
        out.extend_from_slice(&SHAMIR_MAGIC_GIDS);
        out.push(SHAMIR_FORMAT_VERSION);
        out.push(self.threshold);
        out.push(self.total_shares);
        out.push(self.share_index);
        out.extend_from_slice(&self.secret_id);
        out.push(val_len as u8);

        // Valor del fragmento
        out.extend_from_slice(&self.share_value);

        // Suma de verificación (4 bytes)
        let digest = sha256(&out);
        if let Some(chk) = digest.get(..SHAMIR_CHECKSUM_LEN) {
            out.extend_from_slice(chk);
        }

        out
    }

    /// Deserializa y valida íntegramente un fragmento binario canónico fail-closed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecoveryError> {
        let min_len = SHAMIR_HEADER_LEN.saturating_add(SHAMIR_CHECKSUM_LEN);
        if bytes.len() < min_len {
            return Err(RecoveryError::InvalidShareFormat(
                "longitud de fragmento inferior a la cabecera mínima",
            ));
        }

        // 1. Validar magic
        let magic: [u8; 4] = bytes
            .get(..4)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0; 4]);
        if magic != SHAMIR_MAGIC_GIDS {
            return Err(RecoveryError::InvalidShareFormat(
                "constante mágica desconocida (se esperaba GIDS)",
            ));
        }

        // 2. Validar versión de formato
        let format_version = bytes.get(4).copied().unwrap_or(0);
        if format_version != SHAMIR_FORMAT_VERSION {
            return Err(RecoveryError::InvalidShareFormat(
                "versión de formato de fragmento no soportada",
            ));
        }

        let threshold = bytes.get(5).copied().unwrap_or(0);
        let total_shares = bytes.get(6).copied().unwrap_or(0);
        let share_index = bytes.get(7).copied().unwrap_or(0);

        if threshold < SHAMIR_MIN_THRESHOLD || threshold > total_shares {
            return Err(RecoveryError::InvalidShamirThreshold(
                "umbral k debe satisfacer 2 <= k <= n <= 255",
            ));
        }
        if share_index == 0 {
            return Err(RecoveryError::DuplicateShareIndex);
        }

        let secret_id: [u8; 4] = bytes
            .get(8..12)
            .and_then(|s| s.try_into().ok())
            .ok_or(RecoveryError::InvalidShareFormat("secret_id inválido"))?;

        let val_len = bytes.get(12).copied().unwrap_or(0) as usize;
        if val_len == 0 || val_len > MAX_SHAMIR_SECRET_LEN {
            return Err(RecoveryError::InvalidShareFormat(
                "longitud de valor de fragmento inválida",
            ));
        }

        let expected_total_len = SHAMIR_HEADER_LEN
            .saturating_add(val_len)
            .saturating_add(SHAMIR_CHECKSUM_LEN);
        if bytes.len() != expected_total_len {
            return Err(RecoveryError::InvalidShareFormat(
                "longitud del paquete no coincide con la longitud declarada",
            ));
        }

        let payload_and_header = bytes
            .get(..SHAMIR_HEADER_LEN.saturating_add(val_len))
            .ok_or(RecoveryError::InvalidShareFormat(
                "rango de payload inválido",
            ))?;
        let expected_checksum = sha256(payload_and_header);

        let actual_checksum = bytes
            .get(SHAMIR_HEADER_LEN.saturating_add(val_len)..expected_total_len)
            .ok_or(RecoveryError::InvalidChecksum)?;

        if let Some(chk) = expected_checksum.get(..SHAMIR_CHECKSUM_LEN) {
            if chk != actual_checksum {
                return Err(RecoveryError::InvalidChecksum);
            }
        } else {
            return Err(RecoveryError::InvalidChecksum);
        }

        let share_val_bytes = bytes
            .get(SHAMIR_HEADER_LEN..SHAMIR_HEADER_LEN.saturating_add(val_len))
            .ok_or(RecoveryError::InvalidShareFormat("rango de valor inválido"))?;

        Ok(Self {
            threshold,
            total_shares,
            share_index,
            secret_id,
            share_value: share_val_bytes.to_vec(),
        })
    }

    /// Codifica el fragmento en formato legible Crockford Base32 agrupado con guiones.
    #[must_use]
    pub fn to_compact_code(&self) -> String {
        let binary = self.to_bytes();
        let total_bits = binary.len().saturating_mul(8);
        let chunks = total_bits.saturating_add(4) / 5;
        let mut encoded = String::with_capacity(chunks);

        for i in 0..chunks {
            let bit_start = i.saturating_mul(5);
            let byte_start = bit_start / 8;
            let bit_offset = bit_start % 8;

            let b0 = binary.get(byte_start).copied().unwrap_or(0) as u32;
            let b1 = binary
                .get(byte_start.saturating_add(1))
                .copied()
                .unwrap_or(0) as u32;

            let chunk = (b0 << 8) | b1;
            let shift = 16u32.saturating_sub(5).saturating_sub(bit_offset as u32);
            let val = ((chunk >> shift) & 0x1F) as usize;
            let c = CROCKFORD_ALPHABET.get(val).copied().unwrap_or(b'0');
            encoded.push(c as char);
        }

        let mut formatted = String::with_capacity(encoded.len().saturating_add(encoded.len() / 4));
        for (i, c) in encoded.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                formatted.push('-');
            }
            formatted.push(c);
        }
        formatted
    }

    /// Parsea un fragmento desde una cadena legible Crockford Base32.
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

        let total_bits = clean.len().saturating_mul(5);
        let total_bytes = total_bits / 8;
        let mut binary = vec![0u8; total_bytes];

        for (i, &c) in clean.iter().enumerate() {
            let val = CROCKFORD_ALPHABET
                .iter()
                .position(|&b| b == c as u8)
                .ok_or(RecoveryError::InvalidShareFormat(
                    "carácter no permitido en alfabeto Crockford Base32",
                ))? as u8;

            let bit_start = i.saturating_mul(5);
            for bit_pos in 0..5 {
                let target_bit = bit_start.saturating_add(bit_pos);
                if target_bit >= total_bytes.saturating_mul(8) {
                    continue;
                }
                let bit_val = (val >> (4u32.saturating_sub(bit_pos as u32))) & 1;
                let byte_idx = target_bit / 8;
                let bit_in_byte = target_bit % 8;
                if let Some(byte) = binary.get_mut(byte_idx) {
                    *byte |= bit_val << (7u32.saturating_sub(bit_in_byte as u32));
                }
            }
        }

        Self::from_bytes(&binary)
    }
}

impl Drop for ShamirShare {
    fn drop(&mut self) {
        self.share_value.zeroize();
    }
}

impl ZeroizeOnDrop for ShamirShare {}

impl fmt::Debug for ShamirShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShamirShare")
            .field("threshold", &self.threshold)
            .field("total_shares", &self.total_shares)
            .field("share_index", &self.share_index)
            .field("secret_id", &self.secret_id)
            .field("value", &"***REDACTED***")
            .finish()
    }
}

/// Orquestador para división y reconstrucción polinómica de secretos mediante Shamir Secret Sharing.
pub struct ShamirSecretSharing;

impl ShamirSecretSharing {
    /// Divide un secreto arbitrario de longitud $L$ ($1 \le L \le 1024$) en $n$ fragmentos
    /// con umbral de reconstrucción $k$ ($2 \le k \le n \le 255$).
    ///
    /// # Errores
    /// - [`RecoveryError::InvalidShamirThreshold`] si $k < 2$ o $k > n$.
    /// - [`RecoveryError::PayloadLimitExceeded`] si el secreto supera 1024 bytes o está vacío.
    /// - [`RecoveryError::InsufficientEntropy`] si el CSPRNG inyectado falla.
    pub fn split<R: Rng>(
        secret: &[u8],
        threshold: u8,
        total_shares: u8,
        rng: &R,
    ) -> Result<Vec<ShamirShare>, RecoveryError> {
        if secret.is_empty() {
            return Err(RecoveryError::SerializationFailed(
                "el secreto no puede estar vacío",
            ));
        }
        if secret.len() > MAX_SHAMIR_SECRET_LEN {
            return Err(RecoveryError::PayloadLimitExceeded(secret.len()));
        }
        if threshold < SHAMIR_MIN_THRESHOLD || threshold > total_shares {
            return Err(RecoveryError::InvalidShamirThreshold(
                "el umbral debe satisfacer 2 <= threshold <= total_shares <= 255",
            ));
        }

        let secret_hash = sha256(secret);
        let mut secret_id = [0u8; 4];
        if let Some(src) = secret_hash.get(..4) {
            secret_id.copy_from_slice(src);
        }

        let secret_len = secret.len();
        let degree = (threshold as usize).saturating_sub(1);

        // Generar coeficientes aleatorios independientes para el polinomio f(x)
        // coefficients[c] tiene longitud secret_len (para c = 0..degree-1)
        let mut random_coefficients = Vec::with_capacity(degree);
        for _ in 0..degree {
            let mut coeff_bytes = vec![0u8; secret_len];
            rng.fill_bytes(&mut coeff_bytes)
                .map_err(|_| RecoveryError::InsufficientEntropy)?;
            random_coefficients.push(coeff_bytes);
        }

        // Evaluar f(x) para cada guardián x in 1..=total_shares
        let mut shares = Vec::with_capacity(total_shares as usize);
        for x_idx in 1..=total_shares {
            let mut share_val = vec![0u8; secret_len];
            for byte_pos in 0..secret_len {
                let s_byte = secret.get(byte_pos).copied().unwrap_or(0);

                // Construir polinomio para este byte: [s_byte, c_1[byte_pos], ..., c_{k-1}[byte_pos]]
                let mut poly = Vec::with_capacity(threshold as usize);
                poly.push(s_byte);
                for coeff in &random_coefficients {
                    poly.push(coeff.get(byte_pos).copied().unwrap_or(0));
                }

                if let Some(out) = share_val.get_mut(byte_pos) {
                    *out = gf256_eval_poly(&poly, x_idx);
                }
            }

            shares.push(ShamirShare::new(
                threshold,
                total_shares,
                x_idx,
                secret_id,
                share_val,
            ));
        }

        // Limpiar coeficientes aleatorios de la memoria
        for mut c in random_coefficients {
            c.zeroize();
        }

        Ok(shares)
    }

    /// Reconstruye el secreto original a partir de al menos $k$ fragmentos válidos
    /// mediante interpolación polinómica de Lagrange en $x = 0$.
    ///
    /// # Errores
    /// - [`RecoveryError::InsufficientShares`] si se proveen menos de $k$ fragmentos.
    /// - [`RecoveryError::DuplicateShareIndex`] si existen fragmentos con el mismo índice $x$.
    /// - [`RecoveryError::SecretIdMismatch`] si los fragmentos provienen de divisiones distintas.
    /// - [`RecoveryError::InvalidChecksum`] si el secreto reconstruido no coincide con el `secret_id`.
    pub fn combine(shares: &[ShamirShare]) -> Result<Vec<u8>, RecoveryError> {
        let first = shares.first().ok_or(RecoveryError::InsufficientShares)?;
        let k = first.threshold as usize;

        if shares.len() < k {
            return Err(RecoveryError::InsufficientShares);
        }

        let secret_id = first.secret_id;
        let expected_len = first.share_value.len();

        // Validar homogeneidad de metadatos y consistencia de fragmentos
        for share in shares {
            if share.threshold as usize != k {
                return Err(RecoveryError::InvalidShareFormat(
                    "umbrales inconsistentes entre los fragmentos proporcionados",
                ));
            }
            if share.secret_id != secret_id {
                return Err(RecoveryError::SecretIdMismatch);
            }
            if share.share_value.len() != expected_len {
                return Err(RecoveryError::InvalidShareFormat(
                    "longitudes de valor inconsistentes entre los fragmentos",
                ));
            }
        }

        // Seleccionar exactamente los primeros k fragmentos y verificar que sus índices sean únicos
        let selected = shares.get(..k).ok_or(RecoveryError::InsufficientShares)?;
        for i in 0..k {
            let xi = selected.get(i).map(|s| s.share_index).unwrap_or(0);
            if xi == 0 {
                return Err(RecoveryError::DuplicateShareIndex);
            }
            for j in (i.saturating_add(1))..k {
                let xj = selected.get(j).map(|s| s.share_index).unwrap_or(0);
                if xi == xj {
                    return Err(RecoveryError::DuplicateShareIndex);
                }
            }
        }

        // 1. Calcular los coeficientes de Lagrange en x = 0 para cada fragmento j:
        // l_j(0) = Prod_{m != j} (0 ^ x_m) / (x_j ^ x_m) = Prod_{m != j} (x_m / (x_j ^ x_m))
        let mut lagrange_weights = Vec::with_capacity(k);
        for j in 0..k {
            let xj = selected.get(j).map(|s| s.share_index).unwrap_or(0);
            let mut num = 1u8;
            let mut den = 1u8;
            for m in 0..k {
                if m == j {
                    continue;
                }
                let xm = selected.get(m).map(|s| s.share_index).unwrap_or(0);
                num = gf256_mul(num, xm);
                den = gf256_mul(den, gf256_add(xj, xm));
            }
            let den_inv = gf256_inv(den)?;
            let weight = gf256_mul(num, den_inv);
            lagrange_weights.push(weight);
        }

        // 2. Reconstruir el secreto f(0) byte a byte:
        // S_b = Sum_{j=0}^{k-1} y_{j, b} * l_j(0)
        let mut secret = vec![0u8; expected_len];
        for (j, share) in selected.iter().enumerate() {
            let weight = lagrange_weights.get(j).copied().unwrap_or(0);
            for (byte_pos, out_byte) in secret.iter_mut().enumerate() {
                let y = share.share_value.get(byte_pos).copied().unwrap_or(0);
                *out_byte ^= gf256_mul(y, weight);
            }
        }

        // 3. Verificar que el hash del secreto reconstruido coincida con el secret_id (fail-closed contra manipulación)
        let computed_hash = sha256(&secret);
        let mut computed_id = [0u8; 4];
        if let Some(src) = computed_hash.get(..4) {
            computed_id.copy_from_slice(src);
        }

        if computed_id != secret_id {
            secret.zeroize();
            return Err(RecoveryError::InvalidChecksum);
        }

        Ok(secret)
    }

    /// Divide la entropía de 128 bits de un [`RecoveryCode`] en $n$ fragmentos Shamir con umbral $k$.
    pub fn split_recovery_code<R: Rng>(
        code: &RecoveryCode,
        threshold: u8,
        total_shares: u8,
        rng: &R,
    ) -> Result<Vec<ShamirShare>, RecoveryError> {
        Self::split(code.entropy(), threshold, total_shares, rng)
    }

    /// Reconstruye un [`RecoveryCode`] a partir de al menos $k$ fragmentos Shamir válidos.
    pub fn combine_recovery_code(shares: &[ShamirShare]) -> Result<RecoveryCode, RecoveryError> {
        let reconstructed_bytes = Self::combine(shares)?;
        if reconstructed_bytes.len() != RECOVERY_ENTROPY_LEN {
            return Err(RecoveryError::InvalidRecoveryCode(
                "longitud de entropía reconstruida distinta a 16 bytes",
            ));
        }

        let mut entropy_arr = [0u8; RECOVERY_ENTROPY_LEN];
        if let Some(src) = reconstructed_bytes.get(..RECOVERY_ENTROPY_LEN) {
            entropy_arr.copy_from_slice(src);
        }

        let code = RecoveryCode::from_entropy(entropy_arr);
        entropy_arr.zeroize();
        Ok(code)
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
    use gravital_id_testkit::SeededRng;

    #[test]
    fn test_shamir_split_and_combine_exact_threshold() {
        let rng = SeededRng::new(0x1111);
        let secret = b"my_super_secret_master_key_32_b!";
        let threshold = 3;
        let total = 5;

        let shares =
            ShamirSecretSharing::split(secret, threshold, total, &rng).expect("split must succeed");
        assert_eq!(shares.len(), 5);

        // Cualquier subconjunto de 3 fragmentos debe reconstruir exactamente el secreto
        let subset1 = &[shares[0].clone(), shares[1].clone(), shares[2].clone()];
        let rec1 = ShamirSecretSharing::combine(subset1).expect("rec 1");
        assert_eq!(&rec1, secret);

        let subset2 = &[shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let rec2 = ShamirSecretSharing::combine(subset2).expect("rec 2");
        assert_eq!(&rec2, secret);

        let subset3 = &[shares[1].clone(), shares[3].clone(), shares[4].clone()];
        let rec3 = ShamirSecretSharing::combine(subset3).expect("rec 3");
        assert_eq!(&rec3, secret);
    }

    #[test]
    fn test_shamir_insufficient_shares_fails() {
        let rng = SeededRng::new(0x2222);
        let secret = b"test_insufficient_shares_vector!";
        let shares = ShamirSecretSharing::split(secret, 3, 5, &rng).expect("split");

        // 2 fragmentos con umbral 3 debe fallar de forma cerrada (INV-05)
        let subset = &[shares[0].clone(), shares[1].clone()];
        let res = ShamirSecretSharing::combine(subset);
        assert!(matches!(res, Err(RecoveryError::InsufficientShares)));
    }

    #[test]
    fn test_shamir_duplicate_index_fails() {
        let rng = SeededRng::new(0x3333);
        let secret = b"test_duplicate_index_shares_xyz!";
        let shares = ShamirSecretSharing::split(secret, 3, 5, &rng).expect("split");

        // Proveer 3 fragmentos pero dos con el mismo índice (duplicados)
        let subset = &[shares[0].clone(), shares[0].clone(), shares[1].clone()];
        let res = ShamirSecretSharing::combine(subset);
        assert!(matches!(res, Err(RecoveryError::DuplicateShareIndex)));
    }

    #[test]
    fn test_shamir_corrupted_share_fails_checksum() {
        let rng = SeededRng::new(0x4444);
        let secret = b"test_corrupted_share_checksum!!";
        let mut shares = ShamirSecretSharing::split(secret, 3, 5, &rng).expect("split");

        // Corromper el valor de un fragmento
        if let Some(byte) = shares[0].share_value.get_mut(2) {
            *byte ^= 0xFF;
        }

        let subset = &[shares[0].clone(), shares[1].clone(), shares[2].clone()];
        let res = ShamirSecretSharing::combine(subset);
        assert!(matches!(res, Err(RecoveryError::InvalidChecksum)));
    }

    #[test]
    fn test_shamir_share_binary_roundtrip() {
        let rng = SeededRng::new(0x5555);
        let secret = b"binary_share_serialization_test";
        let shares = ShamirSecretSharing::split(secret, 2, 3, &rng).expect("split");

        for share in &shares {
            let bytes = share.to_bytes();
            assert_eq!(&bytes[..4], &SHAMIR_MAGIC_GIDS);

            let restored = ShamirShare::from_bytes(&bytes).expect("parse share bytes");
            assert_eq!(share.threshold, restored.threshold);
            assert_eq!(share.total_shares, restored.total_shares);
            assert_eq!(share.share_index, restored.share_index);
            assert_eq!(share.secret_id, restored.secret_id);
            assert_eq!(share.value(), restored.value());
        }
    }

    #[test]
    fn test_shamir_compact_code_roundtrip() {
        let rng = SeededRng::new(0x6666);
        let secret = b"compact_crockford_base32_shares";
        let shares = ShamirSecretSharing::split(secret, 2, 4, &rng).expect("split");

        for share in &shares {
            let compact = share.to_compact_code();
            let parsed = ShamirShare::from_compact_code(&compact).expect("parse compact");
            assert_eq!(share.value(), parsed.value());
            assert_eq!(share.share_index, parsed.share_index);
        }
    }

    #[test]
    fn test_shamir_recovery_code_roundtrip() {
        let rng = SeededRng::new(0x7777);
        let code = RecoveryCode::generate(&rng).expect("generate recovery code");

        // Dividir el código de recuperación en 5 fragmentos con umbral 3
        let shares = ShamirSecretSharing::split_recovery_code(&code, 3, 5, &rng)
            .expect("split recovery code");

        // Reconstruir con fragmentos 2, 3, 5
        let subset = &[shares[1].clone(), shares[2].clone(), shares[4].clone()];
        let restored_code =
            ShamirSecretSharing::combine_recovery_code(subset).expect("combine recovery code");

        assert_eq!(code.entropy(), restored_code.entropy());
        assert_eq!(code.to_mnemonic(), restored_code.to_mnemonic());
    }

    #[test]
    fn test_shamir_debug_redacted() {
        let rng = SeededRng::new(0x8888);
        let shares =
            ShamirSecretSharing::split(b"sensitive_secret_data", 2, 3, &rng).expect("split");
        let debug = format!("{:?}", shares[0]);
        assert!(debug.contains("***REDACTED***"));
        assert!(!debug.contains("sensitive_secret_data"));
    }
}
