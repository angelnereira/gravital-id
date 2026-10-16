//! Índices ciegos (Blind Indexing) basados en HMAC-SHA-256 (F5.T03).
//!
//! Trazabilidad:
//! - `REQ-STOR-003`: Búsquedas sin metadatos en claro mediante índices ciegos.
//! - `STORAGE_FORMAT.md §4`: Fórmula canónica `BlindIndex(attr, val) = HMAC-SHA256(BIK, "idx:" || attr || ":" || val)`.
//! - `INV-02`: Ningún dato personal ni metadato en claro en índices o almacenamiento.
//! - `INV-03`: BIK protegida en memoria con [`SecretBytes`] y zeroización.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use gravital_id_crypto::mac::{hmac_sha256, HMAC_OUTPUT_LEN};
use gravital_id_crypto::secret::SecretBytes;
use gravital_id_types::{ErrorCode, GidError};

use crate::envelope::derive_bik;

/// Etiqueta de índice ciego criptográfico de 256 bits (32 bytes).
///
/// Representa el resultado pseudoaleatorio de un HMAC-SHA-256 sobre un atributo y valor.
/// Para un observador externo sin la BIK, es indistinguible de ruido blanco uniforme (`P-09`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlindIndex([u8; HMAC_OUTPUT_LEN]);

impl BlindIndex {
    /// Longitud en bytes de un `BlindIndex` (32 bytes).
    pub const LEN: usize = HMAC_OUTPUT_LEN;

    /// Longitud en caracteres hexadecimales de un `BlindIndex` (64 caracteres).
    pub const HEX_LEN: usize = HMAC_OUTPUT_LEN * 2;

    /// Construye una nueva instancia a partir de un array de 32 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; HMAC_OUTPUT_LEN]) -> Self {
        Self(bytes)
    }

    /// Retorna una referencia a los 32 bytes del índice ciego.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HMAC_OUTPUT_LEN] {
        &self.0
    }

    /// Retorna los primeros 16 bytes (128 bits) para particionado o hashing de clave primaria.
    #[must_use]
    pub fn truncated_16(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        if let Some(src) = self.0.get(0..16) {
            out.copy_from_slice(src);
        }
        out
    }

    /// Codifica el índice ciego a cadena hexadecimal minúscula de 64 caracteres.
    #[must_use]
    pub fn to_hex(&self) -> String {
        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
        let mut hex = Vec::with_capacity(Self::HEX_LEN);
        for &b in &self.0 {
            let high = (b >> 4) as usize;
            let low = (b & 0x0f) as usize;
            if let Some(&h) = HEX_CHARS.get(high) {
                hex.push(h);
            }
            if let Some(&l) = HEX_CHARS.get(low) {
                hex.push(l);
            }
        }
        // SAFETY: Sólo contiene caracteres ASCII de HEX_CHARS.
        String::from_utf8(hex).unwrap_or_default()
    }

    /// Decodifica un índice ciego desde una cadena hexadecimal de 64 caracteres.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedMessage`] si la longitud es incorrecta o contiene caracteres no hex.
    pub fn from_hex(s: &str) -> Result<Self, GidError> {
        if s.len() != Self::HEX_LEN {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "blind index hex string must be exactly 64 characters",
            ));
        }

        let mut bytes = [0u8; Self::LEN];
        let s_bytes = s.as_bytes();
        for i in 0..Self::LEN {
            let high_idx = i.saturating_mul(2);
            let low_idx = high_idx.saturating_add(1);
            let h_byte = *s_bytes.get(high_idx).ok_or_else(|| {
                GidError::new(ErrorCode::MalformedMessage, "invalid hex index bounds")
            })?;
            let l_byte = *s_bytes.get(low_idx).ok_or_else(|| {
                GidError::new(ErrorCode::MalformedMessage, "invalid hex index bounds")
            })?;

            let high = decode_hex_nibble(h_byte)?;
            let low = decode_hex_nibble(l_byte)?;
            let combined = (high << 4) | low;
            if let Some(slot) = bytes.get_mut(i) {
                *slot = combined;
            }
        }

        Ok(Self(bytes))
    }
}

fn decode_hex_nibble(byte: u8) -> Result<u8, GidError> {
    match byte {
        b'0'..=b'9' => Ok(byte.saturating_sub(b'0')),
        b'a'..=b'f' => Ok(byte.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Ok(byte.saturating_sub(b'A').saturating_add(10)),
        _ => Err(GidError::new(
            ErrorCode::MalformedMessage,
            "invalid character in hex string",
        )),
    }
}

impl fmt::Display for BlindIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for BlindIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlindIndex(\"{}\")", self.to_hex())
    }
}

/// Generador de índices ciegos instanciado con la Blind Index Key (BIK).
///
/// Trazabilidad: `REQ-STOR-003`, `STORAGE_FORMAT.md §4`.
pub struct BlindIndexer {
    bik: SecretBytes<32>,
}

impl BlindIndexer {
    /// Longitud máxima permitida para el nombre de atributo indexable.
    pub const MAX_ATTR_NAME_LEN: usize = 64;

    /// Crea un nuevo indexador ciego con la BIK especificada.
    #[must_use]
    pub const fn new(bik: SecretBytes<32>) -> Self {
        Self { bik }
    }

    /// Inicializa el indexador ciego derivando automáticamente la BIK a partir de la KEK.
    ///
    /// # Errores
    /// [`ErrorCode::InvalidKeyFormat`] si la derivación de clave falla.
    pub fn from_kek(kek: &SecretBytes<32>) -> Result<Self, GidError> {
        let bik = derive_bik(kek)?;
        Ok(Self::new(bik))
    }

    /// Computa el índice ciego para un par `(attribute_name, value)`.
    ///
    /// $$\text{BlindIndex} = \text{HMAC-SHA256}(\text{BIK}, \texttt{"idx:"} \parallel \text{attribute\_name} \parallel \texttt{":"} \parallel \text{value})$$
    ///
    /// # Errores
    /// [`ErrorCode::MalformedMessage`] si `attribute_name` está vacío, excede [`MAX_ATTR_NAME_LEN`],
    /// o contiene dos puntos (`:`).
    pub fn compute_index(&self, attribute_name: &str, value: &str) -> Result<BlindIndex, GidError> {
        if attribute_name.is_empty() {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "attribute name for blind index must not be empty",
            ));
        }
        if attribute_name.len() > Self::MAX_ATTR_NAME_LEN {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "attribute name for blind index exceeds maximum length of 64 characters",
            ));
        }
        if attribute_name.contains(':') {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "attribute name for blind index must not contain ':' delimiter",
            ));
        }

        let prefix = b"idx:";
        let colon = b":";
        let total_len = prefix
            .len()
            .saturating_add(attribute_name.len())
            .saturating_add(colon.len())
            .saturating_add(value.len());

        let mut data = Vec::with_capacity(total_len);
        data.extend_from_slice(prefix);
        data.extend_from_slice(attribute_name.as_bytes());
        data.extend_from_slice(colon);
        data.extend_from_slice(value.as_bytes());

        let tag = hmac_sha256(self.bik.expose_secret(), &data)?;
        Ok(BlindIndex::new(tag))
    }

    /// Computa el índice ciego para el emisor de una credencial (`issuer_id`).
    pub fn compute_issuer_index(&self, issuer_id: &str) -> Result<BlindIndex, GidError> {
        self.compute_index("issuer", issuer_id)
    }

    /// Computa el índice ciego para el tipo de credencial (`vct`).
    pub fn compute_vct_index(&self, vct: &str) -> Result<BlindIndex, GidError> {
        self.compute_index("vct", vct)
    }

    /// Computa el índice ciego para el identificador de registro (`id`).
    pub fn compute_id_index(&self, record_id: &str) -> Result<BlindIndex, GidError> {
        self.compute_index("id", record_id)
    }
}

impl fmt::Debug for BlindIndexer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlindIndexer")
            .field("bik", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn test_bik() -> SecretBytes<32> {
        SecretBytes::new([0x55u8; 32])
    }

    #[test]
    fn blind_index_hex_round_trip() {
        let raw = [0xabu8; 32];
        let index = BlindIndex::new(raw);
        let hex = index.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(
            hex,
            "abababababababababababababababababababababababababababababababab"
        );

        let decoded = BlindIndex::from_hex(&hex).expect("hex decode");
        assert_eq!(index, decoded);
    }

    #[test]
    fn blind_index_from_hex_rejects_invalid_inputs() {
        assert!(BlindIndex::from_hex("").is_err());
        assert!(BlindIndex::from_hex("abc").is_err());
        // 64 chars con caracter no hex 'g'
        let mut bad_hex = "a".repeat(63);
        bad_hex.push('g');
        assert!(BlindIndex::from_hex(&bad_hex).is_err());
    }

    // // Verifies: REQ-STOR-003 (determinismo y no revelación de metadatos)
    #[test]
    fn blind_indexing_is_deterministic_and_unrelated_to_plaintext() {
        let indexer = BlindIndexer::new(test_bik());

        let idx1 = indexer
            .compute_index("vct", "https://credentials.gravital.io/vct/id-v1")
            .expect("compute");
        let idx2 = indexer
            .compute_index("vct", "https://credentials.gravital.io/vct/id-v1")
            .expect("compute");
        assert_eq!(idx1, idx2);

        let idx_other = indexer
            .compute_index("vct", "https://credentials.gravital.io/vct/id-v2")
            .expect("compute");
        assert_ne!(idx1, idx_other);

        // Ningún fragmento del plaintext aparece en los bytes del índice ni en su hex (P-09, INV-02)
        let hex = idx1.to_hex();
        assert!(!hex.contains("vct"));
        assert!(!hex.contains("credentials"));
        assert!(!hex.contains("gravital"));
    }

    #[test]
    fn blind_indexing_rejects_colons_or_empty_attr() {
        let indexer = BlindIndexer::new(test_bik());
        assert!(indexer.compute_index("", "val").is_err());
        assert!(indexer.compute_index("attr:colon", "val").is_err());
    }

    #[test]
    fn blind_indexer_from_kek_produces_consistent_indices() {
        let kek = SecretBytes::new([0x77u8; 32]);
        let indexer1 = BlindIndexer::from_kek(&kek).expect("indexer1");
        let indexer2 = BlindIndexer::from_kek(&kek).expect("indexer2");

        let idx1 = indexer1.compute_issuer_index("iss-panama").expect("idx");
        let idx2 = indexer2.compute_issuer_index("iss-panama").expect("idx");
        assert_eq!(idx1, idx2);
    }
}
