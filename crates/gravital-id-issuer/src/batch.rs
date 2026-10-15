//! Emisión por lotes con claves, sales e índices distintos (F3.T08, REQ-CRED-006).
//!
//! ARCHITECTURE §8.3: para mitigar la correlación, un emisor PUEDE emitir **N copias** de
//! la misma credencial, cada una con clave de vinculación distinta, sales distintas e
//! **índice de estado distinto** (compartir índice permitiría correlacionar copias).
//!
//! Trazabilidad:
//! - **REQ-CRED-006:** El emisor DEBERÍA soportar emisión por lotes con claves, sales e
//!   índices de estado distintos por copia.
//! - **REQ-CRED-002:** Cada divulgación usa sal ≥ 128 bits del CSPRNG inyectado.
//! - **INV-03:** Las claves privadas del titular nunca pasan por aquí: solo claves públicas
//!   (`cnf.jwk`), y la firma del emisor se delega al `KeyStore`.
//! - **INV-05:** Un lote mal formado se rechaza entero; no se emite ninguna copia.

use alloc::format;
use alloc::vec::Vec;

use gravital_id_crypto::JwkEcP256;
use gravital_id_types::{ErrorCode, GidError};

/// Número máximo de copias por lote (límite operativo del emisor).
pub const MAX_BATCH_COPIES: usize = 64;

/// Plan de emisión de un lote de copias de la misma credencial.
///
/// Cada copia usa una clave de vinculación y un índice de estado propios, tomados de los
/// vectores en el mismo orden. Las sales las genera el CSPRNG inyectado en cada divulgación,
/// por lo que son distintas en todas las copias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchPlan {
    copies: Vec<BatchCopy>,
}

impl BatchPlan {
    /// Construye un plan de lote a partir de claves de titular e índices de estado.
    ///
    /// # Errores
    /// - [`ErrorCode::MalformedSdJwt`] si el lote está vacío, supera [`MAX_BATCH_COPIES`],
    ///   o si el número de claves o de índices no coincide con el número de copias.
    /// - [`ErrorCode::MalformedStatusList`] si hay índices repetidos.
    /// - [`ErrorCode::InvalidKeyFormat`] si hay claves de titular repetidas.
    pub fn new(holder_keys: Vec<JwkEcP256>, status_indices: Vec<u64>) -> Result<Self, GidError> {
        if holder_keys.is_empty() {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "a batch must contain at least one copy",
            ));
        }
        if holder_keys.len() > MAX_BATCH_COPIES {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!(
                    "a batch cannot contain more than {MAX_BATCH_COPIES} copies, got {}",
                    holder_keys.len()
                ),
            ));
        }
        if holder_keys.len() != status_indices.len() {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!(
                    "a batch of {} copies needs {} status indices, got {}",
                    holder_keys.len(),
                    holder_keys.len(),
                    status_indices.len()
                ),
            ));
        }

        // Índices de estado distintos: compartirlos correlacionaría las copias (ARCHITECTURE §8.3).
        for (index, idx) in status_indices.iter().enumerate() {
            if status_indices
                .iter()
                .skip(index.saturating_add(1))
                .any(|other| other == idx)
            {
                return Err(GidError::new(
                    ErrorCode::MalformedStatusList,
                    format!("status index {idx} is allocated to more than one copy"),
                ));
            }
        }

        // Claves de vinculación distintas: dos copias con la misma clave son rastreables.
        for (index, key) in holder_keys.iter().enumerate() {
            if holder_keys
                .iter()
                .skip(index.saturating_add(1))
                .any(|other| other == key)
            {
                return Err(GidError::new(
                    ErrorCode::InvalidKeyFormat,
                    format!(
                        "holder keys must be distinct per copy (repeated thumbprint {})",
                        key.thumbprint_base64url()
                    ),
                ));
            }
        }

        let copies = holder_keys
            .into_iter()
            .zip(status_indices)
            .map(|(holder_key, status_idx)| BatchCopy {
                holder_key,
                status_idx,
            })
            .collect();

        Ok(Self { copies })
    }

    /// Número de copias del lote.
    #[must_use]
    pub fn len(&self) -> usize {
        self.copies.len()
    }

    /// Indica si el lote no tiene copias (nunca ocurre: el constructor lo impide).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.copies.is_empty()
    }

    /// Copias del lote en orden de emisión.
    #[must_use]
    pub fn copies(&self) -> &[BatchCopy] {
        &self.copies
    }
}

/// Una copia del lote: clave de titular e índice de estado que le corresponden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchCopy {
    /// Clave pública de vinculación del titular para esta copia (`cnf.jwk`).
    pub holder_key: JwkEcP256,
    /// Índice de estado exclusivo de esta copia.
    pub status_idx: u64,
}
