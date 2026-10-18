//! Detección de divergencias RPC y prevención de split-views (F7.T03, REQ-LEDG-005, REQ-LEDG-006).

use crate::error::IndexerError;

/// Muestra de cabecera de bloque obtenida de un proveedor RPC específico.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeaderSample {
    /// Identificador o URL del proveedor RPC consultado.
    pub provider: String,
    /// Altura del bloque reportada.
    pub block_number: u64,
    /// Hash del bloque reportado (ej. `0xabc...`).
    pub block_hash: String,
    /// Hash del bloque padre reportado.
    pub parent_hash: String,
}

/// Detector de divergencias y discrepancias entre múltiples proveedores RPC.
#[derive(Debug, Default, Clone, Copy)]
pub struct RpcDivergenceDetector;

impl RpcDivergenceDetector {
    /// Comprueba que todas las muestras de cabecera de bloque para la misma altura sean idénticas.
    ///
    /// # Errores
    /// Devuelve [`IndexerError::RpcDivergence`] si dos o más proveedores reportan hashes distintos
    /// para el mismo número de bloque (detección de split-view o bifurcación no resuelta).
    pub fn check_samples(samples: &[BlockHeaderSample]) -> Result<String, IndexerError> {
        let first = samples.first().ok_or_else(|| IndexerError::RpcDivergence {
            block_number: 0,
            reason: "No se proporcionaron muestras de proveedores RPC para validar consistencia"
                .to_string(),
        })?;

        for sample in samples {
            if sample.block_number != first.block_number {
                return Err(IndexerError::RpcDivergence {
                    block_number: sample.block_number,
                    reason: format!(
                        "Inconsistencia en alturas de bloque comparadas: '{}' reportó {} mientras '{}' reportó {}",
                        sample.provider, sample.block_number, first.provider, first.block_number
                    ),
                });
            }

            if sample.block_hash != first.block_hash {
                return Err(IndexerError::RpcDivergence {
                    block_number: sample.block_number,
                    reason: format!(
                        "Divergencia crítica en block_hash en altura {}: '{}' reportó {} mientras '{}' reportó {}",
                        sample.block_number, sample.provider, sample.block_hash, first.provider, first.block_hash
                    ),
                });
            }

            if sample.parent_hash != first.parent_hash {
                return Err(IndexerError::RpcDivergence {
                    block_number: sample.block_number,
                    reason: format!(
                        "Divergencia crítica en parent_hash en altura {}: '{}' reportó {} mientras '{}' reportó {}",
                        sample.block_number, sample.provider, sample.parent_hash, first.provider, first.parent_hash
                    ),
                });
            }
        }

        Ok(first.block_hash.clone())
    }

    /// Evalúa las alturas de cabezas finalizadas reportadas por múltiples proveedores.
    ///
    /// Para aplicar el principio **fail-closed (INV-05)**:
    /// 1. Si la discrepancia entre cualquier par excede `max_allowed_skew`, se reporta divergencia.
    /// 2. De lo contrario, se devuelve la altura mínima observada para no indexar bloques que
    ///    algún proveedor no considere todavía finalizados.
    ///
    /// # Errores
    /// Devuelve [`IndexerError::RpcDivergence`] si el desfase entre proveedores supera el límite tolerado.
    pub fn safe_finalized_head(
        heads: &[(String, u64)],
        max_allowed_skew: u64,
    ) -> Result<u64, IndexerError> {
        if heads.is_empty() {
            return Err(IndexerError::RpcDivergence {
                block_number: 0,
                reason: "Lista vacía de cabezas finalizadas".to_string(),
            });
        }

        let mut min_head = u64::MAX;
        let mut max_head = 0u64;

        for (_, head) in heads {
            min_head = min_head.min(*head);
            max_head = max_head.max(*head);
        }

        let skew = max_head.saturating_sub(min_head);
        if skew > max_allowed_skew {
            return Err(IndexerError::RpcDivergence {
                block_number: min_head,
                reason: format!(
                    "Desfase excesivo entre proveedores RPC ({skew} bloques > límite {max_allowed_skew}): min={min_head}, max={max_head}"
                ),
            });
        }

        Ok(min_head)
    }
}
