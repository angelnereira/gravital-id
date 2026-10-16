//! Fragmentación Multi-QR y acumulador con verificación de integridad (REQ-PRES-005, ADR-0011, PROTOCOL.md §3.3).
//!
//! Trazabilidad:
//! - `REQ-PRES-005`: Transporte QR bidireccional offline entre verificador y titular.
//! - `REQ-PRES-006`: Segmentación y reconstrucción determinista multi-código con verificación de integridad.
//! - `ADR-0011`: Presupuesto de 1.200 caracteres Base45 para QR único; división en fragmentos de $\le 900$ caracteres.
//! - `PROTOCOL.md §3.3`: Formato canónico `GID01/P<índice>/<total>/<hash8>/<fragmento>` (y legado `PIP1/M/`).
//! - `INV-01`: Cero llamadas de red.
//! - `INV-05`: Rechazo fail-closed ante hashes discrepantes, índices fuera de rango o fragmentos incompletos (`GID-E1008`).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use gravital_id_codec::base64url;
use gravital_id_crypto::sha256;
use gravital_id_types::{ErrorCode, GidError};

/// Presupuesto máximo de un código QR individual en caracteres Base45 (`ADR-0011`).
pub const MAX_SINGLE_QR_CHARS: usize = 1200;

/// Carga útil máxima de cada fragmento Multi-QR en caracteres Base45 (`ADR-0011`, `PROTOCOL.md §3.3`).
pub const MAX_FRAGMENT_PAYLOAD_CHARS: usize = 900;

/// Número mínimo de fragmentos para activar el modo Multi-QR.
pub const MIN_MULTI_QR_FRAGMENTS: usize = 2;

/// Número máximo de fragmentos permitidos para presentaciones ópticas (`PROTOCOL.md §3.3`).
pub const MAX_MULTI_QR_FRAGMENTS: usize = 8;

/// Prefijo canónico de cabecera de fragmento Multi-QR (`PROTOCOL.md §3.3`).
pub const MULTI_QR_CANONICAL_PREFIX: &str = "GID01/P";

/// Prefijo legado de compatibilidad para fragmentos Multi-QR (`PROTOCOL.md §3.3`).
pub const MULTI_QR_LEGACY_PREFIX: &str = "PIP1/M/";

/// Longitud fija del hash de integridad de sesión truncado en caracteres Base64URL (48 bits).
pub const INTEGRITY_HASH8_LEN: usize = 8;

/// Segmenta un texto Base45 en uno o varios códigos QR según los presupuestos normativos (`ADR-0011`, `PROTOCOL.md §3.3`).
///
/// Si la longitud del texto es $\le 1.200$ caracteres, se emite un único código QR.
/// Si supera los 1.200 caracteres, se segmenta en $N$ fragmentos equilibrados ($2 \le N \le 8$)
/// de hasta 900 caracteres cada uno, precedidos por la cabecera canónica `GID01/P<índice>/<total>/<hash8>/<fragmento>`.
///
/// # Errores
/// [`ErrorCode::MalformedMessage`] si el tamaño total excede la capacidad máxima de 8 fragmentos
/// (en cuyo caso el protocolo exige utilizar transporte de proximidad NFC o BLE).
pub fn segment_presentation(base45_text: &str) -> Result<Vec<String>, GidError> {
    if base45_text.len() <= MAX_SINGLE_QR_CHARS {
        return Ok(vec![base45_text.to_string()]);
    }

    // Calcular el número de fragmentos necesarios
    let total_len = base45_text.len();
    let num_frags = total_len
        .saturating_add(MAX_FRAGMENT_PAYLOAD_CHARS)
        .saturating_sub(1)
        .checked_div(MAX_FRAGMENT_PAYLOAD_CHARS)
        .ok_or_else(|| {
            GidError::new(ErrorCode::MalformedMessage, "division by zero in num_frags")
        })?;

    let total = num_frags.max(MIN_MULTI_QR_FRAGMENTS);
    if total > MAX_MULTI_QR_FRAGMENTS {
        return Err(GidError::new(
            ErrorCode::MalformedMessage,
            format!(
                "presentation size ({} characters) exceeds multi-qr limit of {MAX_MULTI_QR_FRAGMENTS} fragments",
                total_len
            ),
        ));
    }

    // Calcular hash de integridad SHA-256 sobre el texto Base45 completo
    let digest = sha256(base45_text.as_bytes());
    let hash_b64 = base64url::encode(&digest);
    let hash8 = hash_b64.get(..INTEGRITY_HASH8_LEN).ok_or_else(|| {
        GidError::new(
            ErrorCode::MalformedMessage,
            "failed to compute integrity hash8",
        )
    })?;

    // Distribuir equitativamente la carga útil
    let chunk_size = total_len
        .saturating_add(total)
        .saturating_sub(1)
        .checked_div(total)
        .ok_or_else(|| {
            GidError::new(
                ErrorCode::MalformedMessage,
                "division by zero in chunk_size",
            )
        })?;

    let mut fragments = Vec::with_capacity(total);
    let bytes = base45_text.as_bytes();

    for i in 1..=total {
        let start = (i.saturating_sub(1)).saturating_mul(chunk_size);
        let end = (start.saturating_add(chunk_size)).min(total_len);

        let slice = bytes.get(start..end).ok_or_else(|| {
            GidError::new(
                ErrorCode::MalformedMessage,
                "slice index out of bounds during segmentation",
            )
        })?;
        let chunk_str = core::str::from_utf8(slice).map_err(|_| {
            GidError::new(ErrorCode::MalformedMessage, "invalid utf-8 in base45 slice")
        })?;

        let header = format!("{MULTI_QR_CANONICAL_PREFIX}{i}/{total}/{hash8}/{chunk_str}");
        fragments.push(header);
    }

    Ok(fragments)
}

/// Acumulador y reensamblador de fragmentos Multi-QR con verificación de integridad (`PROTOCOL.md §3.3`).
#[derive(Debug, Clone, Default)]
pub struct MultiQrCollector {
    expected_total: Option<usize>,
    expected_hash8: Option<String>,
    received_slots: Vec<Option<String>>,
}

impl MultiQrCollector {
    /// Crea un nuevo acumulador vacío para una sesión de captura Multi-QR.
    #[must_use]
    pub fn new() -> Self {
        Self {
            expected_total: None,
            expected_hash8: None,
            received_slots: Vec::new(),
        }
    }

    /// Retorna el número total de fragmentos esperados si ya se ha recibido al menos uno.
    #[must_use]
    pub fn expected_total(&self) -> Option<usize> {
        self.expected_total
    }

    /// Retorna la cantidad de fragmentos únicos recibidos hasta el momento.
    #[must_use]
    pub fn received_count(&self) -> usize {
        self.received_slots.iter().filter(|s| s.is_some()).count()
    }

    /// Indica si todos los fragmentos han sido reunidos.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        if let Some(total) = self.expected_total {
            self.received_slots.len() == total && self.received_slots.iter().all(|s| s.is_some())
        } else {
            false
        }
    }

    /// Procesa un fragmento escaneado.
    ///
    /// Si este fragmento completa el total, verifica la integridad SHA-256 y retorna `Ok(Some(full_base45))`.
    /// Si faltan fragmentos por capturar, retorna `Ok(None)`.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedMessage`] si la cabecera es inválida, el índice está fuera de rango,
    /// o el hash de integridad no coincide.
    pub fn add_fragment(&mut self, raw_scan: &str) -> Result<Option<String>, GidError> {
        // Detectar y quitar prefijo (canónico o legado)
        let body = if let Some(stripped) = raw_scan.strip_prefix(MULTI_QR_CANONICAL_PREFIX) {
            stripped
        } else if let Some(stripped) = raw_scan.strip_prefix(MULTI_QR_LEGACY_PREFIX) {
            stripped
        } else {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "multi-qr fragment missing required prefix ('GID01/P' or 'PIP1/M/')",
            ));
        };

        // Formato esperado: <índice>/<total>/<hash8>/<fragmento>
        let mut parts = body.splitn(4, '/');
        let index_str = parts.next().ok_or_else(|| {
            GidError::new(ErrorCode::MalformedMessage, "missing fragment index field")
        })?;
        let total_str = parts.next().ok_or_else(|| {
            GidError::new(ErrorCode::MalformedMessage, "missing fragment total field")
        })?;
        let hash8 = parts.next().ok_or_else(|| {
            GidError::new(ErrorCode::MalformedMessage, "missing fragment hash8 field")
        })?;
        let chunk = parts.next().ok_or_else(|| {
            GidError::new(ErrorCode::MalformedMessage, "missing fragment chunk field")
        })?;

        let index: usize = index_str.parse().map_err(|_| {
            GidError::new(ErrorCode::MalformedMessage, "invalid fragment index number")
        })?;
        let total: usize = total_str.parse().map_err(|_| {
            GidError::new(ErrorCode::MalformedMessage, "invalid fragment total number")
        })?;

        if !(MIN_MULTI_QR_FRAGMENTS..=MAX_MULTI_QR_FRAGMENTS).contains(&total) {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                format!("multi-qr total fragments {total} out of bounds ({MIN_MULTI_QR_FRAGMENTS}..={MAX_MULTI_QR_FRAGMENTS})"),
            ));
        }

        if !(1..=total).contains(&index) {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                format!("multi-qr fragment index {index} out of bounds (1..={total})"),
            ));
        }

        if hash8.len() != INTEGRITY_HASH8_LEN {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                format!(
                    "multi-qr integrity hash length must be exactly {INTEGRITY_HASH8_LEN} chars"
                ),
            ));
        }

        // Validar coherencia con fragmentos previos de la sesión
        match &self.expected_total {
            Some(exp_t) if *exp_t != total => {
                return Err(GidError::new(
                    ErrorCode::MalformedMessage,
                    format!(
                        "mismatched total fragments across scans: expected {exp_t}, got {total}"
                    ),
                ));
            }
            Some(_) => {}
            None => {
                self.expected_total = Some(total);
                self.received_slots = vec![None; total];
            }
        }

        match &self.expected_hash8 {
            Some(exp_h) if exp_h != hash8 => {
                return Err(GidError::new(
                    ErrorCode::MalformedMessage,
                    format!(
                        "mismatched integrity hash across scans: expected {exp_h}, got {hash8}"
                    ),
                ));
            }
            Some(_) => {}
            None => {
                self.expected_hash8 = Some(hash8.to_string());
            }
        }

        // Guardar fragmento en su índice (index - 1)
        let slot_idx = index.saturating_sub(1);
        if let Some(slot) = self.received_slots.get_mut(slot_idx) {
            *slot = Some(chunk.to_string());
        }

        // Si ya están todos los fragmentos, concatenar y verificar integridad
        if self.is_complete() {
            let mut full = String::new();
            for s in self.received_slots.iter().flatten() {
                full.push_str(s);
            }

            // Verificar SHA-256
            let full_digest = sha256(full.as_bytes());
            let full_b64 = base64url::encode(&full_digest);
            let calculated_hash8 = full_b64.get(..INTEGRITY_HASH8_LEN).ok_or_else(|| {
                GidError::new(
                    ErrorCode::MalformedMessage,
                    "failed to compute reassembled hash",
                )
            })?;

            if let Some(expected) = &self.expected_hash8 {
                if calculated_hash8 != expected {
                    return Err(GidError::new(
                        ErrorCode::MalformedMessage,
                        format!("multi-qr integrity verification failed: expected {expected}, calculated {calculated_hash8}"),
                    ));
                }
            }

            Ok(Some(full))
        } else {
            Ok(None)
        }
    }

    /// Finaliza la captura devolviendo el payload reensamblado o [`ErrorCode::MultiQrIncomplete`] si expira el temporizador (`PROTOCOL.md §3.3`).
    ///
    /// # Errores
    /// [`ErrorCode::MultiQrIncomplete`] (`GID-E1008`) si no se han completado todos los fragmentos.
    pub fn finalize(&self) -> Result<String, GidError> {
        if !self.is_complete() {
            return Err(GidError::new(
                ErrorCode::MultiQrIncomplete,
                format!(
                    "multi-qr capture incomplete: received {} of {:?} fragments",
                    self.received_count(),
                    self.expected_total
                ),
            ));
        }

        let mut full = String::new();
        for s in self.received_slots.iter().flatten() {
            full.push_str(s);
        }
        Ok(full)
    }
}
