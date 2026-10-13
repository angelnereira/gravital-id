//! Compresión DEFLATE acotada (F2.T05, REQ-STAT-003).
//!
//! El perfil de compresión del transporte offline es zlib/DEFLATE
//! (`CRYPTO_PROFILES.md §5.1`, `spikes/qr/REPORT.md`): contenedor zlib
//! (RFC 1950) con datos DEFLATE (RFC 1951) y suma de comprobación adler32, que
//! refuerza el fail-closed (INV-05): datos corruptos se detectan en lugar de
//! aceptarse en silencio.
//!
//! **Límites obligatorios** (`CRYPTO_PROFILES.md §5.1`, para listas de estado):
//! - Ratio máximo de expansión: **10:1** respecto de la entrada comprimida.
//! - Límite absoluto de salida: **2 MiB** por lista de estado.
//!
//! La descompresión pasa el límite efectivo al backend (`miniz_oxide`, puro
//! Rust y `no_std`, ADR-0007), de modo que una bomba de descompresión aborta sin
//! asignar memoria de más. Para otros usos (p. ej. el transporte QR de
//! `PROTOCOL.md §3.2`) se llama a [`inflate_bounded`] con los límites del perfil
//! correspondiente.

use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;

use gravital_id_types::{ErrorCode, GidError};
use miniz_oxide::inflate::{decompress_to_vec_zlib_with_limit, TINFLStatus};

/// Límite absoluto de salida por defecto: 2 MiB (`CRYPTO_PROFILES.md §5.1`).
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 2 * 1024 * 1024;

/// Ratio máximo de expansión por defecto: 10:1 (`CRYPTO_PROFILES.md §5.1`).
pub const DEFAULT_MAX_EXPANSION_RATIO: usize = 10;

/// Nivel de compresión usado por el perfil (máximo; `spikes/qr/REPORT.md`).
pub const PROFILE_COMPRESSION_LEVEL: u8 = 9;

/// Error interno (motivo estable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeflateError {
    /// Entrada comprimida truncada o corrupta (adler32 no coincide).
    CorruptStream,
    /// Salida por encima del límite absoluto.
    OutputTooLarge,
    /// Salida por encima del ratio de expansión permitido.
    RatioExceeded,
}

impl fmt::Display for DeflateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CorruptStream => f.write_str("corrupt or truncated deflate stream"),
            Self::OutputTooLarge => f.write_str("decompressed output exceeds the size limit"),
            Self::RatioExceeded => f.write_str("decompression ratio exceeds the allowed limit"),
        }
    }
}

/// Convierte el motivo interno en el error canónico del protocolo.
fn to_gid_error(reason: DeflateError) -> GidError {
    let code = match reason {
        DeflateError::RatioExceeded => ErrorCode::DecompressionRatioExceeded,
        _ => ErrorCode::MalformedMessage,
    };
    GidError::new(code, reason.to_string())
}

/// Descomprime zlib/DEFLATE con límites de salida.
///
/// El límite efectivo es el más restrictivo de `max_output` y
/// `max_ratio * input.len()`; cuál se superó determina el código de error.
///
/// # Errores
/// - [`ErrorCode::DecompressionRatioExceeded`] si la salida supera `max_ratio`
///   veces la entrada comprimida.
/// - [`ErrorCode::MalformedMessage`] si supera `max_output` o si el flujo está
///   truncado o es corrupto (adler32).
pub fn inflate_bounded(
    input: &[u8],
    max_output: usize,
    max_ratio: usize,
) -> Result<Vec<u8>, GidError> {
    let ratio_cap = input.len().saturating_mul(max_ratio);

    // Se prueba primero con la cota más restrictiva: así el error identifica
    // exactamente qué límite se superó.
    let (cap, ratio_error): (usize, DeflateError) = if ratio_cap < max_output {
        (ratio_cap, DeflateError::RatioExceeded)
    } else {
        (max_output, DeflateError::OutputTooLarge)
    };

    match decompress_to_vec_zlib_with_limit(input, cap) {
        Ok(out) => Ok(out),
        Err(error) if error.status == TINFLStatus::HasMoreOutput && ratio_cap < max_output => {
            // El ratio cortó: ¿cabría en el límite absoluto? Si también lo
            // supera, el error es el absoluto.
            if decompress_to_vec_zlib_with_limit(input, max_output).is_ok() {
                Err(to_gid_error(ratio_error))
            } else {
                Err(to_gid_error(DeflateError::OutputTooLarge))
            }
        }
        Err(error) if error.status == TINFLStatus::HasMoreOutput => {
            Err(to_gid_error(DeflateError::OutputTooLarge))
        }
        Err(_) => Err(to_gid_error(DeflateError::CorruptStream)),
    }
}

/// Descomprime zlib/DEFLATE con los límites de **lista de estado**
/// ([`DEFAULT_MAX_OUTPUT_BYTES`] y [`DEFAULT_MAX_EXPANSION_RATIO`],
/// `CRYPTO_PROFILES.md §5.1`).
///
/// # Errores
/// En las mismas condiciones que [`inflate_bounded`].
pub fn inflate(input: &[u8]) -> Result<Vec<u8>, GidError> {
    inflate_bounded(input, DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_MAX_EXPANSION_RATIO)
}

/// Comprime a zlib/DEFLATE con el nivel del perfil (9).
///
/// # Errores
/// Nunca falla: `miniz_oxide` siempre produce salida; se devuelve `Vec` por
/// ergonomía con el resto del crate.
#[must_use]
pub fn deflate(input: &[u8]) -> Vec<u8> {
    deflate_at_level(input, PROFILE_COMPRESSION_LEVEL)
}

/// Comprime a zlib/DEFLATE con un nivel explícito (0–9).
#[must_use]
pub fn deflate_at_level(input: &[u8], level: u8) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(input, level.min(9))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec;

    /// Generador determinista de bytes poco compresibles (LCG de 64 bits).
    fn pseudo_random_bytes(len: usize) -> Vec<u8> {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut out = vec![0u8; len];
        for slot in out.iter_mut() {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *slot = (state >> 33) as u8;
        }
        out
    }

    // ---------- Round-trip ----------

    // // Verifies: REQ-STAT-003
    #[test]
    fn round_trips_payloads() {
        let repetitive = [0u8; 4096];
        let incompressible = pseudo_random_bytes(8 * 1024);
        let cases: [&[u8]; 4] = [b"", b"Gravital ID", &repetitive, &incompressible];
        for payload in cases {
            let compressed = deflate(payload);
            // Round-trip mecánico: límites generosos (los límites del perfil se
            // prueban por separado).
            let restored =
                inflate_bounded(&compressed, DEFAULT_MAX_OUTPUT_BYTES, 1024).expect("inflate");
            assert_eq!(restored, payload);
        }
    }

    // // Verifies: REQ-STAT-003 (el nivel del perfil comprime datos repetidos)
    #[test]
    fn profile_level_compresses_repetitive_data() {
        let payload = vec![0x41u8; 8192];
        let compressed = deflate(&payload);
        assert!(
            compressed.len() < payload.len() / 10,
            "expected strong compression"
        );
    }

    // // Verifies: REQ-STAT-003 (límites del perfil: dentro se aceptan)
    #[test]
    fn accepts_payloads_within_status_list_limits() {
        // Datos poco compresibles se mantienen por debajo del ratio 10:1.
        let payload = pseudo_random_bytes(8 * 1024);
        let compressed = deflate(&payload);
        let restored = inflate(&compressed).expect("inflate con límites de lista");
        assert_eq!(restored, payload);
    }

    // ---------- Bomba de descompresión (CRYPTO_PROFILES.md §5.1) ----------

    // // Verifies: REQ-STAT-003 (caso negativo: ratio de expansión)
    #[test]
    fn rejects_decompression_bombs_by_ratio() {
        // 1 MiB de ceros comprimida: expande muy por encima de 10:1.
        let payload = vec![0u8; 1024 * 1024];
        let compressed = deflate(&payload);
        let err = inflate(&compressed).expect_err("bomb must be rejected");
        assert_eq!(err.code, ErrorCode::DecompressionRatioExceeded);
    }

    // // Verifies: REQ-STAT-003 (caso negativo: límite absoluto de salida)
    #[test]
    fn rejects_output_above_absolute_limit() {
        // Cota de 4 KiB con ratio alto: el límite absoluto debe cortar antes.
        let payload = vec![0u8; 256 * 1024];
        let compressed = deflate(&payload);
        let err =
            inflate_bounded(&compressed, 4 * 1024, 1_000_000).expect_err("absolute limit must cut");
        assert_eq!(err.code, ErrorCode::MalformedMessage);
        assert_eq!(
            format!("{err}"),
            "[GID-E1001] decompressed output exceeds the size limit"
        );
    }

    // ---------- Integridad (adler32) y flujos truncados ----------

    // // Verifies: REQ-STAT-003 (caso negativo: flujo corrupto o truncado)
    #[test]
    fn rejects_corrupt_streams() {
        // Basura.
        assert!(inflate(&[0x00, 0x01, 0x02, 0x03, 0x04]).is_err());
        // Cabecera zlib inválida.
        assert!(inflate(&[0xFF, 0xFF, 0x00, 0x00]).is_err());
        // Flujo truncado: el round-trip recortado.
        let compressed = deflate(b"un payload suficientemente largo para comprimir");
        if let Some(prefix) = compressed.get(..compressed.len().saturating_sub(4)) {
            assert!(inflate_bounded(prefix, DEFAULT_MAX_OUTPUT_BYTES, 1024).is_err());
        }
        // Checksum adler32 alterado: el último byte cambia.
        let mut corrupted = deflate(b"datos cuyo checksum se corrompe al final");
        if let Some(last) = corrupted.last_mut() {
            *last ^= 0xFF;
            assert!(inflate_bounded(&corrupted, DEFAULT_MAX_OUTPUT_BYTES, 1024).is_err());
        }
    }

    // // Verifies: REQ-STAT-003 (nivel explícito)
    #[test]
    fn explicit_level_round_trips() {
        let payload = b"datos de prueba para nivel 1";
        let compressed = deflate_at_level(payload, 1);
        assert_eq!(
            inflate_bounded(&compressed, DEFAULT_MAX_OUTPUT_BYTES, 1024).expect("inflate"),
            payload
        );
    }

    // ---------- Límite cero ----------

    // // Verifies: REQ-STAT-003 (caso negativo: cota cero rechaza todo)
    #[test]
    fn zero_limit_rejects_everything() {
        let compressed = deflate(b"algo");
        let err = inflate_bounded(&compressed, 0, 1_000_000).expect_err("zero limit must reject");
        assert_eq!(err.code, ErrorCode::MalformedMessage);
    }
}
