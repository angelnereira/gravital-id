//! Codificación base64url estricta, sin relleno (F2.T02, REQ-VER-008).
//!
//! Reglas (RFC 4648 §3.5, §4; perfil `v1` de `CRYPTO_PROFILES.md`):
//! - Alfabeto URL-safe: `A–Z`, `a–z`, `0–9`, `-`, `_`.
//! - **Sin relleno**: cualquier `=` se rechaza.
//! - **Canónica**: los bits sobrantes del último carácter deben ser cero
//!   (p. ej. `Zg` es válido para `f`; `Zh` no, porque sus 4 bits bajos no son 0).
//! - **Acotada**: entradas por encima de [`MAX_INPUT_LEN`] se rechazan antes de
//!   asignar memoria (REQ-VER-008).
//!
//! Todo el módulo cumple INV-10: sin indexaciones ni aritmética que puedan
//! entrar en pánico (los accesos a tablas usa `get` y la aritmética usa
//! operaciones `checked`/`saturating`/`wrapping`).

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use gravital_id_types::{ErrorCode, GidError};

/// Longitud máxima de entrada aceptada por `decode` (64 KiB).
///
/// Alineada con el tamaño máximo de credencial SD-JWT en línea
/// (`CRYPTO_PROFILES.md §5.2`); los transportes con presupuestos más ajustados
/// (QR) usan [`decode_bounded`].
pub const MAX_INPUT_LEN: usize = 64 * 1024;

/// Tabla de decodificación: `INVALID` marca caracteres fuera del alfabeto.
const INVALID: u8 = 0xFF;

/// Alfabeto de codificación (índice → carácter).
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Tabla inversa (carácter ASCII → valor de 6 bits, o `INVALID`).
const DECODE_TABLE: [u8; 256] = build_decode_table();

/// Construye la tabla inversa en tiempo de compilación.
///
/// Excepción de lints justificada (AGENTS.md §14): este código se evalúa en
/// tiempo de compilación (`const fn`). Un índice o una aritmética inválidos
/// serían error de compilación, nunca un pánico en tiempo de ejecución, de modo
/// que INV-10 sigue intacto para el binario final.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const fn build_decode_table() -> [u8; 256] {
    let mut table = [INVALID; 256];
    let mut i = 0usize;
    while i < 64 {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
}

/// Error interno de decodificación (motivo estable para pruebas y mensajes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeError {
    /// Carácter fuera del alfabeto base64url (incluye `=`, espacios y controles).
    InvalidCharacter(char),
    /// Longitud imposible: `len % 4 == 1` no puede salir de ninguna codificación.
    InvalidLength,
    /// Los bits sobrantes del último carácter no son cero (no canónica).
    NonCanonicalTrailingBits,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCharacter(ch) => {
                write!(f, "invalid base64url character: U+{:04X}", *ch as u32)
            }
            Self::InvalidLength => f.write_str("invalid base64url length"),
            Self::NonCanonicalTrailingBits => f.write_str("non-canonical trailing bits"),
        }
    }
}

/// Decodifica base64url estricta con cota de salida.
///
/// # Errores
/// [`ErrorCode::MalformedMessage`] si la salida supera `max_output`, la entrada
/// contiene un carácter fuera del alfabeto (incluido `=`), tiene longitud
/// `% 4 == 1`, o sus bits sobrantes no son cero.
pub fn decode_bounded(input: &str, max_output: usize) -> Result<Vec<u8>, GidError> {
    let bytes = input.as_bytes();
    let expected_len = expected_output_len(bytes.len()).map_err(to_gid_error)?;
    if expected_len > max_output {
        return Err(GidError::new(
            ErrorCode::MalformedMessage,
            "base64url output exceeds the configured bound",
        ));
    }

    let mut out = Vec::new();
    if out.try_reserve_exact(expected_len).is_err() {
        return Err(GidError::new(
            ErrorCode::MalformedMessage,
            "base64url output cannot be allocated",
        ));
    }

    let (chunks, remainder) = bytes.as_chunks::<4>();
    for chunk in chunks {
        let c0 = lookup(chunk.first().copied().unwrap_or(0))?;
        let c1 = lookup(chunk.get(1).copied().unwrap_or(0))?;
        let c2 = lookup(chunk.get(2).copied().unwrap_or(0))?;
        let c3 = lookup(chunk.get(3).copied().unwrap_or(0))?;
        out.push(c0.wrapping_shl(2) | c1.wrapping_shr(4));
        out.push(c1.wrapping_shl(4) | c2.wrapping_shr(2));
        out.push(c2.wrapping_shl(6) | c3);
    }

    match remainder.len() {
        0 => {}
        2 => {
            let c0 = lookup(remainder.first().copied().unwrap_or(0))?;
            let c1 = lookup(remainder.get(1).copied().unwrap_or(0))?;
            // 1 byte de salida: los 4 bits bajos de c1 deben ser cero.
            if c1 & 0x0F != 0 {
                return Err(to_gid_error(DecodeError::NonCanonicalTrailingBits));
            }
            out.push(c0.wrapping_shl(2) | c1.wrapping_shr(4));
        }
        3 => {
            let c0 = lookup(remainder.first().copied().unwrap_or(0))?;
            let c1 = lookup(remainder.get(1).copied().unwrap_or(0))?;
            let c2 = lookup(remainder.get(2).copied().unwrap_or(0))?;
            // 2 bytes de salida: los 2 bits bajos de c2 deben ser cero.
            if c2 & 0x03 != 0 {
                return Err(to_gid_error(DecodeError::NonCanonicalTrailingBits));
            }
            out.push(c0.wrapping_shl(2) | c1.wrapping_shr(4));
            out.push(c1.wrapping_shl(4) | c2.wrapping_shr(2));
        }
        // remainder.len() == 1 queda descartado por expected_output_len.
        _ => return Err(to_gid_error(DecodeError::InvalidLength)),
    }

    Ok(out)
}

/// Decodifica base64url estricta con las cotas por defecto: entrada ≤
/// [`MAX_INPUT_LEN`] y salida ≤ [`MAX_INPUT_LEN`].
///
/// # Errores
/// [`ErrorCode::MalformedMessage`] en las mismas condiciones que
/// [`decode_bounded`], más el exceso de [`MAX_INPUT_LEN`] en la entrada.
pub fn decode(input: &str) -> Result<Vec<u8>, GidError> {
    if input.len() > MAX_INPUT_LEN {
        return Err(GidError::new(
            ErrorCode::MalformedMessage,
            "base64url input exceeds the maximum length",
        ));
    }
    decode_bounded(input, MAX_INPUT_LEN)
}

/// Codifica bytes a base64url sin relleno (salida canónica).
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let capacity = bytes.len().div_ceil(3).saturating_mul(4);
    let mut out = String::with_capacity(capacity);

    let (chunks, remainder) = bytes.as_chunks::<3>();
    for chunk in chunks {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(encode_six_bits(b0.wrapping_shr(2)) as char);
        out.push(encode_six_bits((b0 & 0x03).wrapping_shl(4) | b1.wrapping_shr(4)) as char);
        out.push(encode_six_bits((b1 & 0x0F).wrapping_shl(2) | b2.wrapping_shr(6)) as char);
        out.push(encode_six_bits(b2 & 0x3F) as char);
    }

    match remainder.len() {
        0 => {}
        1 => {
            let b0 = remainder.first().copied().unwrap_or(0);
            out.push(encode_six_bits(b0.wrapping_shr(2)) as char);
            out.push(encode_six_bits((b0 & 0x03).wrapping_shl(4)) as char);
        }
        2 => {
            let b0 = remainder.first().copied().unwrap_or(0);
            let b1 = remainder.get(1).copied().unwrap_or(0);
            out.push(encode_six_bits(b0.wrapping_shr(2)) as char);
            out.push(encode_six_bits((b0 & 0x03).wrapping_shl(4) | b1.wrapping_shr(4)) as char);
            out.push(encode_six_bits((b1 & 0x0F).wrapping_shl(2)) as char);
        }
        _ => {}
    }

    out
}

/// Longitud de salida esperada para una entrada válida de `input_len` caracteres.
fn expected_output_len(input_len: usize) -> Result<usize, DecodeError> {
    let rem = input_len.checked_rem(4).ok_or(DecodeError::InvalidLength)?;
    let base = input_len
        .checked_div(4)
        .ok_or(DecodeError::InvalidLength)?
        .checked_mul(3)
        .ok_or(DecodeError::InvalidLength)?;
    match rem {
        0 => Ok(base),
        2 => base.checked_add(1).ok_or(DecodeError::InvalidLength),
        3 => base.checked_add(2).ok_or(DecodeError::InvalidLength),
        // rem == 1 (y cualquier otro resto) es imposible en base64.
        _ => Err(DecodeError::InvalidLength),
    }
}

/// Busca un carácter en la tabla inversa.
fn lookup(byte: u8) -> Result<u8, GidError> {
    match DECODE_TABLE.get(usize::from(byte)) {
        Some(&value) if value != INVALID => Ok(value),
        Some(_) => Err(to_gid_error(DecodeError::InvalidCharacter(byte as char))),
        // byte -> usize siempre cae dentro de la tabla de 256 entradas.
        None => Err(to_gid_error(DecodeError::InvalidCharacter(byte as char))),
    }
}

/// Codifica un índice de 6 bits al alfabeto base64url.
///
/// El índice siempre es < 64 por construcción (desplazamientos sobre `u8` con
/// máscaras); la rama `None` es inalcanzable y devuelve `A` para preservar la
/// ausencia de pánicos (INV-10).
fn encode_six_bits(index: u8) -> u8 {
    match ALPHABET.get(usize::from(index)) {
        Some(&ch) => ch,
        None => b'A',
    }
}

/// Convierte el motivo interno en el error canónico del protocolo.
fn to_gid_error(reason: DecodeError) -> GidError {
    GidError::new(ErrorCode::MalformedMessage, reason.to_string())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).
mod tests {
    use super::*;
    use alloc::format;

    // // Verifies: REQ-VER-008 (vectores RFC 4648 §10)
    #[test]
    fn encode_matches_rfc4648_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg");
        assert_eq!(encode(b"fo"), "Zm8");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg");
        assert_eq!(encode(b"fooba"), "Zm9vYmE");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    // // Verifies: REQ-VER-008 (round-trip de los vectores)
    #[test]
    fn decode_matches_rfc4648_vectors() {
        assert_eq!(decode("").expect("empty is valid"), Vec::<u8>::new());
        assert_eq!(decode("Zg").expect("canonical"), b"f");
        assert_eq!(decode("Zm8").expect("canonical"), b"fo");
        assert_eq!(decode("Zm9v").expect("canonical"), b"foo");
        assert_eq!(decode("Zm9vYg").expect("canonical"), b"foob");
        assert_eq!(decode("Zm9vYmE").expect("canonical"), b"fooba");
        assert_eq!(decode("Zm9vYmFy").expect("canonical"), b"foobar");
    }

    // // Verifies: REQ-VER-008 (caso negativo: relleno prohibido)
    #[test]
    fn decode_rejects_padding() {
        for padded in ["Zg==", "Zm8=", "Zg=", "=", "===="] {
            let err = decode(padded).expect_err("padding is not part of the profile");
            assert_eq!(err.code, ErrorCode::MalformedMessage);
        }
    }

    // // Verifies: REQ-VER-008 (caso negativo: caracteres fuera del alfabeto)
    #[test]
    fn decode_rejects_non_alphabet_characters() {
        for bad in ["Z+g", "Z/g", "Zm9 v", "Zm9\n", "Zm©v", " Zm9v"] {
            assert!(decode(bad).is_err(), "expected rejection for {bad:?}");
        }
    }

    // // Verifies: REQ-VER-008 (caso negativo: longitud imposible)
    #[test]
    fn decode_rejects_impossible_length() {
        for bad in ["Z", "Zm9", "Zm9vY"] {
            assert!(decode(bad).is_err(), "expected rejection for {bad:?}");
        }
    }

    // // Verifies: REQ-VER-008 (caso negativo: bits sobrantes no canónicos)
    #[test]
    fn decode_rejects_non_canonical_trailing_bits() {
        // 'h' = índice 33 = 0b100001: los 4 bits bajos (0b0001) no son cero.
        assert!(decode("Zh").is_err());
        // 'V' = índice 21 = 0b010101: los 2 bits bajos no son cero.
        assert!(decode("ZmV").is_err());
        // El carácter canónico sí pasa.
        assert_eq!(decode("Zg").expect("canonical"), b"f");
    }

    // // Verifies: REQ-VER-008 (caso negativo: cota de salida)
    #[test]
    fn decode_bounded_rejects_output_above_bound() {
        let encoded = encode(b"foobar");
        assert!(decode_bounded(&encoded, 6).is_ok());
        let err = decode_bounded(&encoded, 5).expect_err("bound exceeded");
        assert_eq!(err.code, ErrorCode::MalformedMessage);
    }

    // // Verifies: REQ-VER-008 (caso negativo: entrada por encima del límite)
    #[test]
    fn decode_rejects_input_above_max_len() {
        let long = "Z".repeat(MAX_INPUT_LEN + 4);
        assert!(decode(&long).is_err());
    }

    // // Verifies: REQ-VER-008 (todos los bytes del alfabeto son válidos)
    #[test]
    fn full_alphabet_round_trips() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        let encoded = encode(&bytes);
        assert!(!encoded.contains('='), "no padding in output");
        assert!(
            encoded
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "only base64url alphabet"
        );
        assert_eq!(decode(&encoded).expect("round-trip"), bytes);
    }

    // // Verifies: REQ-VER-008 (el mensaje de error describe el motivo sin material sensible)
    #[test]
    fn error_message_is_stable() {
        let err = decode("Zh").expect_err("non-canonical");
        assert_eq!(format!("{err}"), "[GID-E1001] non-canonical trailing bits");
    }
}
