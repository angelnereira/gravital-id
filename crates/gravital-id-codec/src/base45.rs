//! Codificación Base45 (RFC 9285, F2.T05).
//!
//! Base45 codifica 2 bytes en 3 caracteres del alfabeto alfanumérico de QR.
//! Reglas implementadas del RFC:
//! - Alfabeto de 45 caracteres (Tabla 1): `0-9`, `A-Z`, espacio, `$%*+-.:/`.
//! - Bytes impares: el último byte se codifica en 2 caracteres.
//! - **Sin relleno**: `Base64`-style padding no existe.
//! - Validación estricta (§6): se rechaza cualquier carácter fuera del
//!   alfabeto y cualquier trío que decodifique a un entero > 65535.
//! - Longitudes inválidas (`% 3 == 1`) se rechazan.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use gravital_id_types::{ErrorCode, GidError};

/// Alfabeto Base45 (RFC 9285 Tabla 1). El índice es el valor en base 45.
const ALPHABET: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-.:/";

/// Valor inválido en la tabla inversa (carácter fuera del alfabeto).
const INVALID: u8 = 0xFF;

/// Tabla inversa ASCII → valor base 45.
const DECODE_TABLE: [u8; 256] = build_decode_table();

/// Construye la tabla inversa en tiempo de compilación.
///
/// Excepción de lints justificada (AGENTS.md §14): código evaluado en
/// compilación; un índice inválido sería error de compilación, nunca un pánico
/// en ejecución (INV-10).
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const fn build_decode_table() -> [u8; 256] {
    let mut table = [INVALID; 256];
    let mut i = 0usize;
    while i < 45 {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
}

/// Error interno (motivo estable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base45Error {
    /// Carácter fuera del alfabeto RFC 9285.
    InvalidCharacter(char),
    /// Longitud inválida: `% 3 == 1` no puede salir de ninguna codificación.
    InvalidLength,
    /// Trío que decodifica a un entero mayor que 65535 (§6).
    TripletOutOfRange,
}

impl fmt::Display for Base45Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCharacter(ch) => {
                write!(f, "invalid base45 character: U+{:04X}", *ch as u32)
            }
            Self::InvalidLength => f.write_str("invalid base45 length"),
            Self::TripletOutOfRange => {
                f.write_str("base45 triplet decodes to a value greater than 65535")
            }
        }
    }
}

/// Convierte el motivo interno en el error canónico del protocolo.
fn to_gid_error(reason: Base45Error) -> GidError {
    GidError::new(ErrorCode::MalformedMessage, reason.to_string())
}

/// Busca un carácter en la tabla inversa.
fn lookup(byte: u8) -> Result<u8, GidError> {
    match DECODE_TABLE.get(usize::from(byte)) {
        Some(&value) if value != INVALID => Ok(value),
        _ => Err(to_gid_error(Base45Error::InvalidCharacter(byte as char))),
    }
}

/// Codifica bytes a Base45 (RFC 9285 §4).
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let capacity = bytes.len().div_ceil(2).checked_mul(3).unwrap_or(usize::MAX);
    let mut out = String::with_capacity(capacity);

    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        let a = chunk.first().copied().unwrap_or(0);
        let b = chunk.get(1).copied().unwrap_or(0);
        let n = u32::from(a).wrapping_mul(256).wrapping_add(u32::from(b));
        // n = c + d*45 + e*45^2, con c el menos significativo.
        let c = n % 45;
        let d = (n / 45) % 45;
        let e = n / (45 * 45);
        for value in [c, d, e] {
            let index = usize::try_from(value).unwrap_or(0);
            if let Some(&ch) = ALPHABET.get(index) {
                out.push(ch as char);
            }
        }
    }

    // Byte final solitario: 2 caracteres.
    if let Some(&a) = chunks.remainder().first() {
        let n = u32::from(a);
        let c = n % 45;
        let d = n / 45;
        for value in [c, d] {
            let index = usize::try_from(value).unwrap_or(0);
            if let Some(&ch) = ALPHABET.get(index) {
                out.push(ch as char);
            }
        }
    }

    out
}

/// Decodifica Base45 (RFC 9285 §4) con validación estricta (§6).
///
/// # Errores
/// [`ErrorCode::MalformedMessage`] si la longitud es inválida (`% 3 == 1`),
/// hay caracteres fuera del alfabeto, o un trío decodifica a más de 65535.
pub fn decode(input: &str) -> Result<Vec<u8>, GidError> {
    let chars: Vec<u32> = input.chars().map(|c| c as u32).collect();
    let values = decode_values(&chars)?;
    Ok(values)
}

/// Decodifica los valores de carácter ya resueltos.
fn decode_values(chars: &[u32]) -> Result<Vec<u8>, GidError> {
    if chars.len() % 3 == 1 {
        return Err(to_gid_error(Base45Error::InvalidLength));
    }

    let mut out = Vec::new();
    let reserve = chars.len().div_ceil(3).saturating_mul(2).saturating_add(1);
    out.try_reserve(reserve)
        .map_err(|_| to_gid_error(Base45Error::InvalidLength))?;

    let mut index = 0usize;
    while index < chars.len() {
        let remaining = chars.len().saturating_sub(index);
        if remaining >= 3 {
            let c = lookup_u32(chars.get(index).copied())?;
            let d = lookup_u32(chars.get(index.saturating_add(1)).copied())?;
            let e = lookup_u32(chars.get(index.saturating_add(2)).copied())?;
            let n = u32::from(c)
                .checked_add(
                    u32::from(d)
                        .checked_mul(45)
                        .ok_or_else(|| to_gid_error(Base45Error::TripletOutOfRange))?,
                )
                .ok_or_else(|| to_gid_error(Base45Error::TripletOutOfRange))?
                .checked_add(
                    u32::from(e)
                        .checked_mul(45 * 45)
                        .ok_or_else(|| to_gid_error(Base45Error::TripletOutOfRange))?,
                )
                .ok_or_else(|| to_gid_error(Base45Error::TripletOutOfRange))?;
            if n > 65535 {
                return Err(to_gid_error(Base45Error::TripletOutOfRange));
            }
            out.push((n / 256) as u8);
            out.push((n % 256) as u8);
            index = index.saturating_add(3);
        } else {
            // Grupo final de 2 caracteres: 1 byte.
            let c = lookup_u32(chars.get(index).copied())?;
            let d = lookup_u32(chars.get(index.saturating_add(1)).copied())?;
            let n = u32::from(c)
                .checked_add(
                    u32::from(d)
                        .checked_mul(45)
                        .ok_or_else(|| to_gid_error(Base45Error::TripletOutOfRange))?,
                )
                .ok_or_else(|| to_gid_error(Base45Error::TripletOutOfRange))?;
            if n > 255 {
                // Un byte no puede superar 255: codificación inválida.
                return Err(to_gid_error(Base45Error::TripletOutOfRange));
            }
            out.push(n as u8);
            index = index.saturating_add(2);
        }
    }

    Ok(out)
}

/// Resuelve un punto de código a su valor base 45.
fn lookup_u32(code_point: Option<u32>) -> Result<u8, GidError> {
    let byte = u8::try_from(code_point.ok_or_else(|| to_gid_error(Base45Error::InvalidLength))?)
        .map_err(|_| to_gid_error(Base45Error::InvalidCharacter(' ')))?;
    lookup(byte)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).
mod tests {
    use super::*;
    use alloc::format;

    // ---------- Vectores de RFC 9285 §4.3 / §4.4 ----------

    // // Verifies: REQ-STAT-003
    #[test]
    fn encodes_rfc9285_examples() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"AB"), "BB8");
        assert_eq!(encode(b"Hello!!"), "%69 VD92EX0");
        assert_eq!(encode(b"base-45"), "UJCLQE7W581");
        assert_eq!(encode(b"ietf!"), "QED8WEX0");
    }

    // // Verifies: REQ-STAT-003
    #[test]
    fn decodes_rfc9285_examples() {
        assert_eq!(decode("").expect("empty is valid"), Vec::<u8>::new());
        assert_eq!(decode("BB8").expect("valid"), b"AB");
        assert_eq!(decode("%69 VD92EX0").expect("valid"), b"Hello!!");
        assert_eq!(decode("UJCLQE7W581").expect("valid"), b"base-45");
        assert_eq!(decode("QED8WEX0").expect("valid"), b"ietf!");
    }

    // ---------- Validación estricta (RFC 9285 §6) ----------

    // // Verifies: REQ-STAT-003 (caso negativo: carácter fuera del alfabeto)
    #[test]
    fn rejects_non_alphabet_characters() {
        for bad in ["BB8=", "BB€8", "BBé8", "bb8", "BB_", "BB#"] {
            assert!(decode(bad).is_err(), "expected rejection for {bad:?}");
        }
    }

    // // Verifies: REQ-STAT-003 (caso negativo: longitud % 3 == 1)
    #[test]
    fn rejects_invalid_lengths() {
        for bad in ["B", "BB", "BBBB", "BBBBBBBBBB"] {
            assert!(decode(bad).is_err(), "expected rejection for {bad:?}");
        }
    }

    // // Verifies: REQ-STAT-003 (caso negativo: trío > 65535, §6)
    #[test]
    fn rejects_triplets_above_65535() {
        // "GGW" representa 65536 (10000 en base 16): más de 16 bits.
        assert!(decode("GGW").is_err());
        // "FGW" representa 65535: válido.
        assert!(decode("FGW").is_ok());
    }

    // // Verifies: REQ-STAT-003 (caso negativo: grupo final > 255)
    #[test]
    fn rejects_final_pair_above_255() {
        // El último grupo de 2 caracteres solo puede codificar 1 byte (0-255).
        // "::" = 44 + 44*45 = 2024 > 255.
        assert!(decode("::").is_err());
    }

    // ---------- Round-trip y mensajes ----------

    // // Verifies: REQ-STAT-003
    #[test]
    fn round_trips_arbitrary_bytes() {
        let cases: [&[u8]; 5] = [
            &[0x00],
            &[0xFF],
            &[0x00, 0x00],
            &[0xDE, 0xAD, 0xBE, 0xEF],
            &[0x01, 0x02, 0x03],
        ];
        for bytes in cases {
            let encoded = encode(bytes);
            assert_eq!(decode(&encoded).expect("round-trip"), bytes);
        }
    }

    // // Verifies: REQ-STAT-003 (mensajes estables)
    #[test]
    fn error_messages_are_stable() {
        assert_eq!(
            format!("{}", decode("GGW").expect_err("out of range")),
            "[GID-E1001] base45 triplet decodes to a value greater than 65535"
        );
        assert_eq!(
            format!("{}", decode("BBBB").expect_err("bad length")),
            "[GID-E1001] invalid base45 length"
        );
    }

    // // Verifies: REQ-STAT-003 (los 45 caracteres del alfabeto son válidos)
    #[test]
    fn every_alphabet_character_is_accepted() {
        for &ch in ALPHABET.iter() {
            let ch_array = [ch];
            let s = core::str::from_utf8(&ch_array).expect("ascii alphabet");
            // Trío con el carácter en posición menos significativa: si el
            // carácter no estuviera en el alfabeto, el error sería
            // InvalidCharacter.
            let group = format!("00{s}");
            let result = decode(&group);
            if let Err(error) = result {
                assert_ne!(
                    error.to_string(),
                    format!("[GID-E1001] invalid base45 character: U+{:04X}", ch as u32),
                    "el carácter {s} del alfabeto fue rechazado"
                );
            }
        }
    }
}
