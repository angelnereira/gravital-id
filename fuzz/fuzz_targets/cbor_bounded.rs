#![no_main]
//! Objetivo de fuzzing del lector CBOR acotado (F2.T04/F2.T11).
//!
//! Propiedades invariantadas:
//! 1. `parse` nunca entra en pánico para ninguna entrada (INV-10).
//! 2. Determinismo (REQ-VER-009).
//! 3. En modo determinista, la recodificación canónica de lo aceptado vuelve a
//!    parsear al mismo valor: el lector impone la forma canónica de RFC 8949
//!    §4.2 (enteros más cortos, sin longitudes indefinidas, claves ordenadas y
//!    únicas, flotantes en su anchura mínima).

use gravital_id_codec::cbor::{self, Limits as CborLimits, Strictness, Value as CborValue};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = CborLimits::profile_default();

    // 1 y 2: nunca pánico, determinista, en ambos modos.
    let deterministic = Strictness::deterministic();
    let permissive = Strictness::permissive();

    let strict_first = cbor::parse_with_options(data, &limits, &deterministic);
    let strict_second = cbor::parse_with_options(data, &limits, &deterministic);
    debug_assert_eq!(format!("{strict_first:?}"), format!("{strict_second:?}"));

    let _ = cbor::parse_with_options(data, &limits, &permissive);

    // 3: lo aceptado en modo determinista es canónico.
    if let Ok(value) = strict_first {
        let encoded = canonical_encode(&value);
        let reparsed = cbor::parse(&encoded)
            .expect("canonical re-encoding of accepted input must parse");
        assert_eq!(reparsed, value, "canonical round-trip must preserve value");
    }
});

/// Recodificación canónica mínima (RFC 8949 §4.2) usada por la propiedad 3.
///
/// Cubre los tipos que el protocolo transporta; es deliberadamente conservadora.
fn canonical_encode(value: &CborValue) -> Vec<u8> {
    let mut out = Vec::new();
    encode_value(value, &mut out);
    out
}

fn encode_value(value: &CborValue, out: &mut Vec<u8>) {
    match value {
        CborValue::Null => out.push(0xf6),
        CborValue::Undefined => out.push(0xf7),
        CborValue::Bool(false) => out.push(0xf4),
        CborValue::Bool(true) => out.push(0xf5),
        CborValue::Simple(v) => {
            if *v < 24 {
                out.push(0xe0 | v);
            } else {
                out.push(0xf8);
                out.push(*v);
            }
        }
        CborValue::UInt(n) => encode_head(0, *n, out),
        // -(1 + n) → major 1 con argumento n.
        CborValue::NInt(n) => encode_head(1, *n, out),
        CborValue::Float(f) => {
            // Anchura mínima que preserva el valor (RFC 8949 §4.2.2). El cast a
            // f32 puede subdesbordar a cero: solo se acepta si preserva valor.
            let bits64 = f.to_bits();
            let value32 = *f as f32;
            let bits32 = value32.to_bits();
            let fits16 = value32 as f64 == *f && f32_bits_fit_f16(bits32);
            let fits32 = value32 as f64 == *f && f64_bits_fit_f32(bits64);
            if fits16 {
                out.push(0xf9);
                out.extend_from_slice(&f32_bits_to_f16(bits32).to_be_bytes());
            } else if fits32 {
                out.push(0xfa);
                out.extend_from_slice(&bits32.to_be_bytes());
            } else {
                out.push(0xfb);
                out.extend_from_slice(&bits64.to_be_bytes());
            }
        }
        CborValue::Bytes(bytes) => {
            encode_head(2, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        CborValue::Text(text) => {
            encode_head(3, text.len() as u64, out);
            out.extend_from_slice(text.as_bytes());
        }
        CborValue::Array(items) => {
            encode_head(4, items.len() as u64, out);
            for item in items {
                encode_value(item, out);
            }
        }
        CborValue::Map(entries) => {
            encode_head(5, entries.len() as u64, out);
            for (key, value) in entries {
                encode_value(key, out);
                encode_value(value, out);
            }
        }
        CborValue::Tag(tag, item) => {
            encode_head(6, *tag, out);
            encode_value(item, out);
        }
    }
}

/// Escribe la cabecera CBOR con el argumento en su forma más corta.
fn encode_head(major: u8, argument: u64, out: &mut Vec<u8>) {
    let initial = major << 5;
    match argument {
        0..=23 => out.push(initial | argument as u8),
        24..=0xFF => {
            out.push(initial | 24);
            out.push(argument as u8);
        }
        0x100..=0xFFFF => {
            out.push(initial | 25);
            out.extend_from_slice(&(argument as u16).to_be_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(initial | 26);
            out.extend_from_slice(&(argument as u32).to_be_bytes());
        }
        _ => {
            out.push(initial | 27);
            out.extend_from_slice(&argument.to_be_bytes());
        }
    }
}

/// `true` si el valor `f32` dado por sus bits es representable exactamente en
/// binary16 (espejo de la verificación del lector).
fn f32_bits_fit_f16(bits: u32) -> bool {
    let exponent = (bits >> 23) & 0xFF;
    let mantissa = bits & 0x7F_FF_FF;
    if exponent == 0 {
        return mantissa == 0;
    }
    let unbalanced = i64::from(exponent) - 127;
    if !(-24..=15).contains(&unbalanced) {
        return false;
    }
    if unbalanced >= -14 {
        mantissa % (1u32 << 13) == 0
    } else {
        let modulus_shift = u32::try_from(-unbalanced - 1).unwrap_or(23);
        mantissa.checked_rem(1u32 << modulus_shift) == Some(0)
    }
}

/// `true` si el valor `f64` dado por sus bits es representable exactamente en
/// `f32` (espejo de la verificación del lector).
fn f64_bits_fit_f32(bits: u64) -> bool {
    let exponent = (bits >> 52) & 0x7FF;
    let mantissa = bits & 0xF_FFFF_FFFF_FFFF;
    if exponent == 0 {
        return mantissa == 0;
    }
    let unbalanced = i64::from(exponent as u32) - 1023;
    if !(-149..=127).contains(&unbalanced) {
        return false;
    }
    if unbalanced >= -126 {
        mantissa % (1u64 << 29) == 0
    } else {
        let modulus_shift = u32::try_from(-unbalanced - 97).unwrap_or(52);
        mantissa.checked_rem(1u64 << modulus_shift) == Some(0)
    }
}

/// Convierte unos bits `f32` (que caben en binary16) a su codificación f16.
fn f32_bits_to_f16(bits: u32) -> u16 {
    let sign = ((bits & 0x8000_0000) >> 16) as u16;
    let exponent = (bits >> 23) & 0xFF;
    let mantissa = bits & 0x7F_FF_FF;
    if exponent == 0 {
        return sign; // ±0
    }
    let unbalanced = i64::from(exponent) - 127;
    if unbalanced >= -14 {
        let biased = u16::try_from(unbalanced + 15).unwrap_or(0);
        sign | (biased << 10) | ((mantissa >> 13) as u16)
    } else {
        // Subnormal: valor = k × 2^-24 con k = (2^23 + m) >> (23 - d).
        let d = u32::try_from(unbalanced + 24).unwrap_or(0);
        let k = ((1u64 << 23) | u64::from(mantissa)) >> (23u32.saturating_sub(d));
        sign | (k as u16)
    }
}
