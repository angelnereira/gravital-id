//! Transcodificación binaria biyectiva sin pérdida para presentaciones offline (REQ-PRES-005, PROTOCOL.md §3.2).
//!
//! Trazabilidad:
//! - `REQ-PRES-005`: Transporte offline por QR de dos pasos con compresión DEFLATE y Base45.
//! - `PROTOCOL.md §3.2`: Algoritmo de transcodificación binaria biyectiva sin pérdida entre SD-JWT y CBOR.
//! - `ADR-0011`: Formato Base45 con prefijo canónico `GID1:` (aceptando `PIP1:` como alias de compatibilidad).
//! - `INV-01`: Cero dependencias de red en la codificación o decodificación.
//! - `INV-05`: Rechazo fail-closed ante flujos truncados, ratios anómalos o firmas corruptas.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use gravital_id_codec::base45;
use gravital_id_codec::base64url;
use gravital_id_codec::cbor::{self, Value as CborValue};
use gravital_id_codec::deflate;
use gravital_id_types::{ErrorCode, GidError};

/// Prefijo canónico normativo para presentaciones offline en Base45 (`PROTOCOL.md §3.2`, `ADR-0011`).
pub const BASE45_CANONICAL_PREFIX: &str = "GID1:";

/// Prefijo legado de compatibilidad aceptado en decodificación (`ADR-0001`).
pub const BASE45_LEGACY_PREFIX: &str = "PIP1:";

/// Versión normativa de la tupla CBOR de presentación transcodificada (`PROTOCOL.md §3.2`).
pub const TRANSCODED_PRESENTATION_VERSION: u64 = 1;

/// Límite máximo de salida descomprimida para presentaciones QR (64 KiB).
pub const MAX_PRESENTATION_DECOMPRESSED_BYTES: usize = 64 * 1024;

/// Ratio máximo de expansión de compresión DEFLATE (10:1 según `CRYPTO_PROFILES.md §5.1`).
pub const MAX_PRESENTATION_EXPANSION_RATIO: usize = 10;

/// Longitud fija de la firma ES256 en formato binario P1363 (32 bytes `r` + 32 bytes `s`).
pub const ES256_P1363_SIGNATURE_LEN: usize = 64;

/// Codifica un entero sin signo a CBOR determinista según RFC 8949 §4.2.1.
fn cbor_encode_uint(val: u64, out: &mut Vec<u8>) {
    if val < 24 {
        out.push(val as u8);
    } else if val <= 0xFF {
        out.push(0x18);
        out.push(val as u8);
    } else if val <= 0xFFFF {
        out.push(0x19);
        out.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val <= 0xFFFF_FFFF {
        out.push(0x1A);
        out.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        out.push(0x1B);
        out.extend_from_slice(&val.to_be_bytes());
    }
}

/// Codifica una cadena de bytes a CBOR determinista (major type 2).
fn cbor_encode_bstr(bytes: &[u8], out: &mut Vec<u8>) {
    let len = bytes.len() as u64;
    if len < 24 {
        out.push(0x40 | (len as u8));
    } else if len <= 0xFF {
        out.push(0x58);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x59);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else if len <= 0xFFFF_FFFF {
        out.push(0x5A);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    } else {
        out.push(0x5B);
        out.extend_from_slice(&len.to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

/// Codifica la cabecera de un array a CBOR determinista (major type 4).
fn cbor_encode_array_header(len: usize, out: &mut Vec<u8>) {
    let count = len as u64;
    if count < 24 {
        out.push(0x80 | (count as u8));
    } else if count <= 0xFF {
        out.push(0x98);
        out.push(count as u8);
    } else if count <= 0xFFFF {
        out.push(0x99);
        out.extend_from_slice(&(count as u16).to_be_bytes());
    } else {
        out.push(0x9A);
        out.extend_from_slice(&(count as u32).to_be_bytes());
    }
}

/// Transcodifica una presentación SD-JWT compacta a CBOR determinista sin pérdida (`PROTOCOL.md §3.2`).
///
/// Divide el SD-JWT en sus componentes, decodifica los segmentos Base64URL a bytes binarios crudos
/// y los empaqueta en la estructura CBOR `TranscodedPresentation`.
///
/// # Errores
/// [`ErrorCode::MalformedSdJwt`] si la estructura o codificación de la presentación es inválida.
pub fn transcode_sd_jwt_to_cbor(raw_sd_jwt: &str) -> Result<Vec<u8>, GidError> {
    let mut seg_iter = raw_sd_jwt.split('~');
    let issuer_jwt_str = seg_iter.next().ok_or_else(|| {
        GidError::new(
            ErrorCode::MalformedSdJwt,
            "SD-JWT presentation cannot be empty",
        )
    })?;

    // El primer segmento es siempre el Issuer-Signed JWT
    let mut issuer_parts = issuer_jwt_str.split('.');
    let issuer_header_b64 = issuer_parts.next().ok_or_else(|| {
        GidError::new(ErrorCode::MalformedSdJwt, "missing issuer JWT header part")
    })?;
    let issuer_payload_b64 = issuer_parts.next().ok_or_else(|| {
        GidError::new(ErrorCode::MalformedSdJwt, "missing issuer JWT payload part")
    })?;
    let issuer_sig_b64 = issuer_parts.next().ok_or_else(|| {
        GidError::new(
            ErrorCode::MalformedSdJwt,
            "missing issuer JWT signature part",
        )
    })?;
    if issuer_parts.next().is_some() {
        return Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            "issuer JWT must have exactly 3 parts",
        ));
    }

    let issuer_header = base64url::decode(issuer_header_b64)?;
    let issuer_payload = base64url::decode(issuer_payload_b64)?;
    let issuer_sig = base64url::decode(issuer_sig_b64)?;
    if issuer_sig.len() != ES256_P1363_SIGNATURE_LEN {
        return Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            format!(
                "issuer signature must be exactly 64 bytes (got {})",
                issuer_sig.len()
            ),
        ));
    }

    // Segmentos intermedios y final:
    // En SD-JWT (RFC 9901):
    // <issuer_jwt>~<disc_1>~...~<disc_k>~<kb_jwt>  (si hay KB-JWT)
    // <issuer_jwt>~<disc_1>~...~<disc_k>~          (si no hay KB-JWT, termina en tilde)
    let remainder: Vec<&str> = seg_iter.collect();
    let mut disclosures = Vec::new();
    let mut kb_header = Vec::new();
    let mut kb_payload = Vec::new();
    let mut kb_sig = Vec::new();

    if let Some((&last_seg, disc_segs)) = remainder.split_last() {
        if last_seg.contains('.') {
            // El último segmento tiene puntos: es el KB-JWT
            let mut kb_parts = last_seg.split('.');
            let kbh_b64 = kb_parts.next().ok_or_else(|| {
                GidError::new(ErrorCode::KeyBindingFailed, "missing KB-JWT header")
            })?;
            let kbp_b64 = kb_parts.next().ok_or_else(|| {
                GidError::new(ErrorCode::KeyBindingFailed, "missing KB-JWT payload")
            })?;
            let kbs_b64 = kb_parts.next().ok_or_else(|| {
                GidError::new(ErrorCode::KeyBindingFailed, "missing KB-JWT signature")
            })?;
            if kb_parts.next().is_some() {
                return Err(GidError::new(
                    ErrorCode::KeyBindingFailed,
                    "KB-JWT must have exactly 3 parts",
                ));
            }
            kb_header = base64url::decode(kbh_b64)?;
            kb_payload = base64url::decode(kbp_b64)?;
            kb_sig = base64url::decode(kbs_b64)?;
            if kb_sig.len() != ES256_P1363_SIGNATURE_LEN {
                return Err(GidError::new(
                    ErrorCode::KeyBindingFailed,
                    format!(
                        "KB-JWT signature must be exactly 64 bytes (got {})",
                        kb_sig.len()
                    ),
                ));
            }

            for &d in disc_segs {
                if !d.is_empty() {
                    let d_bytes = base64url::decode(d)?;
                    disclosures.push(d_bytes);
                }
            }
        } else {
            // No hay KB-JWT; todos los segmentos no vacíos son divulgaciones
            for &d in &remainder {
                if !d.is_empty() {
                    let d_bytes = base64url::decode(d)?;
                    disclosures.push(d_bytes);
                }
            }
        }
    }

    // Construcción de la tupla CBOR determinista de 8 elementos
    // TranscodedPresentation = [ version, issuer_header, issuer_payload, issuer_sig, disclosures, kb_header, kb_payload, kb_sig ]
    let mut out = Vec::new();
    cbor_encode_array_header(8, &mut out);
    cbor_encode_uint(TRANSCODED_PRESENTATION_VERSION, &mut out);
    cbor_encode_bstr(&issuer_header, &mut out);
    cbor_encode_bstr(&issuer_payload, &mut out);
    cbor_encode_bstr(&issuer_sig, &mut out);

    cbor_encode_array_header(disclosures.len(), &mut out);
    for d in &disclosures {
        cbor_encode_bstr(d, &mut out);
    }

    cbor_encode_bstr(&kb_header, &mut out);
    cbor_encode_bstr(&kb_payload, &mut out);
    cbor_encode_bstr(&kb_sig, &mut out);

    Ok(out)
}

/// Reconstruye exactamente la cadena compacta SD-JWT a partir de la tupla CBOR transcodificada.
///
/// Garantía biyectiva: la cadena resultante es **idéntica byte a byte** a la emitida originalmente,
/// permitiendo la verificación criptográfica sin alteración de firmas (INV-01, REQ-PRES-005).
///
/// # Errores
/// [`ErrorCode::MalformedMessage`] si la estructura CBOR no coincide con la tupla esperada.
pub fn reconstruct_sd_jwt_from_cbor(cbor_bytes: &[u8]) -> Result<String, GidError> {
    let val = cbor::parse(cbor_bytes)?;

    let items = match val {
        CborValue::Array(arr) => arr,
        _ => {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "transcoded CBOR presentation root must be an array",
            ))
        }
    };

    if items.len() != 8 {
        return Err(GidError::new(
            ErrorCode::MalformedMessage,
            format!(
                "transcoded CBOR presentation array must contain 8 items (got {})",
                items.len()
            ),
        ));
    }

    let mut iter = items.into_iter();
    let item_version = iter
        .next()
        .ok_or_else(|| GidError::new(ErrorCode::MalformedMessage, "missing version"))?;
    let item_issuer_header = iter
        .next()
        .ok_or_else(|| GidError::new(ErrorCode::MalformedMessage, "missing issuer_header"))?;
    let item_issuer_payload = iter
        .next()
        .ok_or_else(|| GidError::new(ErrorCode::MalformedMessage, "missing issuer_payload"))?;
    let item_issuer_sig = iter
        .next()
        .ok_or_else(|| GidError::new(ErrorCode::MalformedMessage, "missing issuer_sig"))?;
    let item_disclosures = iter
        .next()
        .ok_or_else(|| GidError::new(ErrorCode::MalformedMessage, "missing disclosures"))?;
    let item_kb_header = iter
        .next()
        .ok_or_else(|| GidError::new(ErrorCode::MalformedMessage, "missing kb_header"))?;
    let item_kb_payload = iter
        .next()
        .ok_or_else(|| GidError::new(ErrorCode::MalformedMessage, "missing kb_payload"))?;
    let item_kb_sig = iter
        .next()
        .ok_or_else(|| GidError::new(ErrorCode::MalformedMessage, "missing kb_sig"))?;

    // 0: version
    match item_version {
        CborValue::UInt(v) if v == TRANSCODED_PRESENTATION_VERSION => {}
        _ => {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "unsupported transcoded presentation version",
            ))
        }
    }

    // 1: issuer_header
    let issuer_header = match item_issuer_header {
        CborValue::Bytes(b) => b,
        _ => {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "expected bytes for issuer_header",
            ))
        }
    };

    // 2: issuer_payload
    let issuer_payload = match item_issuer_payload {
        CborValue::Bytes(b) => b,
        _ => {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "expected bytes for issuer_payload",
            ))
        }
    };

    // 3: issuer_sig
    let issuer_sig = match item_issuer_sig {
        CborValue::Bytes(b) => b,
        _ => {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "expected bytes for issuer_sig",
            ))
        }
    };

    // 4: disclosures
    let disclosures_arr = match item_disclosures {
        CborValue::Array(arr) => arr,
        _ => {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "expected array for disclosures",
            ))
        }
    };

    // 5: kb_header
    let kb_header = match item_kb_header {
        CborValue::Bytes(b) => b,
        _ => {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "expected bytes for kb_header",
            ))
        }
    };

    // 6: kb_payload
    let kb_payload = match item_kb_payload {
        CborValue::Bytes(b) => b,
        _ => {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "expected bytes for kb_payload",
            ))
        }
    };

    // 7: kb_sig
    let kb_sig = match item_kb_sig {
        CborValue::Bytes(b) => b,
        _ => {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "expected bytes for kb_sig",
            ))
        }
    };

    // Ensamblar Issuer JWT
    let h_b64 = base64url::encode(&issuer_header);
    let p_b64 = base64url::encode(&issuer_payload);
    let s_b64 = base64url::encode(&issuer_sig);

    let mut out = format!("{h_b64}.{p_b64}.{s_b64}");

    // Ensamblar Disclosures
    for d_val in disclosures_arr {
        match d_val {
            CborValue::Bytes(d_bytes) => {
                let d_b64 = base64url::encode(&d_bytes);
                out.push('~');
                out.push_str(&d_b64);
            }
            _ => {
                return Err(GidError::new(
                    ErrorCode::MalformedMessage,
                    "expected bytes for disclosure item",
                ))
            }
        }
    }

    out.push('~');

    // Ensamblar KB-JWT si está presente
    if !kb_header.is_empty() || !kb_payload.is_empty() || !kb_sig.is_empty() {
        let kbh_b64 = base64url::encode(&kb_header);
        let kbp_b64 = base64url::encode(&kb_payload);
        let kbs_b64 = base64url::encode(&kb_sig);
        out.push_str(&format!("{kbh_b64}.{kbp_b64}.{kbs_b64}"));
    }

    Ok(out)
}

/// Codifica una presentación SD-JWT compacta en formato Base45 comprimido para transporte QR (`PROTOCOL.md §3.2`).
///
/// Proceso:
/// 1. Transcodificación biyectiva a CBOR determinista.
/// 2. Compresión zlib/DEFLATE (nivel 9).
/// 3. Codificación Base45 con prefijo canónico `GID1:`.
///
/// # Errores
/// [`ErrorCode::MalformedSdJwt`] si la presentación es inválida.
pub fn encode_presentation_to_base45(raw_sd_jwt: &str) -> Result<String, GidError> {
    let cbor_bytes = transcode_sd_jwt_to_cbor(raw_sd_jwt)?;
    let compressed = deflate::deflate(&cbor_bytes);
    let b45 = base45::encode(&compressed);
    Ok(format!("{BASE45_CANONICAL_PREFIX}{b45}"))
}

/// Decodifica una presentación en Base45 comprimido recuperando la cadena compacta SD-JWT original.
///
/// Admite tanto el prefijo canónico `GID1:` como el prefijo legado `PIP1:` (`ADR-0001`).
///
/// # Errores
/// [`ErrorCode::MalformedMessage`] si el prefijo falta, la descompresión excede cotas o el CBOR es inválido.
pub fn decode_presentation_from_base45(base45_input: &str) -> Result<String, GidError> {
    let payload = if let Some(stripped) = base45_input.strip_prefix(BASE45_CANONICAL_PREFIX) {
        stripped
    } else if let Some(stripped) = base45_input.strip_prefix(BASE45_LEGACY_PREFIX) {
        stripped
    } else {
        return Err(GidError::new(
            ErrorCode::MalformedMessage,
            "offline presentation missing required 'GID1:' prefix",
        ));
    };

    let compressed = base45::decode(payload)?;
    let cbor_bytes = deflate::inflate_bounded(
        &compressed,
        MAX_PRESENTATION_DECOMPRESSED_BYTES,
        MAX_PRESENTATION_EXPANSION_RATIO,
    )?;

    reconstruct_sd_jwt_from_cbor(&cbor_bytes)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    #[test]
    fn cbor_uint_encoding_all_ranges() {
        let cases = [
            10u64,
            23,
            24,
            255,
            256,
            65535,
            65536,
            0xFFFF_FFFF,
            0x1_0000_0000,
        ];
        for &val in &cases {
            let mut out = Vec::new();
            cbor_encode_uint(val, &mut out);
            let parsed = cbor::parse(&out).expect("parse uint");
            assert_eq!(parsed, CborValue::UInt(val));
        }
    }

    #[test]
    fn cbor_bstr_encoding_all_ranges() {
        let cases = [5, 23, 24, 255, 256, 1000];
        for &len in &cases {
            let data = alloc::vec![0x42; len];
            let mut out = Vec::new();
            cbor_encode_bstr(&data, &mut out);
            let parsed = cbor::parse(&out).expect("parse bstr");
            assert_eq!(parsed, CborValue::Bytes(data));
        }

        // Caso len > 0xFFFF
        let mut out_large = Vec::new();
        cbor_encode_bstr(&alloc::vec![0x42; 70_000], &mut out_large);
        assert_eq!(out_large.first().copied(), Some(0x5A));
    }

    #[test]
    fn cbor_array_header_encoding_all_ranges() {
        let cases = [0, 5, 23, 24, 255, 256, 1000];
        for &len in &cases {
            let mut out = Vec::new();
            cbor_encode_array_header(len, &mut out);
            out.resize(out.len().saturating_add(len), 0x00);
            let parsed = cbor::parse(&out).expect("parse array");
            if let CborValue::Array(items) = parsed {
                assert_eq!(items.len(), len);
            } else {
                panic!("expected array");
            }
        }

        // Caso len > 0xFFFF
        let mut out_large = Vec::new();
        cbor_encode_array_header(70_000, &mut out_large);
        assert_eq!(out_large.first().copied(), Some(0x9A));
    }
}
