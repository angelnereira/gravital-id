//! # `gravital-id-proximity`
//!
//! Núcleo de proximidad: máquinas de estado sans-I/O, cifrado de sesión HPKE y
//! vinculación al transcrito, reutilizable sobre NFC y BLE (F20, `ROADMAP.md §27`).
//!
//! - **Capa arquitectónica:** L4 (sans-I/O; sin I/O de red ni de disco).
//! - **Garantía no_std:** No (usa `alloc`); compatible con WASM.
//!
//! ## Estado
//!
//! F20.T01: andamiaje del crate. F20.T02: mensajes CBOR con ida y vuelta.

#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use gravital_id_codec::cbor::{self, Value as CborValue};
use gravital_id_types::GidError;

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Tipo de error canónico del subsistema de proximidad.
pub type ProximityError = GidError;

// ---------------------------------------------------------------------------
// Mensajes CBOR (F20.T02)
// ---------------------------------------------------------------------------

/// Solicitud de proximidad emitida por el verificador.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProximityRequest {
    /// Versión del protocolo de proximidad.
    pub version: u8,
    /// Identificador de audiencia del verificador.
    pub verifier_id: String,
    /// Desafío fresco (>= 128 bits) contra replay.
    pub nonce: Vec<u8>,
    /// Instante de expiración (Unix, segundos).
    pub expires_at: u64,
}

impl ProximityRequest {
    /// Codifica la solicitud a CBOR determinista (RFC 8949 §4.2).
    /// Codifica el mensaje a CBOR determinista.
    #[must_use]
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // array de 4 elementos
        encode_array_header(4, &mut out);
        encode_uint(self.version as u64, &mut out);
        encode_text(&self.verifier_id, &mut out);
        encode_bstr(&self.nonce, &mut out);
        encode_uint(self.expires_at, &mut out);
        out
    }

    /// Decodifica una solicitud desde CBOR.
    /// Decodifica el mensaje desde CBOR.
    pub fn from_cbor(input: &[u8]) -> Result<Self, ProximityError> {
        let value = cbor::parse(input)?;
        let arr = match value {
            CborValue::Array(a) => a,
            _ => {
                return Err(GidError::new(
                    gravital_id_types::ErrorCode::MalformedMessage,
                    "ProximityRequest must be a CBOR array",
                ))
            }
        };
        if arr.len() != 4 {
            return Err(GidError::new(
                gravital_id_types::ErrorCode::MalformedMessage,
                "ProximityRequest must have 4 items",
            ));
        }
        let version = match arr.first() {
            Some(CborValue::UInt(n)) => *n as u8,
            _ => {
                return Err(GidError::new(
                    gravital_id_types::ErrorCode::MalformedMessage,
                    "invalid version",
                ))
            }
        };
        let verifier_id = match arr.get(1) {
            Some(CborValue::Text(t)) => t.clone(),
            _ => {
                return Err(GidError::new(
                    gravital_id_types::ErrorCode::MalformedMessage,
                    "invalid verifier_id",
                ))
            }
        };
        let nonce = match arr.get(2) {
            Some(CborValue::Bytes(b)) => b.clone(),
            _ => {
                return Err(GidError::new(
                    gravital_id_types::ErrorCode::MalformedMessage,
                    "invalid nonce",
                ))
            }
        };
        let expires_at = match arr.get(3) {
            Some(CborValue::UInt(n)) => *n,
            _ => {
                return Err(GidError::new(
                    gravital_id_types::ErrorCode::MalformedMessage,
                    "invalid expires_at",
                ))
            }
        };
        Ok(Self {
            version,
            verifier_id,
            nonce,
            expires_at,
        })
    }
}

/// Mensaje inicial del titular en la sesión de proximidad.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HolderHello {
    /// Versión del protocolo de proximidad.
    pub version: u8,
    /// Clave pública efímera del titular (P-256, formato no comprimido).
    pub holder_ephemeral_key: Vec<u8>,
}

impl HolderHello {
    /// Codifica el mensaje a CBOR determinista.
    #[must_use]
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_array_header(2, &mut out);
        encode_uint(self.version as u64, &mut out);
        encode_bstr(&self.holder_ephemeral_key, &mut out);
        out
    }

    /// Decodifica el mensaje desde CBOR.
    pub fn from_cbor(input: &[u8]) -> Result<Self, ProximityError> {
        let value = cbor::parse(input)?;
        let arr = match value {
            CborValue::Array(a) => a,
            _ => {
                return Err(GidError::new(
                    gravital_id_types::ErrorCode::MalformedMessage,
                    "HolderHello must be a CBOR array",
                ))
            }
        };
        if arr.len() != 2 {
            return Err(GidError::new(
                gravital_id_types::ErrorCode::MalformedMessage,
                "HolderHello must have 2 items",
            ));
        }
        let version = match arr.first() {
            Some(CborValue::UInt(n)) => *n as u8,
            _ => {
                return Err(GidError::new(
                    gravital_id_types::ErrorCode::MalformedMessage,
                    "invalid version",
                ))
            }
        };
        let holder_ephemeral_key = match arr.get(1) {
            Some(CborValue::Bytes(b)) => b.clone(),
            _ => {
                return Err(GidError::new(
                    gravital_id_types::ErrorCode::MalformedMessage,
                    "invalid holder_ephemeral_key",
                ))
            }
        };
        Ok(Self {
            version,
            holder_ephemeral_key,
        })
    }
}

/// Respuesta cifrada del titular con la presentación reconstruida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProximityResponse {
    /// Versión del protocolo de proximidad.
    pub version: u8,
    /// Carga cifrada (HPKE) con el transcrito como AAD.
    pub ciphertext: Vec<u8>,
}

impl ProximityResponse {
    /// Codifica el mensaje a CBOR determinista.
    #[must_use]
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_array_header(2, &mut out);
        encode_uint(self.version as u64, &mut out);
        encode_bstr(&self.ciphertext, &mut out);
        out
    }

    /// Decodifica el mensaje desde CBOR.
    pub fn from_cbor(input: &[u8]) -> Result<Self, ProximityError> {
        let value = cbor::parse(input)?;
        let arr = match value {
            CborValue::Array(a) => a,
            _ => {
                return Err(GidError::new(
                    gravital_id_types::ErrorCode::MalformedMessage,
                    "ProximityResponse must be a CBOR array",
                ))
            }
        };
        if arr.len() != 2 {
            return Err(GidError::new(
                gravital_id_types::ErrorCode::MalformedMessage,
                "ProximityResponse must have 2 items",
            ));
        }
        let version = match arr.first() {
            Some(CborValue::UInt(n)) => *n as u8,
            _ => {
                return Err(GidError::new(
                    gravital_id_types::ErrorCode::MalformedMessage,
                    "invalid version",
                ))
            }
        };
        let ciphertext = match arr.get(1) {
            Some(CborValue::Bytes(b)) => b.clone(),
            _ => {
                return Err(GidError::new(
                    gravital_id_types::ErrorCode::MalformedMessage,
                    "invalid ciphertext",
                ))
            }
        };
        Ok(Self {
            version,
            ciphertext,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers CBOR de codificación (determinista, RFC 8949 §4.2)
// ---------------------------------------------------------------------------

fn encode_uint(val: u64, out: &mut Vec<u8>) {
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

fn encode_bstr(bytes: &[u8], out: &mut Vec<u8>) {
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

fn encode_text(s: &str, out: &mut Vec<u8>) {
    let bytes = s.as_bytes();
    let len = bytes.len() as u64;
    if len < 24 {
        out.push(0x60 | (len as u8));
    } else if len <= 0xFF {
        out.push(0x78);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x79);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else if len <= 0xFFFF_FFFF {
        out.push(0x7A);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    } else {
        out.push(0x7B);
        out.extend_from_slice(&len.to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

fn encode_array_header(len: usize, out: &mut Vec<u8>) {
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    // Verifies: REQ-PROX-003 (mensajes CBOR con ida y vuelta)
    #[test]
    fn proximity_request_roundtrip() {
        let req = ProximityRequest {
            version: 1,
            verifier_id: "https://verifier.example".into(),
            nonce: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            expires_at: 1_700_000_000,
        };
        let bytes = req.to_cbor();
        let decoded = ProximityRequest::from_cbor(&bytes).expect("decode");
        assert_eq!(req, decoded);
    }

    #[test]
    fn holder_hello_roundtrip() {
        let h = HolderHello {
            version: 1,
            holder_ephemeral_key: vec![0u8; 65],
        };
        let bytes = h.to_cbor();
        let decoded = HolderHello::from_cbor(&bytes).expect("decode");
        assert_eq!(h, decoded);
    }

    #[test]
    fn proximity_response_roundtrip() {
        let r = ProximityResponse {
            version: 1,
            ciphertext: vec![9, 8, 7, 6],
        };
        let bytes = r.to_cbor();
        let decoded = ProximityResponse::from_cbor(&bytes).expect("decode");
        assert_eq!(r, decoded);
    }

    #[test]
    fn malformed_request_rejected() {
        assert!(ProximityRequest::from_cbor(&[0xFF]).is_err());
    }
}
