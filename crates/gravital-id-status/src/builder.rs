//! Constructor de Token Status Lists en formato JWT (F7.T05, REQ-ISS-003, REQ-STAT-001, REQ-STAT-002, REQ-STAT-005, REQ-STAT-007).
//!
//! Trazabilidad:
//! - **REQ-STAT-001:** Token Status List en formato JWT (`typ: statuslist+jwt`, `alg: ES256`).
//! - **REQ-STAT-002:** Tamaño mínimo normativo por perfil (>= 131.072 bits / entradas) para k-anonimidad.
//! - **REQ-STAT-005:** Publicación direccionada por contenido (URI con digest SHA-256).
//! - **REQ-STAT-007:** Estados soportados: válido, revocado y suspendido.
//! - **INV-01 / INV-05 / INV-08 / INV-10:** Sin I/O, fail-closed, solo ES256, sin pánicos.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use gravital_id_codec::base64url;
use gravital_id_crypto::sha256;
use gravital_id_types::{ErrorCode, GidError, UnixTime};

use crate::signer::StatusSigner;
use crate::status_list::{
    StatusListVerifier, TokenStatus, STATUS_LIST_ALG, STATUS_LIST_TYP, SUPPORTED_BITS_PER_ENTRY,
};

/// Tamaño mínimo normativo de una lista de estado por perfil (REQ-STAT-002, ARCHITECTURE §10.3).
///
/// 131.072 entradas garantizan un tamaño de al menos 16 KiB en 1 bit por entrada, o 32 KiB
/// en 2 bits por entrada, impidiendo la correlación temporal y el rastreo de titulares.
pub const MIN_STATUS_LIST_ENTRIES: usize = 131_072;

/// Token Status List firmada y lista para distribución direccionada por contenido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTokenStatusList {
    jwt: String,
    sha256_digest: [u8; 32],
    sha256_hex: String,
    bits_per_entry: u8,
    capacity: usize,
}

impl SignedTokenStatusList {
    /// JWT compacto completo (`header.payload.signature`).
    #[must_use]
    pub fn jwt(&self) -> &str {
        &self.jwt
    }

    /// Digest SHA-256 binario del JWT completo.
    #[must_use]
    pub fn sha256_digest(&self) -> &[u8; 32] {
        &self.sha256_digest
    }

    /// Digest SHA-256 en formato hexadecimal en minúsculas (64 caracteres).
    #[must_use]
    pub fn sha256_hex(&self) -> &str {
        &self.sha256_hex
    }

    /// Bits por entrada (1 o 2).
    #[must_use]
    pub fn bits_per_entry(&self) -> u8 {
        self.bits_per_entry
    }

    /// Capacidad total de entradas de la lista.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Construye la URI direccionada por contenido (REQ-STAT-005) a partir de una URL base.
    ///
    /// Formato: `{base_url}/{sha256_hex}.jwt`. Si `base_url` termina en `/`, se normaliza.
    #[must_use]
    pub fn content_addressed_uri(&self, base_url: &str) -> String {
        let base = base_url.trim_end_matches('/');
        format!("{base}/{}.jwt", self.sha256_hex)
    }
}

/// Constructor y gestor en memoria de una Token Status List.
#[derive(Debug, Clone)]
pub struct TokenStatusListBuilder {
    bits_per_entry: u8,
    capacity: usize,
    bitmap: Vec<u8>,
    uri: Option<String>,
    issuer: Option<String>,
    issued_at: Option<UnixTime>,
    expires_at: Option<UnixTime>,
    kid: Option<String>,
}

impl TokenStatusListBuilder {
    /// Crea un nuevo constructor con el número de bits por entrada y la capacidad requerida.
    ///
    /// # Errores
    /// - [`ErrorCode::MalformedStatusList`] si `bits_per_entry` no es 1 ni 2.
    /// - [`ErrorCode::MalformedStatusList`] si `capacity < MIN_STATUS_LIST_ENTRIES` (REQ-STAT-002).
    pub fn new(bits_per_entry: u8, capacity: usize) -> Result<Self, GidError> {
        if !SUPPORTED_BITS_PER_ENTRY.contains(&bits_per_entry) {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                format!("unsupported bits per entry: {bits_per_entry}; only 1 and 2 are supported"),
            ));
        }

        if capacity < MIN_STATUS_LIST_ENTRIES {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                format!(
                    "capacity {capacity} is lower than minimum allowed of {MIN_STATUS_LIST_ENTRIES} entries (REQ-STAT-002)"
                ),
            ));
        }

        let total_bits = capacity.saturating_mul(usize::from(bits_per_entry));
        let num_bytes = total_bits.saturating_add(7) / 8;
        let bitmap = vec![0u8; num_bytes];

        Ok(Self {
            bits_per_entry,
            capacity,
            bitmap,
            uri: None,
            issuer: None,
            issued_at: None,
            expires_at: None,
            kid: None,
        })
    }

    /// Bits por entrada de la lista (1 o 2).
    #[must_use]
    pub fn bits_per_entry(&self) -> u8 {
        self.bits_per_entry
    }

    /// Capacidad total de entradas de la lista.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Asigna la URI explícita de la lista (opcional).
    pub fn with_uri(&mut self, uri: impl Into<String>) -> &mut Self {
        self.uri = Some(uri.into());
        self
    }

    /// Asigna el identificador o URI del emisor (`iss`).
    pub fn with_issuer(&mut self, issuer: impl Into<String>) -> &mut Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Asigna el instante de emisión (`iat`).
    pub fn with_issued_at(&mut self, iat: UnixTime) -> &mut Self {
        self.issued_at = Some(iat);
        self
    }

    /// Asigna el instante de expiración (`exp`).
    pub fn with_expires_at(&mut self, exp: UnixTime) -> &mut Self {
        self.expires_at = Some(exp);
        self
    }

    /// Asigna el identificador de clave (`kid`) para la cabecera JWS.
    pub fn with_kid(&mut self, kid: impl Into<String>) -> &mut Self {
        self.kid = Some(kid.into());
        self
    }

    /// Modifica el estado de una entrada específica en la lista.
    ///
    /// # Errores
    /// - [`ErrorCode::StatusIndexOutOfRange`] si `index >= capacity`.
    /// - [`ErrorCode::MalformedStatusList`] si se solicita `TokenStatus::Suspended` en una lista de 1 bit.
    pub fn set_status(&mut self, index: u64, status: TokenStatus) -> Result<(), GidError> {
        let cap_u64 = u64::try_from(self.capacity).unwrap_or(u64::MAX);
        if index >= cap_u64 {
            return Err(GidError::new(
                ErrorCode::StatusIndexOutOfRange,
                format!(
                    "status index {index} is out of range for capacity {}",
                    self.capacity
                ),
            ));
        }

        let bits = usize::from(self.bits_per_entry);
        if bits == 1 && status == TokenStatus::Suspended {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "status 'Suspended' is not supported in 1-bit status lists (REQ-STAT-007)",
            ));
        }

        let bit_offset = (index as usize).saturating_mul(bits);
        let byte_index = bit_offset / 8;
        let bit_index_in_byte = (bit_offset % 8) as u32;

        let Some(byte) = self.bitmap.get_mut(byte_index) else {
            return Err(GidError::new(
                ErrorCode::StatusIndexOutOfRange,
                "internal bitmap buffer bounds exceeded",
            ));
        };

        match self.bits_per_entry {
            1 => {
                let shift = 7u32.saturating_sub(bit_index_in_byte);
                let mask = 1u8 << shift;
                match status {
                    TokenStatus::Valid => {
                        *byte &= !mask;
                    }
                    TokenStatus::Revoked => {
                        *byte |= mask;
                    }
                    TokenStatus::Suspended => unreachable!(),
                }
            }
            2 => {
                let shift = 6u32.saturating_sub(bit_index_in_byte);
                let mask = 0b11u8 << shift;
                let val: u8 = match status {
                    TokenStatus::Valid => 0b00,
                    TokenStatus::Revoked => 0b01,
                    TokenStatus::Suspended => 0b10,
                };
                *byte = (*byte & !mask) | ((val & 0b11) << shift);
            }
            _ => {
                return Err(GidError::new(
                    ErrorCode::MalformedStatusList,
                    format!("unsupported bits per entry {}", self.bits_per_entry),
                ));
            }
        }

        Ok(())
    }

    /// Consulta el estado actual de una entrada en el constructor.
    ///
    /// # Errores
    /// [`ErrorCode::StatusIndexOutOfRange`] si `index >= capacity`.
    pub fn get_status(&self, index: u64) -> Result<TokenStatus, GidError> {
        let cap_u64 = u64::try_from(self.capacity).unwrap_or(u64::MAX);
        if index >= cap_u64 {
            return Err(GidError::new(
                ErrorCode::StatusIndexOutOfRange,
                format!(
                    "status index {index} is out of range for capacity {}",
                    self.capacity
                ),
            ));
        }

        let bits = usize::from(self.bits_per_entry);
        let bit_offset = (index as usize).saturating_mul(bits);
        let byte_index = bit_offset / 8;
        let bit_index_in_byte = (bit_offset % 8) as u32;

        let Some(&byte) = self.bitmap.get(byte_index) else {
            return Err(GidError::new(
                ErrorCode::StatusIndexOutOfRange,
                "internal bitmap buffer bounds exceeded",
            ));
        };

        match self.bits_per_entry {
            1 => {
                let shift = 7u32.saturating_sub(bit_index_in_byte);
                let raw = (byte >> shift) & 0b1;
                match raw {
                    0 => Ok(TokenStatus::Valid),
                    1 => Ok(TokenStatus::Revoked),
                    _ => unreachable!(),
                }
            }
            2 => {
                let shift = 6u32.saturating_sub(bit_index_in_byte);
                let raw = (byte >> shift) & 0b11;
                match raw {
                    0b00 => Ok(TokenStatus::Valid),
                    0b01 => Ok(TokenStatus::Revoked),
                    0b10 => Ok(TokenStatus::Suspended),
                    _ => Err(GidError::new(
                        ErrorCode::MalformedStatusList,
                        format!("undefined status value {raw} for 2 bits per entry"),
                    )),
                }
            }
            _ => Err(GidError::new(
                ErrorCode::MalformedStatusList,
                format!("unsupported bits per entry {}", self.bits_per_entry),
            )),
        }
    }

    /// Retorna una referencia a los bytes crudos del bitmap antes de comprimir.
    #[must_use]
    pub fn raw_bitmap(&self) -> &[u8] {
        &self.bitmap
    }

    /// Genera la representación comprimida en zlib/DEFLATE de los bytes del bitmap.
    ///
    /// Para cumplir con [`MAX_EXPANSION_RATIO`] (10:1, `REQ-STAT-003`, `CRYPTO_PROFILES.md §5.1`),
    /// si una lista esparsa comprimida a nivel 9 produce un ratio mayor a 10:1, se emite con un
    /// nivel de compresión que garantice que ningún verificador la rechace por exceso de ratio.
    #[must_use]
    pub fn compress_lst(&self) -> Vec<u8> {
        let compressed_l9 = gravital_id_codec::deflate::deflate_at_level(&self.bitmap, 9);
        let min_len = self
            .bitmap
            .len()
            .div_ceil(crate::status_list::MAX_EXPANSION_RATIO);
        if compressed_l9.len() >= min_len {
            compressed_l9
        } else {
            gravital_id_codec::deflate::deflate_at_level(&self.bitmap, 0)
        }
    }

    /// Construye la cabecera JSON serializada canónica.
    fn build_header_json(&self, kid_override: Option<&str>) -> String {
        let kid = kid_override.or(self.kid.as_deref());
        match kid {
            Some(k) => {
                format!(
                    "{{\"alg\":\"{STATUS_LIST_ALG}\",\"kid\":\"{k}\",\"typ\":\"{STATUS_LIST_TYP}\"}}"
                )
            }
            None => {
                format!("{{\"alg\":\"{STATUS_LIST_ALG}\",\"typ\":\"{STATUS_LIST_TYP}\"}}")
            }
        }
    }

    /// Construye el payload JSON serializado canónico conforme a IETF Token Status List.
    fn build_payload_json(&self) -> String {
        let compressed = self.compress_lst();
        let lst_b64 = base64url::encode(&compressed);

        let mut status_list_fields = Vec::with_capacity(4);
        status_list_fields.push(format!("\"bits\":{}", self.bits_per_entry));
        if let Some(exp) = self.expires_at {
            status_list_fields.push(format!("\"exp\":{}", exp.as_seconds()));
        }
        status_list_fields.push(format!("\"lst\":\"{lst_b64}\""));
        if let Some(ref uri) = self.uri {
            status_list_fields.push(format!("\"uri\":\"{uri}\""));
        }

        let status_list_obj = format!("{{{}}}", status_list_fields.join(","));

        let mut payload_fields = Vec::with_capacity(3);
        if let Some(iat) = self.issued_at {
            payload_fields.push(format!("\"iat\":{}", iat.as_seconds()));
        }
        if let Some(ref iss) = self.issuer {
            payload_fields.push(format!("\"iss\":\"{iss}\""));
        }
        payload_fields.push(format!("\"status_list\":{status_list_obj}"));

        format!("{{{}}}", payload_fields.join(","))
    }

    /// Firma la Token Status List con el firmante inyectado, produciendo el JWT compacto
    /// y validando exhaustivamente su decodificación antes de retornarlo (fail-closed).
    ///
    /// # Errores
    /// [`GidError`] si la firma criptográfica o la auto-verificación fallan.
    pub fn sign<S: StatusSigner>(&self, signer: &S) -> Result<SignedTokenStatusList, GidError> {
        let header_json = self.build_header_json(signer.kid());
        let payload_json = self.build_payload_json();

        let header_b64 = base64url::encode(header_json.as_bytes());
        let payload_b64 = base64url::encode(payload_json.as_bytes());

        let signing_input = format!("{header_b64}.{payload_b64}");
        let digest = sha256(signing_input.as_bytes());

        let signature_bytes = signer.sign_digest(&digest)?;
        let sig_b64 = base64url::encode(&signature_bytes);

        let jwt = format!("{signing_input}.{sig_b64}");

        // Auto-verificación inmediata fail-closed con el verificador del núcleo
        let parsed = StatusListVerifier::parse(&jwt)?;
        if parsed.bits_per_entry() != self.bits_per_entry {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "signed list failed internal verification: bits mismatch",
            ));
        }

        let jwt_sha256 = sha256(jwt.as_bytes());
        let sha256_hex = hex_encode(&jwt_sha256);

        Ok(SignedTokenStatusList {
            jwt,
            sha256_digest: jwt_sha256,
            sha256_hex,
            bits_per_entry: self.bits_per_entry,
            capacity: self.capacity,
        })
    }
}

/// Codifica bytes a string hexadecimal en minúsculas.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let cap = bytes.len().saturating_mul(2);
    let mut hex = Vec::with_capacity(cap);
    for &b in bytes {
        let high = (b >> 4) as usize;
        let low = (b & 0x0f) as usize;
        if let Some(&h) = HEX_CHARS.get(high) {
            hex.push(h);
        }
        if let Some(&l) = HEX_CHARS.get(low) {
            hex.push(l);
        }
    }
    String::from_utf8(hex).unwrap_or_default()
}
