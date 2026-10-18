//! Constructor de Manifiestos de Estado del Emisor (F7.T05, REQ-STAT-005, REQ-STAT-006, REQ-STAT-008, ADR-0017).
//!
//! Trazabilidad:
//! - **REQ-STAT-008:** Manifiesto firmado por el emisor con versión monotónica incremental.
//! - **REQ-STAT-005:** Enlaces direccionados por contenido a las Token Status Lists.
//! - **REQ-STAT-006:** Hash SHA-256 del manifiesto preparado para anclaje en `StatusAnchor.sol`.
//! - **INV-01 / INV-05 / INV-08 / INV-10:** Sin I/O, fail-closed, solo ES256, sin pánicos.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use gravital_id_codec::base64url;
use gravital_id_crypto::sha256;
use gravital_id_types::{ErrorCode, GidError, UnixTime};

use crate::manifest::{IssuerStatusManifest, StatusManifestVerifier, MANIFEST_LIST_TYPE};
use crate::signer::StatusSigner;
use crate::status_list::STATUS_LIST_ALG;

/// Tipo de token normativo en cabecera JWS para manifiestos de estado.
pub const STATUS_MANIFEST_TYP: &str = "statusmanifest+jwt";

/// Manifiesto de estado firmado por el emisor con su hash para anclaje.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedStatusManifest {
    jwt: String,
    manifest_version: u64,
    manifest_hash: [u8; 32],
    manifest_hash_hex: String,
    manifest: IssuerStatusManifest,
}

impl SignedStatusManifest {
    /// JWT compacto completo (`header.payload.signature`).
    #[must_use]
    pub fn jwt(&self) -> &str {
        &self.jwt
    }

    /// Versión monotónica del manifiesto.
    #[must_use]
    pub fn manifest_version(&self) -> u64 {
        self.manifest_version
    }

    /// Hash SHA-256 de 32 bytes del manifiesto completo para anclaje en el ledger (`StatusAnchor`).
    #[must_use]
    pub fn manifest_hash(&self) -> &[u8; 32] {
        &self.manifest_hash
    }

    /// Hash SHA-256 en formato hexadecimal en minúsculas (64 caracteres).
    #[must_use]
    pub fn manifest_hash_hex(&self) -> &str {
        &self.manifest_hash_hex
    }

    /// Estructura parseada y validada del manifiesto.
    #[must_use]
    pub fn manifest(&self) -> &IssuerStatusManifest {
        &self.manifest
    }
}

/// Entrada para una lista de estado dentro del constructor del manifiesto.
#[derive(Debug, Clone)]
struct BuilderListEntry {
    status_list_id: String,
    uri: String,
    sha256_hex: String,
    valid_until: Option<UnixTime>,
}

/// Constructor de Manifiestos de Estado de Emisor (`IssuerStatusManifest`).
#[derive(Debug, Clone)]
pub struct IssuerStatusManifestBuilder {
    issuer_id: String,
    manifest_version: u64,
    issued_at: Option<UnixTime>,
    valid_until: Option<UnixTime>,
    kid: Option<String>,
    lists: Vec<BuilderListEntry>,
}

impl IssuerStatusManifestBuilder {
    /// Crea un constructor para un emisor específico y versión monotónica incremental.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedStatusList`] si `issuer_id` está vacío o contiene espacios en blanco.
    pub fn new(issuer_id: impl Into<String>, manifest_version: u64) -> Result<Self, GidError> {
        let id = issuer_id.into();
        let trimmed = id.trim();
        if trimmed.is_empty() {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "issuer_id must not be empty",
            ));
        }

        Ok(Self {
            issuer_id: trimmed.to_string(),
            manifest_version,
            issued_at: None,
            valid_until: None,
            kid: None,
            lists: Vec::new(),
        })
    }

    /// Identificador del emisor.
    #[must_use]
    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    /// Versión monotónica del manifiesto.
    #[must_use]
    pub fn manifest_version(&self) -> u64 {
        self.manifest_version
    }

    /// Asigna el instante de emisión del manifiesto (`issued_at`).
    pub fn with_issued_at(&mut self, iat: UnixTime) -> &mut Self {
        self.issued_at = Some(iat);
        self
    }

    /// Asigna el instante de validez límite del manifiesto (`valid_until`).
    pub fn with_valid_until(&mut self, valid_until: UnixTime) -> &mut Self {
        self.valid_until = Some(valid_until);
        self
    }

    /// Asigna el identificador de clave (`kid`) para la cabecera JWS.
    pub fn with_kid(&mut self, kid: impl Into<String>) -> &mut Self {
        self.kid = Some(kid.into());
        self
    }

    /// Añade una Token Status List al manifiesto.
    ///
    /// # Errores
    /// - [`ErrorCode::MalformedStatusList`] si `status_list_id` o `uri` están vacíos.
    /// - [`ErrorCode::MalformedStatusList`] si `sha256_hex` no tiene exactamente 64 caracteres hexadecimales.
    pub fn add_status_list(
        &mut self,
        status_list_id: impl Into<String>,
        uri: impl Into<String>,
        sha256_hex: impl Into<String>,
        valid_until: Option<UnixTime>,
    ) -> Result<&mut Self, GidError> {
        let sl_id = status_list_id.into();
        if sl_id.trim().is_empty() {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "status_list_id must not be empty",
            ));
        }

        let u = uri.into();
        if u.trim().is_empty() {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "status list uri must not be empty",
            ));
        }

        let sha = sha256_hex.into().to_ascii_lowercase();
        if !is_sha256_hex(&sha) {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "status list sha256 must be exactly 64 hexadecimal characters",
            ));
        }

        self.lists.push(BuilderListEntry {
            status_list_id: sl_id,
            uri: u,
            sha256_hex: sha,
            valid_until,
        });

        Ok(self)
    }

    /// Construye la cabecera JSON serializada.
    fn build_header_json(&self, kid_override: Option<&str>) -> String {
        let kid = kid_override.or(self.kid.as_deref());
        match kid {
            Some(k) => {
                format!(
                    "{{\"alg\":\"{STATUS_LIST_ALG}\",\"kid\":\"{k}\",\"typ\":\"{STATUS_MANIFEST_TYP}\"}}"
                )
            }
            None => {
                format!("{{\"alg\":\"{STATUS_LIST_ALG}\",\"typ\":\"{STATUS_MANIFEST_TYP}\"}}")
            }
        }
    }

    /// Construye el payload JSON serializado canónico conforme a `IssuerStatusManifest`.
    fn build_payload_json(&self) -> Result<String, GidError> {
        if let (Some(iat), Some(exp)) = (self.issued_at, self.valid_until) {
            if exp.as_seconds() < iat.as_seconds() {
                return Err(GidError::new(
                    ErrorCode::MalformedStatusList,
                    "valid_until cannot be before issued_at",
                ));
            }
        }

        let mut entries = Vec::with_capacity(self.lists.len());
        for list in &self.lists {
            let mut fields = Vec::with_capacity(5);
            fields.push(format!("\"sha256\":\"{}\"", list.sha256_hex));
            fields.push(format!("\"status_list_id\":\"{}\"", list.status_list_id));
            fields.push(format!("\"type\":\"{MANIFEST_LIST_TYPE}\""));
            fields.push(format!("\"uri\":\"{}\"", list.uri));
            if let Some(vu) = list.valid_until {
                fields.push(format!("\"valid_until\":{}", vu.as_seconds()));
            }
            entries.push(format!("{{{}}}", fields.join(",")));
        }

        let lists_array = format!("[{}]", entries.join(","));

        let mut payload_fields = Vec::with_capacity(5);
        if let Some(iat) = self.issued_at {
            payload_fields.push(format!("\"issued_at\":{}", iat.as_seconds()));
        }
        payload_fields.push(format!("\"issuer_id\":\"{}\"", self.issuer_id));
        payload_fields.push(format!("\"manifest_version\":{}", self.manifest_version));
        payload_fields.push(format!("\"status_lists\":{lists_array}"));
        if let Some(vu) = self.valid_until {
            payload_fields.push(format!("\"valid_until\":{}", vu.as_seconds()));
        }

        Ok(format!("{{{}}}", payload_fields.join(",")))
    }

    /// Firma el Manifiesto de Estado con el firmante inyectado, produciendo el JWS compacto
    /// y validando exhaustivamente su decodificación y firma antes de retornarlo (fail-closed).
    ///
    /// # Errores
    /// [`GidError`] si la firma criptográfica o la auto-verificación fallan.
    pub fn sign<S: StatusSigner>(&self, signer: &S) -> Result<SignedStatusManifest, GidError> {
        let header_json = self.build_header_json(signer.kid());
        let payload_json = self.build_payload_json()?;

        let header_b64 = base64url::encode(header_json.as_bytes());
        let payload_b64 = base64url::encode(payload_json.as_bytes());

        let signing_input = format!("{header_b64}.{payload_b64}");
        let digest = sha256(signing_input.as_bytes());

        let signature_bytes = signer.sign_digest(&digest)?;
        let sig_b64 = base64url::encode(&signature_bytes);

        let jwt = format!("{signing_input}.{sig_b64}");

        // Auto-verificación inmediata fail-closed con el parser y verificador del núcleo
        let manifest = StatusManifestVerifier::parse(&jwt)?;
        StatusManifestVerifier::verify_signature(&jwt, signer.public_key())?;

        let manifest_hash = sha256(jwt.as_bytes());
        let manifest_hash_hex = hex_encode(&manifest_hash);

        Ok(SignedStatusManifest {
            jwt,
            manifest_version: self.manifest_version,
            manifest_hash,
            manifest_hash_hex,
            manifest,
        })
    }
}

/// Comprueba si una cadena está formada por exactamente 64 caracteres hexadecimales.
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
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
