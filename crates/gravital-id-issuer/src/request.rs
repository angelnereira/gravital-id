//! Solicitud de emisión de una credencial SD-JWT VC (F3.T08).
//!
//! Describe **qué** debe contener la credencial sin conocer nada de criptografía ni de
//! `KeyStore`: el emisor (servicio o biblioteca) construye la solicitud y la firma la
//! delega a [`gravital_id_keys::KeyStore`] (INV-03).
//!
//! Trazabilidad:
//! - **REQ-CRED-004:** Los claims se validan contra el esquema del perfil antes de firmar.
//! - **REQ-CRED-006:** La emisión por lotes requiere claves, sales e índices distintos
//!   por copia (ARCHITECTURE §8.3).
//! - **REQ-VER-008:** Los atributos están acotados en número y tamaño.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use gravital_id_codec::json::Value;
use gravital_id_crypto::JwkEcP256;
use gravital_id_types::{ErrorCode, GidError, ProfileId, UnixTime, Vct};

/// Número máximo de atributos por credencial (CRYPTO_PROFILES §5.2).
pub const MAX_ATTRIBUTES: usize = 64;

/// Un atributo de la credencial y cómo se divulga.
#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    /// Nombre del claim (p. ej. `given_name`).
    pub name: String,
    /// Valor del claim.
    pub value: Value,
    /// Si es `true`, el claim se divulga selectivamente (`_sd`); si no, queda siempre visible.
    pub selective: bool,
}

impl Attribute {
    /// Atributo con divulgación selectiva (caso habitual de los perfiles).
    #[must_use]
    pub fn selective(name: impl Into<String>, value: Value) -> Self {
        Self {
            name: name.into(),
            value,
            selective: true,
        }
    }

    /// Atributo siempre visible (sin divulgación selectiva).
    #[must_use]
    pub fn plain(name: impl Into<String>, value: Value) -> Self {
        Self {
            name: name.into(),
            value,
            selective: false,
        }
    }
}

/// Asignación de la entrada de estado de la credencial en su Token Status List (ADR-0005).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusAllocation {
    /// Índice dentro de la lista.
    pub idx: u64,
    /// URI de la lista de estado (direccionada por contenido en F7).
    pub uri: String,
}

impl StatusAllocation {
    /// Construye una asignación de estado validando la URI.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedStatusList`] si la URI está vacía o contiene espacios o controles.
    pub fn new(idx: u64, uri: impl Into<String>) -> Result<Self, GidError> {
        let reference = gravital_id_credential::StatusListReference::new(idx, uri)?;
        Ok(Self {
            idx: reference.idx,
            uri: reference.uri,
        })
    }
}

/// Solicitud de emisión de una credencial SD-JWT VC.
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialRequest {
    issuer_uri: String,
    profile: ProfileId,
    issued_at: UnixTime,
    expires_at: Option<UnixTime>,
    attributes: Vec<Attribute>,
    status: Option<StatusAllocation>,
    holder_key: Option<JwkEcP256>,
    recovery_thumbprint: Option<String>,
    decoys: usize,
}

impl CredentialRequest {
    /// Crea una solicitud con los datos mínimos: emisor, perfil e instante de emisión.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedSdJwt`] si `issuer_uri` no es una URL HTTPS válida.
    pub fn new(
        issuer_uri: impl Into<String>,
        profile: ProfileId,
        issued_at: UnixTime,
    ) -> Result<Self, GidError> {
        Ok(Self {
            issuer_uri: issuer_uri.into(),
            profile,
            issued_at,
            expires_at: None,
            attributes: Vec::new(),
            status: None,
            holder_key: None,
            recovery_thumbprint: None,
            decoys: 0,
        })
    }

    /// Identificador del emisor (`iss`).
    #[must_use]
    pub fn issuer_uri(&self) -> &str {
        &self.issuer_uri
    }

    /// Perfil cuyos esquemas gobiernan la credencial.
    #[must_use]
    pub fn profile(&self) -> &ProfileId {
        &self.profile
    }

    /// Instante de emisión (`iat`).
    #[must_use]
    pub fn issued_at(&self) -> UnixTime {
        self.issued_at
    }

    /// Atributos declarados hasta ahora.
    #[must_use]
    pub fn attributes(&self) -> &[Attribute] {
        &self.attributes
    }

    /// Añade un atributo con divulgación selectiva.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedSdJwt`] si se supera [`MAX_ATTRIBUTES`] o el nombre está vacío.
    pub fn attribute(self, name: impl Into<String>, value: Value) -> Result<Self, GidError> {
        self.push_attribute(Attribute::selective(name, value))
    }

    /// Añade un atributo siempre visible.
    ///
    /// # Errores
    /// Los de [`CredentialRequest::attribute`].
    pub fn plain_attribute(self, name: impl Into<String>, value: Value) -> Result<Self, GidError> {
        self.push_attribute(Attribute::plain(name, value))
    }

    /// Añade un atributo ya construido.
    ///
    /// # Errores
    /// Los de [`CredentialRequest::attribute`].
    pub fn push_attribute(mut self, attribute: Attribute) -> Result<Self, GidError> {
        self.push(attribute)?;
        Ok(self)
    }

    fn push(&mut self, attribute: Attribute) -> Result<(), GidError> {
        if self.attributes.len() >= MAX_ATTRIBUTES {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("a credential cannot declare more than {MAX_ATTRIBUTES} attributes"),
            ));
        }
        if attribute.name.is_empty() {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "attribute name must not be empty",
            ));
        }
        self.attributes.push(attribute);
        Ok(())
    }

    /// Configura la expiración (`exp`).
    #[must_use]
    pub fn expires_at(mut self, expires_at: UnixTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Configura la asignación de estado (`status`, REQ-CRED-007).
    #[must_use]
    pub fn status(mut self, status: StatusAllocation) -> Self {
        self.status = Some(status);
        self
    }

    /// Configura la clave pública de vinculación del titular (`cnf.jwk`).
    #[must_use]
    pub fn holder_key(mut self, holder_key: JwkEcP256) -> Self {
        self.holder_key = Some(holder_key);
        self
    }

    /// Configura la huella de la clave de recuperación del titular (`cnf.rec`, REQ-REC-004, REQ-REC-007).
    #[must_use]
    pub fn recovery_thumbprint(mut self, thumbprint: impl Into<String>) -> Self {
        self.recovery_thumbprint = Some(thumbprint.into());
        self
    }

    /// Configura digests señuelo (REQ-CRED-003).
    #[must_use]
    pub fn decoys(mut self, decoys: usize) -> Self {
        self.decoys = decoys;
        self
    }

    /// Clave pública de vinculación declarada, si la hay.
    #[must_use]
    pub fn holder_key_ref(&self) -> Option<&JwkEcP256> {
        self.holder_key.as_ref()
    }

    /// Huella de recuperación declarada, si la hay.
    #[must_use]
    pub fn recovery_thumbprint_ref(&self) -> Option<&str> {
        self.recovery_thumbprint.as_deref()
    }

    /// Asignación de estado declarada, si la hay.
    #[must_use]
    pub fn status_ref(&self) -> Option<&StatusAllocation> {
        self.status.as_ref()
    }

    /// Instante de expiración, si se fijó.
    #[must_use]
    pub fn expires_at_ref(&self) -> Option<UnixTime> {
        self.expires_at
    }

    /// Número de digests señuelo configurados.
    #[must_use]
    pub fn decoy_count(&self) -> usize {
        self.decoys
    }

    /// `vct` que corresponde al perfil de la solicitud.
    ///
    /// # Errores
    /// [`ErrorCode::SchemaValidationFailed`] si el perfil no tiene esquema registrado.
    pub fn vct(&self) -> Result<Vct, GidError> {
        let schema =
            gravital_id_credential::ProfileSchema::lookup(&self.profile).ok_or_else(|| {
                GidError::new(
                    ErrorCode::SchemaValidationFailed,
                    format!(
                        "no compile-time schema registered for profile '{}'",
                        self.profile
                    ),
                )
            })?;
        Vct::parse(schema.vct).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("profile schema declares an invalid vct: {e}"),
            )
        })
    }

    /// Comprueba la coherencia interna de la solicitud antes de emitir (fail-closed).
    ///
    /// # Errores
    /// - [`ErrorCode::MalformedSdJwt`]: ventana de vigencia invertida o atributos duplicados.
    /// - [`ErrorCode::SchemaValidationFailed`]: perfil sin esquema registrado.
    pub fn validate(&self) -> Result<(), GidError> {
        let schema =
            gravital_id_credential::ProfileSchema::lookup(&self.profile).ok_or_else(|| {
                GidError::new(
                    ErrorCode::SchemaValidationFailed,
                    format!(
                        "no compile-time schema registered for profile '{}'",
                        self.profile
                    ),
                )
            })?;

        if let Some(exp) = self.expires_at {
            if exp.as_seconds() < self.issued_at.as_seconds() {
                return Err(GidError::new(
                    ErrorCode::MalformedSdJwt,
                    "credential 'exp' cannot be before 'iat'",
                ));
            }
        }

        for (index, attribute) in self.attributes.iter().enumerate() {
            if self
                .attributes
                .iter()
                .skip(index.saturating_add(1))
                .any(|other| other.name == attribute.name)
            {
                return Err(GidError::new(
                    ErrorCode::MalformedSdJwt,
                    format!("attribute '{}' is declared twice", attribute.name),
                ));
            }
            // Un claim siempre visible de la capa VC no puede declararse como atributo.
            if gravital_id_credential::vc::is_always_visible_claim(&attribute.name) {
                return Err(GidError::new(
                    ErrorCode::MalformedSdJwt,
                    format!(
                        "attribute '{}' is always visible in an SD-JWT VC",
                        attribute.name
                    ),
                ));
            }
        }

        // El `vct` del perfil debe ser válido: la credencial lo declara tal cual.
        let _ = Vct::parse(schema.vct).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("profile schema declares an invalid vct: {e}"),
            )
        })?;

        Ok(())
    }

    /// Deriva la solicitud de una copia del lote con su clave de titular y su índice de estado.
    ///
    /// Mantiene el contenido común (perfil, atributos, validez) y la URI de la lista, y
    /// fija la clave de vinculación y el índice propios de la copia (ARCHITECTURE §8.3).
    ///
    /// # Errores
    /// [`ErrorCode::MalformedStatusList`] si la solicitud no declara la URI de la lista.
    pub fn clone_for_copy(&self, holder_key: JwkEcP256, status_idx: u64) -> Result<Self, GidError> {
        let Some(status) = self.status_ref() else {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "a batch request must declare the status list uri (one entry per copy)",
            ));
        };
        let mut copy = self.clone();
        copy.holder_key = Some(holder_key);
        copy.status = Some(StatusAllocation {
            idx: status_idx,
            uri: status.uri.clone(),
        });
        Ok(copy)
    }
}
