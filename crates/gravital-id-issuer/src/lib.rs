//! # `gravital-id-issuer`
//!
//! API de construcción y firma de credenciales SD-JWT VC para emisores, incluida la
//! emisión por lotes con claves, sales e índices de estado distintos (F3.T08).
//!
//! - **Capa arquitectónica:** L3
//! - **Garantía no_std:** Sí (`#![no_std]` + `alloc`)
//!
//! Trazabilidad:
//! - **REQ-CRED-002:** La sal de cada divulgación la genera el CSPRNG inyectado (≥ 128 bits).
//! - **REQ-CRED-004:** Los claims se validan contra el esquema del perfil antes de firmar.
//! - **REQ-CRED-005:** Los predicados del perfil se precomputan en el instante de emisión.
//! - **REQ-CRED-006:** Emisión por lotes con claves, sales e índices distintos por copia.
//! - **REQ-CRED-008:** Cabecera `typ: dc+sd-jwt` y algoritmo `ES256`; `none` rechazado.
//! - **INV-03:** La firma se delega al `KeyStore`; ninguna clave privada cruza esta API.
//! - **INV-08 / INV-11:** Solo ES256, y el instante de emisión lo pasa el llamador.
//! - **INV-05:** Una solicitud o un lote inválido se rechaza sin emitir ninguna credencial.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use gravital_id_codec::json::Value;
use gravital_id_credential::{
    profile_age_predicates, Disclosure, IssuedSdJwt, ProfileSchema, SdJwtVcBuilder,
};
use gravital_id_crypto::{JwkEcP256, Rng};
use gravital_id_keys::{KeyHandle, KeyStore, SigningPurpose};
use gravital_id_types::{ErrorCode, GidError, Kid, ProfileId, UnixTime, Vct};

pub mod batch;
pub mod request;

pub use batch::{BatchCopy, BatchPlan, MAX_BATCH_COPIES};
pub use request::{Attribute, CredentialRequest, StatusAllocation, MAX_ATTRIBUTES};

/// Credencial emitida junto con los metadatos que el emisor necesita para operarla.
#[derive(Debug, Clone, PartialEq)]
pub struct IssuedCredential {
    issued: IssuedSdJwt,
    profile: ProfileId,
    vct: Vct,
    holder_key: Option<JwkEcP256>,
    status_idx: Option<u64>,
    issued_at: UnixTime,
    expires_at: Option<UnixTime>,
}

impl IssuedCredential {
    /// Serialización compacta SD-JWT de la credencial emitida.
    #[must_use]
    pub fn compact(&self) -> &str {
        self.issued.to_compact_serialization()
    }

    /// Divulgaciones emitidas (el titular las conserva para presentar la credencial).
    #[must_use]
    pub fn disclosures(&self) -> &[Disclosure] {
        self.issued.disclosures()
    }

    /// Perfil aplicado.
    #[must_use]
    pub fn profile(&self) -> &ProfileId {
        &self.profile
    }

    /// Tipo de credencial declarado.
    #[must_use]
    pub fn vct(&self) -> &Vct {
        &self.vct
    }

    /// Clave pública de vinculación del titular declarada en `cnf.jwk`.
    #[must_use]
    pub fn holder_key(&self) -> Option<&JwkEcP256> {
        self.holder_key.as_ref()
    }

    /// Índice de estado asignado, si la credencial lleva referencia de estado.
    #[must_use]
    pub fn status_index(&self) -> Option<u64> {
        self.status_idx
    }

    /// Instante de emisión (`iat`).
    #[must_use]
    pub fn issued_at(&self) -> UnixTime {
        self.issued_at
    }

    /// Instante de expiración (`exp`), si se fijó.
    #[must_use]
    pub fn expires_at(&self) -> Option<UnixTime> {
        self.expires_at
    }

    /// JWS firmado del emisor.
    #[must_use]
    pub fn jwt(&self) -> &str {
        self.issued.jwt()
    }
}

/// Emisor de credenciales SD-JWT VC (F3.T08).
///
/// No guarda estado: cada llamada recibe la solicitud, el `KeyStore` del emisor, el handle
/// de su clave de firma y el CSPRNG inyectado. El identificador de clave (`kid`) es opcional.
pub struct Issuer;

impl Issuer {
    /// Construye el constructor SD-JWT VC de una solicitud ya validada.
    ///
    /// Añade los atributos solicitados, precomputa los predicados del perfil y fija los
    /// claims opcionales (`exp`, `cnf`, `status`).
    fn build(
        request: &CredentialRequest,
        holder_key: Option<JwkEcP256>,
        status_idx: Option<u64>,
    ) -> Result<SdJwtVcBuilder, GidError> {
        request.validate()?;

        let schema = ProfileSchema::lookup(request.profile()).ok_or_else(|| {
            GidError::new(
                ErrorCode::SchemaValidationFailed,
                format!(
                    "no compile-time schema registered for profile '{}'",
                    request.profile()
                ),
            )
        })?;

        let mut builder = SdJwtVcBuilder::new(
            request.issuer_uri().to_string(),
            request.vct()?,
            request.issued_at(),
        )?
        .profile(request.profile().clone())
        .set_decoys(request.decoy_count());

        // Atributos solicitados.
        for attribute in request.attributes() {
            builder = if attribute.selective {
                builder.add_sd_claim(attribute.name.clone(), attribute.value.clone())
            } else {
                builder.add_plain_claim(attribute.name.clone(), attribute.value.clone())
            };
        }

        // REQ-CRED-005: predicados precomputados en el instante de emisión del lote.
        for (name, value) in Self::profile_predicates(schema, request)? {
            builder = builder.add_sd_claim(name, value);
        }

        if let Some(expires_at) = request.expires_at_ref() {
            builder = builder.exp(expires_at);
        }
        if let Some(holder_key) = holder_key {
            builder = builder.cnf_jwk(holder_key);
        }
        if let Some(status) = request.status_ref() {
            builder = builder.status_list(status_idx.unwrap_or(status.idx), status.uri.clone())?;
        }

        Ok(builder)
    }

    /// Predicados que el perfil declara, si la solicitud incluye `birth_date`.
    fn profile_predicates(
        schema: &ProfileSchema,
        request: &CredentialRequest,
    ) -> Result<Vec<(String, Value)>, GidError> {
        let Some(birth_date) = request
            .attributes()
            .iter()
            .find(|attribute| attribute.name == "birth_date")
            .and_then(|attribute| attribute.value.as_str())
            .map(ToString::to_string)
        else {
            return Ok(Vec::new());
        };

        let mut predicates = Vec::new();
        for predicate in profile_age_predicates(schema, &birth_date, request.issued_at())? {
            let (name, value) = predicate.to_claim();
            predicates.push((name.to_string(), value));
        }
        Ok(predicates)
    }

    /// Emite y firma una credencial a partir de una solicitud.
    ///
    /// # Errores
    /// Los de validación de la solicitud, del esquema del perfil y de la firma delegada al
    /// `KeyStore`. Si algo falla no se devuelve ninguna credencial parcial.
    pub fn issue<S: KeyStore, P: SigningPurpose, R: Rng>(
        request: &CredentialRequest,
        key_store: &S,
        signing_key: &KeyHandle<P>,
        kid: Option<Kid>,
        rng: &R,
    ) -> Result<IssuedCredential, GidError> {
        let status_idx = request.status_ref().map(|status| status.idx);
        let holder_key = request.holder_key_ref().cloned();
        let builder = Self::build(request, holder_key.clone(), status_idx)?;
        let issued = builder.issue_signed(key_store, signing_key, kid, rng)?;

        Ok(IssuedCredential {
            issued,
            profile: request.profile().clone(),
            vct: request.vct()?,
            holder_key,
            status_idx,
            issued_at: request.issued_at(),
            expires_at: request.expires_at_ref(),
        })
    }

    /// Emite un lote de copias de la misma credencial (REQ-CRED-006).
    ///
    /// La solicitud aporta el contenido común (perfil, atributos, validez y URI de la lista);
    /// el plan aporta la clave de vinculación y el índice de estado de cada copia. Si alguna
    /// copia falla, se devuelve el error y no se entrega ninguna credencial parcial.
    ///
    /// # Errores
    /// Los de [`BatchPlan`], los de [`Issuer::issue`] y [`ErrorCode::MalformedSdJwt`] si la
    /// solicitud declara una clave de titular (cada copia fija la suya) o carece de URI de lista.
    pub fn issue_batch<S: KeyStore, P: SigningPurpose, R: Rng>(
        request: &CredentialRequest,
        plan: &BatchPlan,
        key_store: &S,
        signing_key: &KeyHandle<P>,
        kid: Option<Kid>,
        rng: &R,
    ) -> Result<Vec<IssuedCredential>, GidError> {
        request.validate()?;

        if request.holder_key_ref().is_some() {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "a batch request must not declare a holder key: each copy sets its own",
            ));
        }
        if request.status_ref().is_none() {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "a batch request must declare the status list uri (one entry per copy)",
            ));
        }

        let mut issued = Vec::with_capacity(plan.len());
        for copy in plan.copies() {
            let copy_request = request.clone_for_copy(copy.holder_key.clone(), copy.status_idx)?;
            let credential = Self::issue(&copy_request, key_store, signing_key, kid.clone(), rng)?;
            issued.push(credential);
        }
        Ok(issued)
    }

    /// Copia del lote, expuesta para que el emisor pueda auditar el reparto.
    #[must_use]
    pub fn copy_of(plan: &BatchPlan, index: usize) -> Option<&BatchCopy> {
        plan.copies().get(index)
    }
}

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
