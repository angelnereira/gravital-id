//! Construcción y firma de presentaciones SD-JWT con divulgación selectiva y KB-JWT (REQ-PRES-001, REQ-PRES-002, REQ-PRIV-005).
//!
//! Trazabilidad:
//! - `REQ-PRES-001`: Selección de atributos para presentación con consentimiento explícito.
//! - `REQ-PRES-002`: Inclusión de Key Binding JWT (`KB-JWT`) con `nonce`, `aud`, `iat` y `sd_hash`.
//! - `REQ-PRIV-001`: Divulgación selectiva compartiendo únicamente los claims aprobados por el titular.
//! - `REQ-PRIV-005`: Cero persistencia del contenido de presentaciones ni nonces del verificador.
//! - `REQ-KEY-008`: Asociación segura de la clave del titular sin permitir sustitución no autenticada.
//! - `INV-03`: Sin custodia de claves privadas; firma delegada al `KeyStore`.

use alloc::string::String;
use alloc::vec::Vec;

use gravital_id_credential::{KbIssuer, ParsedSdJwt};
use gravital_id_keys::{HolderBinding, KeyHandle, KeyStore};
use gravital_id_types::{ErrorCode, GidError, UnixTime};

use crate::credential::WalletCredential;
use crate::plan::DisclosurePlan;

/// Generador de presentaciones SD-JWT con Key Binding JWT (`REQ-PRES-002`).
pub struct PresentationBuilder;

impl PresentationBuilder {
    /// Construye una presentación interactiva SD-JWT aplicando divulgación selectiva y firmando el KB-JWT.
    ///
    /// Valida:
    /// - Que el plan de divulgación esté satisfecho (`is_satisfiable == true`).
    /// - Que el identificador de la credencial coincida con el plan.
    /// - Que el handle de clave del titular coincida exactamente con la clave vinculada en la credencial (`REQ-KEY-008`).
    /// - Que únicamente los claims aprobados por el titular en `plan` sean incluidos en la presentación (`REQ-PRIV-001`).
    ///
    /// Invariante de privacidad (`REQ-PRIV-005`):
    /// La presentación generada y los nonces del verificador se retornan en memoria y **NUNCA** se persisten.
    pub fn build(
        credential: &WalletCredential,
        plan: &DisclosurePlan,
        aud: &str,
        nonce: &str,
        iat: UnixTime,
        key_store: &impl KeyStore,
        handle: &KeyHandle<HolderBinding>,
    ) -> Result<String, GidError> {
        if !plan.is_satisfiable() {
            return Err(GidError::new(
                ErrorCode::MissingRequiredClaim,
                "cannot build presentation from an unsatisfied disclosure plan",
            ));
        }

        if credential.id != plan.credential_id {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "credential id does not match disclosure plan credential id",
            ));
        }

        // REQ-KEY-008: Verificar que la clave del titular pasada coincide con la ligada a la credencial
        if handle.id() != credential.holder_binding_key_id {
            return Err(GidError::new(
                ErrorCode::KeyBindingFailed,
                "holder key handle does not match credential binding key id",
            ));
        }

        let parsed = ParsedSdJwt::parse(&credential.raw_sd_jwt)?;
        let raw_issuer_jwt = parsed.raw_issuer_jwt();

        let approved_claims = plan.disclosed_claim_names();

        // Filtrar divulgaciones aprobadas
        let mut selected_disclosures = Vec::new();
        for disc in parsed.disclosures() {
            if let Some(cname) = disc.claim_name() {
                if approved_claims.iter().any(|&c| c == cname) {
                    selected_disclosures.push(disc.encoded());
                }
            }
        }

        // Ensamblar prefijo SD-JWT con divulgaciones seleccionadas terminado en `~`
        let mut sd_jwt_prefix = String::from(raw_issuer_jwt);
        sd_jwt_prefix.push('~');

        for disc_encoded in selected_disclosures {
            sd_jwt_prefix.push_str(disc_encoded);
            sd_jwt_prefix.push('~');
        }

        // Crear KB-JWT firmado con el KeyStore del titular (RFC 9901 §6, REQ-PRES-002, INV-03)
        let presentation =
            KbIssuer::create_presentation(&sd_jwt_prefix, aud, nonce, iat, key_store, handle)?;

        Ok(presentation)
    }
}
