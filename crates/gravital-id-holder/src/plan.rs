//! Plan de divulgación selectiva y consentimiento del titular (REQ-PRES-001, REQ-PRIV-001).
//!
//! Trazabilidad:
//! - `REQ-PRES-001`: La wallet DEBE permitir al titular seleccionar qué atributos
//!   presentar ante una solicitud, mostrando claramente qué datos se van a divulgar
//!   antes de confirmar la presentación (P-09).
//! - `REQ-PRIV-001`: Las presentaciones DEBEN realizarse mediante divulgación selectiva,
//!   compartiendo únicamente los atributos necesarios para la verificación (P-09).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use gravital_id_codec::json::Value;
use gravital_id_credential::ParsedSdJwt;
use gravital_id_types::{ErrorCode, GidError, Vct};

use crate::credential::{CredentialId, WalletCredential};
use crate::query::CredentialQuery;

/// Atributo individual incluido en el plan de divulgación para inspección y consentimiento.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedClaim {
    /// Nombre del claim (ej. "given_name", "birth_date").
    pub name: String,
    /// Vista previa en texto o representación para UI (sin registrar en logs ni auditoría persistente).
    pub value_preview: String,
    /// Indica si el verificador marcó este claim como obligatorio.
    pub required: bool,
    /// Indica si el titular ha consentido divulgar este claim.
    pub disclosed: bool,
}

/// Plan estructurado de divulgación generado para que el titular inspeccione
/// y consienta los atributos a compartir antes de firmar la presentación (`REQ-PRES-001`).
#[derive(Debug, Clone, PartialEq)]
pub struct DisclosurePlan {
    /// Identificador de la consulta DCQL asociada.
    pub query_id: String,
    /// Identificador local de la credencial seleccionada para responder.
    pub credential_id: CredentialId,
    /// Tipo de credencial (`vct`).
    pub vct: Vct,
    /// Lista de claims planificados con estado de consentimiento.
    pub claims: Vec<PlannedClaim>,
    /// Nombres de claims obligatorios requeridos por la consulta pero ausentes en la credencial.
    pub missing_required_claims: Vec<String>,
}

impl DisclosurePlan {
    /// Construye un nuevo plan de divulgación evaluando una credencial candidata contra una consulta DCQL.
    ///
    /// Extrae los valores de los claims directamente de las divulgaciones parseadas del SD-JWT emitido.
    pub fn build(
        query: &CredentialQuery,
        credential: &WalletCredential,
        parsed_sd_jwt: &ParsedSdJwt,
    ) -> Result<Self, GidError> {
        if !query.matches_vct(&credential.vct) {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                format!(
                    "credential vct '{}' does not match query accepted vcts",
                    credential.vct
                ),
            ));
        }

        let mut planned_claims = Vec::new();
        let mut missing_required = Vec::new();

        // Mapear claims disponibles en las divulgaciones del SD-JWT
        let disclosures = parsed_sd_jwt.disclosures();

        for req_claim in &query.claims {
            let mut found = false;

            for disc in disclosures {
                if let Some(cname) = disc.claim_name() {
                    if cname == req_claim.name {
                        let val_str = match disc.claim_value() {
                            Some(Value::String(s)) => s.clone(),
                            Some(Value::Number(n)) => n.to_string(),
                            Some(Value::Bool(b)) => b.to_string(),
                            Some(Value::Null) => "null".to_string(),
                            Some(other) => gravital_id_credential::to_canonical_json(other),
                            None => String::new(),
                        };

                        planned_claims.push(PlannedClaim {
                            name: req_claim.name.clone(),
                            value_preview: val_str,
                            required: req_claim.required,
                            disclosed: true, // Por defecto se seleccionan los solicitados
                        });
                        found = true;
                        break;
                    }
                }
            }

            if !found && req_claim.required {
                missing_required.push(req_claim.name.clone());
            }
        }

        Ok(Self {
            query_id: query.id.clone(),
            credential_id: credential.id.clone(),
            vct: credential.vct.clone(),
            claims: planned_claims,
            missing_required_claims: missing_required,
        })
    }

    /// Indica si la credencial satisface todos los requisitos obligatorios de la consulta.
    #[must_use]
    pub fn is_satisfiable(&self) -> bool {
        self.missing_required_claims.is_empty()
    }

    /// Modifica la selección de divulgación de un claim específico por el titular (`REQ-PRES-001`).
    ///
    /// Si el claim es obligatorio (`required == true`) y se intenta desmarcar, devuelve un error
    /// indicando que no puede excluirse un atributo mandatorio para esta consulta.
    pub fn set_claim_disclosed(
        &mut self,
        claim_name: &str,
        disclose: bool,
    ) -> Result<(), GidError> {
        for claim in &mut self.claims {
            if claim.name == claim_name {
                if claim.required && !disclose {
                    return Err(GidError::new(
                        ErrorCode::MissingRequiredClaim,
                        format!("cannot omit required claim '{claim_name}' from presentation"),
                    ));
                }
                claim.disclosed = disclose;
                return Ok(());
            }
        }

        Err(GidError::new(
            ErrorCode::MalformedMessage,
            format!("claim '{claim_name}' not found in disclosure plan"),
        ))
    }

    /// Retorna los nombres de los claims que el titular ha consentido divulgar.
    #[must_use]
    pub fn disclosed_claim_names(&self) -> Vec<&str> {
        let mut list = Vec::new();
        for claim in &self.claims {
            if claim.disclosed {
                list.push(claim.name.as_str());
            }
        }
        list
    }
}
