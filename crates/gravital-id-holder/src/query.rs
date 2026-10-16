//! Subconjunto normativo de DCQL para consultas de presentación (REQ-PRES-003, PROTOCOL.md §7.2.2, §3.1).
//!
//! Trazabilidad:
//! - `REQ-PRES-003`: La wallet DEBE admitir solicitudes de presentación basadas en un
//!   subconjunto de DCQL (Digital Credentials Query Language) que especifique los tipos
//!   de credencial (`vct`) y los claims requeridos y opcionales (P-09).
//! - `REQ-PRIV-001`: Divulgación selectiva compartiendo únicamente los atributos necesarios.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use gravital_id_codec::json::{parse_bytes, Limits, Value};
use gravital_id_credential::to_canonical_json;
use gravital_id_types::{ErrorCode, GidError, Vct};

/// Máximo número de consultas de credenciales en una solicitud DCQL (PROTOCOL.md §7.2.2).
pub const MAX_CREDENTIAL_QUERIES: usize = 4;

/// Máximo número de valores VCT alternativos por consulta.
pub const MAX_VCT_VALUES_PER_QUERY: usize = 4;

/// Máximo número de claims solicitados por consulta.
pub const MAX_CLAIMS_PER_QUERY: usize = 32;

/// Longitud máxima del identificador de consulta.
pub const MAX_QUERY_ID_LEN: usize = 32;

/// Especificación de un claim solicitado en una consulta DCQL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedClaim {
    /// Nombre del claim solicitado (ej. "given_name", "birth_date").
    pub name: String,
    /// Indica si el claim es obligatorio para satisfacer la consulta.
    pub required: bool,
}

impl RequestedClaim {
    /// Crea un claim obligatorio.
    #[must_use]
    pub fn required(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            required: true,
        }
    }

    /// Crea un claim opcional.
    #[must_use]
    pub fn optional(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            required: false,
        }
    }
}

/// Consulta individual de credencial dentro de una solicitud DCQL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialQuery {
    /// Identificador local de la consulta (ej. "cred1", <= 32 caracteres).
    pub id: String,
    /// Tipos de credencial admitidos (`vct_values`, 1..=4).
    pub vct_values: Vec<Vct>,
    /// Claims solicitados en la consulta (0..=32).
    pub claims: Vec<RequestedClaim>,
}

impl CredentialQuery {
    /// Crea una nueva consulta validando límites de seguridad (REQ-VER-008).
    pub fn new(
        id: impl Into<String>,
        vct_values: Vec<Vct>,
        claims: Vec<RequestedClaim>,
    ) -> Result<Self, GidError> {
        let id_str = id.into();
        if id_str.is_empty() || id_str.len() > MAX_QUERY_ID_LEN {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                format!(
                    "query id length must be between 1 and {MAX_QUERY_ID_LEN} bytes (got {})",
                    id_str.len()
                ),
            ));
        }

        if vct_values.is_empty() || vct_values.len() > MAX_VCT_VALUES_PER_QUERY {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                format!(
                    "vct_values must have between 1 and {MAX_VCT_VALUES_PER_QUERY} items (got {})",
                    vct_values.len()
                ),
            ));
        }

        if claims.len() > MAX_CLAIMS_PER_QUERY {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                format!(
                    "claims list cannot exceed {MAX_CLAIMS_PER_QUERY} items (got {})",
                    claims.len()
                ),
            ));
        }

        Ok(Self {
            id: id_str,
            vct_values,
            claims,
        })
    }

    /// Comprueba si la consulta admite un `vct` determinado.
    #[must_use]
    pub fn matches_vct(&self, vct: &Vct) -> bool {
        self.vct_values.iter().any(|v| v == vct)
    }
}

/// Consulta de credenciales DCQL (Digital Credentials Query Language).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcqlQuery {
    /// Consultas de credenciales contenidas (1..=4).
    pub credentials: Vec<CredentialQuery>,
}

impl DcqlQuery {
    /// Crea una nueva consulta DCQL validando cotas de seguridad.
    pub fn new(credentials: Vec<CredentialQuery>) -> Result<Self, GidError> {
        if credentials.is_empty() || credentials.len() > MAX_CREDENTIAL_QUERIES {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                format!(
                    "DCQL query credentials count must be between 1 and {MAX_CREDENTIAL_QUERIES} (got {})",
                    credentials.len()
                ),
            ));
        }

        Ok(Self { credentials })
    }

    /// Parsea una consulta DCQL desde JSON (formato OpenID4VP / VerificationRequest de PROTOCOL.md §3.1).
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, GidError> {
        let val = parse_bytes(bytes, &Limits::profile_default()).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedMessage,
                format!("failed to parse DCQL JSON: {e}"),
            )
        })?;

        let obj = match val {
            Value::Object(map) => map,
            _ => {
                return Err(GidError::new(
                    ErrorCode::MalformedMessage,
                    "DCQL JSON root must be an object",
                ))
            }
        };

        let mut creds_val = None;
        for (k, v) in obj {
            if k == "credentials" {
                creds_val = Some(v);
                break;
            }
        }

        let creds_arr = match creds_val {
            Some(Value::Array(arr)) => arr,
            _ => {
                return Err(GidError::new(
                    ErrorCode::MalformedMessage,
                    "missing or invalid 'credentials' array in DCQL query",
                ))
            }
        };

        if creds_arr.is_empty() || creds_arr.len() > MAX_CREDENTIAL_QUERIES {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                format!(
                    "credentials query count {} exceeds range 1..={MAX_CREDENTIAL_QUERIES}",
                    creds_arr.len()
                ),
            ));
        }

        let mut queries = Vec::with_capacity(creds_arr.len());
        for item in creds_arr {
            let item_obj = match item {
                Value::Object(m) => m,
                _ => {
                    return Err(GidError::new(
                        ErrorCode::MalformedMessage,
                        "credential query item must be an object",
                    ))
                }
            };

            let mut id = None;
            let mut vct_values = Vec::new();
            let mut claims = Vec::new();

            for (k, v) in item_obj {
                match k.as_str() {
                    "id" => {
                        if let Value::String(s) = v {
                            id = Some(s);
                        }
                    }
                    "meta" => {
                        if let Value::Object(meta_obj) = v {
                            for (mk, mv) in meta_obj {
                                if mk == "vct_values" {
                                    if let Value::Array(varr) = mv {
                                        for vitem in varr {
                                            if let Value::String(vs) = vitem {
                                                let vct = Vct::parse(&vs)?;
                                                vct_values.push(vct);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    "vct_values" => {
                        if let Value::Array(varr) = v {
                            for vitem in varr {
                                if let Value::String(vs) = vitem {
                                    let vct = Vct::parse(&vs)?;
                                    vct_values.push(vct);
                                }
                            }
                        }
                    }
                    "claims" => {
                        if let Value::Array(carr) = v {
                            for citem in carr {
                                match citem {
                                    Value::String(cname) => {
                                        claims.push(RequestedClaim::required(cname));
                                    }
                                    Value::Object(cobj) => {
                                        let mut cname = None;
                                        let mut required = true;
                                        for (ck, cv) in cobj {
                                            if ck == "name" || ck == "path" {
                                                if let Value::String(s) = cv {
                                                    cname = Some(s);
                                                }
                                            } else if ck == "required" {
                                                if let Value::Bool(b) = cv {
                                                    required = b;
                                                }
                                            }
                                        }
                                        if let Some(name) = cname {
                                            claims.push(RequestedClaim { name, required });
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            let id = id.ok_or_else(|| {
                GidError::new(
                    ErrorCode::MalformedMessage,
                    "missing 'id' in credential query",
                )
            })?;

            let q = CredentialQuery::new(id, vct_values, claims)?;
            queries.push(q);
        }

        Ok(Self {
            credentials: queries,
        })
    }

    /// Serializa la consulta a JSON canónico.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut creds_arr = Vec::with_capacity(self.credentials.len());

        for q in &self.credentials {
            let mut vct_arr = Vec::with_capacity(q.vct_values.len());
            for vct in &q.vct_values {
                vct_arr.push(Value::String(vct.as_str().to_string()));
            }

            let mut claims_arr = Vec::with_capacity(q.claims.len());
            for c in &q.claims {
                claims_arr.push(Value::Object(vec![
                    ("name".to_string(), Value::String(c.name.clone())),
                    ("required".to_string(), Value::Bool(c.required)),
                ]));
            }

            let q_obj = Value::Object(vec![
                ("claims".to_string(), Value::Array(claims_arr)),
                ("id".to_string(), Value::String(q.id.clone())),
                ("vct_values".to_string(), Value::Array(vct_arr)),
            ]);
            creds_arr.push(q_obj);
        }

        let root = Value::Object(vec![("credentials".to_string(), Value::Array(creds_arr))]);
        to_canonical_json(&root)
    }
}

impl fmt::Display for DcqlQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_canonical_json())
    }
}
