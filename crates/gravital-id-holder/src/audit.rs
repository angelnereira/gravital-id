//! Registro local mínimo de eventos de auditoría para la wallet (REQ-STOR-006).
//!
//! Trazabilidad:
//! - `REQ-STOR-006`: La wallet DEBE registrar eventos de auditoría local (emisiones recibidas,
//!   presentaciones realizadas, claves rotadas, sincronizaciones) de forma apendible,
//!   con retención configurable y sin incluir datos personales ni identificadores
//!   correlacionables (P-09).
//! - `INV-02`: Ningún dato personal, ni hash de dato personal, ni identificador de titular
//!   va a logs ni a almacenamiento de auditoría.
//! - `REQ-PRIV-005`: No persistir presentaciones ni nonces.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use gravital_id_codec::json::{parse_bytes, Limits, Number, Value};
use gravital_id_credential::to_canonical_json;
use gravital_id_types::{ErrorCode, GidError, UnixTime, Vct};

/// Tipos de eventos auditables soportados por la wallet del titular (`REQ-STOR-006`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEventType {
    /// Se importó una nueva credencial verificable.
    CredentialImported {
        /// Tipo de credencial (VCT).
        vct: Vct,
    },
    /// Se construyó una presentación para un verificador.
    PresentationCreated {
        /// Tipo de credencial presentada.
        vct: Vct,
        /// Identificador local de la consulta DCQL respondida.
        query_id: String,
    },
    /// Se eliminó una credencial del almacenamiento.
    CredentialDeleted {
        /// Identificador local abstracto del registro eliminado.
        credential_id: String,
    },
    /// Se eliminó un lote de credenciales.
    BatchDeleted {
        /// Cantidad de registros eliminados.
        count: usize,
    },
    /// Se rotó una clave criptográfica del titular.
    KeyRotated {
        /// Identificador abstracto de la clave.
        key_id: String,
    },
    /// Se completó una sincronización de estado.
    SyncCompleted,
    /// Se purgaron registros antiguos del historial de auditoría.
    AuditLogPurged {
        /// Cantidad de registros depurados.
        records_removed: usize,
    },
}

/// Registro inmutable de un evento de auditoría local en la wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletAuditEvent {
    /// Identificador único del evento (ej. `evt_...`).
    pub event_id: String,
    /// Marca de tiempo Unix cuando ocurrió el evento.
    pub timestamp: UnixTime,
    /// Categoría y detalles abstractos del evento.
    pub event_type: AuditEventType,
}

impl WalletAuditEvent {
    /// Crea un nuevo evento de auditoría.
    #[must_use]
    pub fn new(
        event_id: impl Into<String>,
        timestamp: UnixTime,
        event_type: AuditEventType,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            timestamp,
            event_type,
        }
    }

    /// Serializa el evento a JSON canónico ordenado.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let (type_str, detail_kvs) = match &self.event_type {
            AuditEventType::CredentialImported { vct } => (
                "credential_imported",
                vec![("vct".to_string(), Value::String(vct.as_str().to_string()))],
            ),
            AuditEventType::PresentationCreated { vct, query_id } => (
                "presentation_created",
                vec![
                    ("query_id".to_string(), Value::String(query_id.clone())),
                    ("vct".to_string(), Value::String(vct.as_str().to_string())),
                ],
            ),
            AuditEventType::CredentialDeleted { credential_id } => (
                "credential_deleted",
                vec![(
                    "credential_id".to_string(),
                    Value::String(credential_id.clone()),
                )],
            ),
            AuditEventType::BatchDeleted { count } => (
                "batch_deleted",
                vec![(
                    "count".to_string(),
                    Value::Number(Number::PosInt(*count as u64)),
                )],
            ),
            AuditEventType::KeyRotated { key_id } => (
                "key_rotated",
                vec![("key_id".to_string(), Value::String(key_id.clone()))],
            ),
            AuditEventType::SyncCompleted => ("sync_completed", vec![]),
            AuditEventType::AuditLogPurged { records_removed } => (
                "audit_log_purged",
                vec![(
                    "records_removed".to_string(),
                    Value::Number(Number::PosInt(*records_removed as u64)),
                )],
            ),
        };

        let mut root_obj = vec![
            ("event_id".to_string(), Value::String(self.event_id.clone())),
            (
                "event_type".to_string(),
                Value::String(type_str.to_string()),
            ),
            (
                "timestamp".to_string(),
                Value::Number(Number::PosInt(self.timestamp.as_seconds())),
            ),
        ];

        if !detail_kvs.is_empty() {
            root_obj.push(("details".to_string(), Value::Object(detail_kvs)));
        }

        // Ordenar claves para JSON canónico
        root_obj.sort_by(|a, b| a.0.cmp(&b.0));
        to_canonical_json(&Value::Object(root_obj))
    }

    /// Deserializa un evento de auditoría desde JSON.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, GidError> {
        let val = parse_bytes(bytes, &Limits::profile_default()).map_err(|e| {
            GidError::new(
                ErrorCode::StorageReadFailed,
                format!("failed to parse audit event JSON: {e}"),
            )
        })?;

        let obj = match val {
            Value::Object(map) => map,
            _ => {
                return Err(GidError::new(
                    ErrorCode::StorageReadFailed,
                    "audit event JSON root must be an object",
                ))
            }
        };

        let mut event_id = None;
        let mut timestamp = None;
        let mut event_type_str = None;
        let mut details_map = Vec::new();

        for (k, v) in obj {
            match k.as_str() {
                "event_id" => {
                    if let Value::String(s) = v {
                        event_id = Some(s);
                    }
                }
                "timestamp" => {
                    if let Value::Number(Number::PosInt(secs)) = v {
                        timestamp = Some(UnixTime::from_seconds(secs));
                    }
                }
                "event_type" => {
                    if let Value::String(s) = v {
                        event_type_str = Some(s);
                    }
                }
                "details" => {
                    if let Value::Object(d) = v {
                        details_map = d;
                    }
                }
                _ => {}
            }
        }

        let event_id = event_id.ok_or_else(|| {
            GidError::new(
                ErrorCode::StorageReadFailed,
                "missing 'event_id' in audit event",
            )
        })?;
        let timestamp = timestamp.ok_or_else(|| {
            GidError::new(
                ErrorCode::StorageReadFailed,
                "missing 'timestamp' in audit event",
            )
        })?;
        let type_str = event_type_str.ok_or_else(|| {
            GidError::new(
                ErrorCode::StorageReadFailed,
                "missing 'event_type' in audit event",
            )
        })?;

        let event_type = match type_str.as_str() {
            "credential_imported" => {
                let vct_str = get_string_prop(&details_map, "vct")?;
                let vct = Vct::parse(&vct_str)?;
                AuditEventType::CredentialImported { vct }
            }
            "presentation_created" => {
                let vct_str = get_string_prop(&details_map, "vct")?;
                let vct = Vct::parse(&vct_str)?;
                let query_id = get_string_prop(&details_map, "query_id")?;
                AuditEventType::PresentationCreated { vct, query_id }
            }
            "credential_deleted" => {
                let credential_id = get_string_prop(&details_map, "credential_id")?;
                AuditEventType::CredentialDeleted { credential_id }
            }
            "batch_deleted" => {
                let count = get_u64_prop(&details_map, "count")? as usize;
                AuditEventType::BatchDeleted { count }
            }
            "key_rotated" => {
                let key_id = get_string_prop(&details_map, "key_id")?;
                AuditEventType::KeyRotated { key_id }
            }
            "sync_completed" => AuditEventType::SyncCompleted,
            "audit_log_purged" => {
                let records_removed = get_u64_prop(&details_map, "records_removed")? as usize;
                AuditEventType::AuditLogPurged { records_removed }
            }
            other => {
                return Err(GidError::new(
                    ErrorCode::StorageReadFailed,
                    format!("unknown audit event_type '{other}'"),
                ))
            }
        };

        Ok(Self {
            event_id,
            timestamp,
            event_type,
        })
    }
}

fn get_string_prop(kvs: &[(String, Value)], key: &str) -> Result<String, GidError> {
    for (k, v) in kvs {
        if k == key {
            if let Value::String(s) = v {
                return Ok(s.clone());
            }
        }
    }
    Err(GidError::new(
        ErrorCode::StorageReadFailed,
        format!("missing or invalid property '{key}' in audit details"),
    ))
}

fn get_u64_prop(kvs: &[(String, Value)], key: &str) -> Result<u64, GidError> {
    for (k, v) in kvs {
        if k == key {
            if let Value::Number(Number::PosInt(n)) = v {
                return Ok(*n);
            }
        }
    }
    Err(GidError::new(
        ErrorCode::StorageReadFailed,
        format!("missing or invalid integer property '{key}' in audit details"),
    ))
}
