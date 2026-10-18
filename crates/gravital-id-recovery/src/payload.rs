//! Estructura de datos y serialización del contenido de la bóveda respaldada (`BackupPayload`).
//!
//! Trazabilidad:
//! - `REQ-REC-002`: Formato de respaldo versionado y estructurado.
//! - `REQ-STOR-001`: Cero datos personales persistidos fuera del cifrado.
//! - `ADR-0009`, `ADR-0027`, `ADR-0029`: Respaldo completo de credenciales, ranuras y roles.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use gravital_id_codec::base64url;
use gravital_id_codec::json::{parse_bytes, Limits, Number, Value};
use gravital_id_credential::to_canonical_json;
use gravital_id_crypto::secret::SecretBytes;
use gravital_id_types::UnixTime;
use zeroize::Zeroize;

use crate::error::RecoveryError;

/// Versión normativa del esquema del payload de respaldo.
pub const BACKUP_SCHEMA_VERSION: u16 = 1;

/// Límite máximo de bytes admitidos para deserializar un payload de respaldo (16 MiB).
pub const MAX_BACKUP_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// Registro de una credencial del titular en el paquete de respaldo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupCredential {
    /// Identificador local único de la credencial.
    pub id: String,
    /// Tipo de credencial verificable (`vct`).
    pub vct: String,
    /// Identificador URI del emisor de la credencial.
    pub issuer: String,
    /// Representación serializada compacta de la credencial SD-JWT emitida con sus disclosures.
    pub serialized_sd_jwt: String,
}

/// Registro de una ranura de dispositivo activo del titular (`ADR-0029`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupDeviceSlot {
    /// Clase de factor de dispositivo (`mobile`, `card`, `other`).
    pub device_factor_class: String,
    /// Índice de revocación asignado en la lista de estado del emisor.
    pub status_index: u64,
}

/// Registro de una vinculación de rol en un inquilino (`ADR-0027`, `pip-tenant-role-v1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupTenantRole {
    /// Identificador del inquilino o servicio federado.
    pub tenant_id: String,
    /// Tipo de credencial de rol (`vct`).
    pub role_vct: String,
    /// Identificador seudónimo consistente del titular en ese inquilino.
    pub tenant_subject_id: String,
}

/// Contenido estructurado de la bóveda del titular preparado para empaquetado o restaurado.
#[derive(Clone, PartialEq, Eq)]
pub struct BackupPayload {
    /// Versión del esquema del payload (`1`).
    pub schema_version: u16,
    /// Secreto maestro de recuperación para derivar claves de re-vinculación (`REQ-REC-004`).
    pub recovery_secret: SecretBytes<32>,
    /// Credenciales almacenadas del titular.
    pub credentials: Vec<BackupCredential>,
    /// Ranuras de factor de dispositivo registradas (`ADR-0029`).
    pub device_slots: Vec<BackupDeviceSlot>,
    /// Vinculaciones de rol en inquilinos conectados (`ADR-0027`).
    pub tenant_roles: Vec<BackupTenantRole>,
    /// Instante temporal de creación del respaldo.
    pub created_at: UnixTime,
}

impl BackupPayload {
    /// Crea un nuevo payload con versión de esquema actual.
    #[must_use]
    pub fn new(
        recovery_secret: SecretBytes<32>,
        credentials: Vec<BackupCredential>,
        device_slots: Vec<BackupDeviceSlot>,
        tenant_roles: Vec<BackupTenantRole>,
        created_at: UnixTime,
    ) -> Self {
        Self {
            schema_version: BACKUP_SCHEMA_VERSION,
            recovery_secret,
            credentials,
            device_slots,
            tenant_roles,
            created_at,
        }
    }

    /// Serializa el payload en un JSON canónico acotado.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, RecoveryError> {
        let mut cred_values = Vec::with_capacity(self.credentials.len());
        for c in &self.credentials {
            cred_values.push(Value::Object(vec![
                ("id".to_string(), Value::String(c.id.clone())),
                ("issuer".to_string(), Value::String(c.issuer.clone())),
                (
                    "serialized_sd_jwt".to_string(),
                    Value::String(c.serialized_sd_jwt.clone()),
                ),
                ("vct".to_string(), Value::String(c.vct.clone())),
            ]));
        }

        let mut slot_values = Vec::with_capacity(self.device_slots.len());
        for s in &self.device_slots {
            slot_values.push(Value::Object(vec![
                (
                    "class".to_string(),
                    Value::String(s.device_factor_class.clone()),
                ),
                (
                    "status_index".to_string(),
                    Value::Number(Number::PosInt(s.status_index)),
                ),
            ]));
        }

        let mut role_values = Vec::with_capacity(self.tenant_roles.len());
        for r in &self.tenant_roles {
            role_values.push(Value::Object(vec![
                ("role_vct".to_string(), Value::String(r.role_vct.clone())),
                ("tenant_id".to_string(), Value::String(r.tenant_id.clone())),
                (
                    "tenant_subject_id".to_string(),
                    Value::String(r.tenant_subject_id.clone()),
                ),
            ]));
        }

        let secret_b64 = base64url::encode(self.recovery_secret.expose_secret());

        let root = Value::Object(vec![
            (
                "created_at".to_string(),
                Value::Number(Number::PosInt(self.created_at.as_seconds())),
            ),
            ("credentials".to_string(), Value::Array(cred_values)),
            ("device_slots".to_string(), Value::Array(slot_values)),
            ("recovery_secret".to_string(), Value::String(secret_b64)),
            (
                "schema_version".to_string(),
                Value::Number(Number::PosInt(self.schema_version as u64)),
            ),
            ("tenant_roles".to_string(), Value::Array(role_values)),
        ]);

        Ok(to_canonical_json(&root).into_bytes())
    }

    /// Deserializa y valida un payload en JSON canónico, verificando límites de DoS.
    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, RecoveryError> {
        if bytes.len() > MAX_BACKUP_PAYLOAD_BYTES {
            return Err(RecoveryError::PayloadLimitExceeded(bytes.len()));
        }

        let limits = Limits {
            max_input_bytes: MAX_BACKUP_PAYLOAD_BYTES,
            max_depth: 16,
            max_elements: 65_536,
            max_string_bytes: 2 * 1024 * 1024,
        };

        let parsed = parse_bytes(bytes, &limits).map_err(|_| {
            RecoveryError::DeserializationFailed("formato JSON de payload inválido")
        })?;

        let obj = match parsed {
            Value::Object(map) => map,
            _ => {
                return Err(RecoveryError::DeserializationFailed(
                    "el payload raíz debe ser un objeto JSON",
                ))
            }
        };

        let find_field = |name: &str| -> Option<&Value> {
            obj.iter().find(|(k, _)| k.as_str() == name).map(|(_, v)| v)
        };

        let schema_ver = match find_field("schema_version") {
            Some(Value::Number(Number::PosInt(n))) => *n as u16,
            _ => {
                return Err(RecoveryError::DeserializationFailed(
                    "campo schema_version faltante o inválido",
                ))
            }
        };

        if schema_ver != BACKUP_SCHEMA_VERSION {
            return Err(RecoveryError::DeserializationFailed(
                "versión de esquema no soportada",
            ));
        }

        let created_at_sec = match find_field("created_at") {
            Some(Value::Number(Number::PosInt(n))) => *n,
            _ => {
                return Err(RecoveryError::DeserializationFailed(
                    "campo created_at faltante o inválido",
                ))
            }
        };

        let secret_str = match find_field("recovery_secret") {
            Some(Value::String(s)) => s,
            _ => {
                return Err(RecoveryError::DeserializationFailed(
                    "campo recovery_secret faltante o inválido",
                ))
            }
        };

        let secret_vec = base64url::decode(secret_str).map_err(|_| {
            RecoveryError::DeserializationFailed("recovery_secret no es Base64URL válido")
        })?;
        if secret_vec.len() != 32 {
            return Err(RecoveryError::DeserializationFailed(
                "recovery_secret debe tener exactamente 32 bytes",
            ));
        }
        let mut secret_arr = [0u8; 32];
        if let Some(src) = secret_vec.get(..32) {
            secret_arr.copy_from_slice(src);
        }
        let recovery_secret = SecretBytes::new(secret_arr);
        secret_arr.zeroize();

        // Parsear credentials
        let mut credentials = Vec::new();
        if let Some(Value::Array(items)) = find_field("credentials") {
            for item in items {
                if let Value::Object(c_map) = item {
                    let get_str = |k: &str| -> Option<String> {
                        c_map
                            .iter()
                            .find(|(key, _)| key.as_str() == k)
                            .and_then(|(_, val)| match val {
                                Value::String(s) => Some(s.clone()),
                                _ => None,
                            })
                    };
                    let id = get_str("id").unwrap_or_default();
                    let vct = get_str("vct").unwrap_or_default();
                    let issuer = get_str("issuer").unwrap_or_default();
                    let serialized_sd_jwt = get_str("serialized_sd_jwt").unwrap_or_default();
                    credentials.push(BackupCredential {
                        id,
                        vct,
                        issuer,
                        serialized_sd_jwt,
                    });
                }
            }
        }

        // Parsear device_slots
        let mut device_slots = Vec::new();
        if let Some(Value::Array(items)) = find_field("device_slots") {
            for item in items {
                if let Value::Object(s_map) = item {
                    let mut factor_class = "mobile".to_string();
                    let mut status_idx = 0u64;
                    for (k, v) in s_map {
                        if k == "class" {
                            if let Value::String(s) = v {
                                factor_class = s.clone();
                            }
                        } else if k == "status_index" {
                            if let Value::Number(Number::PosInt(n)) = v {
                                status_idx = *n;
                            }
                        }
                    }
                    device_slots.push(BackupDeviceSlot {
                        device_factor_class: factor_class,
                        status_index: status_idx,
                    });
                }
            }
        }

        // Parsear tenant_roles
        let mut tenant_roles = Vec::new();
        if let Some(Value::Array(items)) = find_field("tenant_roles") {
            for item in items {
                if let Value::Object(r_map) = item {
                    let get_str = |k: &str| -> Option<String> {
                        r_map
                            .iter()
                            .find(|(key, _)| key.as_str() == k)
                            .and_then(|(_, val)| match val {
                                Value::String(s) => Some(s.clone()),
                                _ => None,
                            })
                    };
                    let tenant_id = get_str("tenant_id").unwrap_or_default();
                    let role_vct = get_str("role_vct").unwrap_or_default();
                    let tenant_subject_id = get_str("tenant_subject_id").unwrap_or_default();
                    tenant_roles.push(BackupTenantRole {
                        tenant_id,
                        role_vct,
                        tenant_subject_id,
                    });
                }
            }
        }

        Ok(Self {
            schema_version: schema_ver,
            recovery_secret,
            credentials,
            device_slots,
            tenant_roles,
            created_at: UnixTime::from_seconds(created_at_sec),
        })
    }
}

impl core::fmt::Debug for BackupPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BackupPayload")
            .field("schema_version", &self.schema_version)
            .field("recovery_secret", &"***REDACTED***")
            .field("credentials_count", &self.credentials.len())
            .field("device_slots_count", &self.device_slots.len())
            .field("tenant_roles_count", &self.tenant_roles.len())
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec;

    #[test]
    fn test_payload_canonical_roundtrip() {
        let secret = SecretBytes::new([0xAA; 32]);
        let now = UnixTime::from_seconds(1_770_000_000);

        let credentials = vec![BackupCredential {
            id: "cred-01".to_string(),
            vct: "https://credentials.example.com/vct/id".to_string(),
            issuer: "https://issuer.example.com".to_string(),
            serialized_sd_jwt: "header.payload.signature~disc1~disc2~".to_string(),
        }];

        let device_slots = vec![BackupDeviceSlot {
            device_factor_class: "mobile".to_string(),
            status_index: 42,
        }];

        let tenant_roles = vec![BackupTenantRole {
            tenant_id: "hospital-san-fernando".to_string(),
            role_vct: "urn:pip:tenant:role:medico".to_string(),
            tenant_subject_id: "tenant-sub-123".to_string(),
        }];

        let payload = BackupPayload::new(secret, credentials, device_slots, tenant_roles, now);
        let json_bytes = payload.to_canonical_json().expect("to json");

        let restored = BackupPayload::from_canonical_json(&json_bytes).expect("from json");
        assert_eq!(payload.schema_version, restored.schema_version);
        assert_eq!(payload.recovery_secret, restored.recovery_secret);
        assert_eq!(payload.created_at, restored.created_at);
        assert_eq!(payload.credentials, restored.credentials);
        assert_eq!(payload.device_slots, restored.device_slots);
        assert_eq!(payload.tenant_roles, restored.tenant_roles);
    }

    #[test]
    fn test_payload_debug_redacted() {
        let payload = BackupPayload::new(
            SecretBytes::new([0x55; 32]),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            UnixTime::from_seconds(1_770_000_000),
        );
        let debug = format!("{payload:?}");
        assert!(debug.contains("***REDACTED***"));
        assert!(!debug.contains("0x55"));
    }
}
