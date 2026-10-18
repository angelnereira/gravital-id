//! Gestor de alto nivel para exportación y restauración de respaldos (`RecoveryManager`).
//!
//! Trazabilidad:
//! - `REQ-REC-002`: Respaldo cifrado protegido con código de recuperación.
//! - `INV-01`: Cero dependencias de red en capa L3.
//! - `INV-02`: Ausencia de datos personales en errores o metadatos en claro.
//! - `INV-05`: Fail-closed ante cualquier fallo criptográfico o de formato.

use alloc::vec::Vec;

use gravital_id_crypto::Rng;
use gravital_id_types::UnixTime;

use crate::code::RecoveryCode;
use crate::error::RecoveryError;
use crate::package::EncryptedBackupPackage;
use crate::payload::BackupPayload;

/// Gestor de operaciones de recuperación y respaldo del titular.
pub struct RecoveryManager;

impl RecoveryManager {
    /// Exporta el contenido de la bóveda del titular a un paquete binario cifrado y autenticado.
    pub fn export_backup<R: Rng>(
        payload: &BackupPayload,
        code: &RecoveryCode,
        created_at: UnixTime,
        rng: &R,
    ) -> Result<Vec<u8>, RecoveryError> {
        let json_bytes = payload.to_canonical_json()?;
        EncryptedBackupPackage::seal(&json_bytes, code, created_at, rng)
    }

    /// Restaura y verifica íntegramente el contenido de la bóveda a partir de un paquete binario y el código.
    pub fn restore_backup(
        package_bytes: &[u8],
        code: &RecoveryCode,
    ) -> Result<BackupPayload, RecoveryError> {
        let decrypted_bytes = EncryptedBackupPackage::open(package_bytes, code)?;
        BackupPayload::from_canonical_json(&decrypted_bytes)
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
    use crate::payload::{BackupCredential, BackupDeviceSlot, BackupTenantRole};
    use alloc::vec;
    use gravital_id_crypto::secret::SecretBytes;
    use gravital_id_testkit::SeededRng;

    #[test]
    fn test_manager_export_and_restore_full_journey() {
        let rng = SeededRng::new(0xBEEF);
        let code = RecoveryCode::generate(&rng).expect("generate recovery code");
        let now = UnixTime::from_seconds(1_770_000_123);

        let credentials = vec![BackupCredential {
            id: "cred-cedula-01".into(),
            vct: "https://credentials.te.gob.pa/vct/cedula-v1".into(),
            issuer: "https://issuer.te.gob.pa".into(),
            serialized_sd_jwt: "sdjwt-payload-and-disclosures~".into(),
        }];

        let device_slots = vec![
            BackupDeviceSlot {
                device_factor_class: "mobile".into(),
                status_index: 101,
            },
            BackupDeviceSlot {
                device_factor_class: "card".into(),
                status_index: 202,
            },
        ];

        let tenant_roles = vec![BackupTenantRole {
            tenant_id: "hospital-nacional".into(),
            role_vct: "urn:pip:tenant:role:medico".into(),
            tenant_subject_id: "tenant-sub-456".into(),
        }];

        let payload = BackupPayload::new(
            SecretBytes::new([0x77; 32]),
            credentials,
            device_slots,
            tenant_roles,
            now,
        );

        // 1. Exportar respaldo
        let package_bytes =
            RecoveryManager::export_backup(&payload, &code, now, &rng).expect("export backup");
        assert!(!package_bytes.is_empty());

        // 2. Restaurar con código correcto
        let restored =
            RecoveryManager::restore_backup(&package_bytes, &code).expect("restore backup");

        assert_eq!(restored.schema_version, payload.schema_version);
        assert_eq!(restored.recovery_secret, payload.recovery_secret);
        assert_eq!(restored.credentials, payload.credentials);
        assert_eq!(restored.device_slots, payload.device_slots);
        assert_eq!(restored.tenant_roles, payload.tenant_roles);

        // 3. Restaurar con código incorrecto debe fallar de forma cerrada
        let wrong_code = RecoveryCode::generate(&rng).expect("generate recovery code");
        let err = RecoveryManager::restore_backup(&package_bytes, &wrong_code);
        assert!(matches!(err, Err(RecoveryError::DecryptionFailed)));
    }
}
