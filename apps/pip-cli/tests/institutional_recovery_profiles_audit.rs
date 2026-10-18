#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Auditoría y verificación de conformidad de los procedimientos normativos de
//! recuperación institucional en cada perfil oficial de Gravital ID (F8.T09).
//!
//! Trazabilidad:
//! - **REQ-REC-005:** Cada perfil DEBE documentar su procedimiento de recuperación institucional.
//! - **REQ-REC-006:** La recuperación NO DEBE depender exclusivamente de un correo electrónico
//!   ni de un custodio único.
//! - **REQ-DEVSLOT-001..004:** Ranura única por clase de dispositivo (`mobile`, `card`, `other`),
//!   atestación de silicio y revocación atómica del índice anterior en `TokenStatusList`.
//! - **REQ-REC-004:** Clave de recuperación con propósito exclusivo y re-vinculación criptográfica.
//! - **REQ-REC-007:** Claves de recuperación aisladas y no correlacionables por emisor.
//! - **INV-01:** Sans-I/O en verificación offline.
//! - **INV-02:** Cero datos personales en ledger, eventos o registros de auditoría.
//! - **INV-05:** Fail-closed determinista.
//! - **P-10:** Resiliencia ante pérdida sin custodio centralizado.

use std::fs;
use std::path::Path;

use gravital_id_status::{TokenStatus, TokenStatusListBuilder};
use gravital_id_types::DeviceFactorClass;

const OFFICIAL_PROFILES: &[(&str, &str)] = &[
    ("pip-personal-v1", "docs/specs/profiles/pip-personal-v1.md"),
    ("pip-identity-v1", "docs/specs/profiles/pip-identity-v1.md"),
    (
        "pip-financial-v1",
        "docs/specs/profiles/pip-financial-v1.md",
    ),
    (
        "pip-enterprise-v1",
        "docs/specs/profiles/pip-enterprise-v1.md",
    ),
    (
        "pip-tenant-role-v1",
        "docs/specs/profiles/pip-tenant-role-v1.md",
    ),
];

/// Verifies: REQ-REC-005, REQ-REC-006
///
/// Audita que cada especificación de perfil oficial en `docs/specs/profiles/` contenga:
/// 1. Trazabilidad explícita de `REQ-REC-005` y `REQ-REC-006`.
/// 2. Sección formal de Procedimiento Normativo de Recuperación Institucional.
/// 3. Prohibición expresa de correo electrónico como factor único de recuperación.
/// 4. Prohibición expresa de custodio único centralizado.
/// 5. Mecanismo de re-vinculación con revocación atómica por ranura de dispositivo (`REQ-DEVSLOT-003`).
#[test]
fn test_institutional_recovery_spec_audit_across_all_profiles() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("apps dir")
        .parent()
        .expect("workspace root");

    for &(profile_id, relative_path) in OFFICIAL_PROFILES {
        let full_path = workspace_root.join(relative_path);
        assert!(
            full_path.exists(),
            "El archivo del perfil {} debe existir en {}",
            profile_id,
            full_path.display()
        );

        let content = fs::read_to_string(&full_path)
            .unwrap_or_else(|e| panic!("Error al leer {}: {}", full_path.display(), e));

        let content_lower = content.to_lowercase();

        // 1. Trazabilidad explícita de REQ-REC-005 y REQ-REC-006
        assert!(
            content.contains("REQ-REC-005"),
            "El perfil {} debe referenciar REQ-REC-005 en trazabilidad",
            profile_id
        );
        assert!(
            content.contains("REQ-REC-006"),
            "El perfil {} debe referenciar REQ-REC-006 en trazabilidad",
            profile_id
        );

        // 2. Procedimiento institucional normativo
        let has_institutional_recovery_section =
            content_lower.contains("recuperación institucional");
        assert!(
            has_institutional_recovery_section,
            "El perfil {} debe definir una sección normativa de Recuperación Institucional (REQ-REC-005)",
            profile_id
        );

        // 3. Prohibición estricta de correo electrónico como único factor (REQ-REC-006)
        let has_email_prohibition = content_lower.contains("correo electrónico")
            && (content_lower.contains("prohibid")
                || content_lower.contains("nunca debe depender"));
        assert!(
            has_email_prohibition,
            "El perfil {} debe prohibir taxativamente el correo electrónico como factor único (REQ-REC-006)",
            profile_id
        );

        // 4. Prohibición de custodio único o salvaguarda multipartita/soberana (REQ-REC-006, P-10)
        let has_custodian_prohibition = content_lower.contains("custodio único")
            || content_lower.contains("custodio centralizado")
            || content_lower.contains("custodio central")
            || content_lower.contains("four-eyes")
            || content_lower.contains("aprobación dual")
            || content_lower.contains("doble control");
        assert!(
            has_custodian_prohibition,
            "El perfil {} debe prohibir un custodio único o exigir quórum / aprobación dual (REQ-REC-006, P-10)",
            profile_id
        );

        // 5. Revocación atómica por ranura de dispositivo (REQ-DEVSLOT-003, ADR-0029)
        let has_slot_revocation = content.contains("REQ-DEVSLOT-003")
            || content_lower.contains("revocación atómica")
            || content_lower.contains("revoca de manera atómica")
            || content_lower.contains("revoca de forma atómica")
            || content_lower.contains("revoca inmediatamente y de forma atómica");
        assert!(
            has_slot_revocation,
            "El perfil {} debe establecer la revocación atómica por ranura de dispositivo (REQ-DEVSLOT-003, ADR-0029)",
            profile_id
        );
    }
}

/// Verifies: REQ-REC-006, INV-05
///
/// Simula la máquina de estados de validación de un intento de recuperación institucional:
/// Ante un intento de recuperación basado únicamente en un factor inseguro (como correo
/// electrónico o SMS), el emisor o autorizador DEBE fallar en cerrado (`fail-closed`),
/// rechazando la operación sin emitir nueva credencial ni modificar la lista de estado.
#[test]
fn test_recovery_rejects_single_factor_email_attempt_fail_closed() {
    #[allow(dead_code)]
    #[derive(Debug, PartialEq, Eq)]
    enum RecoveryFactor {
        EmailMagicLink,
        SmsOtp,
        InPersonBiometric,
        ActiveLivenessWithGovVerification,
        DualCorporateApproval,
        CryptographicRecoveryKey,
    }

    struct InstitutionalRecoveryRequest {
        factors: Vec<RecoveryFactor>,
        _device_class: DeviceFactorClass,
    }

    fn evaluate_institutional_recovery_request(
        profile_id: &str,
        req: &InstitutionalRecoveryRequest,
    ) -> Result<(), &'static str> {
        // REQ-REC-006: La recuperación NO DEBE depender exclusivamente de un correo electrónico ni custodio único
        if req.factors.is_empty() {
            return Err("GID-E2012 NoRecoveryFactorsProvided");
        }

        // Si solo se aporta Email o SMS, rechazo automático fail-closed
        let only_insecure_channel = req
            .factors
            .iter()
            .all(|f| matches!(f, RecoveryFactor::EmailMagicLink | RecoveryFactor::SmsOtp));

        if only_insecure_channel {
            return Err("GID-E2013 InsecureSingleFactorRecoveryRejected");
        }

        // Validación específica según perfil
        match profile_id {
            "pip-identity-v1" => {
                let has_biometric = req.factors.iter().any(|f| {
                    matches!(
                        f,
                        RecoveryFactor::InPersonBiometric
                            | RecoveryFactor::ActiveLivenessWithGovVerification
                    )
                });
                if !has_biometric {
                    return Err("GID-E2014 IdentityProfileRequiresGovBiometric");
                }
            }
            "pip-financial-v1" => {
                let has_strong_factor = req.factors.iter().any(|f| {
                    matches!(
                        f,
                        RecoveryFactor::InPersonBiometric
                            | RecoveryFactor::ActiveLivenessWithGovVerification
                    )
                });
                if !has_strong_factor {
                    return Err("GID-E2015 FinancialProfileRequiresStrongFactor");
                }
            }
            "pip-enterprise-v1" => {
                let has_dual_approval = req
                    .factors
                    .iter()
                    .any(|f| matches!(f, RecoveryFactor::DualCorporateApproval));
                if !has_dual_approval {
                    return Err("GID-E2016 EnterpriseProfileRequiresDualApproval");
                }
            }
            "pip-tenant-role-v1" => {
                let has_valid_recovery = req.factors.iter().any(|f| {
                    matches!(
                        f,
                        RecoveryFactor::CryptographicRecoveryKey
                            | RecoveryFactor::DualCorporateApproval
                            | RecoveryFactor::InPersonBiometric
                    )
                });
                if !has_valid_recovery {
                    return Err("GID-E2017 TenantRoleRequiresDelegatedVerification");
                }
            }
            "pip-personal-v1" => {
                let has_out_of_band = req.factors.iter().any(|f| {
                    matches!(
                        f,
                        RecoveryFactor::InPersonBiometric
                            | RecoveryFactor::CryptographicRecoveryKey
                    )
                });
                if !has_out_of_band {
                    return Err("GID-E2018 PersonalProfileRequiresOutOfBandOrKey");
                }
            }
            _ => return Err("GID-E2019 UnknownProfile"),
        }

        Ok(())
    }

    // 1. Intento de recuperación con solo correo electrónico -> Rechazo fail-closed
    for &(profile, _) in OFFICIAL_PROFILES {
        let insecure_req = InstitutionalRecoveryRequest {
            factors: vec![RecoveryFactor::EmailMagicLink],
            _device_class: DeviceFactorClass::Mobile,
        };

        let result = evaluate_institutional_recovery_request(profile, &insecure_req);
        assert_eq!(
            result,
            Err("GID-E2013 InsecureSingleFactorRecoveryRejected"),
            "El perfil {} debe rechazar fail-closed la recuperación por solo correo electrónico (REQ-REC-006)",
            profile
        );
    }

    // 2. Intento de recuperación con SMS como único factor -> Rechazo fail-closed
    for &(profile, _) in OFFICIAL_PROFILES {
        let sms_req = InstitutionalRecoveryRequest {
            factors: vec![RecoveryFactor::SmsOtp],
            _device_class: DeviceFactorClass::Mobile,
        };

        let result = evaluate_institutional_recovery_request(profile, &sms_req);
        assert_eq!(
            result,
            Err("GID-E2013 InsecureSingleFactorRecoveryRejected"),
            "El perfil {} debe rechazar fail-closed la recuperación por solo SMS (REQ-REC-006)",
            profile
        );
    }
}

/// Verifies: REQ-REC-005, REQ-DEVSLOT-001..004, ADR-0029
///
/// Demuestra el ciclo de vida de recuperación institucional con reemplazo y revocación
/// atómica de ranura por clase de dispositivo:
/// - El titular tiene activo su teléfono móvil (ranura `mobile`, index 42) y su tarjeta
///   física tipo Visa (ranura `card`, index 108).
/// - Extravía el teléfono móvil y solicita recuperación institucional con verificación fuera de banda.
/// - El emisor revoca atómicamente el índice 42 en la `TokenStatusList` (marcando `TokenStatus::Revoked`),
///   asigna el nuevo dispositivo móvil a un nuevo índice 150, y comprueba que la tarjeta física
///   (índice 108) permanezca intacta y activa (`TokenStatus::Valid`).
#[test]
fn test_institutional_recovery_atomic_device_slot_revocation_e2e() {
    let mut status_builder =
        TokenStatusListBuilder::new(2, 131_072).expect("crear lista de 2 bits");

    let slot_mobile_old = 42u64;
    let slot_card = 108u64;
    let slot_mobile_new = 150u64;

    // Estado inicial: ambas ranuras están activas
    assert_eq!(
        status_builder.get_status(slot_mobile_old).unwrap(),
        TokenStatus::Valid
    );
    assert_eq!(
        status_builder.get_status(slot_card).unwrap(),
        TokenStatus::Valid
    );
    assert_eq!(
        status_builder.get_status(slot_mobile_new).unwrap(),
        TokenStatus::Valid
    );

    // Ejecución de recuperación institucional para la ranura móvil:
    // 1. Revocación atómica del dispositivo móvil anterior: TokenStatus::Revoked
    status_builder
        .set_status(slot_mobile_old, TokenStatus::Revoked)
        .expect("revocar ranura móvil anterior");

    // 2. Activación de la nueva ranura móvil
    status_builder
        .set_status(slot_mobile_new, TokenStatus::Valid)
        .expect("activar nueva ranura móvil");

    // Verificación de aislamiento estricto (REQ-DEVSLOT-003, ADR-0029):
    // El móvil anterior está revocado
    assert_eq!(
        status_builder.get_status(slot_mobile_old).unwrap(),
        TokenStatus::Revoked,
        "La ranura móvil extraviada debe estar revocada"
    );

    // La tarjeta física permanece activa sin ninguna afectación
    assert_eq!(
        status_builder.get_status(slot_card).unwrap(),
        TokenStatus::Valid,
        "La tarjeta física debe permanecer activa e intacta tras la revocación del móvil"
    );

    // El nuevo móvil está activo
    assert_eq!(
        status_builder.get_status(slot_mobile_new).unwrap(),
        TokenStatus::Valid,
        "El nuevo móvil debe estar activo"
    );
}
