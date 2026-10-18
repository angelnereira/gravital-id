//! Gestor de ranuras por clase de dispositivo y reemplazo atómico (`ADR-0029`, `REQ-DEVSLOT-001..004`, `REQ-ISS-006`).
//!
//! Trazabilidad:
//! - **REQ-DEVSLOT-001:** Ranura única por clase de dispositivo (`DeviceFactorClass`: `mobile`, `card`, `other`).
//!   Un titular solo puede mantener un dispositivo activo por clase simultáneamente.
//! - **REQ-DEVSLOT-002:** Independencia entre clases de dispositivo (un titular puede portar 1 móvil y 1 tarjeta).
//! - **REQ-DEVSLOT-003:** Reemplazo atómico por clase: revocación del dispositivo anterior en `TokenStatusList`
//!   sin alterar los dispositivos activos de otras clases.
//! - **REQ-DEVSLOT-004:** Privacidad y no correlación: ningún identificador permanente de hardware en claro.
//! - **REQ-REC-004:** Clave de recuperación exclusiva (`KeyPurpose::HolderRecovery`).
//! - **REQ-ISS-006:** Re-emisión y re-vinculación con revocación atómica en Token Status List.
//! - **INV-01:** Sin I/O de red (`no_std` + `alloc`).
//! - **INV-02:** Cero datos personales o secretos en logs o errores.
//! - **INV-03:** Claves privadas del titular generadas en silicio y nunca extraídas.
//! - **INV-05:** Fail-closed ante cualquier inconsistencia de firma, huella o desafío.
//! - **INV-10:** Sin pánicos ni unwraps.
//! - **INV-11:** Tiempo inyectado deterministamente.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use gravital_id_crypto::jwk::JwkEcP256;
use gravital_id_crypto::sha::sha256;
use gravital_id_crypto::sign::verify_es256_digest_jwk;
use gravital_id_crypto::Rng;
use gravital_id_keys::{KeyHandle, KeyStore, SigningPurpose};
use gravital_id_types::{DeviceFactorClass, ErrorCode, GidError, Kid, UnixTime};

use crate::request::CredentialRequest;
use crate::status_manager::IssuerStatusManager;
use crate::{IssuedCredential, Issuer};

/// Información de una ranura activa de dispositivo asignada a un titular (`ADR-0029`, `REQ-DEVSLOT-001`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveDeviceSlot {
    /// Clase de factor de dispositivo (`mobile`, `card`, `other`).
    pub device_class: DeviceFactorClass,
    /// Identificador de la lista de estado donde se aloja el índice asignado.
    pub status_list_id: String,
    /// Índice dentro de la Token Status List del emisor.
    pub status_index: u64,
    /// Clave pública de vinculación de silicio del dispositivo (`cnf.jwk`).
    pub holder_key: JwkEcP256,
    /// Instante de emisión / activación.
    pub issued_at: UnixTime,
    /// Instante de expiración (si aplica).
    pub expires_at: Option<UnixTime>,
}

/// Resultado del proceso de re-vinculación y reemplazo atómico por clase de dispositivo (`REQ-DEVSLOT-003`).
#[derive(Debug, Clone, PartialEq)]
pub struct AtomicRebindingResult {
    /// Nueva credencial emitida y firmada con la clave del nuevo dispositivo.
    pub issued_credential: IssuedCredential,
    /// Ranura previa revocada atómicamente en la Token Status List (si existía una para esta clase).
    pub revoked_slot: Option<ActiveDeviceSlot>,
    /// Nueva ranura activa registrada para esta clase.
    pub active_slot: ActiveDeviceSlot,
}

/// Gestor institucional de ranuras por clase de dispositivo del emisor (`ADR-0029`, `REQ-DEVSLOT-001..004`).
///
/// Mantiene en memoria el registro `recovery_thumbprint -> (DeviceFactorClass -> ActiveDeviceSlot)`.
/// Cada titular puede tener como máximo un dispositivo activo por clase (`mobile`, `card`, `other`).
#[derive(Debug, Clone, Default)]
pub struct DeviceSlotManager {
    slots: BTreeMap<String, BTreeMap<DeviceFactorClass, ActiveDeviceSlot>>,
}

/// Parámetros de autorización y destino para la ejecución de re-vinculación en el emisor (`SPEC-PIP-REBIND-001`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebindingExecutionParams<'a> {
    /// URI del emisor declarada en el desafío.
    pub issuer_uri: &'a str,
    /// Nonce del desafío de un solo uso.
    pub nonce: &'a str,
    /// Instante en que expira el desafío.
    pub challenge_expires_at: UnixTime,
    /// Clase de factor de forma solicitada (`mobile`, `card`, `other`).
    pub device_class: DeviceFactorClass,
    /// Clave pública de silicio del nuevo dispositivo.
    pub new_holder_key: JwkEcP256,
    /// Clave pública de recuperación del titular asociada a su cuenta.
    pub recovery_public_key: &'a JwkEcP256,
    /// Firma digital P1363 (64 bytes) sobre el transcrito canónico.
    pub signature: &'a [u8; 64],
    /// Identificador preferente de lista de estado (opcional).
    pub preferred_status_list_id: Option<&'a str>,
    /// Instante actual inyectado (INV-11).
    pub now: UnixTime,
}

/// Contexto de almacén de claves y CSPRNG del emisor para la firma de credenciales.
pub struct IssuerSigningContext<'a, S: KeyStore, P: SigningPurpose, R: Rng> {
    /// Almacén de claves del emisor (INV-03).
    pub key_store: &'a S,
    /// Handle de la clave de firma del emisor.
    pub signing_key: &'a KeyHandle<P>,
    /// Identificador de clave de firma opcional (`kid`).
    pub kid: Option<Kid>,
    /// Generador CSPRNG inyectado (INV-11).
    pub rng: &'a R,
}

impl DeviceSlotManager {
    /// Crea un nuevo gestor de ranuras de dispositivo vacío.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: BTreeMap::new(),
        }
    }

    /// Consulta la ranura activa de un titular para una clase de dispositivo concreta.
    #[must_use]
    pub fn active_slot(
        &self,
        recovery_thumbprint: &str,
        device_class: DeviceFactorClass,
    ) -> Option<&ActiveDeviceSlot> {
        self.slots
            .get(recovery_thumbprint)
            .and_then(|class_map| class_map.get(&device_class))
    }

    /// Lista todas las ranuras activas de un titular entre todas las clases.
    #[must_use]
    pub fn active_slots_for_holder(&self, recovery_thumbprint: &str) -> Vec<ActiveDeviceSlot> {
        self.slots
            .get(recovery_thumbprint)
            .map(|class_map| class_map.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Indica si el titular ya posee una ranura activa en la clase solicitada.
    #[must_use]
    pub fn has_active_slot(
        &self,
        recovery_thumbprint: &str,
        device_class: DeviceFactorClass,
    ) -> bool {
        self.active_slot(recovery_thumbprint, device_class)
            .is_some()
    }

    /// Número total de ranuras activas registradas en el emisor.
    #[must_use]
    pub fn total_active_slots(&self) -> usize {
        self.slots.values().map(BTreeMap::len).sum()
    }

    /// Número total de titulares registrados con al menos una ranura activa.
    #[must_use]
    pub fn total_registered_holders(&self) -> usize {
        self.slots.len()
    }

    /// Registra la ranura inicial de un dispositivo para un titular (`REQ-DEVSLOT-001`, `ADR-0029`).
    ///
    /// # Errores
    /// [`ErrorCode::DuplicateDeviceClassActive`] si el titular ya posee un dispositivo activo en
    /// esa misma clase (`REQ-DEVSLOT-001`). En tal caso debe utilizarse el protocolo de re-vinculación.
    pub fn register_initial_slot(
        &mut self,
        recovery_thumbprint: &str,
        slot: ActiveDeviceSlot,
    ) -> Result<(), GidError> {
        if self.has_active_slot(recovery_thumbprint, slot.device_class) {
            return Err(GidError::new(
                ErrorCode::DuplicateDeviceClassActive,
                format!(
                    "device slot for class '{}' is already active for this holder; use atomic rebinding to replace",
                    slot.device_class.as_str()
                ),
            ));
        }

        self.slots
            .entry(recovery_thumbprint.to_string())
            .or_default()
            .insert(slot.device_class, slot);

        Ok(())
    }

    /// Reemplaza atómicamente la ranura de una clase de dispositivo (`REQ-DEVSLOT-003`, `ADR-0029`).
    ///
    /// Devuelve `Some(ActiveDeviceSlot)` con la ranura previa si existía, o `None` si es la primera
    /// asignación en dicha clase.
    pub fn replace_slot_atomic(
        &mut self,
        recovery_thumbprint: &str,
        new_slot: ActiveDeviceSlot,
    ) -> Option<ActiveDeviceSlot> {
        self.slots
            .entry(recovery_thumbprint.to_string())
            .or_default()
            .insert(new_slot.device_class, new_slot)
    }

    /// Revoca y elimina la ranura de una clase de dispositivo de un titular.
    pub fn revoke_slot(
        &mut self,
        recovery_thumbprint: &str,
        device_class: DeviceFactorClass,
    ) -> Option<ActiveDeviceSlot> {
        let class_map = self.slots.get_mut(recovery_thumbprint)?;
        let removed = class_map.remove(&device_class);
        if class_map.is_empty() {
            self.slots.remove(recovery_thumbprint);
        }
        removed
    }

    /// Ejecuta la re-vinculación y reemplazo atómico por clase de dispositivo (`SPEC-PIP-REBIND-001`, `ADR-0029`, `REQ-DEVSLOT-003`).
    ///
    /// Pasos normativos:
    /// 1. Valida la frescura del desafío (`params.now <= params.challenge_expires_at`).
    /// 2. Valida la firma de re-vinculación sobre el transcrito canónico contra `recovery_public_key` (`REQ-REC-004`).
    /// 3. Si existía una ranura activa en `device_class`:
    ///    - Revoca su índice en `IssuerStatusManager` marcándolo como `TokenStatus::Revoked`.
    ///    - Deja inalteradas y válidas todas las ranuras de otras clases (`REQ-DEVSLOT-003`).
    /// 4. Asigna un nuevo índice en `IssuerStatusManager`.
    /// 5. Emite la nueva credencial con `new_holder_key` y `recovery_thumbprint`.
    /// 6. Registra la nueva ranura activa en el gestor.
    ///
    /// # Errores
    /// - [`ErrorCode::CredentialExpired`] si el desafío ha expirado.
    /// - [`ErrorCode::InvalidSignature`] si la firma de re-vinculación no verifica.
    /// - [`ErrorCode::MalformedMessage`] si la huella de recuperación no concuerda.
    /// - Los errores de asignación de estado o emisión de credencial.
    pub fn execute_atomic_rebinding<S: KeyStore, P: SigningPurpose, R: Rng>(
        &mut self,
        params: &RebindingExecutionParams<'_>,
        base_request: &CredentialRequest,
        status_manager: &mut IssuerStatusManager,
        signing_ctx: &IssuerSigningContext<'_, S, P, R>,
    ) -> Result<AtomicRebindingResult, GidError> {
        // 1. Validar frescura del desafío (INV-11)
        if params.now.as_seconds() > params.challenge_expires_at.as_seconds() {
            return Err(GidError::new(
                ErrorCode::CredentialExpired,
                "rebinding challenge has expired",
            ));
        }

        // 2. Transcrito canónico y validación de firma digital ES256 (SPEC-PIP-REBIND-001)
        let new_holder_thumbprint = params.new_holder_key.thumbprint_base64url();
        let transcript = format!(
            "pip-rebinding-v1:{}:{}:{}:{}",
            params.issuer_uri.trim(),
            params.nonce.trim(),
            params.device_class.as_str(),
            new_holder_thumbprint.trim()
        );
        let digest = sha256(transcript.as_bytes());

        verify_es256_digest_jwk(params.recovery_public_key, &digest, params.signature)?;

        // 3. Huella canónica RFC 9278 URI de recuperación
        let recovery_thumbprint_uri = params.recovery_public_key.thumbprint_uri();
        if let Some(req_rec) = base_request.recovery_thumbprint_ref() {
            if req_rec != recovery_thumbprint_uri
                && req_rec != params.recovery_public_key.thumbprint_base64url()
            {
                return Err(GidError::new(
                    ErrorCode::MalformedMessage,
                    "recovery thumbprint in request does not match recovery public key",
                ));
            }
        }

        // 4. REQ-DEVSLOT-003: Revocación atómica del dispositivo anterior de esa misma clase
        let old_slot = self
            .active_slot(&recovery_thumbprint_uri, params.device_class)
            .cloned();
        if let Some(ref old) = old_slot {
            status_manager.revoke(&old.status_list_id, old.status_index)?;
        }

        // 5. Asignación de nuevo índice de estado
        let (allocated_list_id, allocation) = status_manager
            .allocate_with_list_id(params.preferred_status_list_id, signing_ctx.rng)?;

        // 6. Construir solicitud derivada y emitir nueva credencial
        let rebinding_request = base_request.clone_for_rebinding(
            params.new_holder_key.clone(),
            &recovery_thumbprint_uri,
            allocation.clone(),
        );

        let issued = Issuer::issue(
            &rebinding_request,
            signing_ctx.key_store,
            signing_ctx.signing_key,
            signing_ctx.kid.clone(),
            signing_ctx.rng,
        )?;

        // 7. Registrar nueva ranura activa
        let new_slot = ActiveDeviceSlot {
            device_class: params.device_class,
            status_list_id: allocated_list_id,
            status_index: allocation.idx,
            holder_key: params.new_holder_key.clone(),
            issued_at: base_request.issued_at(),
            expires_at: base_request.expires_at_ref(),
        };

        self.replace_slot_atomic(&recovery_thumbprint_uri, new_slot.clone());

        Ok(AtomicRebindingResult {
            issued_credential: issued,
            revoked_slot: old_slot,
            active_slot: new_slot,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use gravital_id_crypto::secret::SecretKeyBytes;
    use gravital_id_crypto::sign::{generate_p256_secret_key, public_key_from_secret_key};
    use gravital_id_types::UnixTime;

    struct DeterministicRng([u8; 32]);
    impl Rng for DeterministicRng {
        fn fill_32_bytes(&self) -> Result<[u8; 32], GidError> {
            Ok(self.0)
        }
        fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), GidError> {
            dest.fill(self.0[0]);
            Ok(())
        }
    }

    fn sample_key(byte: u8) -> (SecretKeyBytes, JwkEcP256) {
        let rng = DeterministicRng([byte; 32]);
        let sec = generate_p256_secret_key(&rng).unwrap();
        let pubk = public_key_from_secret_key(&sec).unwrap();
        (sec, pubk)
    }

    #[test]
    fn test_device_slot_exclusivity_and_independence() {
        let mut manager = DeviceSlotManager::new();
        let holder_rec = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:abc123holder";

        let (_, phone1_jwk) = sample_key(0x11);
        let (_, card_jwk) = sample_key(0x22);
        let (_, phone2_jwk) = sample_key(0x33);

        let phone_slot = ActiveDeviceSlot {
            device_class: DeviceFactorClass::Mobile,
            status_list_id: "sl-01".into(),
            status_index: 10,
            holder_key: phone1_jwk,
            issued_at: UnixTime::from_seconds(1700000000),
            expires_at: None,
        };

        // 1. Alta exitosa de ranura móvil
        assert!(manager
            .register_initial_slot(holder_rec, phone_slot.clone())
            .is_ok());
        assert!(manager.has_active_slot(holder_rec, DeviceFactorClass::Mobile));
        assert!(!manager.has_active_slot(holder_rec, DeviceFactorClass::Card));

        // 2. REQ-DEVSLOT-002: Coexistencia con tarjeta física (clase distinta)
        let card_slot = ActiveDeviceSlot {
            device_class: DeviceFactorClass::Card,
            status_list_id: "sl-01".into(),
            status_index: 20,
            holder_key: card_jwk,
            issued_at: UnixTime::from_seconds(1700000000),
            expires_at: None,
        };
        assert!(manager.register_initial_slot(holder_rec, card_slot).is_ok());
        assert!(manager.has_active_slot(holder_rec, DeviceFactorClass::Mobile));
        assert!(manager.has_active_slot(holder_rec, DeviceFactorClass::Card));
        assert_eq!(manager.active_slots_for_holder(holder_rec).len(), 2);

        // 3. REQ-DEVSLOT-001: Rechazo de duplicidad en la misma clase sin reemplazo atómico
        let duplicate_phone = ActiveDeviceSlot {
            device_class: DeviceFactorClass::Mobile,
            status_list_id: "sl-01".into(),
            status_index: 30,
            holder_key: phone2_jwk,
            issued_at: UnixTime::from_seconds(1700000100),
            expires_at: None,
        };
        let err = manager
            .register_initial_slot(holder_rec, duplicate_phone)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::DuplicateDeviceClassActive);
    }
}
