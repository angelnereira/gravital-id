//! Reconstrucción pura y determinista del estado desde eventos del ledger (F6.T08).
//!
//! Trazabilidad:
//! - **REQ-LEDG-002:** Reconstrucción pura sin dependencias de I/O en L4.
//! - **REQ-TRUST-008:** Determinismo estricto de proyección de estado.
//! - **REQ-LEDG-004:** Control de máquina de estados, timelock y TTL de emergencia.
//! - **INV-02:** Cero datos personales en los registros reconstruidos.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use gravital_id_crypto::JwkEcP256;
use gravital_id_trust::{IssuerState, KeyState};

use crate::adapter::StatusCommitmentRecord;
use crate::error::{LedgerError, LedgerResult};
use crate::event::{
    BundleSignerUpdatedEvent, EventCoordinate, IssuerRegisteredEvent, IssuerSuspendedEvent,
    KeyAddedEvent, KeyCompromisedEvent, KeyRetiredEvent, KeySuspendedEvent, LedgerEvent,
    SequencedLedgerEvent, StatusManifestAnchoredEvent, TrustRootUpdatedEvent,
    VerifierRegisteredEvent,
};

/// Estado operativo de ciclo de vida de un emisor en el registro reconstruido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerLifecycleState {
    /// Emisor activo y plenamente vigente.
    Active,
    /// Emisor suspendido preventivamente con marca temporal de caducidad.
    Suspended {
        /// Timestamp Unix de expiración de la suspensión.
        expires_at: u64,
        /// Dirección que ordenó la suspensión.
        initiated_by: [u8; 20],
    },
    /// Emisor dado de baja definitiva.
    Deregistered,
}

/// Estado de ciclo de vida de una clave pública de emisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLifecycleState {
    /// Clave activa autorizada para firma de credenciales.
    Active,
    /// Clave retirada ordenadamente; credenciales previas a `state_since` siguen vigentes.
    Retired {
        /// Timestamp Unix a partir del cual rige el retiro.
        state_since: u64,
    },
    /// Clave suspendida preventivamente.
    Suspended {
        /// Timestamp de caducidad automática de la suspensión.
        expires_at: u64,
        /// Dirección que ejecutó la suspensión.
        initiated_by: [u8; 20],
    },
    /// Clave irrevocablemente comprometida (estado terminal).
    Compromised {
        /// Timestamp Unix del compromiso.
        state_since: u64,
    },
}

/// Registro reconstruido de una clave pública de emisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyStateRecord {
    /// Identificador canónico de la clave (thumbprint SHA-256).
    pub kid: [u8; 32],
    /// Bytes originales de la clave pública en formato SEC-1 (33 B o 65 B).
    pub public_key_raw: Vec<u8>,
    /// Clave parseada y validada en formato JWK EC P-256.
    pub jwk: JwkEcP256,
    /// Estado de ciclo de vida de la clave.
    pub state: KeyLifecycleState,
    /// Timestamp Unix del último cambio de estado.
    pub state_since: u64,
}

/// Registro reconstruido de un emisor institucional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerStateRecord {
    /// Identificador opaco de 32 bytes del emisor.
    pub issuer_id: [u8; 32],
    /// URI HTTPS canónica o seudónimo del emisor.
    pub uri: String,
    /// Perfiles autorizados (ej. `["pip-personal-v1"]`).
    pub profiles: Vec<String>,
    /// VCTs autorizados para emisión.
    pub vcts: Vec<String>,
    /// Inicio de vigencia de la autorización.
    pub valid_from: u64,
    /// Fin de vigencia de la autorización.
    pub valid_until: u64,
    /// Estado administrativo actual.
    pub state: IssuerLifecycleState,
    /// Claves de firma registradas para este emisor.
    pub keys: BTreeMap<[u8; 32], KeyStateRecord>,
}

/// Registro reconstruido de un verificador autorizado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierStateRecord {
    /// Identificador del verificador.
    pub verifier_id: [u8; 32],
    /// URI del verificador.
    pub uri: String,
    /// Perfiles para los que está autorizado.
    pub profiles: Vec<String>,
    /// Bytes brutos de la clave pública SEC-1.
    pub public_key_raw: Vec<u8>,
    /// Clave pública JWK EC P-256 (si fue provista y es válida).
    pub jwk: Option<JwkEcP256>,
    /// Inicio de vigencia.
    pub valid_from: u64,
    /// Fin de vigencia.
    pub valid_until: u64,
    /// Estado de vigencia activa (false = dado de baja).
    pub active: bool,
}

/// Registro reconstruido de un operador firmante de trust bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSignerStateRecord {
    /// Dirección Ethereum del firmante.
    pub signer_address: [u8; 20],
    /// Identificador de clave.
    pub kid: [u8; 32],
    /// Bytes brutos SEC-1.
    pub public_key_raw: Vec<u8>,
    /// Clave pública JWK.
    pub jwk: JwkEcP256,
    /// Autorización vigente.
    pub authorized: bool,
}

/// Compromiso de la raíz de confianza registrado en el ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRootRecord {
    /// Hash SHA-256 del documento TrustRoot canónico.
    pub root_hash: [u8; 32],
    /// Versión monotónica incremental de la raíz.
    pub root_version: u64,
    /// Timestamp Unix de la actualización.
    pub updated_at: u64,
}

/// Estado global consolidado reconstruido pura y deterministamente desde los eventos del ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerState {
    chain_id: u64,
    registry_address: String,
    last_coordinate: Option<EventCoordinate>,
    issuers: BTreeMap<[u8; 32], IssuerStateRecord>,
    verifiers: BTreeMap<[u8; 32], VerifierStateRecord>,
    bundle_signers: BTreeMap<[u8; 20], BundleSignerStateRecord>,
    trust_root: Option<TrustRootRecord>,
    status_commitments: BTreeMap<[u8; 32], StatusCommitmentRecord>,
}

impl LedgerState {
    /// Crea un nuevo estado vacío inicializado con la red y dirección del registro.
    #[must_use]
    pub fn new(chain_id: u64, registry_address: String) -> Self {
        Self {
            chain_id,
            registry_address,
            last_coordinate: None,
            issuers: BTreeMap::new(),
            verifiers: BTreeMap::new(),
            bundle_signers: BTreeMap::new(),
            trust_root: None,
            status_commitments: BTreeMap::new(),
        }
    }

    /// Identificador de la cadena blockchain.
    #[must_use]
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Dirección del contrato `TrustRegistry` en el ledger.
    #[must_use]
    pub fn registry_address(&self) -> &str {
        &self.registry_address
    }

    /// Última coordenada de evento procesada.
    #[must_use]
    pub const fn last_coordinate(&self) -> Option<EventCoordinate> {
        self.last_coordinate
    }

    /// Mapa de emisores reconstruidos.
    #[must_use]
    pub const fn issuers(&self) -> &BTreeMap<[u8; 32], IssuerStateRecord> {
        &self.issuers
    }

    /// Mapa de verificadores reconstruidos.
    #[must_use]
    pub const fn verifiers(&self) -> &BTreeMap<[u8; 32], VerifierStateRecord> {
        &self.verifiers
    }

    /// Mapa de firmantes de trust bundle autorizados.
    #[must_use]
    pub const fn bundle_signers(&self) -> &BTreeMap<[u8; 20], BundleSignerStateRecord> {
        &self.bundle_signers
    }

    /// Compromiso de raíz de confianza vigente.
    #[must_use]
    pub const fn trust_root(&self) -> Option<&TrustRootRecord> {
        self.trust_root.as_ref()
    }

    /// Compromisos de manifiesto de estado por emisor.
    #[must_use]
    pub const fn status_commitments(&self) -> &BTreeMap<[u8; 32], StatusCommitmentRecord> {
        &self.status_commitments
    }

    /// Aplica un evento secuenciado validando monotonicidad de coordenadas y reglas de estado.
    ///
    /// # Errores
    /// - [`LedgerError::NonMonotonicEventCoordinate`]: Si la coordenada es anterior o igual a la última.
    /// - Errores de transición o integridad específicos de cada evento.
    pub fn apply_event(&mut self, event: &SequencedLedgerEvent) -> LedgerResult<()> {
        if let Some(last) = self.last_coordinate {
            if event.coordinate <= last {
                return Err(LedgerError::NonMonotonicEventCoordinate {
                    last,
                    received: event.coordinate,
                });
            }
        }

        match &event.event {
            LedgerEvent::IssuerRegistered(ev) => self.handle_issuer_registered(ev)?,
            LedgerEvent::IssuerSuspended(ev) => self.handle_issuer_suspended(ev)?,
            LedgerEvent::IssuerReinstated(ev) => self.handle_issuer_reinstated(ev.issuer_id)?,
            LedgerEvent::IssuerDeregistered(ev) => self.handle_issuer_deregistered(ev.issuer_id)?,
            LedgerEvent::KeyAdded(ev) => {
                self.handle_key_added(ev, event.coordinate.block_timestamp)?
            }
            LedgerEvent::KeyRetired(ev) => self.handle_key_retired(ev)?,
            LedgerEvent::KeySuspended(ev) => self.handle_key_suspended(ev)?,
            LedgerEvent::KeyCompromised(ev) => self.handle_key_compromised(ev)?,
            LedgerEvent::VerifierRegistered(ev) => self.handle_verifier_registered(ev)?,
            LedgerEvent::VerifierDeregistered(ev) => {
                self.handle_verifier_deregistered(ev.verifier_id)?;
            }
            LedgerEvent::TrustRootUpdated(ev) => self.handle_trust_root_updated(ev)?,
            LedgerEvent::BundleSignerUpdated(ev) => self.handle_bundle_signer_updated(ev)?,
            LedgerEvent::StatusManifestAnchored(ev) => {
                self.handle_status_manifest_anchored(
                    ev,
                    event.coordinate.block_number,
                    event.coordinate.block_timestamp,
                )?;
            }
        }

        self.last_coordinate = Some(event.coordinate);
        Ok(())
    }

    /// Aplica un lote de eventos secuenciados ordenados.
    pub fn apply_events<'a, I>(&mut self, events: I) -> LedgerResult<usize>
    where
        I: IntoIterator<Item = &'a SequencedLedgerEvent>,
    {
        let mut count: usize = 0;
        for ev in events {
            self.apply_event(ev)?;
            count = count.saturating_add(1);
        }
        Ok(count)
    }

    /// Calcula el estado administrativo efectivo de un emisor en un instante dado.
    ///
    /// Maneja la caducidad automática de suspensiones preventivas (`CONTRACTS.md §3.2`).
    #[must_use]
    pub fn effective_issuer_state(
        &self,
        issuer_id: &[u8; 32],
        at_timestamp: u64,
    ) -> Option<IssuerState> {
        let issuer = self.issuers.get(issuer_id)?;
        match issuer.state {
            IssuerLifecycleState::Active => Some(IssuerState::Active),
            IssuerLifecycleState::Suspended { expires_at, .. } => {
                if at_timestamp >= expires_at {
                    Some(IssuerState::Active)
                } else {
                    Some(IssuerState::Suspended)
                }
            }
            IssuerLifecycleState::Deregistered => None,
        }
    }

    /// Calcula el estado de seguridad efectivo de una clave en un instante dado.
    ///
    /// Maneja la caducidad automática de suspensiones (`CONTRACTS.md §3.2`) e irreversibilidad
    /// de compromisos y retiros.
    #[must_use]
    pub fn effective_key_state(
        &self,
        issuer_id: &[u8; 32],
        kid: &[u8; 32],
        at_timestamp: u64,
    ) -> Option<KeyState> {
        let issuer = self.issuers.get(issuer_id)?;
        let key = issuer.keys.get(kid)?;
        match key.state {
            KeyLifecycleState::Active => Some(KeyState::Active),
            KeyLifecycleState::Retired { .. } => Some(KeyState::Retired),
            KeyLifecycleState::Compromised { .. } => Some(KeyState::Compromised),
            KeyLifecycleState::Suspended { expires_at, .. } => {
                if at_timestamp >= expires_at {
                    Some(KeyState::Active)
                } else {
                    Some(KeyState::Suspended)
                }
            }
        }
    }

    // --- Manejadores internos de eventos ---

    fn handle_issuer_registered(&mut self, ev: &IssuerRegisteredEvent) -> LedgerResult<()> {
        if ev.valid_from >= ev.valid_until {
            return Err(LedgerError::InvalidTimestamps {
                valid_from: ev.valid_from,
                valid_until: ev.valid_until,
            });
        }

        if let Some(existing) = self.issuers.get(&ev.issuer_id) {
            if existing.state != IssuerLifecycleState::Deregistered {
                return Err(LedgerError::IssuerAlreadyExists(ev.issuer_id));
            }
        }

        let record = IssuerStateRecord {
            issuer_id: ev.issuer_id,
            uri: ev.uri.clone(),
            profiles: ev.profiles.clone(),
            vcts: ev.vcts.clone(),
            valid_from: ev.valid_from,
            valid_until: ev.valid_until,
            state: IssuerLifecycleState::Active,
            keys: BTreeMap::new(),
        };

        let _ = self.issuers.insert(ev.issuer_id, record);
        Ok(())
    }

    fn handle_issuer_suspended(&mut self, ev: &IssuerSuspendedEvent) -> LedgerResult<()> {
        let issuer = self
            .issuers
            .get_mut(&ev.issuer_id)
            .ok_or(LedgerError::IssuerNotFound(ev.issuer_id))?;

        if issuer.state == IssuerLifecycleState::Deregistered {
            return Err(LedgerError::IssuerNotFound(ev.issuer_id));
        }

        // Regla: Prohibición de renovación por rol de emergencia mientras la suspensión esté activa
        if let IssuerLifecycleState::Suspended {
            expires_at,
            initiated_by,
        } = issuer.state
        {
            if ev.expires_at > expires_at
                && ev.initiated_by == initiated_by
                && ev.initiated_by != [0u8; 20]
            {
                return Err(LedgerError::EmergencyRenewalForbidden {
                    target_id: ev.issuer_id,
                });
            }
        }

        issuer.state = IssuerLifecycleState::Suspended {
            expires_at: ev.expires_at,
            initiated_by: ev.initiated_by,
        };
        Ok(())
    }

    fn handle_issuer_reinstated(&mut self, issuer_id: [u8; 32]) -> LedgerResult<()> {
        let issuer = self
            .issuers
            .get_mut(&issuer_id)
            .ok_or(LedgerError::IssuerNotFound(issuer_id))?;

        if issuer.state == IssuerLifecycleState::Deregistered {
            return Err(LedgerError::IssuerNotFound(issuer_id));
        }

        issuer.state = IssuerLifecycleState::Active;
        Ok(())
    }

    fn handle_issuer_deregistered(&mut self, issuer_id: [u8; 32]) -> LedgerResult<()> {
        let issuer = self
            .issuers
            .get_mut(&issuer_id)
            .ok_or(LedgerError::IssuerNotFound(issuer_id))?;

        issuer.state = IssuerLifecycleState::Deregistered;
        Ok(())
    }

    fn handle_key_added(&mut self, ev: &KeyAddedEvent, timestamp: u64) -> LedgerResult<()> {
        let issuer = self
            .issuers
            .get_mut(&ev.issuer_id)
            .ok_or(LedgerError::IssuerNotFound(ev.issuer_id))?;

        if issuer.state == IssuerLifecycleState::Deregistered {
            return Err(LedgerError::IssuerNotActive(ev.issuer_id));
        }

        if issuer.keys.contains_key(&ev.kid) {
            return Err(LedgerError::KeyAlreadyExists {
                issuer_id: ev.issuer_id,
                kid: ev.kid,
            });
        }

        let jwk = JwkEcP256::from_sec1_bytes(&ev.public_key)
            .map_err(|e| LedgerError::InvalidPublicKey(format!("invalid SEC-1 public key: {e}")))?;

        let key_record = KeyStateRecord {
            kid: ev.kid,
            public_key_raw: ev.public_key.clone(),
            jwk,
            state: KeyLifecycleState::Active,
            state_since: timestamp,
        };

        let _ = issuer.keys.insert(ev.kid, key_record);
        Ok(())
    }

    fn handle_key_retired(&mut self, ev: &KeyRetiredEvent) -> LedgerResult<()> {
        let issuer = self
            .issuers
            .get_mut(&ev.issuer_id)
            .ok_or(LedgerError::IssuerNotFound(ev.issuer_id))?;

        let key = issuer
            .keys
            .get_mut(&ev.kid)
            .ok_or(LedgerError::KeyNotFound {
                issuer_id: ev.issuer_id,
                kid: ev.kid,
            })?;

        // Compromised es terminal absoluto
        if let KeyLifecycleState::Compromised { .. } = key.state {
            return Err(LedgerError::KeyAlreadyCompromised {
                issuer_id: ev.issuer_id,
                kid: ev.kid,
            });
        }

        key.state = KeyLifecycleState::Retired {
            state_since: ev.state_since,
        };
        key.state_since = ev.state_since;
        Ok(())
    }

    fn handle_key_suspended(&mut self, ev: &KeySuspendedEvent) -> LedgerResult<()> {
        let issuer = self
            .issuers
            .get_mut(&ev.issuer_id)
            .ok_or(LedgerError::IssuerNotFound(ev.issuer_id))?;

        let key = issuer
            .keys
            .get_mut(&ev.kid)
            .ok_or(LedgerError::KeyNotFound {
                issuer_id: ev.issuer_id,
                kid: ev.kid,
            })?;

        // Invariante: Compromised es terminal e irreversible
        if let KeyLifecycleState::Compromised { .. } = key.state {
            return Err(LedgerError::KeyAlreadyCompromised {
                issuer_id: ev.issuer_id,
                kid: ev.kid,
            });
        }

        // Retired no admite suspensión (su destino sólo puede ser compromiso)
        if let KeyLifecycleState::Retired { .. } = key.state {
            return Err(LedgerError::InvalidKeyTransition {
                from: "Retired",
                to: "Suspended",
                reason: "retired keys cannot transition to suspended",
            });
        }

        // Prohibición de renovación por emergencia
        if let KeyLifecycleState::Suspended {
            expires_at,
            initiated_by,
        } = key.state
        {
            if ev.expires_at > expires_at
                && ev.initiated_by == initiated_by
                && ev.initiated_by != [0u8; 20]
            {
                return Err(LedgerError::EmergencyRenewalForbidden { target_id: ev.kid });
            }
        }

        key.state = KeyLifecycleState::Suspended {
            expires_at: ev.expires_at,
            initiated_by: ev.initiated_by,
        };
        Ok(())
    }

    fn handle_key_compromised(&mut self, ev: &KeyCompromisedEvent) -> LedgerResult<()> {
        let issuer = self
            .issuers
            .get_mut(&ev.issuer_id)
            .ok_or(LedgerError::IssuerNotFound(ev.issuer_id))?;

        let key = issuer
            .keys
            .get_mut(&ev.kid)
            .ok_or(LedgerError::KeyNotFound {
                issuer_id: ev.issuer_id,
                kid: ev.kid,
            })?;

        // Compromised es terminal: si ya lo estaba, es idempotente
        key.state = KeyLifecycleState::Compromised {
            state_since: ev.state_since,
        };
        key.state_since = ev.state_since;
        Ok(())
    }

    fn handle_verifier_registered(&mut self, ev: &VerifierRegisteredEvent) -> LedgerResult<()> {
        if ev.valid_from >= ev.valid_until {
            return Err(LedgerError::InvalidTimestamps {
                valid_from: ev.valid_from,
                valid_until: ev.valid_until,
            });
        }

        let jwk =
            if ev.public_key.is_empty() {
                None
            } else {
                Some(JwkEcP256::from_sec1_bytes(&ev.public_key).map_err(|e| {
                    LedgerError::InvalidPublicKey(format!("verifier key invalid: {e}"))
                })?)
            };

        let record = VerifierStateRecord {
            verifier_id: ev.verifier_id,
            uri: ev.uri.clone(),
            profiles: ev.profiles.clone(),
            public_key_raw: ev.public_key.clone(),
            jwk,
            valid_from: ev.valid_from,
            valid_until: ev.valid_until,
            active: true,
        };

        let _ = self.verifiers.insert(ev.verifier_id, record);
        Ok(())
    }

    fn handle_verifier_deregistered(&mut self, verifier_id: [u8; 32]) -> LedgerResult<()> {
        let verifier = self
            .verifiers
            .get_mut(&verifier_id)
            .ok_or(LedgerError::VerifierNotFound(verifier_id))?;

        verifier.active = false;
        Ok(())
    }

    fn handle_trust_root_updated(&mut self, ev: &TrustRootUpdatedEvent) -> LedgerResult<()> {
        if let Some(existing) = &self.trust_root {
            if ev.root_version <= existing.root_version {
                return Err(LedgerError::NonMonotonicRootVersion {
                    current: existing.root_version,
                    proposed: ev.root_version,
                });
            }
        }

        self.trust_root = Some(TrustRootRecord {
            root_hash: ev.root_hash,
            root_version: ev.root_version,
            updated_at: ev.updated_at,
        });
        Ok(())
    }

    fn handle_bundle_signer_updated(&mut self, ev: &BundleSignerUpdatedEvent) -> LedgerResult<()> {
        let jwk = JwkEcP256::from_sec1_bytes(&ev.public_key).map_err(|e| {
            LedgerError::InvalidPublicKey(format!("bundle signer key invalid: {e}"))
        })?;

        let record = BundleSignerStateRecord {
            signer_address: ev.signer_address,
            kid: ev.kid,
            public_key_raw: ev.public_key.clone(),
            jwk,
            authorized: ev.authorized,
        };

        let _ = self.bundle_signers.insert(ev.signer_address, record);
        Ok(())
    }

    fn handle_status_manifest_anchored(
        &mut self,
        ev: &StatusManifestAnchoredEvent,
        block_number: u64,
        block_timestamp: u64,
    ) -> LedgerResult<()> {
        if ev.manifest_hash == [0u8; 32] {
            return Err(LedgerError::InvalidManifestHash(ev.manifest_hash));
        }

        if let Some(existing) = self.status_commitments.get(&ev.issuer_id) {
            if ev.manifest_version <= existing.manifest_version {
                return Err(LedgerError::NonMonotonicManifestVersion {
                    issuer_id: ev.issuer_id,
                    current: existing.manifest_version,
                    proposed: ev.manifest_version,
                });
            }
        }

        let record = StatusCommitmentRecord {
            issuer_id: ev.issuer_id,
            manifest_version: ev.manifest_version,
            manifest_hash: ev.manifest_hash,
            uri_hint: ev.uri_hint.clone(),
            anchored_at: block_timestamp,
            block_number,
        };

        let _ = self.status_commitments.insert(ev.issuer_id, record);
        Ok(())
    }
}
