//! Gestor principal de la wallet del titular (`HolderWallet`, F5.T07, F5.T08).
//!
//! Trazabilidad:
//! - `REQ-STOR-006`: Auditoría local apendible sin PII y con retención configurable.
//! - `REQ-KEY-008`: Asociación segura de credenciales con clave de titular (`KeyHandle`).
//! - `REQ-PRIV-005`: No persistir presentaciones ni nonces del verificador.
//! - `REQ-PRES-001`: Consentimiento explícito y selección de atributos antes de presentar.
//! - `REQ-PRES-003`: Soporte de consultas DCQL.
//! - `REQ-PRIV-001`: Divulgación selectiva estricta.
//! - `INV-01`, `INV-02`, `INV-03`, `INV-05`: Invariantes normativos.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use gravital_id_codec::base64url;
use gravital_id_credential::{ParsedSdJwt, VcValidityPolicy};
use gravital_id_crypto::secret::SecretBytes;
use gravital_id_crypto::{sha256, Rng};
use gravital_id_keys::{HolderBinding, KeyHandle, KeyStore};
use gravital_id_storage::{
    BlindIndexer, CollectionName, EnvelopeEncryption, RecordId, StorageBackend, StorageBatch,
};
use gravital_id_types::{ErrorCode, GidError, UnixTime, Vct};

use crate::audit::{AuditEventType, WalletAuditEvent};
use crate::credential::{CredentialId, WalletCredential, WalletCredentialSummary};
use crate::plan::DisclosurePlan;
use crate::presentation::PresentationBuilder;
use crate::query::CredentialQuery;

/// Nombre de la colección de almacenamiento para eventos de auditoría local.
const AUDIT_COLLECTION: &str = "audit_log";

/// Wallet del titular para gestión segura de credenciales y preparación de presentaciones offline.
pub struct HolderWallet<B: StorageBackend, R: Rng> {
    storage: B,
    kek: SecretBytes<32>,
    indexer: BlindIndexer,
    rng: R,
    audit_seq: u64,
}

impl<B: StorageBackend, R: Rng> HolderWallet<B, R> {
    /// Inicializa una nueva instancia de la wallet con el backend de almacenamiento, KEK y RNG.
    pub fn new(storage: B, kek: SecretBytes<32>, rng: R) -> Result<Self, GidError> {
        let indexer = BlindIndexer::from_kek(&kek)?;
        Ok(Self {
            storage,
            kek,
            indexer,
            rng,
            audit_seq: 1,
        })
    }

    /// Retorna una referencia inmutable al backend de almacenamiento subyacente.
    #[must_use]
    pub fn storage(&self) -> &B {
        &self.storage
    }

    /// Retorna una referencia mutable al backend de almacenamiento subyacente.
    pub fn storage_mut(&mut self) -> &mut B {
        &mut self.storage
    }

    /// Importa una credencial emitida en la wallet previa verificación exhaustiva (F5.T07, REQ-KEY-008).
    ///
    /// Pasos normativos de seguridad:
    /// 1. Parsea y valida sintaxis SD-JWT con límites estrictos.
    /// 2. Valida cabecera `typ: dc+sd-jwt` y vigencia temporal básica.
    /// 3. Extrae el claim `cnf.jwk` y comprueba que coincide exactamente con la clave pública del titular (`handle`).
    /// 4. Asocia la credencial al `holder_binding_key_id` abstracto sin exponer la clave privada (`INV-03`).
    /// 5. Cifra el registro con DEK derivada y AAD canónico (`REQ-STOR-001`).
    /// 6. Indexa con índices ciegos por `vct`, `issuer` y `key_id` (`REQ-STOR-003`).
    /// 7. Registra un evento de auditoría sin datos personales (`REQ-STOR-006`, `INV-02`).
    pub fn import_credential(
        &mut self,
        raw_sd_jwt: &str,
        holder_binding_key_id: &str,
        current_time: UnixTime,
        key_store: &impl KeyStore,
        handle: &KeyHandle<HolderBinding>,
    ) -> Result<CredentialId, GidError> {
        // REQ-KEY-008: Impedir sustitución no autenticada de claves
        if handle.id() != holder_binding_key_id {
            return Err(GidError::new(
                ErrorCode::KeyBindingFailed,
                "holder binding key handle id does not match requested key id",
            ));
        }

        // 1 & 2. Parseo y validación de formato SD-JWT VC
        let parsed = ParsedSdJwt::parse(raw_sd_jwt)?;
        let policy = VcValidityPolicy::default().with_require_cnf(true);
        let vc_claims = parsed.verify_vc(current_time, &policy)?;

        // 3. Confirmación de clave pública de titular ligada a la credencial
        let cnf = vc_claims.cnf.ok_or_else(|| {
            GidError::new(
                ErrorCode::KeyBindingFailed,
                "imported SD-JWT VC must contain 'cnf' holder key confirmation claim",
            )
        })?;

        let holder_pub = key_store.public_key(handle)?;
        if cnf.jwk.to_public_key() != holder_pub.to_public_key() {
            return Err(GidError::new(
                ErrorCode::KeyBindingFailed,
                "holder public key does not match credential 'cnf.jwk'",
            ));
        }

        // 4. Extraer claims disponibles en las divulgaciones emitidas
        let mut available_claims = Vec::new();
        for disc in parsed.disclosures() {
            if let Some(cname) = disc.claim_name() {
                if !available_claims
                    .iter()
                    .any(|existing: &String| existing == cname)
                {
                    available_claims.push(cname.to_string());
                }
            }
        }

        // Generar un CredentialId determinista único basado en hash del SD-JWT
        let id_hash = sha256(raw_sd_jwt.as_bytes());
        let id_suffix = base64url::encode(&id_hash);
        let mut short_suffix = String::new();
        for b in id_suffix.bytes().take(16) {
            short_suffix.push(b as char);
        }
        let cred_id = CredentialId::new(format!("cred_{short_suffix}"))?;
        let record_id = cred_id.to_record_id()?;

        let issuer = vc_claims.iss.clone();

        let cred = WalletCredential {
            id: cred_id.clone(),
            raw_sd_jwt: raw_sd_jwt.to_string(),
            vct: vc_claims.vct.clone(),
            issuer,
            holder_binding_key_id: holder_binding_key_id.to_string(),
            holder_jwk: cnf.jwk,
            issued_at: vc_claims.iat,
            not_before: vc_claims.nbf,
            expires_at: vc_claims.exp,
            available_claims,
        };

        let json_payload = cred.to_canonical_json();
        let col = CollectionName::new(CollectionName::CREDENTIALS)?;

        // 5. Cifrado de sobre DEK/KEK con AAD
        let enc_record = EnvelopeEncryption::encrypt(
            &self.kek,
            &record_id,
            &col,
            json_payload.as_bytes(),
            &self.rng,
        )?;

        // 6. Índices ciegos HMAC-SHA256
        let idx_vct = self.indexer.compute_vct_index(vc_claims.vct.as_str())?;
        let idx_iss = self.indexer.compute_issuer_index(cred.issuer.as_str())?;
        let idx_key = self
            .indexer
            .compute_index("key_id", holder_binding_key_id)?;

        self.storage.put(
            &col,
            &record_id,
            enc_record,
            &[idx_vct, idx_iss, idx_key],
            current_time,
        )?;

        // 7. Registro de auditoría
        self.record_audit_event(
            current_time,
            AuditEventType::CredentialImported { vct: vc_claims.vct },
        )?;

        Ok(cred_id)
    }

    /// Obtiene una credencial completa descifrada por su identificador.
    pub fn get_credential(&self, id: &CredentialId) -> Result<Option<WalletCredential>, GidError> {
        let record_id = id.to_record_id()?;
        let col = CollectionName::new(CollectionName::CREDENTIALS)?;

        let stored = match self.storage.get(&col, &record_id)? {
            Some(s) => s,
            None => return Ok(None),
        };

        let plaintext = EnvelopeEncryption::decrypt(&self.kek, &record_id, &col, &stored.record)?;
        let cred = WalletCredential::from_json_bytes(&plaintext)?;
        Ok(Some(cred))
    }

    /// Lista todas las credenciales almacenadas devolviendo resúmenes ligeros.
    pub fn list_credentials(&self) -> Result<Vec<WalletCredentialSummary>, GidError> {
        let col = CollectionName::new(CollectionName::CREDENTIALS)?;
        let stored_list = self.storage.list(&col)?;

        let mut summaries = Vec::with_capacity(stored_list.len());
        for stored in stored_list {
            let plaintext =
                EnvelopeEncryption::decrypt(&self.kek, &stored.record_id, &col, &stored.record)?;
            let cred = WalletCredential::from_json_bytes(&plaintext)?;
            summaries.push(cred.summary());
        }

        Ok(summaries)
    }

    /// Busca credenciales coincidentes con un tipo `vct` mediante índices ciegos (`REQ-STOR-003`).
    pub fn find_credentials_by_vct(&self, vct: &Vct) -> Result<Vec<CredentialId>, GidError> {
        let col = CollectionName::new(CollectionName::CREDENTIALS)?;
        let idx = self.indexer.compute_vct_index(vct.as_str())?;
        let records = self.storage.query_by_blind_index(&col, &idx)?;

        let mut cred_ids = Vec::with_capacity(records.len());
        for r in records {
            cred_ids.push(CredentialId::new(r.record_id.as_str())?);
        }

        Ok(cred_ids)
    }

    /// Elimina una credencial por su identificador local (`REQ-STOR-006`).
    pub fn delete_credential(
        &mut self,
        id: &CredentialId,
        current_time: UnixTime,
    ) -> Result<bool, GidError> {
        let record_id = id.to_record_id()?;
        let col = CollectionName::new(CollectionName::CREDENTIALS)?;

        let deleted = self.storage.delete(&col, &record_id)?;
        if deleted {
            self.record_audit_event(
                current_time,
                AuditEventType::CredentialDeleted {
                    credential_id: id.as_str().to_string(),
                },
            )?;
        }

        Ok(deleted)
    }

    /// Elimina un lote de credenciales de forma atómica (`REQ-STOR-004`, `REQ-STOR-006`).
    pub fn delete_credentials_batch(
        &mut self,
        ids: &[CredentialId],
        current_time: UnixTime,
    ) -> Result<usize, GidError> {
        if ids.is_empty() {
            return Ok(0);
        }

        let col = CollectionName::new(CollectionName::CREDENTIALS)?;
        let mut batch = StorageBatch::new();

        for id in ids {
            batch.delete(col.clone(), id.to_record_id()?);
        }

        self.storage.execute_transaction(batch.ops())?;

        self.record_audit_event(
            current_time,
            AuditEventType::BatchDeleted { count: ids.len() },
        )?;

        Ok(ids.len())
    }

    /// Prepara un plan de divulgación para una consulta DCQL (`REQ-PRES-001`, `REQ-PRES-003`).
    ///
    /// Si `candidate_id` es `None`, la wallet busca automáticamente una credencial compatible
    /// utilizando los `vct_values` de la consulta mediante índices ciegos.
    pub fn prepare_disclosure_plan(
        &self,
        query: &CredentialQuery,
        candidate_id: Option<&CredentialId>,
    ) -> Result<DisclosurePlan, GidError> {
        let cred_id = match candidate_id {
            Some(id) => id.clone(),
            None => {
                let mut found_id = None;
                for vct in &query.vct_values {
                    let candidates = self.find_credentials_by_vct(vct)?;
                    if let Some(first) = candidates.into_iter().next() {
                        found_id = Some(first);
                        break;
                    }
                }
                found_id.ok_or_else(|| {
                    GidError::new(
                        ErrorCode::RecordNotFound,
                        "no matching credential found for requested vcts",
                    )
                })?
            }
        };

        let cred = self.get_credential(&cred_id)?.ok_or_else(|| {
            GidError::new(
                ErrorCode::RecordNotFound,
                format!("candidate credential '{cred_id}' not found in wallet"),
            )
        })?;

        let parsed = ParsedSdJwt::parse(&cred.raw_sd_jwt)?;
        DisclosurePlan::build(query, &cred, &parsed)
    }

    /// Confirma un plan de divulgación consentido y construye la presentación con KB-JWT (F5.T08, REQ-PRES-001, REQ-PRES-002).
    ///
    /// Invariante de Privacidad (`REQ-PRIV-005`):
    /// La presentación construida y los nonces del verificador se devuelven en memoria y **NUNCA** se persisten.
    pub fn confirm_presentation(
        &mut self,
        plan: &DisclosurePlan,
        aud: &str,
        nonce: &str,
        current_time: UnixTime,
        key_store: &impl KeyStore,
        handle: &KeyHandle<HolderBinding>,
    ) -> Result<String, GidError> {
        let cred = self.get_credential(&plan.credential_id)?.ok_or_else(|| {
            GidError::new(
                ErrorCode::RecordNotFound,
                format!("credential '{}' not found", plan.credential_id),
            )
        })?;

        let presentation =
            PresentationBuilder::build(&cred, plan, aud, nonce, current_time, key_store, handle)?;

        // Registrar auditoría abstracta sin PII ni tokens (INV-02, REQ-PRIV-005)
        self.record_audit_event(
            current_time,
            AuditEventType::PresentationCreated {
                vct: plan.vct.clone(),
                query_id: plan.query_id.clone(),
            },
        )?;

        Ok(presentation)
    }

    /// Lista los eventos de auditoría registrados en la wallet (`REQ-STOR-006`).
    pub fn list_audit_events(&self) -> Result<Vec<WalletAuditEvent>, GidError> {
        let col = CollectionName::new(AUDIT_COLLECTION)?;
        let stored_list = self.storage.list(&col)?;

        let mut events = Vec::with_capacity(stored_list.len());
        for stored in stored_list {
            let plaintext =
                EnvelopeEncryption::decrypt(&self.kek, &stored.record_id, &col, &stored.record)?;
            let evt = WalletAuditEvent::from_json_bytes(&plaintext)?;
            events.push(evt);
        }

        events.sort_by_key(|a| a.timestamp);
        Ok(events)
    }

    /// Depura registros de auditoría más antiguos que `older_than` según política de retención (`REQ-STOR-006`).
    pub fn purge_audit_events(
        &mut self,
        older_than: UnixTime,
        current_time: UnixTime,
    ) -> Result<usize, GidError> {
        let col = CollectionName::new(AUDIT_COLLECTION)?;
        let stored_list = self.storage.list(&col)?;

        let mut ids_to_delete = Vec::new();
        for stored in stored_list {
            let plaintext =
                EnvelopeEncryption::decrypt(&self.kek, &stored.record_id, &col, &stored.record)?;
            if let Ok(evt) = WalletAuditEvent::from_json_bytes(&plaintext) {
                if evt.timestamp < older_than {
                    ids_to_delete.push(stored.record_id);
                }
            }
        }

        if ids_to_delete.is_empty() {
            return Ok(0);
        }

        let mut batch = StorageBatch::new();
        for rid in ids_to_delete {
            batch.delete(col.clone(), rid);
        }

        self.storage.execute_transaction(batch.ops())?;

        let count = batch.ops().len();
        self.record_audit_event(
            current_time,
            AuditEventType::AuditLogPurged {
                records_removed: count,
            },
        )?;

        Ok(count)
    }

    fn record_audit_event(
        &mut self,
        timestamp: UnixTime,
        event_type: AuditEventType,
    ) -> Result<(), GidError> {
        let event_id = format!("evt_{}_{}", timestamp.as_seconds(), self.audit_seq);
        self.audit_seq = self.audit_seq.saturating_add(1);

        let evt = WalletAuditEvent::new(event_id, timestamp, event_type);
        let json_payload = evt.to_canonical_json();

        let record_id = RecordId::new(&evt.event_id)?;
        let col = CollectionName::new(AUDIT_COLLECTION)?;

        let enc_record = EnvelopeEncryption::encrypt(
            &self.kek,
            &record_id,
            &col,
            json_payload.as_bytes(),
            &self.rng,
        )?;

        self.storage
            .put(&col, &record_id, enc_record, &[], timestamp)?;

        Ok(())
    }
}
