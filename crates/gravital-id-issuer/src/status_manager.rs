//! Gestor institucional de Token Status Lists y Manifiestos de Estado (F7.T05, REQ-ISS-003, REQ-STAT-002, REQ-STAT-005, REQ-STAT-006, REQ-STAT-008).
//!
//! Trazabilidad:
//! - **REQ-ISS-003:** El emisor DEBE gestionar listas de estado: asignación, actualización y publicación periódica.
//! - **REQ-STAT-002:** Asignación aleatoria de índices sobre listas con capacidad mínima normada.
//! - **REQ-STAT-005:** Publicación direccionada por contenido vinculada por SHA-256.
//! - **REQ-STAT-006:** Compromisos de manifiesto listos para anclaje en `StatusAnchor.sol`.
//! - **REQ-STAT-008:** Manifiesto firmado con versión monotónica incremental.
//! - **INV-01 / INV-05 / INV-10 / INV-11:** Sin I/O, fail-closed, sin pánicos, CSPRNG inyectado.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use gravital_id_crypto::{sha256, Rng};
use gravital_id_status::{
    IssuerStatusManifestBuilder, SignedStatusManifest, SignedTokenStatusList, StatusSigner,
    TokenStatus, TokenStatusListBuilder,
};
use gravital_id_types::{ErrorCode, GidError, UnixTime};

use crate::request::StatusAllocation;
use crate::status_allocator::StatusIndexAllocator;

/// Compromiso criptográfico del manifiesto de estado listo para anclaje on-chain (`StatusAnchor`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusCommitment {
    /// Identificador del emisor en 32 bytes (SHA-256 de `issuer_id`).
    pub issuer_id: [u8; 32],
    /// Versión monotónica incremental del manifiesto.
    pub manifest_version: u64,
    /// Hash SHA-256 de 32 bytes del JWS del manifiesto canónico (`manifestHash`).
    pub manifest_hash: [u8; 32],
    /// Sugerencia URI para localización pública de las listas (`uriHint`).
    pub uri_hint: String,
}

/// Instantánea publicada de estado del emisor con todas sus listas y manifiesto firmado.
#[derive(Debug, Clone)]
pub struct PublishedStatusSnapshot {
    /// Listas de estado firmadas y direccionadas por contenido.
    pub published_lists: Vec<SignedTokenStatusList>,
    /// Manifiesto de estado firmado con versión incremental.
    pub signed_manifest: SignedStatusManifest,
    /// Compromiso de anclaje para `StatusAnchor.sol`.
    pub commitment: StatusCommitment,
}

/// Una Token Status List administrada por el emisor.
#[derive(Debug, Clone)]
pub struct ManagedStatusList {
    /// Identificador local de la lista (ej: "sl-personal-v1-001").
    pub status_list_id: String,
    /// Bits por entrada (1 o 2).
    pub bits_per_entry: u8,
    /// Capacidad total de entradas.
    pub capacity: usize,
    /// URL base para distribución de esta lista.
    pub base_url: String,
    /// Constructor del bitmap y serializador JWS.
    pub builder: TokenStatusListBuilder,
    /// Asignador aleatorio uniforme de índices.
    pub allocator: StatusIndexAllocator,
    /// Última versión firmada publicada.
    pub last_published: Option<SignedTokenStatusList>,
}

/// Gestor institucional de estado y revocación para un emisor.
#[derive(Debug, Clone)]
pub struct IssuerStatusManager {
    issuer_id: String,
    issuer_id_bytes: [u8; 32],
    manifest_version: u64,
    lists: Vec<ManagedStatusList>,
}

impl IssuerStatusManager {
    /// Construye un gestor de estado para el emisor indicado.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedStatusList`] si `issuer_id` está vacío o contiene solo espacios.
    pub fn new(
        issuer_id: impl Into<String>,
        initial_manifest_version: u64,
    ) -> Result<Self, GidError> {
        let id = issuer_id.into();
        let trimmed = id.trim();
        if trimmed.is_empty() {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "issuer_id must not be empty",
            ));
        }

        let issuer_id_bytes = sha256(trimmed.as_bytes());

        Ok(Self {
            issuer_id: trimmed.to_string(),
            issuer_id_bytes,
            manifest_version: initial_manifest_version,
            lists: Vec::new(),
        })
    }

    /// Identificador del emisor.
    #[must_use]
    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    /// Identificador del emisor en 32 bytes (`sha256(issuer_id)`).
    #[must_use]
    pub fn issuer_id_bytes(&self) -> &[u8; 32] {
        &self.issuer_id_bytes
    }

    /// Versión monotónica actual del manifiesto de estado.
    #[must_use]
    pub fn manifest_version(&self) -> u64 {
        self.manifest_version
    }

    /// Número de listas administradas.
    #[must_use]
    pub fn list_count(&self) -> usize {
        self.lists.len()
    }

    /// Registra una nueva Token Status List bajo el emisor.
    ///
    /// # Errores
    /// - [`ErrorCode::MalformedStatusList`] si `status_list_id` ya está en uso o está vacío.
    /// - [`ErrorCode::MalformedStatusList`] si `capacity < MIN_STATUS_LIST_ENTRIES` (REQ-STAT-002).
    pub fn register_status_list(
        &mut self,
        status_list_id: impl Into<String>,
        bits_per_entry: u8,
        capacity: usize,
        base_url: impl Into<String>,
    ) -> Result<(), GidError> {
        let sl_id = status_list_id.into();
        let trimmed_id = sl_id.trim();
        if trimmed_id.is_empty() {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "status_list_id must not be empty",
            ));
        }

        if self.lists.iter().any(|l| l.status_list_id == trimmed_id) {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                format!("status list with id '{trimmed_id}' is already registered"),
            ));
        }

        let builder = TokenStatusListBuilder::new(bits_per_entry, capacity)?;
        let allocator = StatusIndexAllocator::new(capacity)?;

        self.lists.push(ManagedStatusList {
            status_list_id: trimmed_id.to_string(),
            bits_per_entry,
            capacity,
            base_url: base_url.into(),
            builder,
            allocator,
            last_published: None,
        });

        Ok(())
    }

    /// Asigna de forma aleatoria un índice de estado para una credencial devolviendo también el `status_list_id` (REQ-ISS-003, REQ-STAT-002).
    ///
    /// # Errores
    /// - [`ErrorCode::StatusIndexOutOfRange`] si todas las listas registradas están llenas.
    /// - [`ErrorCode::MalformedStatusList`] si la lista indicada no existe.
    pub fn allocate_with_list_id<R: Rng>(
        &mut self,
        preferred_list_id: Option<&str>,
        rng: &R,
    ) -> Result<(String, StatusAllocation), GidError> {
        let list = match preferred_list_id {
            Some(target_id) => self
                .lists
                .iter_mut()
                .find(|l| l.status_list_id == target_id)
                .ok_or_else(|| {
                    GidError::new(
                        ErrorCode::MalformedStatusList,
                        format!("status list '{target_id}' not found"),
                    )
                })?,
            None => self
                .lists
                .iter_mut()
                .find(|l| !l.allocator.is_full())
                .ok_or_else(|| {
                    GidError::new(
                        ErrorCode::StatusIndexOutOfRange,
                        "all registered status lists are full; register a new status list",
                    )
                })?,
        };

        let list_id = list.status_list_id.clone();
        let index = list.allocator.allocate_random(rng)?;
        let base = list.base_url.trim_end_matches('/');
        let uri = match list.last_published {
            Some(ref pub_list) => pub_list.content_addressed_uri(base),
            None => format!("{base}/{}.jwt", list.status_list_id),
        };

        let alloc = StatusAllocation::new(index, uri)?;
        Ok((list_id, alloc))
    }

    /// Asigna de forma aleatoria un índice de estado para una credencial (REQ-ISS-003, REQ-STAT-002).
    ///
    /// Si se especifica `preferred_list_id`, asigna en esa lista; en caso contrario,
    /// asigna en la primera lista disponible con capacidad libre.
    ///
    /// # Errores
    /// - [`ErrorCode::StatusIndexOutOfRange`] si no hay capacidad libre en la lista o en ninguna lista registrada.
    /// - [`ErrorCode::MalformedStatusList`] si la lista indicada no existe.
    pub fn allocate_for_credential<R: Rng>(
        &mut self,
        preferred_list_id: Option<&str>,
        rng: &R,
    ) -> Result<StatusAllocation, GidError> {
        let (_list_id, alloc) = self.allocate_with_list_id(preferred_list_id, rng)?;
        Ok(alloc)
    }

    /// Revoca una credencial marcando su índice en la lista de estado correspondiente (REQ-STAT-007).
    ///
    /// # Errores
    /// - [`ErrorCode::MalformedStatusList`] si la lista no existe.
    /// - [`ErrorCode::StatusIndexOutOfRange`] si el índice excede la capacidad de la lista.
    pub fn revoke(&mut self, status_list_id: &str, index: u64) -> Result<(), GidError> {
        let list = self
            .lists
            .iter_mut()
            .find(|l| l.status_list_id == status_list_id)
            .ok_or_else(|| {
                GidError::new(
                    ErrorCode::MalformedStatusList,
                    format!("status list '{status_list_id}' not found"),
                )
            })?;

        list.builder.set_status(index, TokenStatus::Revoked)
    }

    /// Suspende temporalmente una credencial en una lista de 2 bits (REQ-STAT-007).
    ///
    /// # Errores
    /// - [`ErrorCode::MalformedStatusList`] si la lista no existe o es de 1 bit.
    /// - [`ErrorCode::StatusIndexOutOfRange`] si el índice excede la capacidad de la lista.
    pub fn suspend(&mut self, status_list_id: &str, index: u64) -> Result<(), GidError> {
        let list = self
            .lists
            .iter_mut()
            .find(|l| l.status_list_id == status_list_id)
            .ok_or_else(|| {
                GidError::new(
                    ErrorCode::MalformedStatusList,
                    format!("status list '{status_list_id}' not found"),
                )
            })?;

        list.builder.set_status(index, TokenStatus::Suspended)
    }

    /// Reactiva una credencial suspendida restableciendo su estado a `Valid` (REQ-STAT-007).
    ///
    /// # Errores
    /// - [`ErrorCode::MalformedStatusList`] si la lista no existe.
    /// - [`ErrorCode::StatusIndexOutOfRange`] si el índice excede la capacidad de la lista.
    pub fn reactivate(&mut self, status_list_id: &str, index: u64) -> Result<(), GidError> {
        let list = self
            .lists
            .iter_mut()
            .find(|l| l.status_list_id == status_list_id)
            .ok_or_else(|| {
                GidError::new(
                    ErrorCode::MalformedStatusList,
                    format!("status list '{status_list_id}' not found"),
                )
            })?;

        list.builder.set_status(index, TokenStatus::Valid)
    }

    /// Consulta el estado actual de una entrada en una lista de estado.
    ///
    /// # Errores
    /// - [`ErrorCode::MalformedStatusList`] si la lista no existe.
    /// - [`ErrorCode::StatusIndexOutOfRange`] si el índice excede la capacidad.
    pub fn status_of(&self, status_list_id: &str, index: u64) -> Result<TokenStatus, GidError> {
        let list = self
            .lists
            .iter()
            .find(|l| l.status_list_id == status_list_id)
            .ok_or_else(|| {
                GidError::new(
                    ErrorCode::MalformedStatusList,
                    format!("status list '{status_list_id}' not found"),
                )
            })?;

        list.builder.get_status(index)
    }

    /// Genera y firma una instantánea completa de estado (Token Status Lists + Manifiesto firmado
    /// con versión monotónica incremental + Compromiso de anclaje para el ledger).
    ///
    /// Trazabilidad: REQ-ISS-003, REQ-STAT-005, REQ-STAT-006, REQ-STAT-008.
    ///
    /// # Errores
    /// [`GidError`] si no hay listas registradas o la firma/verificación criptográfica falla.
    pub fn publish_snapshot<S: StatusSigner>(
        &mut self,
        signer: &S,
        current_time: UnixTime,
        list_validity_seconds: u64,
        manifest_validity_seconds: u64,
        uri_hint: impl Into<String>,
    ) -> Result<PublishedStatusSnapshot, GidError> {
        if self.lists.is_empty() {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "cannot publish snapshot: no status lists registered for this issuer",
            ));
        }

        let new_manifest_version = self.manifest_version.saturating_add(1);
        let list_exp = UnixTime::from_seconds(
            current_time
                .as_seconds()
                .saturating_add(list_validity_seconds),
        );
        let manifest_exp = UnixTime::from_seconds(
            current_time
                .as_seconds()
                .saturating_add(manifest_validity_seconds),
        );

        let mut signed_lists = Vec::with_capacity(self.lists.len());

        for list in &mut self.lists {
            list.builder
                .with_issuer(&self.issuer_id)
                .with_issued_at(current_time)
                .with_expires_at(list_exp);

            if let Some(kid) = signer.kid() {
                list.builder.with_kid(kid);
            }

            let signed = list.builder.sign(signer)?;
            list.last_published = Some(signed.clone());
            signed_lists.push(signed);
        }

        let mut manifest_builder =
            IssuerStatusManifestBuilder::new(&self.issuer_id, new_manifest_version)?;
        manifest_builder
            .with_issued_at(current_time)
            .with_valid_until(manifest_exp);

        if let Some(kid) = signer.kid() {
            manifest_builder.with_kid(kid);
        }

        for (list, signed) in self.lists.iter().zip(&signed_lists) {
            let content_uri = signed.content_addressed_uri(&list.base_url);
            manifest_builder.add_status_list(
                &list.status_list_id,
                &content_uri,
                signed.sha256_hex(),
                Some(list_exp),
            )?;
        }

        let signed_manifest = manifest_builder.sign(signer)?;
        self.manifest_version = new_manifest_version;

        let commitment = StatusCommitment {
            issuer_id: self.issuer_id_bytes,
            manifest_version: new_manifest_version,
            manifest_hash: *signed_manifest.manifest_hash(),
            uri_hint: uri_hint.into(),
        };

        Ok(PublishedStatusSnapshot {
            published_lists: signed_lists,
            signed_manifest,
            commitment,
        })
    }
}
