//! Trait LedgerAdapter y adaptador en memoria para pruebas sans-I/O (F6.T08).
//!
//! Trazabilidad:
//! - **REQ-LEDG-002:** El acceso al ledger DEBE abstraerse con `LedgerAdapter`.
//! - **INV-01:** Verificación y lógica de L4 sans-I/O sin llamadas de red.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::LedgerResult;
use crate::event::SequencedLedgerEvent;

/// Cabecera de un bloque finalizado en el ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    /// Número o altura de bloque.
    pub block_number: u64,
    /// Hash criptográfico del bloque (`bytes32`).
    pub block_hash: [u8; 32],
    /// Hash del bloque predecesor.
    pub parent_hash: [u8; 32],
    /// Marca de tiempo Unix de inclusión del bloque.
    pub timestamp: u64,
}

impl BlockHeader {
    /// Construye una nueva cabecera de bloque.
    #[must_use]
    pub const fn new(
        block_number: u64,
        block_hash: [u8; 32],
        parent_hash: [u8; 32],
        timestamp: u64,
    ) -> Self {
        Self {
            block_number,
            block_hash,
            parent_hash,
            timestamp,
        }
    }
}

/// Registro persistido de un compromiso de manifiesto de estado en el ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusCommitmentRecord {
    /// Identificador del emisor.
    pub issuer_id: [u8; 32],
    /// Versión monotónica incremental del manifiesto.
    pub manifest_version: u64,
    /// Hash SHA-256 del IssuerStatusManifest canónico.
    pub manifest_hash: [u8; 32],
    /// Sugerencia URI para localización de listas de revocación.
    pub uri_hint: String,
    /// Marca de tiempo Unix de anclaje.
    pub anchored_at: u64,
    /// Altura de bloque en que fue incluido.
    pub block_number: u64,
}

/// Trait abstracto de consulta al ledger (REQ-LEDG-002).
///
/// La capa L4 (`gravital-id-ledger`) consume este trait para la reconstrucción de estado.
/// Las implementaciones concretas en L5 (como `gravital-id-ledger-evm`) ejecutan las
/// llamadas RPC hacia nodos blockchain o proveedores múltiples.
pub trait LedgerAdapter {
    /// Retorna el identificador de la red blockchain (EIP-155 `chain_id`).
    fn chain_id(&self) -> u64;

    /// Retorna la cabecera del bloque finalizado más reciente.
    ///
    /// # Errores
    /// [`crate::error::LedgerError::Adapter`] si no es posible consultar el estado del ledger.
    fn finalized_head(&self) -> LedgerResult<BlockHeader>;

    /// Obtiene los eventos finalizados en el rango inclusivo `[from_block, to_block]`.
    ///
    /// Los eventos devueltos deben estar estrictamente ordenados por `EventCoordinate`.
    ///
    /// # Errores
    /// [`crate::error::LedgerError::Adapter`] si la consulta por rangos falla.
    fn fetch_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> LedgerResult<Vec<SequencedLedgerEvent>>;

    /// Retorna el compromiso más reciente anclado para el emisor indicado, si existe.
    ///
    /// # Errores
    /// [`crate::error::LedgerError::Adapter`] si la consulta falla.
    fn get_status_commitment(
        &self,
        issuer_id: &[u8; 32],
    ) -> LedgerResult<Option<StatusCommitmentRecord>>;
}

/// Adaptador determinista en memoria para pruebas unitarias y de integración sans-I/O.
#[derive(Debug, Clone)]
pub struct InMemoryLedgerAdapter {
    chain_id: u64,
    current_head: BlockHeader,
    events: Vec<SequencedLedgerEvent>,
    commitments: BTreeMap<[u8; 32], StatusCommitmentRecord>,
}

impl InMemoryLedgerAdapter {
    /// Crea un nuevo adaptador en memoria con la cabecera inicial.
    #[must_use]
    pub fn new(chain_id: u64, initial_head: BlockHeader) -> Self {
        Self {
            chain_id,
            current_head: initial_head,
            events: Vec::new(),
            commitments: BTreeMap::new(),
        }
    }

    /// Actualiza la cabecera del bloque finalizado.
    pub fn set_head(&mut self, head: BlockHeader) {
        self.current_head = head;
    }

    /// Agrega un evento secuenciado al historial del adaptador.
    pub fn add_event(&mut self, event: SequencedLedgerEvent) {
        self.events.push(event);
        self.events.sort_by_key(|a| a.coordinate);
    }

    /// Registra un compromiso de estado en el adaptador.
    pub fn set_status_commitment(&mut self, commitment: StatusCommitmentRecord) {
        let _ = self.commitments.insert(commitment.issuer_id, commitment);
    }
}

impl LedgerAdapter for InMemoryLedgerAdapter {
    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn finalized_head(&self) -> LedgerResult<BlockHeader> {
        Ok(self.current_head.clone())
    }

    fn fetch_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> LedgerResult<Vec<SequencedLedgerEvent>> {
        let filtered = self
            .events
            .iter()
            .filter(|e| {
                e.coordinate.block_number >= from_block && e.coordinate.block_number <= to_block
            })
            .cloned()
            .collect();
        Ok(filtered)
    }

    fn get_status_commitment(
        &self,
        issuer_id: &[u8; 32],
    ) -> LedgerResult<Option<StatusCommitmentRecord>> {
        Ok(self.commitments.get(issuer_id).cloned())
    }
}
