//! Decodificación y codificación ABI para contratos de Gravital ID (F6.T09).
//!
//! Trazabilidad:
//! - **REQ-LEDG-002:** Abstracción e interoperabilidad de eventos EVM.
//! - **REQ-TRUST-008:** Reconstrucción determinista a partir de logs del ledger.
//! - **REQ-LEDG-001 / INV-02:** Cero datos personales en parámetros y eventos.
//! - **INV-10:** Cero pánicos, indexación segura sin desbordamientos.

use gravital_id_ledger::{
    BundleSignerUpdatedEvent, IssuerDeregisteredEvent, IssuerRegisteredEvent,
    IssuerReinstatedEvent, IssuerSuspendedEvent, KeyAddedEvent, KeyCompromisedEvent,
    KeyRetiredEvent, KeySuspendedEvent, LedgerEvent, StatusCommitmentRecord,
    StatusManifestAnchoredEvent, TrustRootUpdatedEvent, VerifierDeregisteredEvent,
    VerifierRegisteredEvent,
};
use sha3::{Digest, Keccak256};

use crate::error::{EvmLedgerError, EvmLedgerResult};

/// Calcula el hash Keccak-256 estándar de Ethereum para una porción de bytes.
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// =============================================================================
// SELECTORES Y TOPICS DE EVENTOS (CONTRACTS.md §6)
// =============================================================================

/// Selector de función `getLatestCommitment(bytes32)` (4 bytes).
pub const SELECTOR_GET_LATEST_COMMITMENT: [u8; 4] = [0xa1, 0x39, 0x68, 0x7c];

/// Selector de función `anchorStatusManifest(bytes32,uint64,bytes32,string)` (4 bytes).
pub const SELECTOR_ANCHOR_STATUS_MANIFEST: [u8; 4] = [0x6a, 0x02, 0x6f, 0x0a];

/// Topic0 de `IssuerRegistered(bytes32,string,uint64,uint64)`.
pub const TOPIC_ISSUER_REGISTERED: [u8; 32] = [
    0x99, 0x7a, 0x86, 0x2d, 0xa8, 0x3f, 0x70, 0x13, 0x0e, 0xb9, 0x5a, 0xf1, 0xa9, 0x05, 0x91, 0xd0,
    0x4b, 0xf1, 0x7c, 0x72, 0x63, 0xd1, 0x97, 0x15, 0x49, 0x86, 0x64, 0xc7, 0x5c, 0xf2, 0x1e, 0x0a,
];

/// Topic0 de `IssuerSuspended(bytes32,uint64,address)`.
pub const TOPIC_ISSUER_SUSPENDED: [u8; 32] = [
    0x0e, 0xbb, 0xbd, 0xa5, 0xa8, 0x33, 0xf2, 0xc5, 0xd0, 0x21, 0x77, 0x0c, 0xb7, 0x5d, 0xc6, 0xb5,
    0xb0, 0x41, 0x54, 0x14, 0x69, 0x39, 0xa9, 0xf1, 0xb8, 0xb5, 0x9d, 0x98, 0x19, 0x20, 0xde, 0x9f,
];

/// Topic0 de `IssuerReinstated(bytes32)`.
pub const TOPIC_ISSUER_REINSTATED: [u8; 32] = [
    0x86, 0x6c, 0x15, 0x06, 0x09, 0xc3, 0x06, 0xd2, 0xc1, 0xb2, 0x3c, 0xc3, 0xf4, 0x23, 0xc2, 0xc3,
    0xb3, 0x1f, 0x27, 0x31, 0x9b, 0xf0, 0xfb, 0x07, 0x51, 0x59, 0x1d, 0xf4, 0xa4, 0x54, 0x37, 0xec,
];

/// Topic0 de `IssuerDeregistered(bytes32)`.
pub const TOPIC_ISSUER_DEREGISTERED: [u8; 32] = [
    0x8e, 0xb8, 0xb9, 0x01, 0xfe, 0xc5, 0x3b, 0x81, 0x30, 0xf9, 0x6b, 0xd5, 0x5d, 0x45, 0xa9, 0xb3,
    0x3f, 0xc1, 0x5e, 0x8d, 0x04, 0xae, 0x9c, 0xb4, 0xdb, 0xb9, 0x41, 0x47, 0x59, 0x00, 0xb5, 0xbf,
];

/// Topic0 de `KeyAdded(bytes32,bytes32,bytes)`.
pub const TOPIC_KEY_ADDED: [u8; 32] = [
    0xa6, 0x98, 0x1e, 0xfa, 0x75, 0x81, 0x7e, 0x14, 0x07, 0x5d, 0x2e, 0xc0, 0x48, 0xf6, 0x73, 0x94,
    0xb8, 0x66, 0x4a, 0x95, 0x3d, 0x98, 0xab, 0x65, 0xc3, 0x17, 0x3f, 0xc4, 0x2e, 0xfb, 0xaa, 0x97,
];

/// Topic0 de `KeyRetired(bytes32,bytes32,uint64)`.
pub const TOPIC_KEY_RETIRED: [u8; 32] = [
    0x2f, 0x7c, 0xaf, 0xd9, 0x84, 0xeb, 0x5e, 0x5b, 0x10, 0x5c, 0x78, 0x70, 0x68, 0x32, 0x9b, 0x16,
    0xfe, 0x28, 0xd1, 0x2e, 0x9c, 0x1a, 0x25, 0x3a, 0x67, 0xf5, 0xd1, 0xd2, 0x0c, 0x58, 0x6a, 0x6c,
];

/// Topic0 de `KeySuspended(bytes32,bytes32,uint64,address)`.
pub const TOPIC_KEY_SUSPENDED: [u8; 32] = [
    0x22, 0xa2, 0xc6, 0x1c, 0xd6, 0x46, 0x00, 0x2c, 0x6f, 0x51, 0xf0, 0xf1, 0x50, 0x0f, 0xba, 0x45,
    0xdb, 0x3d, 0x06, 0x0c, 0xc7, 0xd9, 0x02, 0xf4, 0xa8, 0x94, 0x17, 0x83, 0x67, 0x73, 0xe7, 0x5f,
];

/// Topic0 de `KeyCompromised(bytes32,bytes32,uint64)`.
pub const TOPIC_KEY_COMPROMISED: [u8; 32] = [
    0x23, 0x2d, 0x30, 0x2d, 0x08, 0x9d, 0xcc, 0xfb, 0xcc, 0xcb, 0x17, 0x72, 0x60, 0xd6, 0x77, 0x8a,
    0x4b, 0x2e, 0x16, 0x9f, 0xcf, 0x6b, 0x87, 0x01, 0x4a, 0x3e, 0xa8, 0x2f, 0xd5, 0x26, 0x44, 0xa8,
];

/// Topic0 de `VerifierRegistered(bytes32,string,bytes,uint64,uint64)`.
pub const TOPIC_VERIFIER_REGISTERED: [u8; 32] = [
    0x23, 0x9e, 0x29, 0x60, 0xac, 0x92, 0x71, 0xd3, 0x6f, 0xee, 0xbd, 0x05, 0x93, 0x9b, 0xa4, 0xc3,
    0x8f, 0xf8, 0xed, 0x32, 0x24, 0xb4, 0x0b, 0x08, 0x36, 0xea, 0x9a, 0xda, 0xe4, 0xb2, 0x8c, 0xda,
];

/// Topic0 de `VerifierDeregistered(bytes32)`.
pub const TOPIC_VERIFIER_DEREGISTERED: [u8; 32] = [
    0x58, 0x53, 0xb2, 0xa9, 0x81, 0x9d, 0x92, 0x08, 0x5e, 0xe1, 0x0c, 0xb9, 0xf2, 0x32, 0x21, 0x41,
    0x00, 0x1c, 0xfc, 0xec, 0xe2, 0xbf, 0x68, 0xba, 0x06, 0x37, 0x09, 0x33, 0x13, 0xa5, 0xd1, 0xbf,
];

/// Topic0 de `TrustRootUpdated(bytes32,uint64,uint64)`.
pub const TOPIC_TRUST_ROOT_UPDATED: [u8; 32] = [
    0xdc, 0x54, 0x8d, 0xa6, 0x19, 0x11, 0x7a, 0x7d, 0x37, 0x69, 0x30, 0xed, 0x57, 0xd0, 0x76, 0x81,
    0x7d, 0x7a, 0xab, 0xcb, 0x0c, 0xbe, 0x19, 0x03, 0x1b, 0xae, 0x44, 0x25, 0x9e, 0xe2, 0xad, 0xd4,
];

/// Topic0 de `BundleSignerUpdated(address,bytes32,bytes,bool)`.
pub const TOPIC_BUNDLE_SIGNER_UPDATED: [u8; 32] = [
    0xbe, 0xe8, 0xb6, 0x1a, 0x09, 0x90, 0x06, 0x3f, 0x1d, 0x0d, 0xca, 0xac, 0x63, 0x5c, 0xdc, 0x10,
    0x10, 0x45, 0xce, 0xc9, 0xc9, 0x45, 0x0c, 0x7e, 0x5e, 0x0e, 0xe9, 0xb9, 0x24, 0x28, 0xc5, 0x3b,
];

/// Topic0 de `StatusManifestAnchored(bytes32,uint64,bytes32,string)`.
pub const TOPIC_STATUS_MANIFEST_ANCHORED: [u8; 32] = [
    0xfd, 0xba, 0x6b, 0xa8, 0x31, 0xc6, 0xf0, 0x7a, 0xdd, 0x34, 0x03, 0xb3, 0xbb, 0xc2, 0xc3, 0xb3,
    0x0a, 0xd3, 0x8f, 0xc0, 0x78, 0x1c, 0x66, 0x1c, 0x7b, 0xfe, 0x1f, 0x7b, 0x2f, 0xfc, 0xd0, 0x1a,
];

// =============================================================================
// DECODIFICADORES ABI SEGUROS
// =============================================================================

/// Extrae un `uint64` codificado en una palabra ABI de 32 bytes (big-endian).
pub fn read_uint64(word: &[u8]) -> EvmLedgerResult<u64> {
    if word.len() != 32 {
        return Err(EvmLedgerError::AbiDecoding(
            "expected 32-byte word for uint64".into(),
        ));
    }
    let slice = word
        .get(24..32)
        .ok_or_else(|| EvmLedgerError::AbiDecoding("slice out of bounds for uint64".into()))?;
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(slice);
    Ok(u64::from_be_bytes(bytes))
}

/// Extrae un `address` (20 bytes) codificado en una palabra ABI de 32 bytes.
pub fn read_address(word: &[u8]) -> EvmLedgerResult<[u8; 20]> {
    if word.len() != 32 {
        return Err(EvmLedgerError::AbiDecoding(
            "expected 32-byte word for address".into(),
        ));
    }
    let slice = word
        .get(12..32)
        .ok_or_else(|| EvmLedgerError::AbiDecoding("slice out of bounds for address".into()))?;
    let mut addr = [0u8; 20];
    addr.copy_from_slice(slice);
    Ok(addr)
}

/// Extrae un `bool` codificado en una palabra ABI de 32 bytes.
pub fn read_bool(word: &[u8]) -> EvmLedgerResult<bool> {
    if word.len() != 32 {
        return Err(EvmLedgerError::AbiDecoding(
            "expected 32-byte word for bool".into(),
        ));
    }
    let val = word
        .get(31)
        .copied()
        .ok_or_else(|| EvmLedgerError::AbiDecoding("slice out of bounds for bool".into()))?;
    match val {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(EvmLedgerError::AbiDecoding(
            "invalid boolean byte value in ABI".into(),
        )),
    }
}

/// Obtiene una palabra ABI de 32 bytes de forma segura a partir de un offset.
pub fn get_word(data: &[u8], offset: usize) -> EvmLedgerResult<&[u8]> {
    let end = offset
        .checked_add(32)
        .ok_or_else(|| EvmLedgerError::AbiDecoding("offset overflow".into()))?;
    data.get(offset..end).ok_or_else(|| {
        EvmLedgerError::AbiDecoding(format!(
            "insufficient data for 32-byte word at offset {offset}"
        ))
    })
}

/// Lee un `uint64` codificado en una palabra ABI en el offset indicado.
pub fn read_uint64_at(data: &[u8], offset: usize) -> EvmLedgerResult<u64> {
    let word = get_word(data, offset)?;
    read_uint64(word)
}

/// Lee un `bool` codificado en una palabra ABI en el offset indicado.
pub fn read_bool_at(data: &[u8], offset: usize) -> EvmLedgerResult<bool> {
    let word = get_word(data, offset)?;
    read_bool(word)
}

/// Lee exactamente 32 bytes en el offset indicado.
pub fn read_bytes32_at(data: &[u8], offset: usize) -> EvmLedgerResult<[u8; 32]> {
    let word = get_word(data, offset)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(word);
    Ok(out)
}

/// Extrae bytes dinámicos (`bytes`) desde un payload ABI a partir de un offset.
pub fn read_dynamic_bytes(data: &[u8], offset: usize) -> EvmLedgerResult<Vec<u8>> {
    let len = usize::try_from(read_uint64_at(data, offset)?).map_err(|_| {
        EvmLedgerError::AbiDecoding("dynamic bytes length exceeds usize bounds".into())
    })?;

    let start = offset
        .checked_add(32)
        .ok_or_else(|| EvmLedgerError::AbiDecoding("offset overflow".into()))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| EvmLedgerError::AbiDecoding("dynamic bytes length overflow".into()))?;

    let slice = data
        .get(start..end)
        .ok_or_else(|| EvmLedgerError::AbiDecoding("dynamic bytes data truncated".into()))?;

    Ok(slice.to_vec())
}

/// Extrae una cadena UTF-8 dinámica (`string`) desde un payload ABI.
pub fn read_dynamic_string(data: &[u8], offset: usize) -> EvmLedgerResult<String> {
    let bytes = read_dynamic_bytes(data, offset)?;
    String::from_utf8(bytes)
        .map_err(|e| EvmLedgerError::AbiDecoding(format!("invalid UTF-8 string in ABI data: {e}")))
}

// =============================================================================
// DECODIFICACIÓN DE LOGS DE EVENTOS
// =============================================================================

/// Decodifica un log de eventos EVM en un `LedgerEvent` tipado.
///
/// Si el topic0 no coincide con ninguno de los 13 eventos del protocolo, devuelve `Ok(None)`.
pub fn decode_event_log(topics: &[[u8; 32]], data: &[u8]) -> EvmLedgerResult<Option<LedgerEvent>> {
    let Some(topic0) = topics.first() else {
        return Ok(None);
    };

    match *topic0 {
        TOPIC_ISSUER_REGISTERED => {
            let issuer_id = *topics.get(1).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 1 for IssuerRegistered".into())
            })?;

            // Data: offset(uri) [32], validFrom [32], validUntil [32], [length, bytes...]
            if data.len() < 96 {
                return Err(EvmLedgerError::AbiDecoding(
                    "IssuerRegistered data too short".into(),
                ));
            }

            let uri_offset = usize::try_from(read_uint64_at(data, 0)?)
                .map_err(|_| EvmLedgerError::AbiDecoding("uri offset exceeds usize".into()))?;
            let valid_from = read_uint64_at(data, 32)?;
            let valid_until = read_uint64_at(data, 64)?;
            let uri = read_dynamic_string(data, uri_offset)?;

            Ok(Some(LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id,
                uri,
                profiles: Vec::new(),
                vcts: Vec::new(),
                valid_from,
                valid_until,
            })))
        }

        TOPIC_ISSUER_SUSPENDED => {
            let issuer_id = *topics.get(1).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 1 for IssuerSuspended".into())
            })?;
            let initiated_by_word = topics.get(2).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 2 for IssuerSuspended".into())
            })?;
            let initiated_by = read_address(initiated_by_word)?;

            if data.len() < 32 {
                return Err(EvmLedgerError::AbiDecoding(
                    "IssuerSuspended data too short".into(),
                ));
            }
            let expires_at = read_uint64_at(data, 0)?;

            Ok(Some(LedgerEvent::IssuerSuspended(IssuerSuspendedEvent {
                issuer_id,
                expires_at,
                initiated_by,
            })))
        }

        TOPIC_ISSUER_REINSTATED => {
            let issuer_id = *topics.get(1).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 1 for IssuerReinstated".into())
            })?;

            Ok(Some(LedgerEvent::IssuerReinstated(IssuerReinstatedEvent {
                issuer_id,
            })))
        }

        TOPIC_ISSUER_DEREGISTERED => {
            let issuer_id = *topics.get(1).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 1 for IssuerDeregistered".into())
            })?;

            Ok(Some(LedgerEvent::IssuerDeregistered(
                IssuerDeregisteredEvent { issuer_id },
            )))
        }

        TOPIC_KEY_ADDED => {
            let issuer_id = *topics.get(1).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 1 for KeyAdded".into())
            })?;
            let kid = *topics.get(2).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 2 for KeyAdded".into())
            })?;

            if data.len() < 32 {
                return Err(EvmLedgerError::AbiDecoding(
                    "KeyAdded data too short".into(),
                ));
            }
            let key_offset = usize::try_from(read_uint64_at(data, 0)?)
                .map_err(|_| EvmLedgerError::AbiDecoding("key offset exceeds usize".into()))?;
            let public_key = read_dynamic_bytes(data, key_offset)?;

            Ok(Some(LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid,
                public_key,
            })))
        }

        TOPIC_KEY_RETIRED => {
            let issuer_id = *topics.get(1).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 1 for KeyRetired".into())
            })?;
            let kid = *topics.get(2).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 2 for KeyRetired".into())
            })?;

            if data.len() < 32 {
                return Err(EvmLedgerError::AbiDecoding(
                    "KeyRetired data too short".into(),
                ));
            }
            let state_since = read_uint64_at(data, 0)?;

            Ok(Some(LedgerEvent::KeyRetired(KeyRetiredEvent {
                issuer_id,
                kid,
                state_since,
            })))
        }

        TOPIC_KEY_SUSPENDED => {
            let issuer_id = *topics.get(1).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 1 for KeySuspended".into())
            })?;
            let kid = *topics.get(2).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 2 for KeySuspended".into())
            })?;
            let initiated_by_word = topics.get(3).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 3 for KeySuspended".into())
            })?;
            let initiated_by = read_address(initiated_by_word)?;

            if data.len() < 32 {
                return Err(EvmLedgerError::AbiDecoding(
                    "KeySuspended data too short".into(),
                ));
            }
            let expires_at = read_uint64_at(data, 0)?;

            Ok(Some(LedgerEvent::KeySuspended(KeySuspendedEvent {
                issuer_id,
                kid,
                expires_at,
                initiated_by,
            })))
        }

        TOPIC_KEY_COMPROMISED => {
            let issuer_id = *topics.get(1).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 1 for KeyCompromised".into())
            })?;
            let kid = *topics.get(2).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 2 for KeyCompromised".into())
            })?;

            if data.len() < 32 {
                return Err(EvmLedgerError::AbiDecoding(
                    "KeyCompromised data too short".into(),
                ));
            }
            let state_since = read_uint64_at(data, 0)?;

            Ok(Some(LedgerEvent::KeyCompromised(KeyCompromisedEvent {
                issuer_id,
                kid,
                state_since,
            })))
        }

        TOPIC_VERIFIER_REGISTERED => {
            let verifier_id = *topics.get(1).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 1 for VerifierRegistered".into())
            })?;

            // Data: offset(uri) [32], offset(publicKey) [32], validFrom [32], validUntil [32]
            if data.len() < 128 {
                return Err(EvmLedgerError::AbiDecoding(
                    "VerifierRegistered data too short".into(),
                ));
            }

            let uri_offset = usize::try_from(read_uint64_at(data, 0)?)
                .map_err(|_| EvmLedgerError::AbiDecoding("uri offset exceeds usize".into()))?;
            let key_offset = usize::try_from(read_uint64_at(data, 32)?)
                .map_err(|_| EvmLedgerError::AbiDecoding("key offset exceeds usize".into()))?;
            let valid_from = read_uint64_at(data, 64)?;
            let valid_until = read_uint64_at(data, 96)?;

            let uri = read_dynamic_string(data, uri_offset)?;
            let public_key = read_dynamic_bytes(data, key_offset)?;

            Ok(Some(LedgerEvent::VerifierRegistered(
                VerifierRegisteredEvent {
                    verifier_id,
                    uri,
                    public_key,
                    profiles: Vec::new(),
                    valid_from,
                    valid_until,
                },
            )))
        }

        TOPIC_VERIFIER_DEREGISTERED => {
            let verifier_id = *topics.get(1).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 1 for VerifierDeregistered".into())
            })?;

            Ok(Some(LedgerEvent::VerifierDeregistered(
                VerifierDeregisteredEvent { verifier_id },
            )))
        }

        TOPIC_TRUST_ROOT_UPDATED => {
            let root_hash = *topics.get(1).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 1 for TrustRootUpdated".into())
            })?;
            let root_version = read_uint64(topics.get(2).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 2 for TrustRootUpdated".into())
            })?)?;

            if data.len() < 32 {
                return Err(EvmLedgerError::AbiDecoding(
                    "TrustRootUpdated data too short".into(),
                ));
            }
            let updated_at = read_uint64_at(data, 0)?;

            Ok(Some(LedgerEvent::TrustRootUpdated(TrustRootUpdatedEvent {
                root_hash,
                root_version,
                updated_at,
            })))
        }

        TOPIC_BUNDLE_SIGNER_UPDATED => {
            let signer_address_word = topics.get(1).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 1 for BundleSignerUpdated".into())
            })?;
            let signer_address = read_address(signer_address_word)?;
            let kid = *topics.get(2).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 2 for BundleSignerUpdated".into())
            })?;

            // Data: offset(publicKey) [32], authorized [32]
            if data.len() < 64 {
                return Err(EvmLedgerError::AbiDecoding(
                    "BundleSignerUpdated data too short".into(),
                ));
            }
            let key_offset = usize::try_from(read_uint64_at(data, 0)?)
                .map_err(|_| EvmLedgerError::AbiDecoding("key offset exceeds usize".into()))?;
            let authorized = read_bool_at(data, 32)?;
            let public_key = read_dynamic_bytes(data, key_offset)?;

            Ok(Some(LedgerEvent::BundleSignerUpdated(
                BundleSignerUpdatedEvent {
                    signer_address,
                    kid,
                    public_key,
                    authorized,
                },
            )))
        }

        TOPIC_STATUS_MANIFEST_ANCHORED => {
            let issuer_id = *topics.get(1).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 1 for StatusManifestAnchored".into())
            })?;
            let manifest_version = read_uint64(topics.get(2).ok_or_else(|| {
                EvmLedgerError::AbiDecoding("missing topic 2 for StatusManifestAnchored".into())
            })?)?;

            // Data: manifestHash [32], offset(uriHint) [32]
            if data.len() < 64 {
                return Err(EvmLedgerError::AbiDecoding(
                    "StatusManifestAnchored data too short".into(),
                ));
            }
            let manifest_hash = read_bytes32_at(data, 0)?;
            let uri_offset = usize::try_from(read_uint64_at(data, 32)?)
                .map_err(|_| EvmLedgerError::AbiDecoding("uri offset exceeds usize".into()))?;
            let uri_hint = read_dynamic_string(data, uri_offset)?;

            Ok(Some(LedgerEvent::StatusManifestAnchored(
                StatusManifestAnchoredEvent {
                    issuer_id,
                    manifest_version,
                    manifest_hash,
                    uri_hint,
                },
            )))
        }

        _ => Ok(None),
    }
}

// =============================================================================
// CODIFICACIÓN Y RETORNO DE LLAMADAS (CALLS)
// =============================================================================

/// Codifica la llamada calldata para `IStatusAnchor.getLatestCommitment(bytes32 issuerId)`.
#[must_use]
pub fn encode_get_latest_commitment_call(issuer_id: &[u8; 32]) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(36);
    calldata.extend_from_slice(&SELECTOR_GET_LATEST_COMMITMENT);
    calldata.extend_from_slice(issuer_id);
    calldata
}

/// Decodifica el retorno ABI de `getLatestCommitment` en un `StatusCommitmentRecord`.
///
/// Retorna `Ok(None)` si `manifestVersion == 0`.
pub fn decode_get_latest_commitment_return(
    issuer_id: [u8; 32],
    output: &[u8],
) -> EvmLedgerResult<Option<StatusCommitmentRecord>> {
    if output.is_empty() {
        return Ok(None);
    }
    if output.len() < 128 {
        return Err(EvmLedgerError::AbiDecoding(
            "getLatestCommitment return data too short (must be >= 128 bytes)".into(),
        ));
    }

    let manifest_hash = read_bytes32_at(output, 0)?;
    let manifest_version = read_uint64_at(output, 32)?;
    let anchored_at = read_uint64_at(output, 64)?;
    let block_number = read_uint64_at(output, 96)?;

    if manifest_version == 0 {
        return Ok(None);
    }

    Ok(Some(StatusCommitmentRecord {
        issuer_id,
        manifest_version,
        manifest_hash,
        uri_hint: String::new(),
        anchored_at,
        block_number,
    }))
}

/// Codifica la llamada calldata para `IStatusAnchor.anchorStatusManifest(bytes32,uint64,bytes32,string)`.
///
/// Formato calldata ABI EVM:
/// - Selector: 4 bytes (`SELECTOR_ANCHOR_STATUS_MANIFEST`).
/// - Argumento 0: `issuerId` (32 bytes).
/// - Argumento 1: `manifestVersion` (uint64, 32 bytes con padding de ceros a la izquierda).
/// - Argumento 2: `manifestHash` (32 bytes).
/// - Argumento 3: Offset a `uriHint` (uint256 = 128 / 0x80).
/// - Tail (offset 128): Longitud de `uriHint` (uint256, 32 bytes).
/// - Tail: Bytes de `uriHint` rellenados con ceros al siguiente múltiplo de 32 bytes.
#[must_use]
pub fn encode_anchor_status_manifest_call(
    issuer_id: &[u8; 32],
    manifest_version: u64,
    manifest_hash: &[u8; 32],
    uri_hint: &str,
) -> Vec<u8> {
    let uri_bytes = uri_hint.as_bytes();
    let uri_len = uri_bytes.len();
    let padded_uri_len = uri_len.div_ceil(32).saturating_mul(32);
    let total_len = 164usize.saturating_add(padded_uri_len);

    let mut calldata = Vec::with_capacity(total_len);
    calldata.extend_from_slice(&SELECTOR_ANCHOR_STATUS_MANIFEST);
    calldata.extend_from_slice(issuer_id);

    let mut ver_word = [0u8; 32];
    ver_word[24..32].copy_from_slice(&manifest_version.to_be_bytes());
    calldata.extend_from_slice(&ver_word);

    calldata.extend_from_slice(manifest_hash);

    let mut offset_word = [0u8; 32];
    offset_word[24..32].copy_from_slice(&128u64.to_be_bytes());
    calldata.extend_from_slice(&offset_word);

    let mut len_word = [0u8; 32];
    len_word[24..32].copy_from_slice(&(uri_len as u64).to_be_bytes());
    calldata.extend_from_slice(&len_word);

    calldata.extend_from_slice(uri_bytes);
    let padding = padded_uri_len.saturating_sub(uri_len);
    calldata.resize(calldata.len().saturating_add(padding), 0);

    calldata
}

/// Decodifica una llamada calldata a `IStatusAnchor.anchorStatusManifest(...)`.
///
/// Retorna `(issuer_id, manifest_version, manifest_hash, uri_hint)`.
///
/// # Errores
/// [`EvmLedgerError::AbiDecoding`] si los datos están truncados o el selector no coincide.
pub fn decode_anchor_status_manifest_call(
    calldata: &[u8],
) -> EvmLedgerResult<([u8; 32], u64, [u8; 32], String)> {
    if calldata.len() < 4 + 128 + 32 {
        return Err(EvmLedgerError::AbiDecoding(
            "anchorStatusManifest calldata too short".into(),
        ));
    }

    if calldata.get(0..4) != Some(&SELECTOR_ANCHOR_STATUS_MANIFEST) {
        return Err(EvmLedgerError::AbiDecoding(
            "invalid selector for anchorStatusManifest".into(),
        ));
    }

    let args = calldata.get(4..).ok_or_else(|| {
        EvmLedgerError::AbiDecoding("anchorStatusManifest calldata missing arguments".into())
    })?;
    let issuer_id = read_bytes32_at(args, 0)?;
    let manifest_version = read_uint64_at(args, 32)?;
    let manifest_hash = read_bytes32_at(args, 64)?;
    let offset = usize::try_from(read_uint64_at(args, 96)?)
        .map_err(|_| EvmLedgerError::AbiDecoding("offset exceeds usize".into()))?;

    let uri_hint = read_dynamic_string(args, offset)?;

    Ok((issuer_id, manifest_version, manifest_hash, uri_hint))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn test_selector_and_topic_hashes_consistency() {
        assert_eq!(
            &keccak256(b"getLatestCommitment(bytes32)")[0..4],
            &SELECTOR_GET_LATEST_COMMITMENT
        );
        assert_eq!(
            keccak256(b"anchorStatusManifest(bytes32,uint64,bytes32,string)")[..4],
            SELECTOR_ANCHOR_STATUS_MANIFEST
        );
        assert_eq!(
            keccak256(b"IssuerRegistered(bytes32,string,uint64,uint64)"),
            TOPIC_ISSUER_REGISTERED
        );
        assert_eq!(
            keccak256(b"IssuerSuspended(bytes32,uint64,address)"),
            TOPIC_ISSUER_SUSPENDED
        );
        assert_eq!(
            keccak256(b"IssuerReinstated(bytes32)"),
            TOPIC_ISSUER_REINSTATED
        );
        assert_eq!(
            keccak256(b"IssuerDeregistered(bytes32)"),
            TOPIC_ISSUER_DEREGISTERED
        );
        assert_eq!(
            keccak256(b"KeyAdded(bytes32,bytes32,bytes)"),
            TOPIC_KEY_ADDED
        );
        assert_eq!(
            keccak256(b"KeyRetired(bytes32,bytes32,uint64)"),
            TOPIC_KEY_RETIRED
        );
        assert_eq!(
            keccak256(b"KeySuspended(bytes32,bytes32,uint64,address)"),
            TOPIC_KEY_SUSPENDED
        );
        assert_eq!(
            keccak256(b"KeyCompromised(bytes32,bytes32,uint64)"),
            TOPIC_KEY_COMPROMISED
        );
        assert_eq!(
            keccak256(b"VerifierRegistered(bytes32,string,bytes,uint64,uint64)"),
            TOPIC_VERIFIER_REGISTERED
        );
        assert_eq!(
            keccak256(b"VerifierDeregistered(bytes32)"),
            TOPIC_VERIFIER_DEREGISTERED
        );
        assert_eq!(
            keccak256(b"TrustRootUpdated(bytes32,uint64,uint64)"),
            TOPIC_TRUST_ROOT_UPDATED
        );
        assert_eq!(
            keccak256(b"BundleSignerUpdated(address,bytes32,bytes,bool)"),
            TOPIC_BUNDLE_SIGNER_UPDATED
        );
        assert_eq!(
            keccak256(b"StatusManifestAnchored(bytes32,uint64,bytes32,string)"),
            TOPIC_STATUS_MANIFEST_ANCHORED
        );
    }

    #[test]
    fn test_abi_helpers_positive_and_negative() {
        let mut u64_word = [0u8; 32];
        u64_word[24..32].copy_from_slice(&123456789u64.to_be_bytes());
        assert_eq!(read_uint64(&u64_word).unwrap(), 123456789);
        assert!(read_uint64(&[0u8; 31]).is_err());

        let mut addr_word = [0u8; 32];
        addr_word[12..32].copy_from_slice(&[0x12; 20]);
        assert_eq!(read_address(&addr_word).unwrap(), [0x12; 20]);
        assert!(read_address(&[0u8; 31]).is_err());

        let mut bool_word = [0u8; 32];
        bool_word[31] = 1;
        assert!(read_bool(&bool_word).unwrap());
        bool_word[31] = 0;
        assert!(!read_bool(&bool_word).unwrap());
        bool_word[31] = 2;
        assert!(read_bool(&bool_word).is_err());
        assert!(read_bool(&[0u8; 30]).is_err());

        let data = vec![0u8; 64];
        assert!(get_word(&data, 0).is_ok());
        assert!(get_word(&data, 32).is_ok());
        assert!(get_word(&data, 33).is_err());

        assert_eq!(read_uint64_at(&u64_word, 0).unwrap(), 123456789);
        assert!(!read_bool_at(&[0u8; 32], 0).unwrap());
        assert_eq!(read_bytes32_at(&u64_word, 0).unwrap(), u64_word);

        // Dynamic bytes
        let mut dyn_data = Vec::new();
        let mut len_word = [0u8; 32];
        len_word[31] = 4;
        dyn_data.extend_from_slice(&len_word);
        dyn_data.extend_from_slice(b"test");
        dyn_data.extend_from_slice(&[0u8; 28]);
        assert_eq!(read_dynamic_bytes(&dyn_data, 0).unwrap(), b"test");
        assert_eq!(read_dynamic_string(&dyn_data, 0).unwrap(), "test");

        // Invalid dynamic string (invalid utf-8)
        let mut inv_utf8 = Vec::new();
        let mut inv_len = [0u8; 32];
        inv_len[31] = 2;
        inv_utf8.extend_from_slice(&inv_len);
        inv_utf8.extend_from_slice(&[0xff, 0xff]);
        inv_utf8.extend_from_slice(&[0u8; 30]);
        assert!(read_dynamic_string(&inv_utf8, 0).is_err());
    }

    #[test]
    fn test_decode_all_events_positive_and_negative() {
        let issuer_id = [0x11u8; 32];
        let kid = [0x22u8; 32];
        let verifier_id = [0x33u8; 32];
        let addr = [0x44u8; 20];
        let mut addr_word = [0u8; 32];
        addr_word[12..32].copy_from_slice(&addr);

        let mut u64_w = [0u8; 32];
        u64_w[31] = 100;

        // Empty topics -> Ok(None)
        assert!(decode_event_log(&[], &[]).unwrap().is_none());
        // Unknown topic0 -> Ok(None)
        assert!(decode_event_log(&[[0xfe; 32]], &[]).unwrap().is_none());

        // IssuerSuspended
        let res = decode_event_log(&[TOPIC_ISSUER_SUSPENDED, issuer_id, addr_word], &u64_w)
            .unwrap()
            .unwrap();
        match res {
            LedgerEvent::IssuerSuspended(e) => {
                assert_eq!(e.issuer_id, issuer_id);
                assert_eq!(e.expires_at, 100);
                assert_eq!(e.initiated_by, addr);
            }
            _ => panic!("wrong event"),
        }
        // IssuerSuspended missing topics / data
        assert!(decode_event_log(&[TOPIC_ISSUER_SUSPENDED], &u64_w).is_err());
        assert!(decode_event_log(&[TOPIC_ISSUER_SUSPENDED, issuer_id], &u64_w).is_err());
        assert!(decode_event_log(&[TOPIC_ISSUER_SUSPENDED, issuer_id, addr_word], &[]).is_err());

        // IssuerReinstated
        let res = decode_event_log(&[TOPIC_ISSUER_REINSTATED, issuer_id], &[])
            .unwrap()
            .unwrap();
        match res {
            LedgerEvent::IssuerReinstated(e) => assert_eq!(e.issuer_id, issuer_id),
            _ => panic!("wrong event"),
        }
        assert!(decode_event_log(&[TOPIC_ISSUER_REINSTATED], &[]).is_err());

        // IssuerDeregistered
        let res = decode_event_log(&[TOPIC_ISSUER_DEREGISTERED, issuer_id], &[])
            .unwrap()
            .unwrap();
        match res {
            LedgerEvent::IssuerDeregistered(e) => assert_eq!(e.issuer_id, issuer_id),
            _ => panic!("wrong event"),
        }
        assert!(decode_event_log(&[TOPIC_ISSUER_DEREGISTERED], &[]).is_err());

        // KeyRetired
        let res = decode_event_log(&[TOPIC_KEY_RETIRED, issuer_id, kid], &u64_w)
            .unwrap()
            .unwrap();
        match res {
            LedgerEvent::KeyRetired(e) => {
                assert_eq!(e.issuer_id, issuer_id);
                assert_eq!(e.kid, kid);
                assert_eq!(e.state_since, 100);
            }
            _ => panic!("wrong event"),
        }
        assert!(decode_event_log(&[TOPIC_KEY_RETIRED, issuer_id], &u64_w).is_err());
        assert!(decode_event_log(&[TOPIC_KEY_RETIRED, issuer_id, kid], &[]).is_err());

        // KeySuspended
        let res = decode_event_log(&[TOPIC_KEY_SUSPENDED, issuer_id, kid, addr_word], &u64_w)
            .unwrap()
            .unwrap();
        match res {
            LedgerEvent::KeySuspended(e) => {
                assert_eq!(e.issuer_id, issuer_id);
                assert_eq!(e.kid, kid);
                assert_eq!(e.expires_at, 100);
                assert_eq!(e.initiated_by, addr);
            }
            _ => panic!("wrong event"),
        }
        assert!(decode_event_log(&[TOPIC_KEY_SUSPENDED, issuer_id, kid], &u64_w).is_err());
        assert!(decode_event_log(&[TOPIC_KEY_SUSPENDED, issuer_id, kid, addr_word], &[]).is_err());

        // KeyCompromised
        let res = decode_event_log(&[TOPIC_KEY_COMPROMISED, issuer_id, kid], &u64_w)
            .unwrap()
            .unwrap();
        match res {
            LedgerEvent::KeyCompromised(e) => {
                assert_eq!(e.issuer_id, issuer_id);
                assert_eq!(e.kid, kid);
                assert_eq!(e.state_since, 100);
            }
            _ => panic!("wrong event"),
        }
        assert!(decode_event_log(&[TOPIC_KEY_COMPROMISED, issuer_id], &u64_w).is_err());
        assert!(decode_event_log(&[TOPIC_KEY_COMPROMISED, issuer_id, kid], &[]).is_err());

        // VerifierRegistered
        let mut verifier_data = Vec::new();
        let mut uri_offset = [0u8; 32];
        uri_offset[31] = 128; // offset to uri
        let mut key_offset = [0u8; 32];
        key_offset[30] = 1; // offset to key (256)
        verifier_data.extend_from_slice(&uri_offset);
        verifier_data.extend_from_slice(&key_offset);
        verifier_data.extend_from_slice(&u64_w); // valid_from
        verifier_data.extend_from_slice(&u64_w); // valid_until

        // uri payload at 128
        let mut uri_len = [0u8; 32];
        uri_len[31] = 5;
        verifier_data.extend_from_slice(&uri_len);
        verifier_data.extend_from_slice(b"https");
        verifier_data.extend_from_slice(&[0u8; 27]);
        verifier_data.extend_from_slice(&[0u8; 64]); // padding to 256

        // key payload at 256
        let mut key_len = [0u8; 32];
        key_len[31] = 3;
        verifier_data.extend_from_slice(&key_len);
        verifier_data.extend_from_slice(b"key");
        verifier_data.extend_from_slice(&[0u8; 29]);

        let res = decode_event_log(&[TOPIC_VERIFIER_REGISTERED, verifier_id], &verifier_data)
            .unwrap()
            .unwrap();
        match res {
            LedgerEvent::VerifierRegistered(e) => {
                assert_eq!(e.verifier_id, verifier_id);
                assert_eq!(e.uri, "https");
                assert_eq!(e.public_key, b"key");
            }
            _ => panic!("wrong event"),
        }
        assert!(decode_event_log(&[TOPIC_VERIFIER_REGISTERED], &verifier_data).is_err());
        assert!(decode_event_log(&[TOPIC_VERIFIER_REGISTERED, verifier_id], &[]).is_err());

        // VerifierDeregistered
        let res = decode_event_log(&[TOPIC_VERIFIER_DEREGISTERED, verifier_id], &[])
            .unwrap()
            .unwrap();
        match res {
            LedgerEvent::VerifierDeregistered(e) => assert_eq!(e.verifier_id, verifier_id),
            _ => panic!("wrong event"),
        }
        assert!(decode_event_log(&[TOPIC_VERIFIER_DEREGISTERED], &[]).is_err());

        // KeyRetired missing topic 1
        assert!(decode_event_log(&[TOPIC_KEY_RETIRED], &u64_w).is_err());

        // KeySuspended missing topics 1, 2
        assert!(decode_event_log(&[TOPIC_KEY_SUSPENDED], &u64_w).is_err());
        assert!(decode_event_log(&[TOPIC_KEY_SUSPENDED, issuer_id], &u64_w).is_err());

        // KeyCompromised missing topic 1
        assert!(decode_event_log(&[TOPIC_KEY_COMPROMISED], &u64_w).is_err());

        // StatusManifestAnchored error paths
        assert!(decode_event_log(&[TOPIC_STATUS_MANIFEST_ANCHORED], &[]).is_err());
        assert!(decode_event_log(&[TOPIC_STATUS_MANIFEST_ANCHORED, issuer_id], &[]).is_err());
        assert!(decode_event_log(
            &[TOPIC_STATUS_MANIFEST_ANCHORED, issuer_id, u64_w],
            &[0u8; 30]
        )
        .is_err());

        // IssuerRegistered error paths
        assert!(decode_event_log(&[TOPIC_ISSUER_REGISTERED], &[]).is_err());
        assert!(decode_event_log(&[TOPIC_ISSUER_REGISTERED, issuer_id], &[0u8; 32]).is_err());

        // KeyAdded error paths
        assert!(decode_event_log(&[TOPIC_KEY_ADDED], &[]).is_err());
        assert!(decode_event_log(&[TOPIC_KEY_ADDED, issuer_id], &[]).is_err());
        assert!(decode_event_log(&[TOPIC_KEY_ADDED, issuer_id, kid], &[]).is_err());

        // TrustRootUpdated error paths
        assert!(decode_event_log(&[TOPIC_TRUST_ROOT_UPDATED], &[]).is_err());
        assert!(decode_event_log(&[TOPIC_TRUST_ROOT_UPDATED, [0x11; 32]], &[]).is_err());
        assert!(decode_event_log(&[TOPIC_TRUST_ROOT_UPDATED, [0x11; 32], u64_w], &[]).is_err());

        // BundleSignerUpdated error paths
        assert!(decode_event_log(&[TOPIC_BUNDLE_SIGNER_UPDATED], &[]).is_err());
        assert!(decode_event_log(&[TOPIC_BUNDLE_SIGNER_UPDATED, addr_word], &[]).is_err());
        assert!(decode_event_log(&[TOPIC_BUNDLE_SIGNER_UPDATED, addr_word, kid], &[]).is_err());
    }

    #[test]
    fn test_commitment_call_and_return_decoding() {
        let issuer_id = [0x55u8; 32];
        let call = encode_get_latest_commitment_call(&issuer_id);
        assert_eq!(&call[0..4], &SELECTOR_GET_LATEST_COMMITMENT);
        assert_eq!(&call[4..36], &issuer_id);

        assert!(decode_get_latest_commitment_return(issuer_id, &[])
            .unwrap()
            .is_none());
        assert!(decode_get_latest_commitment_return(issuer_id, &[0u8; 64]).is_err());
    }

    #[test]
    fn test_anchor_status_manifest_call_roundtrip_and_errors() {
        let issuer_id = [0x42u8; 32];
        let manifest_version = 7u64;
        let manifest_hash = [0xabu8; 32];
        let uri_hint = "https://issuer.example.com/status/manifest.jwt";

        let calldata = encode_anchor_status_manifest_call(
            &issuer_id,
            manifest_version,
            &manifest_hash,
            uri_hint,
        );

        assert_eq!(&calldata[0..4], &SELECTOR_ANCHOR_STATUS_MANIFEST);

        let (dec_issuer, dec_ver, dec_hash, dec_uri) =
            decode_anchor_status_manifest_call(&calldata).expect("should decode valid calldata");

        assert_eq!(dec_issuer, issuer_id);
        assert_eq!(dec_ver, manifest_version);
        assert_eq!(dec_hash, manifest_hash);
        assert_eq!(dec_uri, uri_hint);

        // Error cases:
        // 1. Too short
        assert!(decode_anchor_status_manifest_call(&calldata[..50]).is_err());

        // 2. Invalid selector
        let mut corrupted = calldata.clone();
        corrupted[0] ^= 0xff;
        assert!(decode_anchor_status_manifest_call(&corrupted).is_err());
    }
}
