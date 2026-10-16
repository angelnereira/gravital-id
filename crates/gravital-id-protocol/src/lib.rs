//! # `gravital-id-protocol`
//!
//! Mensajes OID4VCI/OID4VP, perfil offline QR y sobres de operación sans-I/O para Gravital ID.
//!
//! - **Capa arquitectónica:** L4 (sans-I/O)
//! - **Garantía no_std:** No
//! - **Trazabilidad:** REQ-PRES-005, REQ-PRES-006, REQ-PERF-003, PROTOCOL.md §3.

#![forbid(unsafe_code)]

extern crate alloc;

pub mod offline_multi_qr;
pub mod offline_request;
pub mod offline_signed_request;
pub mod offline_transcoding;
pub mod offline_wallet_policy;

pub use offline_multi_qr::{
    segment_presentation, MultiQrCollector, INTEGRITY_HASH8_LEN, MAX_FRAGMENT_PAYLOAD_CHARS,
    MAX_MULTI_QR_FRAGMENTS, MAX_SINGLE_QR_CHARS, MIN_MULTI_QR_FRAGMENTS, MULTI_QR_CANONICAL_PREFIX,
    MULTI_QR_LEGACY_PREFIX,
};
pub use offline_request::{
    VerificationRequest, MAX_AUDIENCE_LEN, MAX_VERIFIER_ID_LEN, MIN_NONCE_LEN,
    VERIFICATION_REQUEST_TYPE,
};
pub use offline_signed_request::{
    parse_and_verify_signed_request, sign_verification_request, SIGNED_REQUEST_TYP,
};
pub use offline_transcoding::{
    decode_presentation_from_base45, encode_presentation_to_base45, reconstruct_sd_jwt_from_cbor,
    transcode_sd_jwt_to_cbor, BASE45_CANONICAL_PREFIX, BASE45_LEGACY_PREFIX,
    MAX_PRESENTATION_DECOMPRESSED_BYTES, MAX_PRESENTATION_EXPANSION_RATIO,
    TRANSCODED_PRESENTATION_VERSION,
};
pub use offline_wallet_policy::{
    ValidatedWalletRequest, WalletRequestPolicy, WalletRequestValidator,
    DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS, DEFAULT_MAX_REQUEST_VALIDITY_SECONDS,
    DEFAULT_SENSITIVE_CLAIMS,
};

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
