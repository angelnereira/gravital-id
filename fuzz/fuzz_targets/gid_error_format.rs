#![no_main]
//! Objetivo de fuzzing de ejemplo (F1.T11, `TEST_STRATEGY.md`).
//!
//! Propiedad invariantada: el formateo de `GidError` nunca entra en pánico, es
//! determinista y siempre contiene el código canónico `GID-Exxxx`. Los objetivos
//! de los parsers (base64url, JSON, CBOR, DEFLATE, Base45, JWK) se añaden en F2
//! (`ROADMAP.md` F2.T11), uno por parser.

use arbitrary::Arbitrary;
use gravital_id_types::{ErrorCode, GidError};
use libfuzzer_sys::fuzz_target;

/// Lista cerrada de variantes del catálogo (espejo de `ErrorCode`).
const CODES: [ErrorCode; 59] = [
    ErrorCode::MalformedMessage,
    ErrorCode::ExpiredRequest,
    ErrorCode::NonceReused,
    ErrorCode::UnsupportedProtocolVersion,
    ErrorCode::DisclosuresMismatch,
    ErrorCode::KeyBindingFailed,
    ErrorCode::DecompressionRatioExceeded,
    ErrorCode::MultiQrIncomplete,
    ErrorCode::Base45DecodeFailed,
    ErrorCode::HpkeDecryptionFailed,
    ErrorCode::InvalidSignature,
    ErrorCode::UnsupportedAlgorithm,
    ErrorCode::InvalidKeyFormat,
    ErrorCode::HighSValueRejected,
    ErrorCode::KeyNotFound,
    ErrorCode::AeadAuthenticationFailed,
    ErrorCode::InsufficientEntropy,
    ErrorCode::MalformedSdJwt,
    ErrorCode::MissingRequiredClaim,
    ErrorCode::InvalidDisclosureDigest,
    ErrorCode::SchemaValidationFailed,
    ErrorCode::CredentialExpired,
    ErrorCode::CredentialNotYetValid,
    ErrorCode::MalformedStatusList,
    ErrorCode::StatusIndexOutOfRange,
    ErrorCode::StatusListExpired,
    ErrorCode::StatusManifestMismatch,
    ErrorCode::CredentialRevoked,
    ErrorCode::CredentialSuspended,
    ErrorCode::UntrustedIssuer,
    ErrorCode::IssuerSuspended,
    ErrorCode::IssuerKeyCompromised,
    ErrorCode::IssuerKeyRetired,
    ErrorCode::InsufficientBundleSignatures,
    ErrorCode::BundleVersionRollback,
    ErrorCode::ClockRollbackDetected,
    ErrorCode::TrustRootChainBroken,
    ErrorCode::VerifierStateCorrupted,
    ErrorCode::StorageReadFailed,
    ErrorCode::StorageWriteFailed,
    ErrorCode::SchemaMigrationFailed,
    ErrorCode::RecordNotFound,
    ErrorCode::HardwareKeystoreFailed,
    ErrorCode::ClockUnavailable,
    ErrorCode::StateStoreCorrupted,
    ErrorCode::TransportTimeout,
    ErrorCode::UnsupportedAid,
    ErrorCode::ProximityMessageTooLarge,
    ErrorCode::ProximitySessionExpired,
    ErrorCode::ConsentPending,
    ErrorCode::CardPinRequired,
    ErrorCode::CardPinBlocked,
    ErrorCode::ProximityDecryptionFailed,
    ErrorCode::InvalidApduCommand,
    ErrorCode::CardNotPersonalized,
    ErrorCode::InvalidSessionCode,
    ErrorCode::FfiBoundaryViolation,
    ErrorCode::WasmMemoryPoisoned,
    ErrorCode::PanicCaught,
];

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    /// Índice arbitrario dentro del catálogo cerrado.
    code_index: u8,
    /// Mensaje arbitrario (incluye UTF-8 arbitrario y cadenas vacías).
    message: String,
    /// Contexto opcional arbitrario.
    details: Option<String>,
}

fuzz_target!(|input: FuzzInput| {
    // El índice arbitrario se proyecta al catálogo cerrado.
    let idx = usize::from(input.code_index) % CODES.len();
    let Some(&code) = CODES.get(idx) else {
        return;
    };

    let mut err = GidError::new(code, input.message.clone());
    if let Some(details) = input.details.clone() {
        err = err.with_details(details);
    }

    // Invariante 1: el formateo contiene el código canónico.
    let rendered = render(&err);
    assert!(rendered.contains(err.code_str()), "falta el código canónico");

    // Invariante 2: determinismo (mismas entradas => misma salida).
    assert_eq!(rendered, render(&err), "formateo no determinista");

    // Invariante 3: el mensaje y el contexto aparecen literalmente.
    assert!(rendered.contains(input.message.as_str()));
    if let Some(details) = &input.details {
        assert!(rendered.contains(details.as_str()));
    }

    // Invariante 4: el código numérico es estable y de 4 dígitos documentadas.
    let numeric = err.numeric_code();
    assert!((1001..=9999).contains(&numeric), "código fuera de rango");
});

/// Formateo canónico de `GidError` vía `Display` (INV-02: nunca incluye material
/// sensible más allá del mensaje provisto por la prueba).
fn render(err: &GidError) -> String {
    format!("{err}")
}
