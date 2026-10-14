//! Catálogo canónico de errores y códigos del protocolo Gravital ID (`ERROR_CODES.md`).
//!
//! Trazabilidad: `REQ-SDK-003`, `REQ-SDK-004`, `ADR-0001`, `ADR-0006`.

use alloc::string::String;
use core::fmt;

/// Catálogo de códigos numéricos de error estables normados en `docs/specs/ERROR_CODES.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
#[repr(u32)]
pub enum ErrorCode {
    // --- Familia 1: Protocolo, Transporte y Codificación (1001..1010) ---
    /// Estructura de mensaje JSON o binario sintácticamente inválida.
    MalformedMessage = 1001,
    /// Solicitud recibida caducada respecto al tiempo confiable.
    ExpiredRequest = 1002,
    /// Nonce de sesión reutilizado o no registrado en la caché (replay).
    NonceReused = 1003,
    /// Versión de protocolo no soportada por el motor.
    UnsupportedProtocolVersion = 1004,
    /// Divulgaciones entregadas no corresponden a los claims solicitados.
    DisclosuresMismatch = 1005,
    /// El KB-JWT no coincide con el `cnf` o el `sd_hash` es erróneo.
    KeyBindingFailed = 1006,
    /// Ratio de expansión DEFLATE superior al límite permitido (mitigación DoS).
    DecompressionRatioExceeded = 1007,
    /// Secuencia de fragmentos Multi-QR incompleta tras expirar el temporizador.
    MultiQrIncomplete = 1008,
    /// Error al decodificar la carga alfanumérica Base45 del código QR.
    Base45DecodeFailed = 1009,
    /// Fallo al desencapsular o descifrar el sobre de operación HPKE.
    HpkeDecryptionFailed = 1010,

    // --- Familia 2: Criptografía y Primitivas (2001..2007) ---
    /// La firma criptográfica no pudo verificarse contra la clave pública.
    InvalidSignature = 2001,
    /// Algoritmo prohibido o no soportado (p. ej. `alg: none`, RSA).
    UnsupportedAlgorithm = 2002,
    /// Clave pública malformada, punto no en curva P-256 o JWK inválido.
    InvalidKeyFormat = 2003,
    /// Firma ECDSA con componente s maleable (s > n/2, rechazo Low-S).
    HighSValueRejected = 2004,
    /// Clave solicitada no presente en el almacén de claves del host.
    KeyNotFound = 2005,
    /// Fallo de autenticación en descifrado simétrico (datos corruptos o KEK incorrecta).
    AeadAuthenticationFailed = 2006,
    /// Generador CSPRNG falló al producir la entropía mínima requerida (128 bits).
    InsufficientEntropy = 2007,

    // --- Familia 3: Credenciales y SD-JWT (3001..3006) ---
    /// Formato de credencial no se ajusta a RFC 9901 / draft-19.
    MalformedSdJwt = 3001,
    /// Falta un claim obligatorio exigido por el esquema del perfil o del vct.
    MissingRequiredClaim = 3002,
    /// El hash de una divulgación no coincide con ninguna entrada del array `_sd`.
    InvalidDisclosureDigest = 3003,
    /// Los claims divulgados no satisfacen el esquema JSON normativo.
    SchemaValidationFailed = 3004,
    /// La credencial ha superado su fecha de expiración exp.
    CredentialExpired = 3005,
    /// La fecha actual es anterior al instante de inicio de vigencia nbf.
    CredentialNotYetValid = 3006,

    // --- Familia 4: Estado y Revocación (4001..4006) ---
    /// Token Status List sintácticamente corrupto o inválido.
    MalformedStatusList = 4001,
    /// El índice asignado en la credencial supera la longitud de la lista.
    StatusIndexOutOfRange = 4002,
    /// Lista de estado caducada más allá de la tolerancia de frescura.
    StatusListExpired = 4003,
    /// El hash de la lista descargada no coincide con el manifest firmado.
    StatusManifestMismatch = 4004,
    /// La credencial figura como revocada en el índice de estado.
    CredentialRevoked = 4005,
    /// La credencial figura como suspendida temporalmente.
    CredentialSuspended = 4006,

    // --- Familia 5: Verificación, Confianza y Ledger (5001..5008) ---
    /// El emisor no existe o no está registrado en el TrustBundle activo.
    UntrustedIssuer = 5001,
    /// El emisor se encuentra en estado de suspensión administrativa.
    IssuerSuspended = 5002,
    /// La clave pública de firma del emisor está catalogada como comprometida.
    IssuerKeyCompromised = 5003,
    /// La clave pública fue retirada antes de emitir la credencial.
    IssuerKeyRetired = 5004,
    /// El TrustBundle contiene menos de k firmas válidas de operadores autorizados.
    InsufficientBundleSignatures = 5005,
    /// Intento de cargar un bundle con versión inferior a la aceptada (anti-rollback).
    BundleVersionRollback = 5006,
    /// El reloj local es anterior al piso de tiempo confiable observado.
    ClockRollbackDetected = 5007,
    /// La nueva raíz no cuenta con las firmas requeridas de la raíz precedente.
    TrustRootChainBroken = 5008,
    /// El estado persistente del verificador falta, está corrupto o fue restaurado.
    ///
    /// `REQ-VER-011`: hasta una reinicialización explícita, el resultado es
    /// `Unverifiable`.
    VerifierStateCorrupted = 5009,

    // --- Familia 6: Almacenamiento Local Cifrado (6001..6004) ---
    /// Error de lectura física en la base de datos o almacenamiento local.
    StorageReadFailed = 6001,
    /// Error al escribir o confirmar transacción atómica en almacenamiento.
    StorageWriteFailed = 6002,
    /// Error al migrar la estructura de esquema a una versión superior.
    SchemaMigrationFailed = 6003,
    /// Registro solicitado no localizado por su índice ciego.
    RecordNotFound = 6004,

    // --- Familia 7: Integración con el Host y SDK (7001..7004) ---
    /// El enclave de seguridad o TEE del host devolvió un error de ejecución.
    HardwareKeystoreFailed = 7001,
    /// El proveedor de reloj inyectado por el host devolvió un valor nulo o inválido.
    ClockUnavailable = 7002,
    /// El almacenamiento de estado persistente del verificador falló su integridad.
    StateStoreCorrupted = 7003,
    /// Tiempo de espera agotado al comunicar con un relay o endpoint de red.
    TransportTimeout = 7004,

    // --- Familia 9: Errores Críticos y FFI (9001..9999) ---
    /// Parámetro nulo, puntero no alineado o violación de contrato FFI.
    FfiBoundaryViolation = 9001,
    /// Instancia de WebAssembly abortada o envenenada tras un fallo irrecuperable.
    WasmMemoryPoisoned = 9002,
    /// Pánico interno en Rust interceptado antes de cruzar hacia el lenguaje host.
    PanicCaught = 9999,
}

impl ErrorCode {
    /// Devuelve el código numérico entero (ej. 1001).
    #[must_use]
    pub const fn numeric_code(self) -> u32 {
        self as u32
    }

    /// Devuelve el identificador canónico formal con prefijo `GID-E` (ej. "GID-E1001").
    #[must_use]
    pub const fn code_str(self) -> &'static str {
        match self {
            Self::MalformedMessage => "GID-E1001",
            Self::ExpiredRequest => "GID-E1002",
            Self::NonceReused => "GID-E1003",
            Self::UnsupportedProtocolVersion => "GID-E1004",
            Self::DisclosuresMismatch => "GID-E1005",
            Self::KeyBindingFailed => "GID-E1006",
            Self::DecompressionRatioExceeded => "GID-E1007",
            Self::MultiQrIncomplete => "GID-E1008",
            Self::Base45DecodeFailed => "GID-E1009",
            Self::HpkeDecryptionFailed => "GID-E1010",

            Self::InvalidSignature => "GID-E2001",
            Self::UnsupportedAlgorithm => "GID-E2002",
            Self::InvalidKeyFormat => "GID-E2003",
            Self::HighSValueRejected => "GID-E2004",
            Self::KeyNotFound => "GID-E2005",
            Self::AeadAuthenticationFailed => "GID-E2006",
            Self::InsufficientEntropy => "GID-E2007",

            Self::MalformedSdJwt => "GID-E3001",
            Self::MissingRequiredClaim => "GID-E3002",
            Self::InvalidDisclosureDigest => "GID-E3003",
            Self::SchemaValidationFailed => "GID-E3004",
            Self::CredentialExpired => "GID-E3005",
            Self::CredentialNotYetValid => "GID-E3006",

            Self::MalformedStatusList => "GID-E4001",
            Self::StatusIndexOutOfRange => "GID-E4002",
            Self::StatusListExpired => "GID-E4003",
            Self::StatusManifestMismatch => "GID-E4004",
            Self::CredentialRevoked => "GID-E4005",
            Self::CredentialSuspended => "GID-E4006",

            Self::UntrustedIssuer => "GID-E5001",
            Self::IssuerSuspended => "GID-E5002",
            Self::IssuerKeyCompromised => "GID-E5003",
            Self::IssuerKeyRetired => "GID-E5004",
            Self::InsufficientBundleSignatures => "GID-E5005",
            Self::BundleVersionRollback => "GID-E5006",
            Self::ClockRollbackDetected => "GID-E5007",
            Self::TrustRootChainBroken => "GID-E5008",
            Self::VerifierStateCorrupted => "GID-E5009",

            Self::StorageReadFailed => "GID-E6001",
            Self::StorageWriteFailed => "GID-E6002",
            Self::SchemaMigrationFailed => "GID-E6003",
            Self::RecordNotFound => "GID-E6004",

            Self::HardwareKeystoreFailed => "GID-E7001",
            Self::ClockUnavailable => "GID-E7002",
            Self::StateStoreCorrupted => "GID-E7003",
            Self::TransportTimeout => "GID-E7004",

            Self::FfiBoundaryViolation => "GID-E9001",
            Self::WasmMemoryPoisoned => "GID-E9002",
            Self::PanicCaught => "GID-E9999",
        }
    }

    /// Devuelve el alias legado con prefijo `PIP-E` para compatibilidad (ej. "PIP-E1001").
    #[must_use]
    pub const fn legacy_code_str(self) -> &'static str {
        match self {
            Self::MalformedMessage => "PIP-E1001",
            Self::ExpiredRequest => "PIP-E1002",
            Self::NonceReused => "PIP-E1003",
            Self::UnsupportedProtocolVersion => "PIP-E1004",
            Self::DisclosuresMismatch => "PIP-E1005",
            Self::KeyBindingFailed => "PIP-E1006",
            Self::DecompressionRatioExceeded => "PIP-E1007",
            Self::MultiQrIncomplete => "PIP-E1008",
            Self::Base45DecodeFailed => "PIP-E1009",
            Self::HpkeDecryptionFailed => "PIP-E1010",

            Self::InvalidSignature => "PIP-E2001",
            Self::UnsupportedAlgorithm => "PIP-E2002",
            Self::InvalidKeyFormat => "PIP-E2003",
            Self::HighSValueRejected => "PIP-E2004",
            Self::KeyNotFound => "PIP-E2005",
            Self::AeadAuthenticationFailed => "PIP-E2006",
            Self::InsufficientEntropy => "PIP-E2007",

            Self::MalformedSdJwt => "PIP-E3001",
            Self::MissingRequiredClaim => "PIP-E3002",
            Self::InvalidDisclosureDigest => "PIP-E3003",
            Self::SchemaValidationFailed => "PIP-E3004",
            Self::CredentialExpired => "PIP-E3005",
            Self::CredentialNotYetValid => "PIP-E3006",

            Self::MalformedStatusList => "PIP-E4001",
            Self::StatusIndexOutOfRange => "PIP-E4002",
            Self::StatusListExpired => "PIP-E4003",
            Self::StatusManifestMismatch => "PIP-E4004",
            Self::CredentialRevoked => "PIP-E4005",
            Self::CredentialSuspended => "PIP-E4006",

            Self::UntrustedIssuer => "PIP-E5001",
            Self::IssuerSuspended => "PIP-E5002",
            Self::IssuerKeyCompromised => "PIP-E5003",
            Self::IssuerKeyRetired => "PIP-E5004",
            Self::InsufficientBundleSignatures => "PIP-E5005",
            Self::BundleVersionRollback => "PIP-E5006",
            Self::ClockRollbackDetected => "PIP-E5007",
            Self::TrustRootChainBroken => "PIP-E5008",
            Self::VerifierStateCorrupted => "PIP-E5009",

            Self::StorageReadFailed => "PIP-E6001",
            Self::StorageWriteFailed => "PIP-E6002",
            Self::SchemaMigrationFailed => "PIP-E6003",
            Self::RecordNotFound => "PIP-E6004",

            Self::HardwareKeystoreFailed => "PIP-E7001",
            Self::ClockUnavailable => "PIP-E7002",
            Self::StateStoreCorrupted => "PIP-E7003",
            Self::TransportTimeout => "PIP-E7004",

            Self::FfiBoundaryViolation => "PIP-E9001",
            Self::WasmMemoryPoisoned => "PIP-E9002",
            Self::PanicCaught => "PIP-E9999",
        }
    }

    /// Nombre del identificador según la especificación.
    #[must_use]
    pub const fn identifier_name(self) -> &'static str {
        match self {
            Self::MalformedMessage => "MalformedMessage",
            Self::ExpiredRequest => "ExpiredRequest",
            Self::NonceReused => "NonceReused",
            Self::UnsupportedProtocolVersion => "UnsupportedProtocolVersion",
            Self::DisclosuresMismatch => "DisclosuresMismatch",
            Self::KeyBindingFailed => "KeyBindingFailed",
            Self::DecompressionRatioExceeded => "DecompressionRatioExceeded",
            Self::MultiQrIncomplete => "MultiQrIncomplete",
            Self::Base45DecodeFailed => "Base45DecodeFailed",
            Self::HpkeDecryptionFailed => "HpkeDecryptionFailed",

            Self::InvalidSignature => "InvalidSignature",
            Self::UnsupportedAlgorithm => "UnsupportedAlgorithm",
            Self::InvalidKeyFormat => "InvalidKeyFormat",
            Self::HighSValueRejected => "HighSValueRejected",
            Self::KeyNotFound => "KeyNotFound",
            Self::AeadAuthenticationFailed => "AeadAuthenticationFailed",
            Self::InsufficientEntropy => "InsufficientEntropy",

            Self::MalformedSdJwt => "MalformedSdJwt",
            Self::MissingRequiredClaim => "MissingRequiredClaim",
            Self::InvalidDisclosureDigest => "InvalidDisclosureDigest",
            Self::SchemaValidationFailed => "SchemaValidationFailed",
            Self::CredentialExpired => "CredentialExpired",
            Self::CredentialNotYetValid => "CredentialNotYetValid",

            Self::MalformedStatusList => "MalformedStatusList",
            Self::StatusIndexOutOfRange => "StatusIndexOutOfRange",
            Self::StatusListExpired => "StatusListExpired",
            Self::StatusManifestMismatch => "StatusManifestMismatch",
            Self::CredentialRevoked => "CredentialRevoked",
            Self::CredentialSuspended => "CredentialSuspended",

            Self::UntrustedIssuer => "UntrustedIssuer",
            Self::IssuerSuspended => "IssuerSuspended",
            Self::IssuerKeyCompromised => "IssuerKeyCompromised",
            Self::IssuerKeyRetired => "IssuerKeyRetired",
            Self::InsufficientBundleSignatures => "InsufficientBundleSignatures",
            Self::BundleVersionRollback => "BundleVersionRollback",
            Self::ClockRollbackDetected => "ClockRollbackDetected",
            Self::TrustRootChainBroken => "TrustRootChainBroken",
            Self::VerifierStateCorrupted => "VerifierStateCorrupted",

            Self::StorageReadFailed => "StorageReadFailed",
            Self::StorageWriteFailed => "StorageWriteFailed",
            Self::SchemaMigrationFailed => "SchemaMigrationFailed",
            Self::RecordNotFound => "RecordNotFound",

            Self::HardwareKeystoreFailed => "HardwareKeystoreFailed",
            Self::ClockUnavailable => "ClockUnavailable",
            Self::StateStoreCorrupted => "StateStoreCorrupted",
            Self::TransportTimeout => "TransportTimeout",

            Self::FfiBoundaryViolation => "FfiBoundaryViolation",
            Self::WasmMemoryPoisoned => "WasmMemoryPoisoned",
            Self::PanicCaught => "PanicCaught",
        }
    }
}

/// Error estructurado canónico expuesto a través de la API y los bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GidError {
    /// Código de error asociado.
    pub code: ErrorCode,
    /// Mensaje descriptivo en inglés (sin información sensible).
    pub message: String,
    /// Información contextual no sensible adicional.
    pub details: Option<String>,
}

impl GidError {
    /// Construye una nueva instancia de error a partir de un código y mensaje.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    /// Añade contexto no sensible al error.
    #[must_use]
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Código numérico entero.
    #[must_use]
    pub fn numeric_code(&self) -> u32 {
        self.code.numeric_code()
    }

    /// Identificador canónico en formato de cadena (ej. "GID-E1001").
    #[must_use]
    pub fn code_str(&self) -> &'static str {
        self.code.code_str()
    }
}

impl fmt::Display for GidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(details) = &self.details {
            write!(
                f,
                "[{}] {}: {}",
                self.code.code_str(),
                self.message,
                details
            )
        } else {
            write!(f, "[{}] {}", self.code.code_str(), self.message)
        }
    }
}

/// Alias para compatibilidad con código y especificaciones iniciales.
pub type PipError = GidError;

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Invariante del catálogo (REQ-SDK-003, PROJECT_STRUCTURE.md §7): todo
    /// código publicado es un entero de 4 dígitas dentro del rango documentado
    /// 1001..=9999. Kani lo comprueba para las 48 variantes del enum.
    #[kani::proof]
    fn error_codes_are_four_digit_numbers() {
        let code: ErrorCode = kani::any();
        let numeric = code.numeric_code();
        assert!(numeric >= 1001, "código por debajo del rango documentado");
        assert!(numeric <= 9999, "código por encima del rango documentado");
    }

    /// Invariante: `GidError` conserva el código canónico y el mensaje sin
    /// transformarlos; el formateo contiene ambos.
    #[kani::proof]
    fn gid_error_display_contains_code_and_message() {
        let code: ErrorCode = kani::any();
        let message = String::from("detalle de prueba");
        let err = GidError::new(code, message.clone());
        assert_eq!(err.code, code);
        assert_eq!(err.message, message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    // // Verifies: REQ-SDK-003
    #[test]
    fn test_error_code_formatting() {
        let err = GidError::new(ErrorCode::NonceReused, "Session nonce was reused");
        assert_eq!(err.numeric_code(), 1003);
        assert_eq!(err.code_str(), "GID-E1003");
        assert_eq!(err.code.legacy_code_str(), "PIP-E1003");
        assert_eq!(err.code.identifier_name(), "NonceReused");
        assert_eq!(format!("{err}"), "[GID-E1003] Session nonce was reused");
    }

    // // Verifies: REQ-SDK-003
    #[test]
    fn test_error_with_details() {
        let err = GidError::new(ErrorCode::MalformedMessage, "Invalid JSON payload")
            .with_details("Unexpected token at line 1 column 4");
        assert_eq!(
            format!("{err}"),
            "[GID-E1001] Invalid JSON payload: Unexpected token at line 1 column 4"
        );
    }
}
