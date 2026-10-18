//! Tipos de error para el servicio de retransmisión `pip-relay` (F7.T06).

use thiserror::Error;

/// Errores producidos durante las operaciones del relay.
#[derive(Debug, Error)]
pub enum RelayError {
    /// Payload excede el tamaño máximo permitido.
    #[error("payload size {actual} bytes exceeds maximum allowed limit of {max} bytes")]
    PayloadTooLarge {
        /// Límite máximo en bytes.
        max: usize,
        /// Tamaño real recibido en bytes.
        actual: usize,
    },

    /// Objeto direccionado por hash no encontrado o caducado.
    #[error("object with hash '{0}' not found or expired")]
    ObjectNotFound(String),

    /// El hash SHA-256 del contenido no coincide con el hash declarado en la ruta.
    #[error("object content hash mismatch: expected {expected}, computed {actual}")]
    ObjectHashMismatch {
        /// Hash esperado.
        expected: String,
        /// Hash real computado.
        actual: String,
    },

    /// Identificador de buzón, sobre o hash sintácticamente inválido.
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),

    /// Código numérico de sesión inválido (no tiene 10 dígitos o falla la suma de Damm).
    #[error("invalid session code: {0}")]
    InvalidSessionCode(String),

    /// Sesión de punto de encuentro ya consumida (consumo de un solo uso).
    #[error("session has already been consumed or closed")]
    SessionAlreadyConsumed,

    /// Sesión de punto de encuentro caducada tras superar el TTL de 180 segundos.
    #[error("session has expired")]
    SessionExpired,

    /// Sesión de punto de encuentro no encontrada.
    #[error("session not found")]
    SessionNotFound,

    /// Tasa de peticiones excedida (rate limit).
    #[error("rate limit exceeded")]
    RateLimitExceeded,

    /// Capacidad máxima de almacenamiento en memoria alcanzada.
    #[error("relay storage capacity exceeded: {0}")]
    CapacityExceeded(String),

    /// Error de configuración.
    #[error("configuration error: {0}")]
    Config(String),

    /// Error interno del servicio.
    #[error("internal error: {0}")]
    Internal(String),
}

impl RelayError {
    /// Retorna el código de estado HTTP correspondiente al error.
    #[must_use]
    pub fn status_code(&self) -> u16 {
        match self {
            Self::PayloadTooLarge { .. } => 413,
            Self::ObjectNotFound(_) | Self::SessionNotFound => 404,
            Self::ObjectHashMismatch { .. }
            | Self::InvalidIdentifier(_)
            | Self::InvalidSessionCode(_)
            | Self::Config(_) => 400,
            Self::SessionAlreadyConsumed => 409,
            Self::SessionExpired => 410,
            Self::RateLimitExceeded => 429,
            Self::CapacityExceeded(_) => 503,
            Self::Internal(_) => 500,
        }
    }

    /// Retorna una representación JSON sanitizada del error sin PII.
    #[must_use]
    pub fn to_json_response(&self) -> String {
        let code = self.status_code();
        let error_type = match self {
            Self::PayloadTooLarge { .. } => "payload_too_large",
            Self::ObjectNotFound(_) => "object_not_found",
            Self::ObjectHashMismatch { .. } => "hash_mismatch",
            Self::InvalidIdentifier(_) => "invalid_identifier",
            Self::InvalidSessionCode(_) => "invalid_session_code",
            Self::SessionAlreadyConsumed => "session_already_consumed",
            Self::SessionExpired => "session_expired",
            Self::SessionNotFound => "session_not_found",
            Self::RateLimitExceeded => "rate_limit_exceeded",
            Self::CapacityExceeded(_) => "capacity_exceeded",
            Self::Config(_) => "bad_request",
            Self::Internal(_) => "internal_error",
        };

        // Sanitización para evitar inyecciones en JSON
        let escaped_msg = self.to_string().replace('"', "\\\"");

        alloc::format!(
            "{{\"error\":\"{}\",\"status\":{},\"message\":\"{}\"}}",
            error_type,
            code,
            escaped_msg
        )
    }
}
extern crate alloc;
