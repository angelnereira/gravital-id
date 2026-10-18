//! Errores tipados para pip-trust-service (F7.T04, REQ-TRUST-003, REQ-TRUST-008).

use thiserror::Error;

/// Errores operativos del servicio de confianza y cofirma.
#[derive(Debug, Error)]
pub enum TrustServiceError {
    /// Error en la configuración o variables de entorno.
    #[error("Error de configuración: {0}")]
    Config(String),

    /// Error durante la reconstrucción o derivación determinista del bundle.
    #[error("Error de derivación del bundle: {0}")]
    Derivation(String),

    /// Error criptográfico (claves, firmas, algoritmos).
    #[error("Error criptográfico: {0}")]
    Crypto(String),

    /// Error generado por un operador individual durante la firma.
    #[error("Error en operador '{operator}': {message}")]
    Operator {
        /// Nombre del operador que falló.
        operator: String,
        /// Mensaje descriptivo.
        message: String,
    },

    /// Operador con estado o cálculo divergente detectado.
    #[error("Operador divergente '{operator}': hash calculado {calculated}, esperado {expected}")]
    DivergentOperator {
        /// Identificador del operador divergente.
        operator: String,
        /// Hash o digest enviado por el operador.
        calculated: String,
        /// Hash o digest canónico esperado.
        expected: String,
    },

    /// Umbral mínimo k-de-n no alcanzado.
    #[error("Umbral de firmas insuficiente: se requieren {required} operadores distintos, se obtuvieron {valid}")]
    InsufficientSignatures {
        /// Firmas distintas requeridas por la raíz.
        required: u32,
        /// Firmas válidas y concordantes obtenidas.
        valid: u32,
    },

    /// Fallo en la agregación o ensamblado del JWS multi-firma.
    #[error("Error de agregación JWS: {0}")]
    Aggregation(String),

    /// Fallo en la persistencia o publicación del bundle en almacenamiento de objetos.
    #[error("Error de publicación en almacenamiento: {0}")]
    Storage(String),

    /// Error de serialización o deserialización de datos JSON/canónicos.
    #[error("Error de serialización: {0}")]
    Serialization(String),

    /// Error en la interacción con el almacenamiento del indexador.
    #[error("Error en almacenamiento de indexador: {0}")]
    Indexer(String),
}
