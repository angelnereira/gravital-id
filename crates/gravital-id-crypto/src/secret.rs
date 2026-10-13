//! Higiene de secretos criptográficos en memoria (F2.T09, REQ-SEC-003, REQ-SEC-004).
//!
//! Garantías del módulo:
//! - **Limpieza segura en drop (`Zeroize`, `ZeroizeOnDrop`):** Los buffers de memoria
//!   se sobrescriben con ceros al salir de ámbito (REQ-SEC-003, INV-03).
//! - **Redacción estricta en depuración y formateo:** Las implementaciones de
//!   [`core::fmt::Debug`] y [`core::fmt::Display`] emiten siempre `"[REDACTED]"`,
//!   impidiendo que material criptográfico confidencial aparezca en registros,
//!   volcados o mensajes de error (REQ-SEC-003, INV-02).
//! - **Comparaciones en tiempo constante:** Implementa [`subtle::ConstantTimeEq`] y
//!   basa [`PartialEq`] en evaluación de tiempo constante para mitigar ataques
//!   de canal lateral de temporización (REQ-SEC-004).

use alloc::vec::Vec;
use core::fmt;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use gravital_id_types::{ErrorCode, GidError};

/// Contenedor de tamaño fijo `N` para material secreto con zeroización en drop.
///
/// Implementa [`Zeroize`] y [`ZeroizeOnDrop`]. Su representación [`fmt::Debug`]
/// y [`fmt::Display`] redacta permanentemente el contenido (REQ-SEC-003).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    /// Construye un nuevo secreto envolviendo un array fijo.
    #[must_use]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Construye un secreto a partir de un slice comprobando longitud exacta.
    ///
    /// # Errores
    /// [`ErrorCode::InvalidKeyFormat`] si la longitud no coincide con `N`.
    pub fn from_slice(slice: &[u8]) -> Result<Self, GidError> {
        if slice.len() != N {
            return Err(GidError::new(
                ErrorCode::InvalidKeyFormat,
                "secret slice length does not match expected size",
            ));
        }
        let mut bytes = [0u8; N];
        if let Some(target) = bytes.get_mut(..N) {
            target.copy_from_slice(slice);
        }
        Ok(Self(bytes))
    }

    /// Expone una referencia inmutable al material secreto.
    ///
    /// Se recomienda mantener el tiempo de vida de la referencia acotado al mínimo necesario.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; N] {
        &self.0
    }

    /// Devuelve la longitud del secreto en bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        N
    }

    /// Indica si el secreto está vacío (siempre `false` para $N > 0$).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([REDACTED])")
    }
}

impl<const N: usize> fmt::Display for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl<const N: usize> ConstantTimeEq for SecretBytes<N> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

// =========================================================================
// SecretVec (Longitud dinámica)
// =========================================================================

/// Contenedor de longitud dinámica para material secreto (sal, contraseñas, claves variables).
///
/// Zeroiza su memoria en drop y redacta su representación formateada (REQ-SEC-003).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretVec(Vec<u8>);

impl SecretVec {
    /// Construye un secreto envolviendo un vector existente.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Construye un secreto copiando desde un slice.
    #[must_use]
    pub fn from_slice(slice: &[u8]) -> Self {
        Self(slice.to_vec())
    }

    /// Expone una referencia inmutable a los bytes secretos.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    /// Devuelve el número de bytes secretos.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Indica si el vector está vacío.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretVec([REDACTED])")
    }
}

impl fmt::Display for SecretVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl ConstantTimeEq for SecretVec {
    fn ct_eq(&self, other: &Self) -> Choice {
        if self.0.len() != other.0.len() {
            Choice::from(0u8)
        } else {
            self.0.ct_eq(&other.0)
        }
    }
}

impl PartialEq for SecretVec {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SecretVec {}

// =========================================================================
// Newtypes de dominio específico
// =========================================================================

/// Clave privada para firmas ES256 (32 bytes).
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKeyBytes(SecretBytes<32>);

impl SecretKeyBytes {
    /// Longitud de la clave en bytes.
    pub const LEN: usize = 32;

    /// Crea una nueva clave secreta desde 32 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LEN]) -> Self {
        Self(SecretBytes::new(bytes))
    }

    /// Crea una clave secreta desde un slice de exactamente 32 bytes.
    ///
    /// # Errores
    /// [`ErrorCode::InvalidKeyFormat`] si la longitud no es exactamente 32 bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self, GidError> {
        Ok(Self(SecretBytes::from_slice(slice)?))
    }

    /// Expone los 32 bytes de la clave privada.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; Self::LEN] {
        self.0.expose_secret()
    }
}

impl fmt::Debug for SecretKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKeyBytes([REDACTED])")
    }
}

impl fmt::Display for SecretKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl ConstantTimeEq for SecretKeyBytes {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Clave simétrica de cifrado AEAD (XChaCha20-Poly1305 / ChaCha20Poly1305 / DEK, 32 bytes).
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AeadKeyBytes(SecretBytes<32>);

impl AeadKeyBytes {
    /// Longitud de la clave AEAD en bytes.
    pub const LEN: usize = 32;

    /// Crea una nueva clave AEAD desde 32 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LEN]) -> Self {
        Self(SecretBytes::new(bytes))
    }

    /// Crea una clave AEAD desde un slice de exactamente 32 bytes.
    ///
    /// # Errores
    /// [`ErrorCode::InvalidKeyFormat`] si la longitud no es 32 bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self, GidError> {
        Ok(Self(SecretBytes::from_slice(slice)?))
    }

    /// Expone los 32 bytes de la clave AEAD.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; Self::LEN] {
        self.0.expose_secret()
    }
}

impl fmt::Debug for AeadKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AeadKeyBytes([REDACTED])")
    }
}

impl fmt::Display for AeadKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl ConstantTimeEq for AeadKeyBytes {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Secreto compartido derivado de acuerdo de claves ECDH o HPKE KEM (32 bytes).
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(SecretBytes<32>);

impl SharedSecret {
    /// Longitud del secreto compartido en bytes.
    pub const LEN: usize = 32;

    /// Crea un nuevo secreto compartido desde 32 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LEN]) -> Self {
        Self(SecretBytes::new(bytes))
    }

    /// Crea un secreto compartido desde un slice de 32 bytes.
    ///
    /// # Errores
    /// [`ErrorCode::InvalidKeyFormat`] si la longitud no es 32 bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self, GidError> {
        Ok(Self(SecretBytes::from_slice(slice)?))
    }

    /// Expone los 32 bytes del secreto compartido.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; Self::LEN] {
        self.0.expose_secret()
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SharedSecret([REDACTED])")
    }
}

impl fmt::Display for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl ConstantTimeEq for SharedSecret {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Clave simétrica para autenticación HMAC-SHA-256.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct HmacKeyBytes(SecretVec);

impl HmacKeyBytes {
    /// Crea una nueva clave HMAC envolviendo un vector.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(SecretVec::new(bytes))
    }

    /// Crea una clave HMAC copiando desde un slice.
    #[must_use]
    pub fn from_slice(slice: &[u8]) -> Self {
        Self(SecretVec::from_slice(slice))
    }

    /// Expone la referencia inmutable al material de clave.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Devuelve la longitud de la clave HMAC.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Indica si la clave está vacía.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for HmacKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HmacKeyBytes([REDACTED])")
    }
}

impl fmt::Display for HmacKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl ConstantTimeEq for HmacKeyBytes {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use alloc::format;

    // // Verifies: REQ-SEC-003 (Debug nunca imprime material secreto en SecretBytes)
    #[test]
    fn secret_bytes_debug_and_display_are_redacted() {
        let raw = [0x42u8; 32];
        let secret = SecretBytes::new(raw);
        let debug_str = format!("{secret:?}");
        let display_str = format!("{secret}");

        assert_eq!(debug_str, "SecretBytes([REDACTED])");
        assert_eq!(display_str, "[REDACTED]");
        assert!(!debug_str.contains("42"));
        assert!(!debug_str.contains("66")); // 0x42 en decimal
    }

    // // Verifies: REQ-SEC-003 (Debug nunca imprime material secreto en SecretVec)
    #[test]
    fn secret_vec_debug_and_display_are_redacted() {
        let raw = alloc::vec![0xAA, 0xBB, 0xCC, 0xDD];
        let secret = SecretVec::new(raw);
        let debug_str = format!("{secret:?}");
        let display_str = format!("{secret}");

        assert_eq!(debug_str, "SecretVec([REDACTED])");
        assert_eq!(display_str, "[REDACTED]");
        assert!(!debug_str.contains("AA"));
        assert!(!debug_str.contains("170")); // 0xAA en decimal
    }

    // // Verifies: REQ-SEC-003 (Debug y Display redactados en newtypes de dominio)
    #[test]
    fn domain_newtypes_debug_and_display_are_redacted() {
        let sk = SecretKeyBytes::new([0x11u8; 32]);
        assert_eq!(format!("{sk:?}"), "SecretKeyBytes([REDACTED])");
        assert_eq!(format!("{sk}"), "[REDACTED]");
        assert!(!format!("{sk:?}").contains("11"));

        let aead = AeadKeyBytes::new([0x22u8; 32]);
        assert_eq!(format!("{aead:?}"), "AeadKeyBytes([REDACTED])");
        assert_eq!(format!("{aead}"), "[REDACTED]");
        assert!(!format!("{aead:?}").contains("22"));

        let shared = SharedSecret::new([0x33u8; 32]);
        assert_eq!(format!("{shared:?}"), "SharedSecret([REDACTED])");
        assert_eq!(format!("{shared}"), "[REDACTED]");
        assert!(!format!("{shared:?}").contains("33"));

        let hmac = HmacKeyBytes::from_slice(&[0x44u8; 32]);
        assert_eq!(format!("{hmac:?}"), "HmacKeyBytes([REDACTED])");
        assert_eq!(format!("{hmac}"), "[REDACTED]");
        assert!(!format!("{hmac:?}").contains("44"));
    }

    // // Verifies: REQ-SEC-003 (zeroize explícito sobrescribe con ceros)
    #[test]
    fn zeroize_clears_memory_correctly() {
        let mut secret = SecretBytes::new([0x77u8; 16]);
        assert_eq!(secret.expose_secret(), &[0x77u8; 16]);

        secret.zeroize();
        assert_eq!(secret.expose_secret(), &[0x00u8; 16]);

        let mut svec = SecretVec::from_slice(&[0x88u8; 24]);
        assert_eq!(svec.expose_secret(), &[0x88u8; 24]);
        assert_eq!(svec.len(), 24);

        svec.zeroize();
        // Vec::zeroize sobrescribe los elementos con ceros y vacía la longitud (clear).
        assert_eq!(svec.len(), 0);
        assert!(svec.is_empty());
        assert_eq!(svec.expose_secret(), &[]);
    }

    // // Verifies: REQ-SEC-004 (comparación en tiempo constante con subtle)
    #[test]
    fn constant_time_equality_behavior() {
        let a = SecretBytes::new([0x01u8; 32]);
        let b = SecretBytes::new([0x01u8; 32]);
        let mut c_bytes = [0x01u8; 32];
        c_bytes[31] = 0x02;
        let c = SecretBytes::new(c_bytes);

        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
        assert_eq!(a, b);
        assert_ne!(a, c);

        let va = SecretVec::from_slice(&[0x05u8; 10]);
        let vb = SecretVec::from_slice(&[0x05u8; 10]);
        let vc = SecretVec::from_slice(&[0x05u8; 11]);
        let vd = SecretVec::from_slice(&[0x06u8; 10]);

        assert_eq!(va, vb);
        assert_ne!(va, vc); // distinta longitud
        assert_ne!(va, vd); // distinto contenido
    }

    // // Verifies: REQ-SEC-003 (validación de longitud en constructores)
    #[test]
    fn slice_constructor_enforces_length() {
        assert!(SecretBytes::<32>::from_slice(&[0u8; 31]).is_err());
        assert!(SecretBytes::<32>::from_slice(&[0u8; 33]).is_err());
        assert!(SecretBytes::<32>::from_slice(&[0u8; 32]).is_ok());

        assert!(SecretKeyBytes::from_slice(&[0u8; 16]).is_err());
        assert!(SecretKeyBytes::from_slice(&[0u8; 32]).is_ok());

        assert!(AeadKeyBytes::from_slice(&[0u8; 24]).is_err());
        assert!(AeadKeyBytes::from_slice(&[0u8; 32]).is_ok());

        assert!(SharedSecret::from_slice(&[0u8; 64]).is_err());
        assert!(SharedSecret::from_slice(&[0u8; 32]).is_ok());
    }
}
