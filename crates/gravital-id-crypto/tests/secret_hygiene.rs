//! Pruebas de integración de higiene de secretos (F2.T09, REQ-SEC-003, REQ-SEC-004).
//!
//! Verifica que:
//! - Los tipos con secretos zeroizan su memoria (REQ-SEC-003).
//! - `Debug` y `Display` redactan invariablemente el material secreto (REQ-SEC-003).
//! - Las comparaciones son en tiempo constante con `subtle` (REQ-SEC-004).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use gravital_id_crypto::secret::{
    AeadKeyBytes, HmacKeyBytes, SecretBytes, SecretKeyBytes, SecretVec, SharedSecret,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

// // Verifies: REQ-SEC-003 (Debug y Display nunca exponen bytes secretos en texto plano)
#[test]
fn test_debug_and_display_never_expose_secrets() {
    let raw = [0x5Au8; 32];
    let secret = SecretBytes::new(raw);
    let debug = format!("{secret:?}");
    let display = format!("{secret}");

    assert_eq!(debug, "SecretBytes([REDACTED])");
    assert_eq!(display, "[REDACTED]");
    assert!(!debug.contains("5A"));
    assert!(!debug.contains("90")); // 0x5A en decimal

    let sk = SecretKeyBytes::new([0xDE; 32]);
    assert_eq!(format!("{sk:?}"), "SecretKeyBytes([REDACTED])");
    assert_eq!(format!("{sk}"), "[REDACTED]");
    assert!(!format!("{sk:?}").contains("DE"));

    let aead = AeadKeyBytes::new([0xAD; 32]);
    assert_eq!(format!("{aead:?}"), "AeadKeyBytes([REDACTED])");
    assert_eq!(format!("{aead}"), "[REDACTED]");

    let shared = SharedSecret::new([0xBE; 32]);
    assert_eq!(format!("{shared:?}"), "SharedSecret([REDACTED])");
    assert_eq!(format!("{shared}"), "[REDACTED]");

    let hmac = HmacKeyBytes::from_slice(&[0xEF; 64]);
    assert_eq!(format!("{hmac:?}"), "HmacKeyBytes([REDACTED])");
    assert_eq!(format!("{hmac}"), "[REDACTED]");
    assert!(!format!("{hmac:?}").contains("EF"));
}

// // Verifies: REQ-SEC-003 (Zeroize borra con ceros el buffer interno de forma determinista)
#[test]
fn test_explicit_zeroize_clears_buffer() {
    let mut secret = SecretBytes::new([0xFEu8; 32]);
    assert_eq!(secret.expose_secret(), &[0xFEu8; 32]);

    secret.zeroize();
    assert_eq!(secret.expose_secret(), &[0x00u8; 32]);

    let mut vec = SecretVec::from_slice(&[0x42u8; 50]);
    assert_eq!(vec.expose_secret(), &[0x42u8; 50]);

    vec.zeroize();
    assert_eq!(vec.expose_secret(), &[]);
    assert_eq!(vec.len(), 0);
}

// // Verifies: REQ-SEC-004 (Comparación constante con subtle en cada byte)
#[test]
fn test_constant_time_comparison_exhaustively() {
    let base = [0x33u8; 32];
    let a = SecretBytes::new(base);
    let b = SecretBytes::new(base);

    // Mismo contenido => igualdad en tiempo constante
    assert!(bool::from(a.ct_eq(&b)));
    assert_eq!(a, b);

    // Probar mutación de 1 bit en cada posición de 0 a 31
    for i in 0..32 {
        let mut modified = base;
        modified[i] ^= 0x01;
        let c = SecretBytes::new(modified);

        assert!(!bool::from(a.ct_eq(&c)), "falló rechazo en índice {i}");
        assert_ne!(a, c);
    }
}

// // Verifies: REQ-SEC-004 (Comparación de SecretVec con distintas longitudes y contenidos)
#[test]
fn test_secret_vec_constant_time_comparison() {
    let s1 = SecretVec::from_slice(b"clave-secreta-de-prueba-12345");
    let s2 = SecretVec::from_slice(b"clave-secreta-de-prueba-12345");
    let s3 = SecretVec::from_slice(b"clave-secreta-de-prueba-12346"); // 1 byte distinto
    let s4 = SecretVec::from_slice(b"clave-secreta-de-prueba-1234"); // longitud distinta

    assert!(bool::from(s1.ct_eq(&s2)));
    assert_eq!(s1, s2);

    assert!(!bool::from(s1.ct_eq(&s3)));
    assert_ne!(s1, s3);

    assert!(!bool::from(s1.ct_eq(&s4)));
    assert_ne!(s1, s4);
}
