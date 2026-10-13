//! # `gravital-id-crypto`
//!
//! Abstracciones y backend criptográfico (ES256, SHA-256, HMAC, XChaCha20-Poly1305, HPKE) para Gravital ID.
//!
//! - **Capa arquitectónica:** L1
//! - **Garantía no_std:** Sí

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod aead;
pub mod ecdh;
pub mod hpke;
pub mod kdf;
pub mod mac;
pub mod rng;
pub mod sha;
pub mod sign;

pub use aead::{open as aead_open, seal as aead_seal, AEAD_KEY_LEN, AEAD_NONCE_LEN, AEAD_TAG_LEN};
pub use ecdh::{agree as ecdh_agree, ES256_SHARED_SECRET_LEN};
pub use kdf::{hkdf_extract_sha256, hkdf_sha256, MAX_HKDF_OUTPUT_LEN};
pub use mac::{constant_time_eq, hmac_sha256, hmac_sha256_verify, HMAC_OUTPUT_LEN};
pub use rng::Rng;
pub use sha::{sha256, Sha256Hasher, SHA256_OUTPUT_LEN};
pub use sign::{
    der_to_p1363, p1363_to_der, sign_es256, verify_es256, verify_es256_der, ES256_PUBLIC_KEY_LEN,
    ES256_SECRET_KEY_LEN, ES256_SIGNATURE_LEN,
};

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
