//! # `gravital-id-credential`
//!
//! Emisión, validación y verificación de credenciales SD-JWT y SD-JWT VC para Gravital ID.
//!
//! - **Capa arquitectónica:** L2
//! - **Garantía no_std:** Sí (`#![no_std]` + `alloc`)
//!
//! Trazabilidad:
//! - **REQ-CRED-002:** Sal de ≥ 128 bits de CSPRNG para cada divulgación.
//! - **REQ-CRED-003:** Digests señuelo (decoys) configurables por perfil en objetos y arrays.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod decoy;
pub mod disclosure;
pub mod issuer;
pub mod json_canonical;
pub mod salt;

pub use decoy::{create_array_decoy_element, generate_decoy_digest, generate_decoy_digests};
pub use disclosure::{Disclosure, DisclosureDigest, DisclosureKind, DIGEST_BASE64URL_LEN};
pub use issuer::{
    EmittedArray, EmittedObject, IssuedSdJwt, JwsHeader, SdArrayBuilder, SdIssuer, SdObjectBuilder,
};
pub use json_canonical::to_canonical_json;
pub use salt::{Salt, MIN_SALT_BYTES};

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
