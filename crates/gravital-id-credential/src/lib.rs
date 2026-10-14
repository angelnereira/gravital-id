//! # `gravital-id-credential`
//!
//! Emisión, validación y verificación de credenciales SD-JWT y SD-JWT VC para Gravital ID.
//!
//! - **Capa arquitectónica:** L2
//! - **Garantía no_std:** Sí (`#![no_std]` + `alloc`)
//!
//! Trazabilidad:
//! - **REQ-CRED-001:** Formato normativo SD-JWT según RFC 9901 y capa SD-JWT VC (`typ: dc+sd-jwt`).
//! - **REQ-CRED-002:** Sal de ≥ 128 bits de CSPRNG para cada divulgación.
//! - **REQ-CRED-003:** Digests señuelo (decoys) configurables por perfil en objetos y arrays.
//! - **REQ-CRED-007:** Referencia de estado obligatoria salvo perfiles de vida corta.
//! - **REQ-CRED-008:** Rechazo de algoritmos fuera de la lista del perfil, incluido `none`.
//! - **REQ-CRED-009:** Rechazo de miembros duplicados en JSON y colisiones de claims divulgados.
//! - **REQ-PRES-002:** Key Binding JWT (KB-JWT) con nonce, aud, iat y sd_hash en presentaciones.
//! - **REQ-VER-003:** Fail-closed: ante cualquier error o ambigüedad no se acepta.
//! - **REQ-VER-008:** Límites acotados de tamaño, profundidad y número de elementos.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod decoy;
pub mod disclosure;
pub mod issuer;
pub mod json_canonical;
pub mod kb;
pub mod parser;
pub mod salt;
pub mod vc;

pub use decoy::{create_array_decoy_element, generate_decoy_digest, generate_decoy_digests};
pub use disclosure::{Disclosure, DisclosureDigest, DisclosureKind, DIGEST_BASE64URL_LEN};
pub use issuer::{
    EmittedArray, EmittedObject, IssuedSdJwt, JwsHeader, SdArrayBuilder, SdIssuer, SdObjectBuilder,
};
pub use json_canonical::to_canonical_json;
pub use kb::{
    calculate_sd_hash, KbIssuer, KbJwtClaims, KbJwtVerifier, KbVerificationPolicy, KB_JWT_ALG,
    KB_JWT_TYP,
};
pub use parser::{
    ParsedSdJwt, SdJwtLimits, DEFAULT_MAX_DISCLOSURES, DEFAULT_MAX_ELEMENTS_PER_CONTAINER,
    DEFAULT_MAX_RECURSION_DEPTH, DEFAULT_MAX_SD_JWT_INPUT_BYTES,
};
pub use salt::{Salt, MIN_SALT_BYTES};
pub use vc::{
    ConfirmationClaim, SdJwtVcBuilder, SdJwtVcClaims, SdJwtVcVerifier, StatusClaim,
    StatusListReference, VcValidityPolicy, DEFAULT_VC_CLOCK_SKEW_SECONDS, MAX_STATUS_URI_BYTES,
    MAX_VC_ISS_BYTES, SD_JWT_VC_DEFAULT_ALG, SD_JWT_VC_TYP, VC_ISS_SCHEME,
};

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
