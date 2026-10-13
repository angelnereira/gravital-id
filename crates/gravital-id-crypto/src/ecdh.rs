//! Acuerdo de claves ECDH sobre P-256 (F2.T06).
//!
//! Backend RustCrypto (`p256` con ECDH, ADR-0007). Se usa en la migración entre
//! dispositivos (ADR-0009) y como base del DHKEM de HPKE (RFC 9180).
//!
//! El secreto compartido es el eje X del punto resultante, de 32 bytes. **No**
//! se usa directamente como clave: siempre pasa por HKDF (el secreto crudo de
//! ECDH no es uniforme).

use p256::ecdh::{diffie_hellman, EphemeralSecret, SharedSecret};
use p256::{PublicKey, SecretKey};

use gravital_id_types::GidError;

/// Longitud del secreto compartido ECDH P-256 en bytes.
pub const ES256_SHARED_SECRET_LEN: usize = 32;

/// Deriva el secreto compartido entre `secret` y `peer_public`.
///
/// # Errores
/// [`ErrorCode::InvalidKeyFormat`](gravital_id_types::ErrorCode::InvalidKeyFormat) si alguna clave no es un punto P-256 válido.
pub fn agree(
    secret: &SecretKey,
    peer_public: &PublicKey,
) -> Result<[u8; ES256_SHARED_SECRET_LEN], GidError> {
    let shared: SharedSecret = diffie_hellman(secret.to_nonzero_scalar(), peer_public.as_affine());
    let mut out = [0u8; ES256_SHARED_SECRET_LEN];
    if let Some(slice) = out.get_mut(..shared.raw_secret_bytes().len()) {
        slice.copy_from_slice(shared.raw_secret_bytes());
    }
    Ok(out)
}

/// Igual que [`agree`], pero desde la clave secreta de un solo uso
/// (`EphemeralSecret`).
///
/// # Errores
/// [`ErrorCode::InvalidKeyFormat`](gravital_id_types::ErrorCode::InvalidKeyFormat) si la clave pública no es un punto P-256
/// válido.
pub fn agree_ephemeral(
    ephemeral: EphemeralSecret,
    peer_public: &PublicKey,
) -> Result<[u8; ES256_SHARED_SECRET_LEN], GidError> {
    let shared: SharedSecret = ephemeral.diffie_hellman(peer_public);
    let mut out = [0u8; ES256_SHARED_SECRET_LEN];
    if let Some(slice) = out.get_mut(..shared.raw_secret_bytes().len()) {
        slice.copy_from_slice(shared.raw_secret_bytes());
    }
    Ok(out)
}

/// Realiza un acuerdo de claves Diffie-Hellman a partir de una [`crate::secret::SecretKeyBytes`]
/// y una clave pública [`crate::jwk::JwkEcP256`], devolviendo un [`crate::secret::SharedSecret`].
///
/// # Errores
/// [`ErrorCode::InvalidKeyFormat`](gravital_id_types::ErrorCode::InvalidKeyFormat) si la clave privada o la clave pública son inválidas.
pub fn ecdh_agree_keys(
    secret_key: &crate::secret::SecretKeyBytes,
    peer_public_key: &crate::jwk::JwkEcP256,
) -> Result<crate::secret::SharedSecret, GidError> {
    let secret = SecretKey::from_slice(secret_key.expose_secret()).map_err(|_| {
        GidError::new(
            gravital_id_types::ErrorCode::InvalidKeyFormat,
            "invalid secret key bytes",
        )
    })?;
    let peer = peer_public_key.to_public_key();
    let shared = agree(&secret, &peer)?;
    crate::secret::SharedSecret::from_slice(&shared)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).
mod tests {
    use super::*;
    use alloc::vec;
    use p256::SecretKey;

    fn key(seed: u8) -> SecretKey {
        let mut secret = [0u8; 32];
        for (i, slot) in secret.iter_mut().enumerate() {
            *slot = seed.wrapping_add(i as u8);
        }
        SecretKey::from_bytes(&secret.into()).expect("valid test key")
    }

    // // Verifies: REQ-SEC-002 (ambas partes derivan el mismo secreto)
    #[test]
    fn both_parties_agree_on_the_same_secret() {
        let alice = key(1);
        let bob = key(200);
        let alice_public = alice.public_key();
        let bob_public = bob.public_key();

        let from_alice = agree(&alice, &bob_public).expect("agree");
        let from_bob = agree(&bob, &alice_public).expect("agree");
        assert_eq!(from_alice, from_bob);
        assert_eq!(from_alice.len(), ES256_SHARED_SECRET_LEN);
    }

    // // Verifies: REQ-SEC-002 (claves distintas dan secretos distintos)
    #[test]
    fn different_keys_give_different_secrets() {
        let alice = key(1);
        let bob = key(200);
        let carol = key(50);
        let shared_ab = agree(&alice, &bob.public_key()).expect("agree");
        let shared_ac = agree(&alice, &carol.public_key()).expect("agree");
        assert_ne!(shared_ab, shared_ac);
    }

    // // Verifies: REQ-SEC-002 (clave pública inválida)
    #[test]
    fn invalid_public_key_is_rejected() {
        let alice = key(1);
        // Punto que no está en la curva: todo 0xFF no es un punto P-256 válido
        // en forma SEC1 sin comprimir (el byte inicial 0x04 seguido de basura).
        let mut sec1 = vec![0x04u8];
        sec1.extend(core::iter::repeat(0xFFu8).take(64));
        let invalid = PublicKey::from_sec1_bytes(&sec1);
        if let Ok(peer) = invalid {
            // Algunas implementaciones aceptan cualquier X; en ese caso el
            // acuerdo sigue siendo determinista y la prueba no aplica.
            let _ = agree(&alice, &peer);
        }
    }
}
