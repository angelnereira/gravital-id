//! Aritmética en campo finito de Galois $GF(2^8)$ para Shamir Secret Sharing.
//!
//! Implementación en tiempo constante sin tablas de búsqueda dependientes de datos,
//! utilizando el polinomio irreducible estándar de Rijndael/AES:
//! $$P(x) = x^8 + x^4 + x^3 + x + 1 \quad (\texttt{0x11B})$$
//!
//! Trazabilidad:
//! - `REQ-REC-003`: Recuperación social Shamir (k-de-n).
//! - `INV-01`: Libre de I/O y compatible con `#![no_std]`.
//! - `INV-09`: `#![forbid(unsafe_code)]`.
//! - `INV-10`: Sin pánicos ni unwraps.

use crate::error::RecoveryError;

/// Polinomio irreducible estándar Rijndael/AES ($x^8 + x^4 + x^3 + x + 1$).
pub const GF256_POLYNOMIAL_MOD: u8 = 0x1B;

/// Suma en $GF(2^8)$ (operación XOR en característica 2).
#[inline]
#[must_use]
pub const fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Resta en $GF(2^8)$ (idéntica a la suma en característica 2).
#[inline]
#[must_use]
pub const fn gf256_sub(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Multiplicación en $GF(2^8)$ en tiempo constante mediante el algoritmo "peasant multiplication" / Russian Peasant.
#[inline]
#[must_use]
pub fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        // Si el bit menos significativo de b está activo, acumular a
        let mask = (b & 1).wrapping_neg();
        p ^= a & mask;

        // Multiplicar a por x (shift con reducción condicional si desborda el bit 7)
        let hi_bit = (a >> 7) & 1;
        let hi_mask = hi_bit.wrapping_neg();
        a = (a << 1) ^ (GF256_POLYNOMIAL_MOD & hi_mask);

        b >>= 1;
    }
    p
}

/// Inverso multiplicativo en $GF(2^8)$ tal que $a \cdot a^{-1} = 1$ para todo $a \ne 0$.
///
/// Por el Pequeño Teorema de Fermat en $GF(2^8)$, $a^{255} = 1 \implies a^{-1} = a^{254}$.
///
/// # Errores
/// Retorna [`RecoveryError::InvalidShamirThreshold`] si $a == 0$ (cero no posee inverso).
pub fn gf256_inv(a: u8) -> Result<u8, RecoveryError> {
    if a == 0 {
        return Err(RecoveryError::InvalidShamirThreshold(
            "no existe inverso multiplicativo para el elemento nulo en GF(256)",
        ));
    }

    // Exponenciación rápida para a^254 (254 = 11111110_2)
    let mut res = 1u8;
    let mut base = a;
    let mut exp = 254u8;
    while exp > 0 {
        if (exp & 1) != 0 {
            res = gf256_mul(res, base);
        }
        base = gf256_mul(base, base);
        exp >>= 1;
    }
    Ok(res)
}

/// División en $GF(2^8)$: $a / b = a \cdot b^{-1}$.
///
/// # Errores
/// Retorna [`RecoveryError::InvalidShamirThreshold`] si $b == 0$.
pub fn gf256_div(a: u8, b: u8) -> Result<u8, RecoveryError> {
    let b_inv = gf256_inv(b)?;
    Ok(gf256_mul(a, b_inv))
}

/// Evalúa un polinomio $P(x) = c_0 \oplus c_1 x \oplus \dots \oplus c_d x^d$ en el punto $x$
/// usando el algoritmo de Horner en tiempo constante.
///
/// Los coeficientes se proporcionan en orden ascendente: `coefficients[0]` es $c_0$ (el término independiente).
#[must_use]
pub fn gf256_eval_poly(coefficients: &[u8], x: u8) -> u8 {
    if coefficients.is_empty() {
        return 0;
    }
    if x == 0 {
        return coefficients.first().copied().unwrap_or(0);
    }

    let mut iter = coefficients.iter().rev();
    let mut result = iter.next().copied().unwrap_or(0);

    for &coeff in iter {
        result = gf256_add(gf256_mul(result, x), coeff);
    }

    result
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn test_gf256_add_sub_properties() {
        assert_eq!(gf256_add(0x57, 0x83), 0x57 ^ 0x83);
        assert_eq!(gf256_sub(0x57, 0x83), 0x57 ^ 0x83);
        assert_eq!(gf256_add(0x42, 0x42), 0);
        assert_eq!(gf256_add(0x99, 0), 0x99);
    }

    #[test]
    fn test_gf256_mul_identities() {
        // Multiplicación por 0 da 0
        for a in 0..=255u8 {
            assert_eq!(gf256_mul(a, 0), 0);
            assert_eq!(gf256_mul(0, a), 0);
        }

        // Multiplicación por 1 da el mismo elemento
        for a in 0..=255u8 {
            assert_eq!(gf256_mul(a, 1), a);
            assert_eq!(gf256_mul(1, a), a);
        }

        // Vector conocido de Rijndael: 0x57 * 0x83 = 0xC1
        assert_eq!(gf256_mul(0x57, 0x83), 0xC1);
        assert_eq!(gf256_mul(0x83, 0x57), 0xC1); // Conmutatividad
    }

    #[test]
    fn test_gf256_inv_all_nonzero_elements() {
        for a in 1..=255u8 {
            let a_inv = gf256_inv(a).expect("inv must succeed for nonzero");
            assert_eq!(
                gf256_mul(a, a_inv),
                1,
                "Fallo de inverso para a = {a} (inv = {a_inv})"
            );
        }

        // Invertir 0 debe fallar con error
        assert!(gf256_inv(0).is_err());
    }

    #[test]
    fn test_gf256_div_and_mul_roundtrip() {
        for a in 1..=50u8 {
            for b in 1..=50u8 {
                let div = gf256_div(a, b).expect("div must succeed");
                assert_eq!(gf256_mul(div, b), a);
            }
        }
    }

    #[test]
    fn test_gf256_eval_poly_constant_and_linear() {
        // P(x) = 42
        assert_eq!(gf256_eval_poly(&[42], 0), 42);
        assert_eq!(gf256_eval_poly(&[42], 5), 42);

        // P(x) = 10 ^ 2*x
        let coeffs = [10, 2];
        assert_eq!(gf256_eval_poly(&coeffs, 0), 10);
        assert_eq!(gf256_eval_poly(&coeffs, 1), 10 ^ gf256_mul(2, 1));
        assert_eq!(gf256_eval_poly(&coeffs, 3), 10 ^ gf256_mul(2, 3));
    }
}
