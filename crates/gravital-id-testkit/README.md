# gravital-id-testkit

> **Capa:** Dev (solo `[dev-dependencies]`) · **no_std:** No

## Propósito

Utilidades de prueba, relojes fijos y datos deterministas para Gravital ID.

## Contenido

| Componente | Implementa | Uso |
|---|---|---|
| `FixedClock` | `gravital_id_types::Clock` | Reloj controlado por la prueba (`advance_seconds`, `advance_millis`, `set`). |
| `SeededRng` | `gravital_id_crypto::Rng` | xoshiro256** sembrado explícitamente; flujo reproducible (`DEFAULT_TEST_SEED`). |

Las utilidades de aserción de `VerificationResult` (cuatro estados, ADR-0020) se
añaden junto al tipo en F4.T06 (`ROADMAP.md` F1.T07, F4.T06).

## Invariantes aplicables

- **INV-11:** determinismo estricto; ninguna prueba usa reloj real ni aleatoriedad sin sembrar.
- **INV-01:** cero I/O en las capas del núcleo.
- **INV-09:** sin código `unsafe` (`#![forbid(unsafe_code)]`).
- **INV-10:** sin pánicos en código de biblioteca.
