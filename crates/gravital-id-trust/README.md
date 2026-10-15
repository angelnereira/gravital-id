# gravital-id-trust

> **Capa:** L2 · **no_std:** Sí (`#![no_std]` + `alloc`)

## Propósito

Raíz de confianza, trust bundle multi-firma y políticas de verificación para Gravital ID.

## Invariantes aplicables

- **INV-01:** Cero I/O en L1–L4 (L1–L3 `no_std`, L4 sans-I/O).
- **INV-05:** Fail-closed: una raíz o un bundle que no cumple se rechaza completo.
- **INV-06:** Las claves llegan del documento firmado, nunca de la red.
- **INV-09:** Sin código `unsafe` (`#![forbid(unsafe_code)]`).
- **INV-10:** Sin pánicos en código de biblioteca.
- **INV-16:** Ninguna clave única sostiene la confianza offline: siempre umbral k-de-n.

## Funcionalidades

### JWS multi-firma (`jws_json.rs`)

- Parseo de la **Serialización JSON General** (RFC 7515 §7.2): `payload`, `signatures[]` con
  `protected` y `signature`. Cada firma se verifica sobre **su propia** entrada firmada
  (`protected_b64.payload_b64`), porque cada firma puede llevar cabecera distinta.
- Rechazo de `alg: none`, de algoritmos fuera de ES256, de `kid` duplicados y de documentos
  sin firmas.

### Raíz de confianza (`root.rs`, `TRUST_BUNDLE.md` §2)

- `TrustRoot` con `framework_id`, `root_version`, `bundle_epoch`, `issued_at`/`valid_until`,
  `chain_id`, `registry_address`, `root_keys` (≤ 32), `root_threshold`, `bundle_signers` y
  `bundle_threshold`.
- Umbrales acotados a `1..=n` (INV-16): un umbral imposible rechaza la raíz.
- **Encadenamiento** (`TrustRootVerifier::verify_chain`): la raíz nueva exige
  `root_version` creciente, mismo `framework_id`, `bundle_epoch` no decreciente,
  ≥ `current.root_threshold` firmas de claves de la raíz anterior y
  ≥ `candidate.root_threshold` firmas de claves propias, todas sobre la entrada firmada del
  candidato (REQ-TRUST-009).
- **Recuperación de avance forzado** (`forces_new_epoch`): al incrementar `bundle_epoch` el
  cliente descarta el bundle previo y reinicia el contador de versión (`TRUST_BUNDLE.md` §6).

### Trust bundle (`bundle.rs`, `TRUST_BUNDLE.md` §3 y §5)

- `TrustBundle` con emisores (perfiles, `vct`, estados, `status_keys`, claves con
  `state`/`state_since`), verificadores y políticas, derivado de un bloque finalizado.
- **Estados de clave** (`ARCHITECTURE.md §11.6`): `active`, `retired` (solo valida
  credenciales con `iat < state_since`, REQ-KEY-006), `suspended` y `compromised`
  (nunca válidas).
- **Cofirma k-de-n de firmantes distintos** (`TrustBundleVerifier::verify`): marco y época
  coincidentes con la raíz, anti-rollback por `(bundle_epoch, bundle_version)`
  (REQ-TRUST-002), umbral de operadores distintos y ventana de validez.
- **Sin punteros de estado** (REQ-TRUST-010, ADR-0017): el bundle no menciona listas de
  estado; las gestiona el `IssuerStatusManifest` de `gravital-id-status`.

## Ejemplo de uso

```rust,ignore
use gravital_id_trust::{TrustBundleVerifier, TrustRootVerifier};

// 1. Ra\u00edz instalada por el integrador (configuraci\u00f3n de confianza).
let (root, _) = TrustRoot::parse(&installed_root_document)?;

// 2. Bundle recibido por cualquier medio (mirror no confiable, QR administrativo, USB).
let (bundle, jws) = TrustBundle::parse(&bundle_document)?;
TrustBundleVerifier::verify(&bundle, &jws, &root, None, clock_now)?;

// 3. Rotaci\u00f3n de ra\u00edz: la nueva debe acumular ambos umbrales.
let (candidate, candidate_jws) = TrustRoot::parse(&new_root_document)?;
TrustRootVerifier::verify_chain(&root, &_root_jws, &candidate, &candidate_jws)?;
if TrustRootVerifier::forces_new_epoch(&root, &candidate) {
    // Se descarta el bundle activo y se reinicia bundle_version = 0.
}
```
