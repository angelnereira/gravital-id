# gravital-id-status

> **Capa:** L2 · **no_std:** Sí (`#![no_std]` + `alloc`)

## Propósito

Verificación e interpretación de Token Status List para Gravital ID.

## Invariantes aplicables

- **INV-01:** Cero I/O en L1–L4 (L1–L3 `no_std`, L4 sans-I/O).
- **INV-06:** Las claves de estado llegan del trust bundle; nunca de la red.
- **INV-09:** Sin código `unsafe` (`#![forbid(unsafe_code)]`).
- **INV-10:** Sin pánicos en código de biblioteca.
- **INV-11:** La frescura se evalúa con el `Clock` inyectado.

## Funcionalidades

### Token Status List (`status_list.rs`, F4.T01)

- **Formato JWT** (`typ: statuslist+jwt`, `alg: ES256`; versiones fijadas en
  `CRYPTO_PROFILES.md`). Rechaza `typ` ajenos, `alg: none` y cualquier algoritmo fuera del
  perfil (INV-08, REQ-STAT-001).
- **Descompresión acotada**: reutiliza `gravital-id-codec::deflate::inflate_bounded` con
  límite absoluto de 2 MiB y ratio 10:1 (REQ-STAT-003); incluye prueba de bomba de
  descompresión.
- **Lectura de 1 y 2 bits** (`TokenStatusList::status_of`): valores empaquetados de izquierda
  a derecha; 1 bit (`0` válido / `1` revocado) y 2 bits (`00` válido, `01` revocado,
  `10` suspendido) (REQ-STAT-007). Un valor no definido para el número de bits declarado se
  rechaza (fail-closed, REQ-VER-003).
- **Coincidencia de URI** (`check_uri`) y **frescura** (`check_freshness`) con el instante
  inyectado (REQ-STAT-004).
- **Índice fuera de rango** con `ErrorCode::StatusIndexOutOfRange`.
- **Verificación de firma** (`verify_signature`) contra la clave de estado del emisor.

### Manifiesto de estado del emisor (`manifest.rs`, ADR-0017)

- **Parseo JWS** del `IssuerStatusManifest` (`TRUST_BUNDLE.md` §7): `issuer_id`,
  `manifest_version`, `issued_at`, `valid_until` y `status_lists[]` con `status_list_id`,
  `type`, `uri`, `sha256` y `valid_until`.
- **Anti-rollback por emisor** (`check_monotonic_version`): rechaza toda versión inferior o
  igual a la última aceptada (REQ-STAT-008).
- **Integridad de lista** (`check_list_digest`): el hash SHA-256 descargado debe coincidir
  con la entrada firmada; la URI debe estar declarada (REQ-SYNC-004).
- **Acotado**: 64 KiB por manifiesto (REQ-VER-008) y validación de `sha256` hexadecimal.

### Caché y frescura (`cache.rs`, F4.T02)

- **`StatusSnapshot`**: lista + URI + instante de obtención (del `Clock` del host).
  `age_seconds(now)` y `check_freshness(now, policy)` calculan la antigíad contra el reloj
  inyectado, nunca contra el reloj del sistema (INV-11).
- **`FreshnessPolicy`**: antigíad máxima por perfil y clase de operación, con las
  constantes normativas `PERSONAL_V1` (7 días), `FINANCIAL_TRANSACTION` (30 min),
  `FINANCIAL_QUERY` (4 h) y `ENTERPRISE_V1` (8 h) de `docs/specs/profiles/*.md` §2.
- **`StatusCache`**: caché en memoria acotada (64 listas por defecto) que expulsa la
  entrada más antigua al llenarse y solo devuelve snapshots frescos (`fresh`).

## Ejemplo de uso

```rust,ignore
use gravital_id_status::{StatusListVerifier, StatusManifestVerifier, TokenStatus};
use gravital_id_types::UnixTime;

// Lista obtenida por cualquier medio (mirror no confiable) y verificada con la clave
// de estado del emisor, que llega del trust bundle.
let list = StatusListVerifier::parse(&status_list_jwt)?;
StatusListVerifier::verify_signature(&status_list_jwt, &issuer_status_key)?;
list.check_uri(status_uri)?;
list.check_freshness(now)?;

// La credencial declara su índice en status.status_list.idx.
match list.status_of(status_idx)? {
    TokenStatus::Valid => { /* continuar la verificación */ }
    TokenStatus::Revoked => { /* ErrorCode::CredentialRevoked */ }
    TokenStatus::Suspended => { /* ErrorCode::CredentialSuspended */ }
}

// Manifiesto del emisor: versión monotónica y hash de la lista.
// Caché: el snapshot guarda el instante de obtención y la frescura se evalúa
// contra el reloj inyectado, con la política del perfil y de la operación.
let snapshot = StatusSnapshot::new(list, status_uri, clock_now);
cache.insert(snapshot.clone());
let fresh = cache.fresh(status_uri, clock_now, &FreshnessPolicy::FINANCIAL_TRANSACTION)?;
fresh.list().status_of(status_idx)?;

let manifest = StatusManifestVerifier::parse(&manifest_jwt)?;
StatusManifestVerifier::verify_signature(&manifest_jwt, &issuer_status_key)?;
manifest.check_freshness(now)?;
manifest.check_monotonic_version(last_accepted_version)?;
StatusManifestVerifier::check_list_digest(&manifest, status_uri, &sha256_hex)?;
```
