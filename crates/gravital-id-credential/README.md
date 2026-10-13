# gravital-id-credential

> **Capa:** L2 · **no_std:** Sí (`#![no_std]` + `alloc`)

## Propósito

Emisión, validación y verificación de credenciales SD-JWT y SD-JWT VC para Gravital ID.

## Invariantes aplicables

- **INV-01:** Cero I/O en L1–L4 (L1–L3 `no_std`, L4 sans-I/O).
- **INV-03:** Sin custodia ni filtrado de claves privadas; firma delegada a través de `KeyStore`.
- **INV-07 / INV-08:** Algoritmo ES256 y hashing SHA-256 únicamente.
- **INV-09:** Sin código `unsafe` (`#![forbid(unsafe_code)]`).
- **INV-10:** Sin pánicos en código de biblioteca.

## Funcionalidades de Emisión (RFC 9901)

- **Divulgaciones selectivas (`Disclosure`):** Formato `[salt, claim_name, claim_value]` para propiedades de objetos y `[salt, element_value]` para elementos de arrays.
- **Sal criptográfica (`Salt`):** Entropía mínima de 128 bits requerida por `REQ-CRED-002` (`MIN_SALT_BYTES = 16`), generada mediante CSPRNG inyectado (`Rng`).
- **Algoritmo de digest (`_sd_alg`):** Configurado automáticamente a `"sha-256"` según RFC 9901 §5.1.1.
- **Digests señuelo (Decoys):** Soporte para inclusión de digests señuelo en arrays `_sd` y arrays con `"..."` según `REQ-CRED-003` para mitigar análisis de longitud.
- **Estructuras anidadas y recursivas:** Claims de objetos y arrays que a su vez contienen claims selectivamente divulgables.
- **Serialización compacta:** Formato `<jwt>~<d1>~<d2>~...~<dn>~` con firma JWS ES256 delegada al `KeyStore`.

## Funcionalidades de Parseo y Verificación (RFC 9901)

- **Parseo de formato compacto (`ParsedSdJwt`):** Soporta tanto credenciales emitidas (`<jwt>~<d1>~...~<dn>~`) como presentaciones con Key Binding (`<jwt>~<d1>~...~<dn>~<kb_jwt>`).
- **Verificación de digests y fail-closed:**
  - Cada divulgación presentada se valida calculando su digest SHA-256 en base64url.
  - Se rechazan presentaciones con divulgaciones duplicadas o digests duplicados en arrays `_sd`.
  - Se rechazan colisiones entre claims revelados y claims llanos del JWT (REQ-CRED-009).
  - Se rechazan divulgaciones no referenciadas por ningún digest en la credencial.
  - Se rechazan algoritmos no soportados (solo `alg: "ES256"` y `_sd_alg: "sha-256"`, prohibiendo `none`).
- **Reconstrucción recursiva de claims:** Sustituye los digests referenciados por sus valores correspondientes en objetos y arrays, omitiendo digests señuelo o no revelados, y removiendo metadatos `_sd` y `_sd_alg`.
- **Verificación criptográfica:** Comprobación de firma JWS ES256 del emisor contra una clave pública JWK EC P-256 (`verify_issuer_signature`).
- **Límites de complejidad (`SdJwtLimits`):** Cotas para tamaño de entrada, número de divulgaciones, profundidad de recursión y elementos por contenedor (REQ-VER-008).

## Ejemplo de uso

```rust
use gravital_id_codec::json::Value;
use gravital_id_credential::{
    JwsHeader, ParsedSdJwt, SdIssuer, SdObjectBuilder,
};
use gravital_id_keys::{IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_testkit::SeededRng;

let rng = SeededRng::new(42);
let mut key_store = SoftwareKeyStore::new(rng);
let handle = key_store.generate_key::<IssuerSigning>().unwrap();
let jwk = key_store.public_key(&handle).unwrap();

// Emisión
let rng_emit = SeededRng::new(100);
let builder = SdObjectBuilder::new()
    .add_plain_claim("iss", Value::String("https://issuer.example.com".into()))
    .add_sd_claim("given_name", Value::String("Alice".into()))
    .set_decoys(2);

let issued = SdIssuer::issue_signed(
    builder,
    &key_store,
    &handle,
    JwsHeader::default(),
    &rng_emit,
).unwrap();

let compact = issued.to_compact_serialization();

// Parseo, verificación y reconstrucción
let parsed = ParsedSdJwt::parse(compact).unwrap();
parsed.verify_issuer_signature(&jwk).unwrap();

let claims = parsed.reconstructed_claims();
assert_eq!(claims.member("given_name"), Some(&Value::String("Alice".into())));
```
