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

## Funcionalidades de la capa SD-JWT VC (`draft-ietf-oauth-sd-jwt-vc-19`)

- **Cabecera normativa (`SdJwtVcBuilder`):** `typ: dc+sd-jwt` y `alg: ES256`, rechazando `none` y
  cualquier algoritmo fuera de la lista autorizada por el perfil (REQ-CRED-008, INV-08).
- **Claims siempre visibles (`ARCHITECTURE.md §8.2`):** `iss` (URL HTTPS del emisor), `vct`,
  `iat`, y opcionales `nbf`, `exp`, `cnf` y `status`. El constructor tipado impide declararlos
  como atributos selectivos: ocultarlos rompería la verificación de vigencia y estado.
- **Vinculación del titular (`cnf.jwk`):** la clave pública del titular se serializa con los
  miembros canónicos RFC 7638 (`crv`, `kty`, `x`, `y`) y se valida en verificación, rechazando
  material privado (`d`) con `ErrorCode::InvalidKeyFormat` (INV-02, INV-03). Es la clave contra la
  que se verifica el KB-JWT de la presentación.
- **Referencia de estado (`status.status_list`):** `idx` + `uri` conforme a ADR-0005; exigida por
  defecto (`VcValidityPolicy::require_status`) y relajable para credenciales de vida corta
  (REQ-CRED-007).
- **Vigencia temporal (`VcValidityPolicy`):** `iat`/`nbf`/`exp` evaluados con el `Clock`
  inyectado (`UnixTime`) y tolerancia de sesgo acotada (`DEFAULT_VC_CLOCK_SKEW_SECONDS = 60`),
  sin `SystemTime` (INV-11, REQ-VER-005). Se rechazan `nbf < iat` y `exp < iat`/`exp < nbf`.
- **Verificación (`ParsedSdJwt::verify_vc`, `SdJwtVcVerifier`):** fail-closed; los claims de la
  capa VC se validan sobre el payload firmado por el emisor, de modo que un emisor no pueda
  ocultarlos tras divulgación selectiva (REQ-VER-003).

## Funcionalidades de esquemas de perfil (REQ-CRED-004)

- **Esquemas en compilación (`ProfileSchema`, `PROFILE_SCHEMAS`):** traducción literal de la
  sección §3 ("Esquema JSON Canónico de Referencia") de `docs/specs/profiles/pip-personal-v1.md`,
  `pip-financial-v1.md` y `pip-enterprise-v1.md` a constantes del crate. No se leen archivos en
  tiempo de ejecución (INV-01) ni se usa un motor JSON Schema completo.
- **Palabras clave admitidas:** `type` (cadena, booleano, entero, array de cadenas), `enum`,
  `pattern` (códigos de país `^[A-Z]{3}$`), `format` (`date` ISO 8601 y `date-time` RFC 3339) y
  `required`. Cualquier palabra clave nueva obliga a ampliar `ClaimKind`: nunca se ignora en
  silencio.
- **Validación en emisión (`SdJwtVcBuilder::profile(...)` + `ProfileSchema::validate`):** exige los
  claims obligatorios del perfil y sus tipos, y que el `vct` de la credencial coincida con el del
  esquema. Un perfil sin esquema registrado hace fallar la emisión (INV-05).
- **Validación en verificación (`VcValidityPolicy::with_profile(...)` + `ParsedSdJwt::verify_vc`):**
  comprueba el `vct` y los **tipos** de los atributos divulgados
  (`ProfileSchema::validate_disclosed`). Los claims `required` no se exigen sobre una
  presentación: el titular puede divulgar un subconjunto de atributos y el verificador no puede
  distinguir un atributo no divulgado de un digest señuelo; la obligación de incluirlos es del
  emisor y se comprueba al emitir.
- **Errores:** todo incumplimiento devuelve `ErrorCode::SchemaValidationFailed` (`PIP-E3004`),
  ya documentado en `docs/specs/ERROR_CODES.md` (F0.T16).

## Funcionalidades de Key Binding JWT (RFC 9901 §6)
- **Cálculo de `sd_hash` (`calculate_sd_hash`):** Digest SHA-256 base64url calculado sobre el prefijo exacto de la presentación (`<jwt>~<d1>~...~<dn>~`) según RFC 9901 §6.2.
- **Emisión de KB-JWT (`KbIssuer`):**
  - Generación de JWT con cabecera `{"alg":"ES256","typ":"kb+jwt"}` y claims tipados (`iat`, `aud`, `nonce`, `sd_hash`).
  - Firma delegada al `KeyStore` con clave de propósito titular (`KeyHandle<HolderBinding>`), garantizando INV-03.
  - Creación de presentación completa adjuntando el KB-JWT al final del prefijo: `<prefix><kb_jwt>`.
- **Verificación de Key Binding (`KbJwtVerifier`, `ParsedSdJwt::verify_key_binding`):**
  - Verificación fail-closed de cabecera (`typ: kb+jwt`, `alg: ES256`, rechazando `none`).
  - Validación del claim `sd_hash` contra el digest del prefijo presentado.
  - Validación de coincidencia de `aud` y `nonce` esperados por el verificador.
  - Política de frescura y sesgo de reloj (`KbVerificationPolicy` con `clock_skew_seconds` y `max_age_seconds`) evaluada sobre el timestamp inyectado (`UnixTime`).
  - Verificación criptográfica de firma ES256 contra la clave pública del titular (`JwkEcP256`).

## Ejemplo de uso

```rust
use gravital_id_codec::json::Value;
use gravital_id_credential::{
    calculate_sd_hash, JwsHeader, KbIssuer, KbVerificationPolicy, ParsedSdJwt, SdIssuer,
    SdObjectBuilder,
};
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_testkit::SeededRng;
use gravital_id_types::UnixTime;

let rng = SeededRng::new(42);
let mut key_store = SoftwareKeyStore::new(rng);
let issuer_handle = key_store.generate_key::<IssuerSigning>().unwrap();
let issuer_jwk = key_store.public_key(&issuer_handle).unwrap();
let holder_handle = key_store.generate_key::<HolderBinding>().unwrap();
let holder_jwk = key_store.public_key(&holder_handle).unwrap();

// 1. Emisión por parte del Emisor
let rng_emit = SeededRng::new(100);
let builder = SdObjectBuilder::new()
    .add_plain_claim("iss", Value::String("https://issuer.example.com".into()))
    .add_sd_claim("given_name", Value::String("Alice".into()))
    .set_decoys(2);

let issued = SdIssuer::issue_signed(
    builder,
    &key_store,
    &issuer_handle,
    JwsHeader::default(),
    &rng_emit,
).unwrap();

let credential_compact = issued.to_compact_serialization();

// 2. Creación de presentación con Key Binding por parte del Titular
let aud = "https://verifier.example.com";
let nonce = "session-nonce-xyz-123";
let now = UnixTime::from_seconds(1_700_000_000);

let presentation = KbIssuer::create_presentation(
    credential_compact,
    aud,
    nonce,
    now,
    &key_store,
    &holder_handle,
).unwrap();

// 3. Verificación de la presentación por parte del Verificador
let parsed = ParsedSdJwt::parse(&presentation).unwrap();
parsed.verify_issuer_signature(&issuer_jwk).unwrap();

let kb_policy = KbVerificationPolicy::default();
let kb_claims = parsed
    .verify_key_binding(aud, nonce, &holder_jwk, now, &kb_policy)
    .unwrap();
assert_eq!(kb_claims.aud, aud);
assert_eq!(kb_claims.nonce, nonce);

let claims = parsed.reconstructed_claims();
assert_eq!(claims.member("given_name"), Some(&Value::String("Alice".into())));
```

### Ejemplo SD-JWT VC (emisión y verificación)

```rust,ignore
use gravital_id_codec::json::Value;
use gravital_id_credential::{ParsedSdJwt, SdJwtVcBuilder, VcValidityPolicy};
use gravital_id_keys::{IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_testkit::SeededRng;
use gravital_id_types::{UnixTime, Vct};

let rng = SeededRng::new(7);
let mut key_store = SoftwareKeyStore::new(rng);
let issuer_handle = key_store.generate_key::<IssuerSigning>().unwrap();
let issuer_jwk = key_store.public_key(&issuer_handle).unwrap();

let now = UnixTime::from_seconds(1_700_000_000);
let rng_emit = SeededRng::new(8);

// El emisor construye la credencial con la capa SD-JWT VC (typ: dc+sd-jwt, alg: ES256).
let issued = SdJwtVcBuilder::new(
    "https://issuer.cedula.example.gov",
    Vct::parse("https://credentials.gravital.io/vct/personal/id-v1").unwrap(),
    now,
)
.unwrap()
.exp(UnixTime::from_seconds(1_700_086_400))
.status_list(7, "https://status.cedula.example.gov/lists/2026-10")
.unwrap()
.add_sd_claim("given_name", Value::String("Ana".into()))
.set_decoys(2)
.issue_signed(&key_store, &issuer_handle, None, &rng_emit)
.unwrap();

// El verifiador comprueba la firma del emisor y después la capa VC.
let parsed = ParsedSdJwt::parse(issued.to_compact_serialization()).unwrap();
parsed.verify_issuer_signature(&issuer_jwk).unwrap();
let vc_claims = parsed.verify_vc(now, &VcValidityPolicy::default()).unwrap();

assert_eq!(vc_claims.iss, "https://issuer.cedula.example.gov");
assert_eq!(vc_claims.iat, now);
assert!(vc_claims.status.is_some());
```

### Ejemplo de esquema de perfil (validación en emisión y verificación)

```rust,ignore
use gravital_id_codec::json::Value;
use gravital_id_credential::{
    ParsedSdJwt, ProfileSchema, SdJwtVcBuilder, VcValidityPolicy,
};
use gravital_id_keys::{IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_testkit::SeededRng;
use gravital_id_types::{ProfileId, UnixTime, Vct};

let rng = SeededRng::new(7);
let mut key_store = SoftwareKeyStore::new(rng);
let issuer_handle = key_store.generate_key::<IssuerSigning>().unwrap();
let issuer_jwk = key_store.public_key(&issuer_handle).unwrap();

let now = UnixTime::from_seconds(1_700_000_000);
let profile = ProfileId::parse("pip-personal-v1").unwrap();
let schema = ProfileSchema::lookup(&profile).unwrap();
let rng_emit = SeededRng::new(8);

// 1. Emisión: los atributos se validan contra el esquema del perfil antes de firmar.
let issued = SdJwtVcBuilder::new(
    "https://issuer.cedula.example.gov",
    Vct::parse("https://credentials.gravital.io/vct/personal/id-v1").unwrap(),
    now,
)
.unwrap()
.profile(profile.clone())
.exp(UnixTime::from_seconds(1_700_086_400))
.status_list(7, "https://status.cedula.example.gov/lists/2026-10")
.unwrap()
.add_sd_claim("given_name", Value::String("Ana".into()))
.add_sd_claim("family_name", Value::String("Perez".into()))
.add_sd_claim("age_over_18", Value::Bool(true))
.issue_signed(&key_store, &issuer_handle, None, &rng_emit)
.unwrap();

// 2. Verificación: la política declara el perfil valida el vct y los atributos divulgados.
let parsed = ParsedSdJwt::parse(issued.to_compact_serialization()).unwrap();
parsed.verify_issuer_signature(&issuer_jwk).unwrap();
let policy = VcValidityPolicy::default().with_profile(profile);
let claims = parsed.verify_vc(now, &policy).unwrap();

assert_eq!(claims.vct.as_str(), schema.vct);
assert_eq!(schema.claim("age_over_18").unwrap().kind, gravital_id_credential::ClaimKind::Boolean);
```
