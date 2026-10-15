# gravital-id-issuer

> **Capa:** L3 · **no_std:** Sí (`#![no_std]` + `alloc`)

## Propósito

Construcción y firma de credenciales verificables de emisor para Gravital ID.

## Funcionalidades

- **API de construcción y firma (`Issuer::issue`):** a partir de una `CredentialRequest`
  (perfil, atributos, validez, estado, clave del titular y señuelos) valida los claims contra
  el esquema del perfil, precomputa los predicados declarados y delega la firma al `KeyStore`
  con `typ: dc+sd-jwt` + `ES256` (INV-03, INV-08).
- **Predicados en emisión:** si la solicitud incluye `birth_date`, el emisor añade los
  predicados del perfil (`age_over_18`, `age_over_21`) calculados en el instante de emisión
  inyectado (REQ-CRED-005, INV-11).
- **Emisión por lotes (`Issuer::issue_batch` + `BatchPlan`):** N copias de la misma credencial
  con **clave de vinculación, sales e índice de estado distintos por copia** (ARCHITECTURE §8.3,
  REQ-CRED-006). El plan rechaza claves o índices repetidos, desajustes de tamaño y lotes
  vacíos o demasiado grandes; si una copia falla no se entrega ninguna credencial parcial.
- **Metadatos operables (`IssuedCredential`):** serialización compacta, divulgaciones, perfil,
  `vct`, clave del titular, índice de estado e `iat`/`exp`.

## Invariantes aplicables

- **INV-01:** Cero I/O en L1–L4 (L1–L3 `no_std`, L4 sans-I/O).
- **INV-09:** Sin código `unsafe` (`#![forbid(unsafe_code)]`).
- **INV-10:** Sin pánicos en código de biblioteca.

## Ejemplo de uso

```rust,ignore
use gravital_id_codec::json::Value;
use gravital_id_issuer::{BatchPlan, CredentialRequest, Issuer, StatusAllocation};
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_testkit::SeededRng;
use gravital_id_types::{ProfileId, UnixTime};

let mut key_store = SoftwareKeyStore::new(SeededRng::new(9));
let issuer_key = key_store.generate_key::<IssuerSigning>().unwrap();
let rng_emit = SeededRng::new(10);

let request = CredentialRequest::new(
    "https://issuer.cedula.example.gov",
    ProfileId::parse("pip-personal-v1").unwrap(),
    UnixTime::from_seconds(1_791_849_600),
)
.unwrap()
.attribute("given_name", Value::String("Ana".into()))
.unwrap()
.attribute("family_name", Value::String("Perez".into()))
.unwrap()
.attribute("birth_date", Value::String("2000-04-12".into()))
.unwrap()
.status(StatusAllocation::new(7, "https://status.example/l/1").unwrap());

// Una credencial.
let credential = Issuer::issue(&request, &key_store, &issuer_key, None, &rng_emit).unwrap();
assert_eq!(credential.status_index(), Some(7));

// Un lote de tres copias con claves e índices distintos.
let holder_keys: Vec<_> = (0..3)
    .map(|_| {
        let handle = key_store.generate_key::<HolderBinding>().unwrap();
        key_store.public_key(&handle).unwrap()
    })
    .collect();
let plan = BatchPlan::new(holder_keys, vec![100, 101, 102]).unwrap();
let credentials =
    Issuer::issue_batch(&request, &plan, &key_store, &issuer_key, None, &rng_emit).unwrap();
assert_eq!(credentials.len(), 3);
```
