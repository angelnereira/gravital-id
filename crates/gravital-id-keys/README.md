# gravital-id-keys

> **Capa:** L1 · **no_std:** Sí (`#![no_std]` + `alloc`)

## Propósito

Gestión y traits de claves, propósitos de clave (`KeyPurpose`), handles tipados (`KeyHandle<P>`), contratos de almacén seguro (`KeyStore`), implementación software en memoria (`SoftwareKeyStore`) y normalización de firmas ECDSA P-256 (DER ↔ IEEE P1363) para Gravital ID.

## Requisitos y especificaciones

- **REQ-KEY-001:** Separación de claves por propósito (`KeyPurpose`) y garantía en tiempo de compilación mediante `KeyHandle<P>`.
- **REQ-KEY-004:** Trait `KeyStore` abstracto e implementable por el host, con implementación software (`SoftwareKeyStore`) para pruebas y entornos que lo admitan bajo la feature `software-keystore`.
- **REQ-KEY-007:** Identificadores de clave derivados como JWK Thumbprints (RFC 7638, SHA-256 base64url).
- **REQ-KEY-009:** Claves de acuerdo (HPKE / ECDH) con propósito propio separado de firma; el sistema de tipos impide en compilación usar una clave para un propósito no autorizado.
- **REQ-KEY-010:** Normalización en Rust de firmas ECDSA DER provenientes de hardware hacia el estándar IEEE P1363 (`r‖s`, 64 bytes).

## Invariantes aplicables

- **INV-01:** Cero I/O de red o disco (`#![no_std]` + `alloc`).
- **INV-02:** Ningún secreto ni material sensible cruza a logs, métricas ni mensajes de error.
- **INV-03:** Ningún servicio custodia claves privadas de titulares; las claves nunca cruzan en claro.
- **INV-07:** Todo acceso criptográfico subyacente se canaliza a través de `gravital-id-crypto`.
- **INV-09:** Prohibido código inseguro (`#![forbid(unsafe_code)]`).
- **INV-10:** Sin pánicos en biblioteca (`unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!` denegados).
- **INV-11:** Aleatoriedad estrictamente inyectada mediante `Rng` (cero llamadas directas al SO o a reloj).

## Módulos

- `purpose`: `KeyPurpose`, `KeyHandle<P>`, marcadores `SigningPurpose` y `KeyAgreementPurpose`, y submódulo `purpose::*` con tipos marcador (`HolderBinding`, `HpkeKeyAgreement`, etc.).
- `keystore`: Contrato `KeyStore` con operaciones de bajo nivel (object-safe para `dyn KeyStore` y bindings) y métodos fuertemente tipados por propósito.
- `signature`: Normalización de firmas `normalize_signature_to_p1363` y `signature_to_der`.
- `software`: `SoftwareKeyStore`, almacén en memoria protegido con `SecretKeyBytes` (`ZeroizeOnDrop`) bajo la feature `software-keystore`.

## Features

- `software-keystore`: Habilita `SoftwareKeyStore` para pruebas, CLI y simulaciones. (Activa por defecto en pruebas).
