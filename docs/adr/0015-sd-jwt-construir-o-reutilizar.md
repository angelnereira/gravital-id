# ADR-0015: SD-JWT: construir o reutilizar

- **Estado:** Propuesto
- **Fecha:** 2026-10-13
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira (pendiente de validación formal del mantenedor)
- **Issue:** #39
- **Requisitos y principios afectados:** REQ-SEC-002, REQ-CRED-001, REQ-CRED-002, REQ-CRED-003, REQ-CRED-009, REQ-VER-003, REQ-PORT-002, REQ-PORT-003, REQ-PORT-004; P-01, P-02, P-06, P-11, P-14; INV-01, INV-03, INV-05, INV-07, INV-09, INV-10, INV-15
- **Fase:** F3 (F3.T01)

## Contexto

El formato de credencial v1 de Gravital ID fue fijado en ADR-0003 como **SD-JWT VC** (Selective Disclosure for JSON Web Tokens Verifiable Credentials), basado en el estándar del IETF **RFC 9901** y el perfil normativo de credenciales. La Fase F3 del proyecto (`ROADMAP.md §8`) tiene como objetivo la emisión, parseo y verificación de credenciales SD-JWT y presentaciones con Key Binding (KB-JWT).

El hito F3.T01 exige evaluar si es viable y seguro reutilizar una biblioteca de la comunidad Rust (crates existentes en crates.io) o si el protocolo debe construir su propia implementación en el crate `gravital-id-credential` (Capa L2).

Esta decisión está estrictamente condicionada por las restricciones arquitectónicas no negociables de Gravital ID:
1. **Invariante INV-01 y ADR-0019 (`no_std` + `alloc` en Capas L1–L3):** `gravital-id-credential` es un crate de Capa L2. Debe compilar para microcontroladores y bare-metal (`thumbv7em-none-eabihf`) y WebAssembly sin sistema operativo (`wasm32-unknown-unknown`), sin enlazar `std` ni depender de un runtime async.
2. **Invariante INV-07 y ADR-0007 (Backend criptográfico unificado):** Todas las operaciones criptográficas (hashing SHA-256 para digests `_sd`, firma y verificación ES256) deben realizarse a través de `gravital-id-crypto`. Ningún crate L1–L4 puede introducir bibliotecas criptográficas externas alternativas (ej. `ring`, `openssl`).
3. **Invariante INV-03 y REQ-KEY-004 (Sin custodia ni exportación de claves privadas):** La creación de presentaciones con Key Binding (KB-JWT) no puede exigir el paso de material privado crudo en memoria; debe delegar la operación de firma al trait abstracto `KeyStore` (`gravital-id-keys`), permitiendo el uso de claves respaldadas por hardware (Secure Enclave, StrongBox, HSM).
4. **Invariantes INV-09 e INV-10 (Higiene de código y robustez):** `#![forbid(unsafe_code)]`, cero pánicos (`unwrap`, `expect`, `panic!`), mitigación de denegación de servicio por recursión JSON o asignación desmedida (REQ-CRED-009) y modelo de errores fail-closed (INV-05).
5. **Conformidad con RFC 9901:** Soporte integral de divulgaciones de objeto (`_sd`), divulgaciones de array (`...`), algorithm identifier (`_sd_alg`), decoys, divulgaciones recursivas y sal de alta entropía ($\ge 128$ bits).

---

## Opciones consideradas

### Opción A — Reutilizar un crate existente de la comunidad (`sd-jwt-rs`, `affinidi-sd-jwt` u homólogos)

Se evaluaron los crates públicos disponibles en el ecosistema Rust:
- **`sd-jwt-rs`** (OpenWallet Foundation / DSR Corporation): Es la implementación de referencia en Rust más conocida.
- **`affinidi-sd-jwt`** (Affinidi Trust Toolkit): Implementación orientada a servicios de identidad.
- **`sd-jwt` / `sdjwt`**: Crates experimentales o prototipos tempranos.

**Evaluación técnica:**
1. **Dependencia estricta de `std`:** Prácticamente la totalidad de las bibliotecas existentes (`sd-jwt-rs`, etc.) dependen directamente de `serde_json` en modo estándar, `jsonwebtoken` y `thiserror` con la feature `std`. Ninguna ofrece compatibilidad `#![no_std]`. Integrarlas en `gravital-id-credential` (L2) violaría de forma inmediata **INV-01**, **ADR-0019** y rompería la verificación de CI en `cargo xtask check-layers` y el target `thumbv7em-none-eabihf`.
2. **Contaminación de la pila criptográfica:** Crates como `jsonwebtoken` traen dependencias pesadas de terceros (como `ring` o parsers RSA/ECDSA propios), violando el principio de backend criptográfico único fijado en **INV-07** y **ADR-0007**, e incrementando drásticamente el tamaño del binario del SDK móvil.
3. **Incompatibilidad con claves de hardware (INV-03):** La arquitectura de estos crates asume que el emisor o titular posee la clave privada en formato de bytes o clave pem en memoria y la pasa directamente a funciones de firma. Esto es incompatible con el trait `KeyStore` de Gravital ID, donde las claves privadas nunca cruzan FFI ni residen en memoria cuando son administradas por Secure Enclave o StrongBox.
4. **Falta de cotas y mitigaciones DoS:** Los crates existentes delegan el parseo a `serde_json::Value` sin límites de anidación, tamaño o elementos, exponiendo al verificador a ataques de agotamiento de memoria o desbordamiento de pila ante entradas adversarias (violando REQ-CRED-009 y REQ-VER-008).
5. **Divergencia de especificaciones:** La mayoría de los crates disponibles se implementaron contra borradores anteriores del IETF (draft-05 a draft-09) y presentan discrepancias sutiles con el estándar final **RFC 9901**.

- **Ventajas:** Menor cantidad de líneas de código escritas en el repositorio para la lógica de digests.
- **Inconvenientes:** Incumplimiento crítico de INV-01, INV-03, INV-07, INV-10 y ADR-0019; incompatibilidad con plataformas embebidas; imposibilidad de delegar firmas a hardware; riesgo en la cadena de suministro (R-10).
- **Riesgo:** Inaceptable (invalida las invariantes del protocolo).

---

### Opción B — Construcción propia en `gravital-id-credential` (L2)

Implementar el motor de SD-JWT y SD-JWT VC directamente en el crate `gravital-id-credential`, apoyándose de manera estricta y exclusiva en las capas inferiores L1 ya verificadas (`gravital-id-types`, `gravital-id-codec`, `gravital-id-crypto` y `gravital-id-keys`).

**Detalle del diseño:**
1. **Capa L2 `#![no_std]` + `alloc`:** Construida enteramente sin biblioteca estándar, compatible con `thumbv7em-none-eabihf`, `wasm32-unknown-unknown` y plataformas móviles (INV-01, ADR-0019).
2. **Parsers acotados y seguros:** Emplea el motor JSON acotado (`gravital-id-codec::json`) para procesar payloads y divulgaciones, heredando de forma nativa la protección contra desbordamientos de pila, límites de tamaño y detección de miembros duplicados (REQ-CRED-009, REQ-VER-008).
3. **Criptografía canónica:** Utiliza `gravital-id-crypto` para calcular los hashes de divulgación (`sha256`) y validar firmas ES256 (RFC 6979) según `CRYPTO_PROFILES.md`.
4. **Firma por delegación con KeyStore:** La emisión de KB-JWT en la presentación delega la firma al trait `KeyStore`, permitiendo soporte nativo y transparente de claves hardware en Android y iOS sin fuga de secretos (INV-03, REQ-PRES-002, REQ-KEY-004).
5. **Conformidad estricta con RFC 9901:** Soporte de divulgaciones de objetos y arrays, claim `_sd_alg`, digests decoys, sales de 128 bits generadas por `Rng` inyectado (INV-11) y formato compacto `<issuer-jwt>~<disclosure 1>~...~<disclosure N>~<optional-kb-jwt>`.
6. **Robustez y Fuzzing:** Cobertura de pruebas unitarias, vectores externos de interoperabilidad y objetivos de fuzzing continuos en `fuzz.yml` (REQ-SEC-005).

- **Ventajas:**
  - Cumplimiento estricto de todas las invariantes del protocolo (INV-01 a INV-16).
  - Portabilidad total y binario optimizado sin sobrecarga de dependencias externas.
  - Integración nativa con `KeyStore` y los códigos de error canónicos de `gravital-id-types`.
  - Conformidad verificada contra los vectores normativos del RFC 9901.
- **Inconvenientes:**
  - Requiere el desarrollo de las tareas F3.T02 a F3.T08 en la Fase F3 (ya presupuestadas en la hoja de ruta).

---

### Opción C — Adaptar y mantener un fork de un crate externo

Crear un fork de `sd-jwt-rs` o similar para adaptarlo a `no_std` y desacoplar su criptografía.

- **Ventajas:** Reutilización parcial del código existente.
- **Inconvenientes:** El esfuerzo de eliminar `std`, reemplazar el parser JSON por uno acotado y sustituir la capa criptográfica equivale prácticamente a una reescritura, sumando la deuda técnica de mantener un fork desvinculado del upstream.
- **Riesgo:** Alto coste de mantenimiento y fragmentación.

---

## Decisión

Se adopta la **Opción B**: **Construir la implementación completa de SD-JWT y SD-JWT VC dentro de `gravital-id-credential` (L2)** como código nativo del protocolo Gravital ID.

No se incorporará ninguna biblioteca externa de SD-JWT ni de JWT general. La emisión, parseo, anonimización selectiva y verificación de credenciales SD-JWT y presentaciones KB-JWT se implementarán sobre las abstracciones L1 existentes (`gravital-id-codec`, `gravital-id-crypto`, `gravital-id-keys`), garantizando el régimen `no_std`, la delegación a hardware seguro y la robustez frente a entradas adversarias.

---

## Consecuencias

### Positivas
- **Invariantes preservadas:** Se mantienen inviolables INV-01 (`no_std`), INV-03 (claves privadas fuera de Rust), INV-07 (criptografía RustCrypto fijada) e INV-10 (sin pánicos).
- **Seguridad y mitigación DoS:** El parseo de tokens se beneficia de los límites estrictos de memoria y profundidad de `gravital-id-codec`.
- **Interoperabilidad:** Implementación directa contra el RFC 9901 oficial, validada con los vectores normativos del IETF en `conformance/vectors/`.
- **Independencia de dependencias:** Cero riesgos de auditoría de licencias o dependencias huérfanas en crates de credenciales.

### Negativas y cómo se mitigan
- **Esfuerzo de desarrollo:** La lógica de emisión, parseo y verificación debe implementarse en las tareas F3.T02–F3.T08. *Mitigación:* La hoja de ruta ya asigna tareas modulares y detalladas para cada componente con criterios de aceptación claros.
- **Riesgo de divergencia de interoperabilidad:** Una implementación propia podría tener discrepancias de interpretación con otras bibliotecas. *Mitigación:* La tarea F3.T10 exige formalmente el intercambio bidireccional de vectores con al menos una implementación externa independiente en otro lenguaje.

### Cambios necesarios en documentación
- Actualización de `docs/adr/README.md` indexando el ADR-0015 en estado Propuesto/Aceptado.
- Confirmación de las dependencias permitidas para Capa L2 en `docs/PROJECT_STRUCTURE.md §4`.

---

## Criterios para revisar esta decisión

Esta decisión solo se revisará si:
1. Surge un crate oficial respaldado por la comunidad o un consorcio de estándares (ej. OpenWallet Foundation) que proporcione soporte de primera clase para `#![no_std]`, abstracción de backend criptográfico compatible con `gravital-id-crypto` y delegación a hardware keystore sin `std`.
2. El RFC 9901 sufre una revisión mayor incompatible que justifique un cambio estructural.
