# REQUIREMENTS.md — Requisitos del sistema

> **Estado:** Borrador normativo v0.2 · **Depende de:** `ARCHITECTURE.md`
> **Revisión v0.2 (2026-10-10):** incorpora la revisión de arquitectura (ADR-0016 a ADR-0020, en estado **Propuesto**); lo que depende de ellos es propuesta hasta su aceptación por un mantenedor humano.
> Cada requisito tiene un ID estable. Los IDs **nunca se reutilizan**: un requisito retirado se marca `RETIRADO` con el ADR que lo retiró.

## Cómo leer este documento

| Columna | Significado |
|---|---|
| **ID** | `REQ-<ÁREA>-<NNN>`. Se cita en issues, PRs, nombres de pruebas y la hoja de ruta. |
| **Nivel** | DEBE (MUST) · DEBERÍA (SHOULD) · PUEDE (MAY), según RFC 2119. |
| **Verif.** | Cómo se demuestra: **T** prueba automatizada · **F** fuzzing · **I** inspección/revisión · **A** análisis/auditoría · **D** demostración. |
| **Fase** | Fase de la hoja de ruta (`ROADMAP.md`) en la que el requisito debe quedar cumplido. |
| **P** | Principio de `ARCHITECTURE.md §4` que lo origina. |

**Trazabilidad obligatoria:** toda prueba que verifique un requisito incluye su ID en el nombre o en un comentario `// Verifies: REQ-XXX-NNN`. `cargo xtask trace` (F1) genera la matriz requisito → pruebas y falla si un requisito DEBE con verificación **T** o **F** de una fase cerrada no tiene pruebas. Los requisitos verificados solo por **I**, **A** o **D** se trazan con un enlace a su evidencia (revisión, informe de auditoría, demostración) en el issue del gate correspondiente.

---

## 1. Requisitos funcionales

### 1.1 Claves (KEY)

| ID | Requisito | Nivel | Verif. | Fase | P |
|---|---|---|---|---|---|
| REQ-KEY-001 | El sistema DEBE separar las claves por propósito (`KeyPurpose`) y el sistema de tipos DEBE impedir usar una clave para un propósito distinto. | DEBE | T, I | F2 | P-07 |
| REQ-KEY-002 | Las claves de vinculación del titular DEBEN usar ES256; DEBEN residir en hardware cuando la plataforma lo ofrezca. | DEBE | T, D | F9 | P-03 |
| REQ-KEY-003 | Las claves privadas del titular NO DEBEN cruzar la frontera FFI ni salir del `KeyStore` en claro. | DEBE | I, A | F9 | P-03 |
| REQ-KEY-004 | El `KeyStore` DEBE ser un trait implementable por el host; DEBE existir una implementación software para pruebas y para perfiles que la permitan. | DEBE | T | F2 | P-11 |
| REQ-KEY-005 | Las claves de emisor DEBEN tener estados `active`, `retired`, `suspended` y `compromised` con la semántica de `ARCHITECTURE.md §11.6`. | DEBE | T | F4 | P-08 |
| REQ-KEY-006 | La rotación de una clave de emisor NO DEBE invalidar credenciales firmadas antes de su retiro. | DEBE | T | F4 | — |
| REQ-KEY-007 | Los identificadores de clave DEBEN ser JWK Thumbprints (RFC 7638, SHA-256). | DEBE | T | F2 | P-04 |
| REQ-KEY-008 | Cada credencial o copia de lote DEBE usar una clave de vinculación distinta. | DEBE | T | F5 | P-09 |
| REQ-KEY-009 | Las claves de acuerdo (HPKE) DEBEN tener un `KeyPurpose` propio; una misma clave NO DEBE usarse para firmar y para acuerdo de claves. | DEBE | T | F2 | P-07 |
| REQ-KEY-010 | La conversión de firmas ECDSA entre DER y P1363 DEBE realizarse en el núcleo Rust; la verificación NO DEBE exigir *low-S* y ninguna firma DEBE usarse como identificador ni como clave de deduplicación. | DEBE | T | F2 | P-11 |

### 1.2 Credenciales (CRED)

| ID | Requisito | Nivel | Verif. | Fase | P |
|---|---|---|---|---|---|
| REQ-CRED-001 | El formato v1 DEBE ser SD-JWT VC sobre RFC 9901, con la versión de borrador fijada en `CRYPTO_PROFILES.md`. | DEBE | T | F3 | P-04 |
| REQ-CRED-002 | Cada divulgación DEBE usar una sal de ≥ 128 bits de un CSPRNG. | DEBE | T, I | F3 | P-07 |
| REQ-CRED-003 | El emisor DEBE soportar digests señuelo configurables por perfil. | DEBE | T | F3 | P-09 |
| REQ-CRED-004 | Los claims DEBEN validarse contra el esquema del perfil y del `vct` en emisión y verificación. | DEBE | T | F3 | P-08 |
| REQ-CRED-005 | Los perfiles PUEDEN definir claims de predicado precomputados (p. ej., `age_over_18`). | PUEDE | T | F3 | P-09 |
| REQ-CRED-006 | El emisor DEBERÍA soportar emisión por lotes con claves, sales e índices de estado distintos por copia. | DEBERÍA | T | F3 | P-09 |
| REQ-CRED-007 | Toda credencial DEBE incluir referencia de estado, salvo perfiles que lo excluyan explícitamente para credenciales de vida corta. | DEBE | T | F4 | P-08 |
| REQ-CRED-008 | Se DEBEN rechazar algoritmos fuera de la lista del perfil, incluido `none`. | DEBE | T, F | F3 | P-07 |
| REQ-CRED-009 | Se DEBEN rechazar JSON con nombres de miembro duplicados en cabeceras, payloads y divulgaciones. | DEBE | T, F | F2 | P-08 |

### 1.3 Presentaciones (PRES)

| ID | Requisito | Nivel | Verif. | Fase | P |
|---|---|---|---|---|---|
| REQ-PRES-001 | Una presentación DEBE contener solo las divulgaciones solicitadas y consentidas. | DEBE | T | F5 | P-09 |
| REQ-PRES-002 | Toda presentación interactiva DEBE incluir KB-JWT con `nonce`, `aud`, `iat` y `sd_hash`. | DEBE | T | F5 | P-08 |
| REQ-PRES-003 | El SDK DEBE separar preparación (qué se divulga y a quién) de confirmación (firma). | DEBE | T, I | F5 | P-09 |
| REQ-PRES-004 | El verificador DEBE mantener una caché de nonces con expiración y rechazar nonces desconocidos o reutilizados. | DEBE | T | F4 | P-08 |
| REQ-PRES-005 | El transporte offline DEBE implementar el flujo QR de dos pasos con la codificación compacta de `PROTOCOL.md` (transcodificación binaria sin pérdida + DEFLATE + Base45); la reconstrucción DEBE reproducir exactamente los bytes firmados. | DEBE | T, D | F5 | P-01 |
| REQ-PRES-006 | Si la respuesta excede el presupuesto de un QR, DEBE usarse fragmentación multi-QR con integridad. | DEBE | T, D | F5 | P-01 |
| REQ-PRES-007 | Los perfiles que lo exijan DEBEN requerir solicitudes de verificador firmadas con clave registrada. | DEBE | T | F5 | P-09 |
| REQ-PRES-008 | La presentación en línea DEBE implementar OpenID4VP 1.0 con DCQL. | DEBE | T | F10 | P-04 |

### 1.4 Verificación (VER)

| ID | Requisito | Nivel | Verif. | Fase | P |
|---|---|---|---|---|---|
| REQ-VER-001 | La verificación NO DEBE realizar I/O de red. | DEBE | T, I | F4 | P-01 |
| REQ-VER-002 | El resultado DEBE ser uno de `Valid`, `ValidWithStaleStatus`, `Unverifiable`, `Invalid`, con lista de comprobaciones y evidencia. | DEBE | T | F4 | P-05 |
| REQ-VER-003 | Ante cualquier error, dato faltante o ambigüedad, el resultado NO DEBE ser `Valid`. | DEBE | T, F | F4 | P-08 |
| REQ-VER-004 | Las claves del emisor DEBEN obtenerse solo del trust bundle; se DEBEN ignorar `jku`, `x5u`, `x5c` y `jwk` para resolver la clave del emisor. | DEBE | T | F4 | P-08 |
| REQ-VER-005 | La tolerancia de reloj DEBE ser configurable y acotada por el perfil. | DEBE | T | F4 | — |
| REQ-VER-006 | El verificador DEBE detectar retroceso de reloj mediante el piso de tiempo confiable. | DEBE | T | F4 | P-08 |
| REQ-VER-007 | El SDK NO DEBE tomar decisiones de negocio; la aceptación la decide la `Policy` del integrador. | DEBE | I | F4 | P-05 |
| REQ-VER-008 | Toda entrada DEBE tener límites de tamaño, profundidad y número de elementos. | DEBE | T, F | F2 | P-08 |
| REQ-VER-009 | Mismas entradas (incluido el instante) DEBEN producir el mismo resultado. | DEBE | T | F4 | P-06 |
| REQ-VER-010 | La precedencia de estados DEBE ser `Invalid` > `Unverifiable` > `ValidWithStaleStatus` > `Valid`. | DEBE | T | F4 | P-08 |
| REQ-VER-011 | El estado persistente del verificador (piso de tiempo, versiones aceptadas, caché de nonces) DEBE leerse y escribirse mediante `VerifierStateStore`; si falta o no es íntegro, el resultado DEBE ser `Unverifiable` hasta una reinicialización explícita. | DEBE | T | F4 | P-08 |
| REQ-VER-012 | Las comprobaciones que dependen de datos no autenticados NO DEBEN evaluarse (quedan `Skipped`); `Valid` DEBE ser inconstruible sin que todas las comprobaciones obligatorias hayan pasado. | DEBE | T, I | F4 | P-08 |

### 1.5 Estado (STAT)

| ID | Requisito | Nivel | Verif. | Fase | P |
|---|---|---|---|---|---|
| REQ-STAT-001 | El estado DEBE implementarse con Token Status List (formato JWT), versión fijada en `CRYPTO_PROFILES.md`. | DEBE | T | F4 | P-04 |
| REQ-STAT-002 | Las listas DEBEN tener un tamaño mínimo por perfil y asignar índices aleatoriamente. | DEBE | T | F7 | P-09 |
| REQ-STAT-003 | La descompresión DEBE tener un límite de tamaño de salida. | DEBE | T, F | F4 | P-08 |
| REQ-STAT-004 | La frescura máxima DEBE definirse por perfil y clase de operación. | DEBE | T | F4 | P-05 |
| REQ-STAT-005 | Las listas DEBEN distribuirse por contenido direccionado vía mirrors no confiables. | DEBE | T | F7 | P-10 |
| REQ-STAT-006 | Los compromisos de listas DEBEN anclarse periódicamente en el ledger. | DEBE | T | F7 | P-14 |
| REQ-STAT-007 | Los estados soportados DEBEN ser válido, revocado y, si el perfil lo permite, suspendido. | DEBE | T | F4 | — |
| REQ-STAT-008 | Cada emisor DEBE publicar un manifiesto de estado firmado y con versión monotónica; el cliente DEBE rechazar versiones inferiores a la última aceptada de ese emisor. | DEBE | T | F7 | P-08 |

### 1.6 Confianza (TRUST)

| ID | Requisito | Nivel | Verif. | Fase | P |
|---|---|---|---|---|---|
| REQ-TRUST-001 | El trust bundle DEBE estar cofirmado por un umbral k-de-n de firmantes distintos, tener versión monotónica y ventana de validez. | DEBE | T | F4 | P-08 |
| REQ-TRUST-002 | El cliente DEBE rechazar bundles con `(bundle_epoch, bundle_version)` inferior al último aceptado. | DEBE | T | F4 | P-08 |
| REQ-TRUST-003 | Los bundles DEBEN derivarse solo de estado finalizado del ledger. | DEBE | T | F7 | P-14 |
| REQ-TRUST-004 | El modo de verificación completa DEBE contrastar el bundle con ≥ 2 fuentes de ledger independientes. | DEBE | T | F7 | P-10 |
| REQ-TRUST-005 | La raíz de confianza DEBE estar fijada en la configuración del integrador; su hash y las claves de los firmantes de bundle DEBEN estar registrados en el ledger. | DEBE | T, I | F7 | P-08 |
| REQ-TRUST-006 | Los firmantes de bundle y las claves de raíz DEBEN poder rotarse mediante una raíz nueva encadenada, con solapamiento y sin interrumpir clientes. | DEBE | T | F8 | P-10 |
| REQ-TRUST-007 | El registro DEBERÍA soportar un registro de verificadores por perfil. | DEBERÍA | T | F6 | P-09 |
| REQ-TRUST-008 | El bundle DEBE derivarse de forma determinista del estado finalizado (payload canónico), de modo que operadores independientes obtengan bytes idénticos. | DEBE | T | F7 | P-15 |
| REQ-TRUST-009 | El cliente DEBE aceptar una raíz nueva solo si la firman el umbral de la raíz anterior y el de la nueva; una raíz nueva DEBE poder incrementar `bundle_epoch` para recuperar de un avance forzado de versión. | DEBE | T | F4 | P-15 |
| REQ-TRUST-010 | El trust bundle NO DEBE contener punteros ni hashes de listas de estado. | DEBE | T | F4 | P-14 |

### 1.7 Ledger (LEDG)

| ID | Requisito | Nivel | Verif. | Fase | P |
|---|---|---|---|---|---|
| REQ-LEDG-001 | Ninguna transacción DEBE contener datos personales, hashes de datos personales ni identificadores de titulares. | DEBE | T, A | F6 | P-02 |
| REQ-LEDG-002 | El acceso al ledger DEBE abstraerse con `LedgerAdapter`; la primera implementación DEBE ser EVM. | DEBE | T, I | F6 | P-14 |
| REQ-LEDG-003 | Los contratos DEBEN ser inmutables (sin proxies actualizables) y desplegarse por versiones. | DEBE | I, A | F6 | — |
| REQ-LEDG-004 | La gobernanza DEBE ser multisig; las altas DEBEN pasar por timelock; las acciones de emergencia NO DEBEN esperar timelock y DEBEN limitarse a suspensiones reversibles con caducidad; marcar una clave como `compromised` DEBE exigir la multisig completa. | DEBE | T | F6 | P-10 |
| REQ-LEDG-005 | El indexador DEBE consumir solo bloques finalizados y tolerar reorganizaciones. | DEBE | T | F7 | P-08 |
| REQ-LEDG-006 | El acceso RPC DEBE soportar múltiples proveedores con failover y verificación de consistencia. | DEBE | T | F7 | P-10 |
| REQ-LEDG-007 | Los emisores que sean personas naturales DEBEN registrarse con identificador seudónimo. | DEBE | I | F6 | P-02 |

### 1.8 Sincronización (SYNC)

| ID | Requisito | Nivel | Verif. | Fase | P |
|---|---|---|---|---|---|
| REQ-SYNC-001 | Las operaciones pendientes DEBEN guardarse en una cola cifrada con claves de idempotencia. | DEBE | T | F7 | P-01 |
| REQ-SYNC-002 | La entrega DEBE ser al-menos-una-vez con deduplicación en el destinatario. | DEBE | T | F7 | — |
| REQ-SYNC-003 | Los reintentos DEBEN usar backoff exponencial con jitter. | DEBE | T | F7 | — |
| REQ-SYNC-004 | Todo contenido recibido de relays DEBE verificarse por firma o hash antes de usarse. | DEBE | T | F7 | P-08 |
| REQ-SYNC-005 | Las descargas de datos públicos NO DEBEN incluir identificadores del titular. | DEBE | T, I | F7 | P-09 |
| REQ-SYNC-006 | Los sobres de operación DEBEN cifrarse al destinatario con HPKE (RFC 9180). | DEBE | T | F7 | P-09 |
| REQ-SYNC-007 | El cliente DEBE soportar múltiples endpoints de relay con failover. | DEBE | T | F7 | P-10 |

### 1.9 Almacenamiento (STOR)

| ID | Requisito | Nivel | Verif. | Fase | P |
|---|---|---|---|---|---|
| REQ-STOR-001 | El almacenamiento DEBE usar cifrado de sobre (DEK/KEK) con AEAD y datos asociados. | DEBE | T | F5 | P-03 |
| REQ-STOR-002 | La KEK DEBE residir en el almacén seguro de la plataforma. | DEBE | T, D | F9 | P-03 |
| REQ-STOR-003 | Las búsquedas DEBEN usar índices ciegos; NO DEBE haber metadatos en claro. | DEBE | T, I | F5 | P-09 |
| REQ-STOR-004 | Las escrituras DEBEN ser atómicas y consistentes ante interrupciones. | DEBE | T | F5 | — |
| REQ-STOR-005 | Las migraciones de esquema DEBEN estar versionadas y probadas con datos de versiones anteriores. | DEBE | T | F5 | — |
| REQ-STOR-006 | No se DEBE persistir el contenido de presentaciones por defecto; el registro de eventos DEBE tener retención limitada. | DEBE | T, I | F5 | P-09 |
| REQ-STOR-007 | Claves y datos DEBEN excluirse de los backups del sistema operativo por defecto. | DEBE | D, I | F9 | P-03 |
| REQ-STOR-008 | El backend DEBE ser intercambiable (SQLite nativo; adaptador del host en web). | DEBE | T | F5 | P-11 |

### 1.10 Recuperación (REC)

| ID | Requisito | Nivel | Verif. | Fase | P |
|---|---|---|---|---|---|
| REQ-REC-001 | La migración entre dispositivos DEBE usar canal efímero ECDH con compromiso previo de claves y verificación SAS. | DEBE | T, D | F8 | P-03 |
| REQ-REC-002 | El respaldo cifrado DEBE protegerse con un código de recuperación generado de ≥ 128 bits. | DEBE | T | F8 | P-03 |
| REQ-REC-003 | El sistema DEBERÍA ofrecer recuperación social con Shamir (k-de-n). | DEBERÍA | T | F8 | P-10 |
| REQ-REC-004 | La clave de recuperación DEBE tener propósito exclusivo y habilitar el protocolo de re-vinculación. | DEBE | T | F8 | P-07 |
| REQ-REC-005 | Cada perfil DEBE documentar su procedimiento de recuperación institucional. | DEBE | I | F8 | — |
| REQ-REC-006 | La recuperación NO DEBE depender exclusivamente de un correo electrónico ni de un custodio único. | DEBE | I | F8 | P-10 |
| REQ-REC-007 | Las claves de recuperación DEBEN derivarse por emisor; la misma huella NO DEBE registrarse ante dos emisores. | DEBE | T | F8 | P-09 |

### 1.11 Emisión (ISS)

| ID | Requisito | Nivel | Verif. | Fase | P |
|---|---|---|---|---|---|
| REQ-ISS-001 | El servicio de emisión DEBE implementar OpenID4VCI 1.0. | DEBE | T | F10 | P-04 |
| REQ-ISS-002 | En producción, las claves del emisor DEBEN residir en HSM/KMS. | DEBE | I, A | F15 | P-03 |
| REQ-ISS-003 | El emisor DEBE gestionar listas de estado: asignación, actualización y publicación periódica. | DEBE | T | F7 | — |
| REQ-ISS-004 | La emisión DEBE exigir prueba de posesión de la clave del titular. | DEBE | T | F10 | P-08 |
| REQ-ISS-005 | El perfil financiero DEBE exigir atestación de clave/dispositivo. | DEBE | T, D | F10 | P-08 |
| REQ-ISS-006 | El emisor DEBE exponer el endpoint de re-vinculación cuando declare soportarlo. | DEBE | T | F8 | — |

### 1.12 SDK (SDK)

| ID | Requisito | Nivel | Verif. | Fase | P |
|---|---|---|---|---|---|
| REQ-SDK-001 | DEBE existir una única API pública (`pip-sdk`); los bindings DEBEN generarse. | DEBE | I | F9 | P-11 |
| REQ-SDK-002 | El SDK DEBE estar disponible en Kotlin, Swift, TypeScript/JavaScript, Python y Dart; y vía C ABI para Go, C# y C/C++. | DEBE | T, D | F9 | P-11 |
| REQ-SDK-003 | Los códigos de error DEBEN ser estables y numéricos en todos los lenguajes. | DEBE | T | F9 | P-11 |
| REQ-SDK-004 | Ningún pánico DEBE cruzar la frontera FFI; en WASM, un pánico DEBE dejar la instancia explícitamente inutilizable (`PIP-E9999`), nunca en estado indefinido. | DEBE | T, F | F9 | P-08 |
| REQ-SDK-005 | El host DEBE poder implementar `KeyStore`, `Clock`, `StorageBackend`, `VerifierStateStore` y `Transport`. | DEBE | T | F9 | P-11 |
| REQ-SDK-006 | El SDK DEBE seguir SemVer, verificado con `cargo-semver-checks`. | DEBE | T | F9 | — |
| REQ-SDK-007 | La misma suite de vectores DEBE ejecutarse en cada lenguaje. | DEBE | T | F9 | P-11 |
| REQ-SDK-008 | El núcleo de verificación DEBE compilar sin dependencias de red ni de ledger. | DEBE | T | F4 | P-14 |
| REQ-SDK-009 | Cada lenguaje DEBE tener guía de integración con ejemplo ejecutable en CI. | DEBE | T, I | F9 | P-12 |

### 1.13 Gobernanza (GOV)

| ID | Requisito | Nivel | Verif. | Fase | P |
|---|---|---|---|---|---|
| REQ-GOV-001 | DEBE existir un marco de confianza documentado: roles, alta/baja de emisores, emergencias. | DEBE | I | F14 | P-12 |
| REQ-GOV-002 | Las ceremonias de claves DEBEN estar documentadas, ensayadas y ser auditables. | DEBE | I, D | F14 | P-08 |
| REQ-GOV-003 | DEBE existir un proceso público de propuestas de cambio del protocolo. | DEBE | I | F14 | P-12 |

---

## 2. Requisitos no funcionales

### 2.1 Seguridad (SEC)

| ID | Requisito | Nivel | Verif. | Fase |
|---|---|---|---|---|
| REQ-SEC-001 | `unsafe` DEBE estar prohibido fuera de los crates de bindings; cada uso DEBE documentar su invariante (`// SAFETY:`). | DEBE | T, I | F1 |
| REQ-SEC-002 | NO se DEBEN implementar primitivas criptográficas propias. | DEBE | I | F2 |
| REQ-SEC-003 | Los tipos con secretos DEBEN zeroizarse y redactar su `Debug`/`Display`. | DEBE | T, I | F2 |
| REQ-SEC-004 | Las comparaciones de secretos y MACs DEBEN ser en tiempo constante. | DEBE | I | F2 |
| REQ-SEC-005 | Todos los parsers DEBEN tener objetivos de fuzzing ejecutados en CI nocturno. | DEBE | F | F2 |
| REQ-SEC-006 | CI DEBE ejecutar `cargo-deny` y `cargo-audit`; cada release DEBE incluir SBOM. | DEBE | T | F1 |
| REQ-SEC-007 | Antes de producción, DEBE completarse auditoría externa criptográfica, del SDK y de contratos. | DEBE | A | F13 |
| REQ-SEC-008 | Antes de producción, DEBE completarse un pentest de servicios y apps de referencia. | DEBE | A | F13 |
| REQ-SEC-009 | Los artefactos de release DEBEN ser reproducibles y firmados. | DEBE | T | F15 |
| REQ-SEC-010 | DEBE existir política de divulgación responsable (`SECURITY.md`). | DEBE | I | F0 |
| REQ-SEC-011 | Las vulnerabilidades NO DEBEN registrarse como issues públicos antes de su corrección. | DEBE | I | F0 |

### 2.2 Privacidad (PRIV)

| ID | Requisito | Nivel | Verif. | Fase |
|---|---|---|---|---|
| REQ-PRIV-001 | Cada flujo DEBE aplicar minimización de datos. | DEBE | I | F5 |
| REQ-PRIV-002 | La verificación NO DEBE contactar al emisor. | DEBE | T | F4 |
| REQ-PRIV-003 | SDK y servicios NO DEBEN registrar datos personales ni secretos. | DEBE | T, I | F7 |
| REQ-PRIV-004 | DEBE completarse una DPIA antes del piloto. | DEBE | A | F14 |
| REQ-PRIV-005 | DEBEN aplicarse mitigaciones de correlación (claves por credencial, lotes, listas completas). | DEBE | T | F5 |

### 2.3 Portabilidad (PORT)

| ID | Requisito | Nivel | Verif. | Fase |
|---|---|---|---|---|
| REQ-PORT-001 | Targets soportados: Linux, macOS y Windows (x86_64, aarch64); Android (arm64-v8a, armeabi-v7a, x86_64); iOS (dispositivo y simulador); `wasm32-unknown-unknown`. | DEBE | T | F9 |
| REQ-PORT-002 | El backend criptográfico por defecto DEBE ser puro Rust y compilar a WASM. | DEBE | T | F2 |
| REQ-PORT-003 | El núcleo (L1–L4) NO DEBE depender de ningún runtime async: los protocolos DEBEN ser máquinas de estado sans-I/O. | DEBE | T, I | F2 |
| REQ-PORT-004 | Los crates L1–L3 DEBEN ser `no_std` + `alloc` y compilar en CI para un target *bare-metal*. | DEBE | T | F1 |

### 2.4 Fiabilidad (REL)

| ID | Requisito | Nivel | Verif. | Fase |
|---|---|---|---|---|
| REQ-REL-001 | Ningún servicio DEBE ser punto único de fallo para verificar o recuperar. | DEBE | A, D | F15 |
| REQ-REL-002 | Los SLOs de servicios DEBEN definirse antes del piloto. | DEBE | I | F15 |
| REQ-REL-003 | Los objetivos de recuperación ante desastres (RPO/RTO) DEBEN definirse y ensayarse. | DEBE | D | F15 |
| REQ-REL-004 | La falta de datos DEBE expresarse como estados del resultado, nunca como pánicos. | DEBE | T | F4 |

### 2.5 Rendimiento (PERF)

| ID | Requisito | Nivel | Verif. | Fase |
|---|---|---|---|---|
| REQ-PERF-001 | Desde F2 DEBEN existir benchmarks reproducibles de verificación, tamaño de credencial, tiempo de arranque y memoria. | DEBE | T | F2 |
| REQ-PERF-002 | Los presupuestos numéricos DEBEN fijarse en el gate G9 a partir de la línea base; CI DEBE fallar ante regresiones que superen el umbral acordado. | DEBE | T | F9 |
| REQ-PERF-003 | El tamaño de la respuesta QR DEBE respetar el presupuesto de cada perfil. | DEBE | T | F5 |

### 2.6 Mantenibilidad (MAINT)

| ID | Requisito | Nivel | Verif. | Fase |
|---|---|---|---|---|
| REQ-MAINT-001 | La toolchain DEBE estar fijada y el MSRV declarado y verificado en CI. | DEBE | T | F1 |
| REQ-MAINT-002 | Las reglas de capas entre crates DEBEN verificarse automáticamente. | DEBE | T | F1 |
| REQ-MAINT-003 | Cada comprobación de verificación DEBE tener al menos un vector negativo. | DEBE | T | F4 |
| REQ-MAINT-004 | Todo ítem público DEBE tener documentación (`missing_docs = deny`). | DEBE | T | F1 |
| REQ-MAINT-005 | La cobertura de líneas DEBERÍA ser ≥ 90 % en `pip-crypto`, `pip-credential`, `pip-status`, `pip-trust` y `pip-verifier`. | DEBERÍA | T | F4 |
| REQ-MAINT-006 | Las reglas de rechazo de `pip-credential`, `pip-status`, `pip-trust` y `pip-verifier` DEBERÍAN someterse a pruebas de mutación; un mutante superviviente sin justificar se trata como bug. | DEBERÍA | T | F4 |

### 2.7 Cumplimiento (COMP)

| ID | Requisito | Nivel | Verif. | Fase |
|---|---|---|---|---|
| REQ-COMP-001 | El sistema DEBE cumplir la Ley 81 de 2019 de Panamá y los regímenes del mercado objetivo, validado por asesoría legal. | DEBE | A | F14 |
| REQ-COMP-002 | Los requisitos KYC/AML del perfil financiero DEBEN validarse con asesoría legal y reguladores antes de su uso en producción. | DEBE | A | F14 |
| REQ-COMP-003 | Las licencias de dependencias DEBEN ser compatibles con la licencia del proyecto (verificado por `cargo-deny`). | DEBE | T | F1 |

### 2.8 Observabilidad (OBS)

| ID | Requisito | Nivel | Verif. | Fase |
|---|---|---|---|---|
| REQ-OBS-001 | Los servicios DEBEN instrumentarse con OpenTelemetry. | DEBE | T | F7 |
| REQ-OBS-002 | DEBEN existir alertas para divergencia ledger/bundle, frescura de listas, fallos de firma y errores RPC. | DEBE | D | F15 |
| REQ-OBS-003 | La telemetría del SDK DEBE estar desactivada por defecto y no contener PII. | DEBE | T, I | F9 |

### 2.9 Documentación (DOC)

| ID | Requisito | Nivel | Verif. | Fase |
|---|---|---|---|---|
| REQ-DOC-001 | Los cambios de comportamiento DEBEN documentarse antes o en el mismo PR que su implementación. | DEBE | I | F0 |
| REQ-DOC-002 | Las decisiones arquitectónicas DEBEN registrarse como ADR. | DEBE | I | F0 |
| REQ-DOC-003 | DEBE existir trazabilidad requisito → prueba generada automáticamente. | DEBE | T | F1 |
| REQ-DOC-004 | Las especificaciones públicas del protocolo DEBEN publicarse en inglés antes de GA. | DEBE | I | F17 |
