# ROADMAP.md — Hoja de ruta completa hasta producción

> **Estado:** Normativo v0.2 · **Depende de:** `ARCHITECTURE.md`, `REQUIREMENTS.md`, `PROJECT_STRUCTURE.md`
> **Revisión v0.2 (2026-10-10):** incorpora la revisión de arquitectura (ADR-0016 a ADR-0020, en estado **Propuesto**); lo que depende de ellos es propuesta hasta su aceptación por un mantenedor humano.
> Esta hoja de ruta cubre **desde el repositorio vacío hasta el producto en producción y su operación continua**. Ninguna fase se omite. Cada tarea se convierte en un issue de GitHub antes de empezar.

---

## 0. Reglas de uso (obligatorias)

1. **Orden.** Las fases se ejecutan en el orden de sus dependencias (§2). Dos fases pueden solaparse **solo** si el diagrama de dependencias lo permite explícitamente.
2. **Gates.** Cada fase termina con un *gate* (`G<n>`). Un gate se cierra cuando **todos** sus criterios se cumplen, con evidencia enlazada (PRs, informes de CI, demos grabadas o scriptadas). Se registra en `docs/STATUS.md` y en un issue `type:gate`.
3. **Ninguna fase cierra su gate mientras siga abierto el gate de una fase de la que depende** (§2). Se puede adelantar trabajo de una fase siguiente si sus dependencias están cumplidas, pero su gate espera.
4. **Una tarea = un issue** (`type:task`, `phase:F<n>`), con el ID de la tarea en el título: `[F3.T04] KB-JWT creación y verificación`. Una tarea grande puede dividirse en sub-issues que referencian al padre.
5. **"Hecho" significa** cumplir la *Definition of Done* de `AGENTS.md §10` **y** el criterio de aceptación de la tarea. Compilar no es terminar.
6. **Las duraciones son orientativas**, para un equipo pequeño (3–5 ingenieros con apoyo de agentes de código). No son compromisos. Los plazos externos (auditorías, asesoría legal, reguladores) no se aceleran con más agentes.
7. **Cambios a esta hoja de ruta** (añadir, mover o retirar tareas) requieren PR con justificación; cambiar el orden de fases o eliminar un gate requiere ADR.
8. **Los spikes** (PoCs de F0) son código desechable en `spikes/`. Nada de un spike pasa a `crates/` sin reescribirse con las reglas de `AGENTS.md`.

---

## 1. Visión general

| Fase | Nombre | Duración orientativa | Hito al cerrar |
|---|---|---|---|
| F0 | Fundación, gobierno y especificación | 3–5 semanas | — |
| F1 | Infraestructura de ingeniería | 1–2 semanas | — |
| F2 | Núcleo: tipos, codificación, criptografía y claves | 3–4 semanas | — |
| F3 | Credenciales SD-JWT VC | 3–5 semanas | — |
| F4 | Estado, confianza y verificación offline | 3–5 semanas | — |
| F5 | Wallet, almacenamiento cifrado y presentación offline | 4–6 semanas | **M1 · Núcleo offline** |
| F6 | Contratos y adaptador de ledger | 3–5 semanas (paralela a F4–F5) | — |
| F7 | Servicios y sincronización | 4–6 semanas | — |
| F8 | Recuperación, migración y rotación | 3–5 semanas | **M2 · MVP del protocolo** |
| F9 | SDK público y bindings multiplataforma | 6–9 semanas | — |
| F10 | Protocolos en línea (OID4VCI/OID4VP) y servicio de emisión | 4–6 semanas (solapa final de F9) | — |
| F11 | Aplicaciones de referencia | 6–8 semanas | — |
| F12 | Conformidad, interoperabilidad y beta en testnet | 3–5 semanas | **M3 · Beta técnica** |
| F13 | Endurecimiento y auditorías externas | 6–10 semanas | — |
| F14 | Privacidad, cumplimiento y marco de confianza | 6–12 semanas (paralela a F11–F13) | — |
| F15 | Preparación de producción | 4–6 semanas | — |
| F16 | Piloto controlado en producción | 8–12 semanas | **M4 · Piloto validado** |
| F17 | Lanzamiento general (GA) | 2–4 semanas | **M5 · Producción** |
| F18 | Operación continua y evolución | Permanente | — |

**Estimación total orientativa hasta M5:** 14–20 meses con los solapamientos permitidos. El MVP (M2) se alcanza aproximadamente entre los meses 6 y 9. Esta estimación es mayor que la del plan inicial de seis fases porque incluye bindings, protocolos en línea, apps, auditorías, cumplimiento, operación y piloto, que el plan inicial no cubría.

---

## 2. Dependencias entre fases

```mermaid
flowchart LR
    F0 --> F1 --> F2 --> F3 --> F4 --> F5
    F2 --> F6
    F4 --> F7
    F6 --> F7
    F5 --> F7
    F7 --> F8
    F8 --> F9
    F9 --> F10
    F8 --> F10
    F10 --> F11
    F9 --> F11
    F11 --> F12
    F12 --> F13
    F9 -. contratación de auditores .-> F13
    F11 --> F14
    F13 --> F15
    F14 --> F15
    F15 --> F16 --> F17 --> F18
```

Solapamientos permitidos: **F6** puede empezar cuando cierra G2 (los contratos no dependen del formato de credencial) y avanzar en paralelo con F3–F5. La tarea F6.T08 (`pip-ledger`) necesita además el modelo de bundle de F4.T03. **F10** puede empezar cuando la API de `pip-sdk` esté congelada (F9.T02). **F14** puede empezar con G11 abierto. La **contratación** de auditores (F13.T01) empieza durante F9.

---

## 3. Hitos

| Hito | Significado | Demostración mínima |
|---|---|---|
| **M1 · Núcleo offline** | El protocolo funciona sin conectividad. | Emitir credencial de prueba → transferir por QR → verificar en otro dispositivo sin red, con divulgación selectiva y rechazo de replay. |
| **M2 · MVP del protocolo** | Confianza pública, sincronización y recuperación funcionan de extremo a extremo en testnet. | Todos los criterios de aceptación del MVP (§24) pasan en una ejecución scriptada y reproducible. |
| **M3 · Beta técnica** | SDK en todos los lenguajes, protocolos estándar, apps de referencia e interoperabilidad, en testnet. | Integradores externos completan flujos con sus propios sistemas. |
| **M4 · Piloto validado** | Uso real limitado en producción con SLOs cumplidos. | Informe de piloto aprobado. |
| **M5 · Producción** | Producto 100 % funcional en producción (definición en §23). | Gate G17 cerrado. |

---

## 4. Pistas transversales (activas en todas las fases)

| Pista | Actividad permanente |
|---|---|
| Seguridad | Revisión de cada PR sensible (CODEOWNERS), triaje de advisories de dependencias, fuzzing nocturno, actualización del threat model ante cualquier cambio de arquitectura. |
| Documentación | Spec-first; `docs/STATUS.md` actualizado al final de cada sesión de trabajo; CHANGELOG por PR. |
| Calidad | CI verde obligatorio; trazabilidad REQ → pruebas; ningún test desactivado sin issue. |
| Dependencias | Actualizaciones semanales automatizadas (Dependabot o Renovate) con revisión humana; ninguna dependencia nueva sin justificación. |
| Bugs | Todo defecto se registra como issue (o advisory privado si es de seguridad) según `AGENTS.md §7`. Triaje al menos semanal. |
| Gestión | Tablero del proyecto sincronizado con las fases; revisión de riesgos (§26) en cada gate. |

---

## 5. F0 — Fundación, gobierno y especificación

**Objetivo:** cerrar las decisiones obligatorias y redactar las especificaciones normativas antes de escribir código de producción.
**Entrada:** este paquete documental (README, AGENTS, ARCHITECTURE, REQUIREMENTS, PROJECT_STRUCTURE, ROADMAP).

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F0.T01 | Crear repositorio con el paquete documental | Repositorio con este contenido; `main` protegida (PR obligatorio, historial lineal); labels de `AGENTS.md §8`; plantillas de issues y PR; tablero con columnas por estado y vistas por fase. | REQ-DOC-001 |
| F0.T02 | ADR-0001: nombre definitivo | Disponibilidad verificada en crates.io, npm, PyPI, Maven Central, pub.dev, NuGet, ruta de módulo Go, organización de GitHub y dominio; búsqueda básica de marcas; reemplazo mecánico de `pip` en todo el repositorio en un único PR. | — |
| F0.T03 | ADR-0002: licencia y contribución | Archivos de licencia; política DCO o CLA; lista de licencias de dependencias permitidas para `deny.toml`. | REQ-COMP-003 |
| F0.T04 | `SECURITY.md` definitivo | Canal privado (GitHub Security Advisories), tiempos de acuse y corrección, alcance, safe harbor. | REQ-SEC-010, REQ-SEC-011 |
| F0.T05 | `THREAT_MODEL.md` | Activos, actores, fronteras de confianza, diagramas de flujo de datos, STRIDE por componente, LINDDUN para privacidad, casos de abuso; cada amenaza mapeada a mitigación y a REQ. | REQ-SEC-* |
| F0.T06 | `CRYPTO_PROFILES.md` | Algoritmos permitidos y prohibidos; versiones exactas fijadas de RFC 9901, borrador SD-JWT VC, Token Status List, OID4VCI 1.0, OID4VP 1.0; tamaños de sal, nonces, límites de entrada, límites de descompresión; política de deprecación. | REQ-CRED-001, REQ-STAT-001 |
| F0.T07 | Spike QR | Informe en `spikes/qr/REPORT.md`: tamaños reales de presentaciones por perfil con DEFLATE + Base45, con y sin transcodificación binaria previa; secuencia multi-QR indexada frente a códigos fuente; lectura con ≥ 3 teléfonos (gama baja, media y alta) y lectores genéricos; propuesta de presupuesto por perfil y umbral de fragmentación. | REQ-PRES-005 |
| F0.T08 | Spike claves en hardware | Firma ES256 desde Rust mediante trait exterior (UniFFI) con Secure Enclave (iOS) y StrongBox/TEE (Android) en dispositivos físicos; latencia medida; formato de firma devuelto por cada plataforma (DER, `s` alto o bajo) documentado; confirmación de viabilidad o ADR alternativo. | REQ-KEY-002 |
| F0.T09 | Spike WASM | ES256, SHA-256 y XChaCha20-Poly1305 de RustCrypto compilados a `wasm32-unknown-unknown`, ejecutados en navegador y Node; tamaño medido; comportamiento ante un pánico (instancia envenenada) comprobado. | REQ-PORT-002 |
| F0.T10 | Spike ledger + ADR-0004 | Contrato mínimo en testnets candidatas; costo de alta de emisor, rotación y anclaje por lotes; tiempo a finalidad; disponibilidad de RPC; ADR-0004 aceptado. | REQ-LEDG-002 |
| F0.T11 | ADRs 0003, 0005–0012, 0016–0018 y 0020 | Cada ADR aceptado o diferido con fecha y fase límite; índice `docs/adr/README.md` actualizado. | REQ-DOC-002 |
| F0.T12 | `PROTOCOL.md` v0.1 | Flujos y mensajes: emisión, presentación offline (QR), presentación en línea, sincronización, sobres de operación, re-vinculación, migración; máquinas de estado; códigos de error de protocolo. | REQ-PRES-*, REQ-SYNC-* |
| F0.T13 | `TRUST_BUNDLE.md` | Formato exacto de la raíz de confianza y del bundle multi-firma, serialización canónica y derivación determinista, límites, reglas de validación, anti-rollback con `bundle_epoch`, rotación por raíz encadenada, manifiesto de estado, ejemplos. | REQ-TRUST-001..010, REQ-STAT-008 |
| F0.T14 | `CONTRACTS.md` v0.1 | Funciones, roles, eventos, errores, invariantes y procedimiento de migración de contratos. | REQ-LEDG-* |
| F0.T15 | Perfiles v0.1 | `pip-personal-v1`, `pip-financial-v1`, `pip-enterprise-v1`: `vct`, esquemas JSON, parámetros de `ARCHITECTURE.md §16` con valores concretos, retención, procedimiento de recuperación. | REQ-CRED-004, REQ-REC-005 |
| F0.T16 | `SDK_API.md` v0.1 y `ERROR_CODES.md` | Objetos, métodos, interfaces del host, semántica de errores, ejemplos en pseudocódigo; catálogo inicial de códigos. | REQ-SDK-001, REQ-SDK-003 |
| F0.T17 | `STORAGE_FORMAT.md` | Registros, datos asociados, índices ciegos, versión de esquema, reglas de migración. | REQ-STOR-* |
| F0.T18 | `TRUST_FRAMEWORK.md` v0.1 (técnico) | Roles; umbrales de la multisig, de la raíz y de los firmantes de bundle; timelock; rol de emergencia limitado a suspender, con su plazo de caducidad; alta y baja de emisores; marcado como pendiente de revisión legal (F14). | REQ-GOV-001 |
| F0.T19 | `TEST_STRATEGY.md` | Niveles de prueba, herramientas, horas mínimas de fuzzing por gate, criterios de cobertura, entornos, datos de prueba. | REQ-MAINT-003 |
| F0.T20 | Análisis regulatorio preliminar | Documento en `docs/legal/`: mercado objetivo, Ley 81 de 2019, requisitos KYC/AML probables del perfil financiero, preguntas para asesoría legal. | REQ-COMP-001 |
| F0.T21 | Revisión cruzada de especificaciones | Cada especificación revisada por alguien distinto de su autor con lista de verificación (consistencia, ambigüedades, trazabilidad). | REQ-DOC-001 |

**Gate G0:**
- Todas las especificaciones v0.1 fusionadas en `main` y revisadas.
- ADRs 0001–0012, 0016–0018 y 0020 aceptados (o diferidos con fase límite permitida).
- Informes de los cuatro spikes publicados; ningún spike reveló una inviabilidad sin resolver.
- Nombre definitivo aplicado.

**Riesgos:** sobre-especificación que retrase el inicio (mitigación: especificaciones v0.1 pueden dejar detalles marcados "a fijar en F<n>", nunca las decisiones de seguridad); spike de hardware fallido (mitigación: perfil personal con claves software cifradas mientras se resuelve).

---

## 6. F1 — Infraestructura de ingeniería

**Objetivo:** que cualquier agente o desarrollador pueda contribuir con calidad verificada automáticamente desde el primer commit de código.
**Entrada:** G0 cerrado.

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F1.T01 | Workspace Cargo | Todos los crates de `PROJECT_STRUCTURE.md §3` creados vacíos con `lib.rs` documentado, `README.md`, lints del workspace y perfiles de compilación. | REQ-MAINT-004 |
| F1.T02 | Toolchain y MSRV (ADR-0014) | `rust-toolchain.toml`; MSRV declarado; job de CI que compila con el MSRV. | REQ-MAINT-001 |
| F1.T03 | `xtask check-layers` | `xtask/layers.toml` con las reglas de `PROJECT_STRUCTURE.md §4`; CI falla ante una dependencia prohibida, incluido cualquier runtime async en L1–L4; falla también si un crate L1–L3 enlaza `std` o si a un crate fuera de `bindings/` le falta `#![forbid(unsafe_code)]` (cada regla probada con un caso negativo). | REQ-MAINT-002, REQ-PORT-003, REQ-PORT-004 |
| F1.T04 | `xtask trace` | Matriz REQ → pruebas generada; falla si un REQ DEBE de una fase cerrada no tiene pruebas. | REQ-DOC-003 |
| F1.T05 | Workflows de CI | `ci.yml`, `security.yml`, `docs.yml` según `PROJECT_STRUCTURE.md §9`. | REQ-SEC-006 |
| F1.T06 | `deny.toml` | Licencias permitidas (ADR-0002), solo crates.io como fuente, advisories, duplicados con aviso. | REQ-COMP-003 |
| F1.T07 | `pip-testkit` base | `FixedClock`, `SeededRng`, utilidades de aserción de resultados de verificación. | REQ-VER-009 |
| F1.T08 | Esqueleto de errores | `PipError` con códigos; `xtask check-error-codes` (códigos únicos y documentados en `ERROR_CODES.md`). | REQ-SDK-003 |
| F1.T09 | `clippy.toml` con métodos y tipos prohibidos | `std::net`, `std::fs`, `std::time::SystemTime::now` prohibidos en crates L1–L4 mediante `disallowed-methods`/`disallowed-types`, como segunda barrera tras `no_std` (L1–L3). | REQ-VER-001, REQ-SEC-001 |
| F1.T10 | Compilación cruzada de humo | CI compila los crates vacíos para `wasm32-unknown-unknown`, `aarch64-linux-android` y `aarch64-apple-ios`; y los crates L1–L3 para un target *bare-metal* (`thumbv7em-none-eabihf`). | REQ-PORT-001, REQ-PORT-004 |
| F1.T11 | Andamiaje de fuzzing y benchmarks | `fuzz/` con un objetivo de ejemplo; `fuzz.yml` nocturno; criterion configurado. | REQ-SEC-005, REQ-PERF-001 |
| F1.T12 | Gobierno del repositorio | `CONTRIBUTING.md`, `CODEOWNERS` (rutas sensibles: `crates/pip-crypto`, `pip-credential`, `pip-trust`, `pip-verifier`, `contracts/`, `docs/specs/`, `.github/`), labels como código. | REQ-DOC-001 |
| F1.T13 | ADR-0019 y esqueleto vertical | ADR-0019 aceptado; `pip-sdk` existe desde esta fase como fachada mínima y un binding (WASM) la compila y ejecuta una prueba de humo en CI, de modo que la forma de la API se valida contra FFI en cada fase y no solo en F9. | REQ-PORT-003, REQ-SDK-001 |
| F1.T14 | Andamiaje de mutación y Kani | `cargo-mutants` y Kani configurados con un ejemplo cada uno; job nocturno. | REQ-MAINT-006 |

**Gate G1:** CI verde en todos los targets; `check-layers`, `trace`, `check-error-codes` y `deny` activos y probados con casos negativos; un PR de ejemplo recorre la plantilla completa.

**Riesgos:** costo de runners macOS (mitigación: matriz móvil completa solo en `main` y nocturna).

---

## 7. F2 — Núcleo: tipos, codificación, criptografía y claves

**Objetivo:** primitivas correctas, acotadas y probadas contra vectores externos, sobre las que se construye todo lo demás.
**Entrada:** G1 cerrado.

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F2.T01 | `pip-types` | Newtypes validados (`IssuerId`, `Kid`, `Vct`, `ProfileId`, `UnixTime`, `BundleVersion`), sin constructores que admitan valores inválidos; pruebas de propiedades. | REQ-VER-008 |
| F2.T02 | base64url estricto | Sin relleno; rechaza caracteres no canónicos y bits sobrantes no nulos; fuzzing. | REQ-VER-008 |
| F2.T03 | JSON acotado | Límites de tamaño, profundidad y elementos; rechazo de miembros duplicados; UTF-8 estricto; números fuera de rango rechazados; fuzzing. | REQ-CRED-009, REQ-VER-008 |
| F2.T04 | CBOR acotado | Límites equivalentes; rechazo de codificaciones no deterministas donde el protocolo lo exija; fuzzing. | REQ-VER-008 |
| F2.T05 | DEFLATE y Base45 | Descompresión con límite de salida (prueba de bomba de descompresión); Base45 según RFC 9285 con vectores del RFC. | REQ-STAT-003 |
| F2.T06 | `CryptoBackend` + RustCrypto | ES256 (firma P1363 `r‖s` de 64 bytes; conversión DER ↔ P1363; rechazo de longitudes y codificaciones inválidas, sin exigir *low-S*), SHA-256, HMAC-SHA-256, HKDF, XChaCha20-Poly1305, ECDH P-256, HPKE (RFC 9180, suite fijada en `CRYPTO_PROFILES.md`), CSPRNG inyectado por el host. | REQ-SEC-002, REQ-PORT-002, REQ-KEY-010 |
| F2.T07 | JWK y thumbprints | Parseo estricto de JWK EC P-256 (validación de punto en la curva, rechazo de miembros privados en contextos públicos); thumbprint RFC 7638. | REQ-KEY-007 |
| F2.T08 | Vectores externos | Ejemplos de RFC 7515 (ES256), RFC 7638, RFC 5869 (HKDF), RFC 9180 (HPKE), Project Wycheproof (ECDSA P-256 y AEAD); todos pasan. | REQ-SEC-002 |
| F2.T09 | Higiene de secretos | Tipos secretos con `Zeroize` y `Debug` redactado; prueba que verifica que `Debug` no imprime material; comparación con `subtle`. | REQ-SEC-003, REQ-SEC-004 |
| F2.T10 | `pip-keys` | `KeyPurpose` (incluido el acuerdo de claves HPKE, separado de la firma), `KeyHandle` tipado por propósito, trait `KeyStore` (generar, firmar, acuerdo de claves, clave pública, borrar, atestación opcional), keystore software bajo feature; prueba de compilación fallida (`trybuild`) al usar una clave con otro propósito. | REQ-KEY-001, REQ-KEY-004, REQ-KEY-009 |
| F2.T11 | Objetivos de fuzzing | Un objetivo por parser (base64url, JSON, CBOR, DEFLATE, Base45, JWK) en `fuzz.yml`. | REQ-SEC-005 |
| F2.T12 | Benchmarks base | Firma, verificación, hash y AEAD en x86_64, aarch64 y WASM; resultados publicados en `docs/STATUS.md`. | REQ-PERF-001 |

**Gate G2:** todos los vectores externos pasan; cada objetivo de fuzzing alcanzó las horas mínimas de `TEST_STRATEGY.md` sin fallos; cobertura de `pip-crypto` ≥ 90 %; los REQ de F2 aparecen trazados.

**Riesgos:** errores sutiles de codificación ECDSA entre JWS y DER (mitigación: vectores Wycheproof y RFC 7515).

---

## 8. F3 — Credenciales SD-JWT VC

**Objetivo:** emitir, parsear y verificar credenciales SD-JWT VC y presentaciones con Key Binding, interoperables con otras implementaciones.
**Entrada:** G2 cerrado.

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F3.T01 | ADR-0015: construir o reutilizar | Evaluación de crates SD-JWT existentes (mantenimiento, auditorías, compatibilidad WASM, licencia, conformidad con RFC 9901) frente a implementación propia; decisión aceptada. | REQ-SEC-002 |
| F3.T02 | Emisión SD-JWT | Divulgaciones de objeto y de array, digests, `_sd_alg`, decoys, estructuras anidadas y recursivas según RFC 9901; sal ≥ 128 bits. | REQ-CRED-002, REQ-CRED-003 |
| F3.T03 | Parseo y verificación SD-JWT | Formato compacto; verificación de digests; rechazo de divulgaciones duplicadas, digests duplicados, claims reservados, divulgaciones no referenciadas; límites. | REQ-CRED-001, REQ-VER-003 |
| F3.T04 | KB-JWT | Creación y verificación (`typ: kb+jwt`, `nonce`, `aud`, `iat`, `sd_hash`); firma delegada al `KeyStore`. | REQ-PRES-002 |
| F3.T05 | Capa SD-JWT VC | `typ: dc+sd-jwt`, `vct`, `cnf.jwk`, claim `status`, vigencia (`iat`/`nbf`/`exp`), `iss`; lista de algoritmos del perfil; rechazo de `none`. | REQ-CRED-001, REQ-CRED-007, REQ-CRED-008 |
| F3.T06 | Esquemas de perfil | Esquemas de `docs/specs/profiles/` incorporados en compilación; validación en emisión y verificación. | REQ-CRED-004 |
| F3.T07 | Claims de predicado | Soporte de predicados definidos por perfil con pruebas. | REQ-CRED-005 |
| F3.T08 | `pip-issuer` | API de construcción y firma; emisión por lotes con claves, sales e índices distintos. | REQ-CRED-006 |
| F3.T09 | Vectores de conformidad v1 | `conformance/vectors/sd-jwt-vc/`: positivos y negativos (al menos uno por regla de rechazo). | REQ-MAINT-003 |
| F3.T10 | Interoperabilidad de formato | Ejemplos de RFC 9901 verificados; intercambio de vectores con ≥ 1 implementación externa independiente en otro lenguaje, en ambos sentidos; informe. | REQ-CRED-001 |
| F3.T11 | Fuzzing y propiedades | Objetivos para SD-JWT y KB-JWT; propiedad: mutar cualquier byte de una presentación válida nunca produce aceptación. | REQ-VER-003, REQ-SEC-005 |

**Gate G3:** interoperabilidad bidireccional demostrada; vectores v1 publicados; fuzzing y cobertura según `TEST_STRATEGY.md`.

**Riesgos:** cambios en el borrador SD-JWT VC (mitigación: versión fijada en `CRYPTO_PROFILES.md`; actualización solo por ADR).

---

## 9. F4 — Estado, confianza y verificación offline

**Objetivo:** un verificador que, sin red, devuelve uno de los cuatro estados con evidencia completa.
**Entrada:** G3 cerrado.

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F4.T01 | `pip-status`: listas | Parseo de Token Status List (JWT), firma, descompresión acotada, lectura de 1 y 2 bits, coincidencia de URI, expiración/TTL; parseo y verificación del manifiesto de estado con versión monotónica. | REQ-STAT-001, REQ-STAT-003, REQ-STAT-007 |
| F4.T02 | `pip-status`: caché y frescura | Snapshot con instante firmado y antigüedad calculada con el `Clock` inyectado. | REQ-STAT-004 |
| F4.T03 | Trust bundle | Modelo de raíz y de bundle; cadena de raíces desde la raíz fijada; verificación de ≥ k firmas de firmantes distintos; anti-rollback por `(bundle_epoch, bundle_version)`; ventana de validez; recuperación de un avance forzado probada. | REQ-TRUST-001, REQ-TRUST-002, REQ-TRUST-009, REQ-TRUST-010 |
| F4.T04 | Piso de tiempo confiable | Trait `VerifierStateStore` (piso de tiempo, versiones aceptadas, nonces) con comprobación de integridad; detección de retroceso de reloj y de estado perdido o restaurado ⇒ `Unverifiable` con evidencia; cota con reloj monotónico cuando exista. | REQ-VER-006, REQ-VER-011 |
| F4.T05 | `Policy` | Estados aceptados por operación, frescura máxima, tolerancia de reloj, emisores y `vct` aceptados, requisitos del perfil. | REQ-VER-005, REQ-VER-007 |
| F4.T06 | Pipeline del verificador | Comprobaciones ordenadas (estructura, emisor autorizado, estado de clave, firma, vigencia, divulgaciones, esquema, vinculación, nonce, estado, política) con evidencia por paso; typestate que impide evaluar comprobaciones sobre datos no autenticados (`Skipped`) y construir `Valid` sin todas las obligatorias (prueba `trybuild`). | REQ-VER-002, REQ-VER-004, REQ-VER-012 |
| F4.T07 | Caché de nonces | Trait + implementación en memoria con expiración, límite de tamaño y rechazo de reutilización. | REQ-PRES-004 |
| F4.T08 | Estados de clave del emisor | Semántica `active`/`retired`/`suspended`/`compromised` de `ARCHITECTURE.md §11.6` con pruebas. | REQ-KEY-005, REQ-KEY-006 |
| F4.T09 | Matriz negativa y cobertura | Un vector por cada comprobación que falla; pruebas de precedencia de estados; cobertura de líneas medida en crates críticos; pruebas de mutación sobre las reglas de rechazo sin mutantes supervivientes sin justificar. | REQ-MAINT-003, REQ-MAINT-005, REQ-MAINT-006, REQ-VER-010 |
| F4.T10 | Verificación sin red | `pip-verifier` compila sin dependencias de red (verificado por `check-layers` y `clippy.toml`); prueba de que ningún camino de verificación invoca `Transport`. | REQ-VER-001, REQ-SDK-008, REQ-PRIV-002 |
| F4.T11 | Determinismo | Propiedad: mismas entradas e instante ⇒ mismo resultado. | REQ-VER-009 |
| F4.T12 | `pip-cli` offline | Subcomandos `dev-issuer`, `dev-bundle`, `issue`, `verify` con archivos locales y clave de desarrollo claramente marcada como insegura. | REQ-VER-001 |

**Gate G4:** demostración scriptada de verificación offline con los cuatro estados reproducidos a voluntad; cobertura ≥ 90 % en `pip-status`, `pip-trust`, `pip-verifier`.

**Riesgos:** ambigüedad en la precedencia de estados (mitigación: tabla de verdad en `PROTOCOL.md` y prueba exhaustiva).

---

## 10. F5 — Wallet, almacenamiento cifrado y presentación offline → **M1**

**Objetivo:** el titular guarda credenciales cifradas y presenta offline por QR con consentimiento y protección de sesión.
**Entrada:** G4 cerrado.

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F5.T01 | `StorageBackend` | Trait clave-valor transaccional; implementación en memoria. | REQ-STOR-008 |
| F5.T02 | Cifrado de sobre | DEK/KEK con XChaCha20-Poly1305 y datos asociados; trait `KekProvider` del host; prueba de que intercambiar registros falla. | REQ-STOR-001 |
| F5.T03 | Índices ciegos | HMAC con clave dedicada; inspección automática de la base de datos: ningún metadato en claro. | REQ-STOR-003 |
| F5.T04 | Backend SQLite | Crate adaptador `pip-storage-sqlite` (L5) con `rusqlite` y SQLite embebido; implementa también `VerifierStateStore`. | REQ-STOR-008 |
| F5.T05 | Migraciones | Versión de esquema; migraciones probadas con fixtures de versiones anteriores. | REQ-STOR-005 |
| F5.T06 | Consistencia ante fallos | Inyección de fallos en cada punto de escritura; tras reinicio, estado anterior o posterior, nunca corrupto. | REQ-STOR-004 |
| F5.T07 | `pip-holder`: gestión | Importar (verificando antes de guardar), listar, borrar, lotes y consumo, registro mínimo de eventos con retención; contenido de presentaciones no persistido. | REQ-STOR-006, REQ-KEY-008, REQ-PRIV-005 |
| F5.T08 | `pip-holder`: presentación | Preparar desde solicitud (subconjunto DCQL acordado en `PROTOCOL.md`), plan de divulgación visible, confirmación y firma KB-JWT vía `KeyStore`. | REQ-PRES-001, REQ-PRES-003, REQ-PRIV-001 |
| F5.T09 | Perfil offline | Solicitud del verificador (CBOR, firma opcional), respuesta, transcodificación binaria sin pérdida + DEFLATE + Base45 (propiedad: la reconstrucción reproduce los bytes exactos), fragmentación multi-QR con índice y hash de integridad. | REQ-PRES-005, REQ-PRES-006 |
| F5.T10 | Presupuesto de tamaño en CI | Prueba que falla si una presentación de referencia de cada perfil excede su presupuesto. | REQ-PERF-003 |
| F5.T11 | Validación de solicitudes por la wallet | Verificador registrado cuando el perfil lo exige, claims solicitados permitidos, expiración. | REQ-PRES-007 |
| F5.T12 | Flujo CLI completo | `pip-cli` emisor → wallet → verificador offline usando imágenes QR generadas y decodificadas (ida y vuelta). | REQ-PRES-005 |
| F5.T13 | Legibilidad QR | QR generados mostrados en pantalla y leídos con lectores genéricos en ≥ 3 teléfonos; resultados registrados. | REQ-PRES-005 |
| F5.T14 | Demostración M1 | Script reproducible de los escenarios MVP-01, MVP-02 y MVP-03 (§24). | — |

**Gate G5 / Hito M1:** demostración M1 aprobada; consistencia ante fallos demostrada; ningún dato en claro en almacenamiento.

**Riesgos:** QR demasiado grandes (mitigación: decoys acotados por perfil, fragmentación, BLE en F18).

---

## 11. F6 — Contratos y adaptador de ledger

**Objetivo:** registro de confianza en cadena, gobernado y probado, y un adaptador robusto ante fallos de red y reorganizaciones.
**Entrada:** G2 cerrado y ADR-0004 aceptado (puede ejecutarse en paralelo a F3–F5); F6.T08 requiere F4.T03 completada.

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F6.T01 | `CONTRACTS.md` v1 | Especificación detallada actualizada desde v0.1; revisada. | REQ-LEDG-* |
| F6.T02 | `TrustRegistry.sol` | Emisores, claves con estados (incluida la suspensión con caducidad), perfiles/`vct`, verificadores, hash de la raíz de confianza y firmantes de bundle; roles; eventos. | REQ-TRUST-007, REQ-LEDG-003 |
| F6.T03 | `StatusAnchor.sol` | Compromisos por lotes (raíz Merkle) con eventos. | REQ-STAT-006 |
| F6.T04 | Gobernanza | Multisig propietaria; `TimelockController` para altas; rol de emergencia limitado a suspensiones reversibles con caducidad, que el propio rol no puede renovar. | REQ-LEDG-004 |
| F6.T05 | Pruebas Foundry | Unitarias, fuzz e invariantes (p. ej., una clave comprometida nunca vuelve a `active`; solo el timelock añade emisores; emergencia no puede añadir, ni marcar `compromised`, ni renovar una suspensión; toda suspensión caduca). | REQ-LEDG-004 |
| F6.T06 | Análisis estático y gas | Slither sin hallazgos altos; snapshot de gas versionado. | REQ-SEC-007 |
| F6.T07 | Verificación "sin datos personales" | Revisión de tipos de parámetros y eventos (solo identificadores de organización, claves públicas, hashes de alta entropía); prueba automatizada sobre las ABI; regla documentada. | REQ-LEDG-001, REQ-LEDG-007 |
| F6.T08 | `pip-ledger` | Trait `LedgerAdapter`, tipos de eventos, reconstrucción pura del estado desde eventos, derivación determinista del bundle (bytes idénticos entre ejecuciones), comparación estado ↔ bundle. | REQ-LEDG-002, REQ-TRUST-008 |
| F6.T09 | `pip-ledger-evm` | Implementación con `alloy`; lectura por rangos solo de bloques finalizados; múltiples RPC; reintentos; verificación de consistencia entre proveedores. | REQ-LEDG-005, REQ-LEDG-006 |
| F6.T10 | Pruebas de fallos | Nodo local con reorganizaciones simuladas, RPC caído, respuestas inconsistentes, eventos duplicados. | REQ-LEDG-005 |
| F6.T11 | Despliegue en testnet | Scripts reproducibles; código verificado en el explorador; direcciones en `deploy/environments/testnet/contracts.json`. | REQ-LEDG-003 |

**Gate G6:** contratos en testnet; invariantes y fuzz pasan; adaptador supera las pruebas de fallos; verificación "sin datos personales" aprobada.

**Riesgos:** cambios de costo de la red (mitigación: anclaje por lotes; ADR-0004 revisable).

---

## 12. F7 — Servicios y sincronización

**Objetivo:** el plano de servicio completo en testnet: indexador, generación de bundles, listas de estado publicadas y ancladas, relays y cliente de sincronización.
**Entrada:** G5 y G6 cerrados.

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F7.T01 | ADR-0013 e IaC base | Proveedor inicial; entornos `dev` y `testnet` como código; sin secretos en el repositorio. | REQ-REL-001 |
| F7.T02 | `pip-service-common` | Configuración tipada, OpenTelemetry, `/healthz`, `/readyz`, apagado ordenado, capa de redacción de logs con prueba de no-PII. | REQ-OBS-001, REQ-PRIV-003 |
| F7.T03 | `pip-indexer` | Ingesta de eventos finalizados, PostgreSQL, idempotencia, reprocesamiento desde un bloque, detección de divergencias entre RPC, métrica de retraso. | REQ-LEDG-005 |
| F7.T04 | `pip-trust-service` | Bundle derivado de forma determinista desde un indexador propio; cofirma: cada operador firma solo lo que derivó y un agregador no confiable reúne ≥ k firmas (claves de desarrollo en `dev`, KMS en `testnet`); publicación en almacenamiento de objetos/CDN; prueba con ≥ 3 operadores y uno divergente. | REQ-TRUST-003, REQ-TRUST-005, REQ-TRUST-008 |
| F7.T05 | Listas de estado del emisor | Asignación aleatoria de índices, tamaño mínimo, actualización, firma, publicación direccionada por contenido, manifiesto de estado firmado, anclaje periódico en `StatusAnchor`. | REQ-ISS-003, REQ-STAT-002, REQ-STAT-005, REQ-STAT-006, REQ-STAT-008 |
| F7.T06 | `pip-relay` | Objetos por hash; buzón de sobres HPKE con idempotencia; límites de tasa y tamaño; TTL; sin registro de contenido. | REQ-SYNC-004, REQ-SYNC-006 |
| F7.T07 | `pip-sync` | Máquina de estado sans-I/O: cola cifrada, idempotencia, backoff con jitter, múltiples relays, verificación de todo contenido; trait `Transport` con implementación por defecto en `pip-transport-http`; descargas públicas sin identificadores; pruebas deterministas sin red ni runtime. | REQ-SYNC-001..007 |
| F7.T08 | Modo de verificación completa | Contraste del bundle con ≥ 2 fuentes de ledger; divergencia ⇒ alarma y rechazo. | REQ-TRUST-004 |
| F7.T09 | Backend `aws-lc-rs` (FIPS), condicional | Solo si ADR-0007 identifica un requisito regulatorio que el HSM/KMS no cubre; seleccionado por tipo, no por feature; mismos vectores que RustCrypto. Si no aplica, la tarea se cierra como no necesaria con referencia al ADR. | REQ-ISS-002 |
| F7.T10 | Integración con contenedores | Cadena local + indexador + trust service + relay + SDK en pruebas automatizadas. | — |
| F7.T11 | Revocación durante periodo offline | Escenario MVP-05 (§24): verificador offline; revocación ocurre; resultado `ValidWithStaleStatus` mientras corresponde y `Invalid` tras sincronizar. | REQ-STAT-004 |
| F7.T12 | Caos | Relay malicioso (rollback, retención, alteración), RPC caído, CDN caída; el sistema degrada a estados explícitos sin aceptar datos falsos. | REQ-REL-004, REQ-SYNC-004 |

**Gate G7:** plano de servicio en testnet funcionando de extremo a extremo; pruebas de caos aprobadas; logs auditados sin PII.

**Riesgos:** complejidad operativa temprana (mitigación: servicios mínimos, sin estado salvo indexador).

---

## 13. F8 — Recuperación, migración y rotación → **M2**

**Objetivo:** el titular sobrevive a la pérdida de dispositivo, y emisores y TFA rotan o revocan claves sin romper el sistema.
**Entrada:** G7 cerrado.

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F8.T01 | Código de recuperación y respaldo | Generación ≥ 128 bits, codificación legible con suma de verificación, derivación HKDF, formato de respaldo versionado y cifrado. | REQ-REC-002 |
| F8.T02 | Shamir k-de-n | Biblioteca revisada (o ADR si no existe una adecuada); pruebas de umbral y de fragmentos insuficientes. | REQ-REC-003 |
| F8.T03 | Clave de recuperación | `KeyPurpose::Recovery`; una clave por emisor derivada del secreto de recuperación y del `IssuerId`; registro de su huella en la emisión como extensión documentada en `PROTOCOL.md`; prueba de que dos emisores nunca reciben la misma huella. | REQ-REC-004, REQ-REC-007 |
| F8.T04 | Re-vinculación | Solicitud firmada, nonce del emisor, revocación de la credencial anterior, emisión nueva; biblioteca y endpoint del emisor. | REQ-REC-004, REQ-ISS-006 |
| F8.T05 | Migración entre dispositivos | QR con clave efímera, ECDH con compromiso previo, SAS, transferencia cifrada, re-vinculación en cola. | REQ-REC-001 |
| F8.T06 | Rotación de clave de emisor E2E | Registro → indexador → bundle → verificadores; credenciales anteriores al retiro siguen válidas. | REQ-KEY-006 |
| F8.T07 | Compromiso de clave de emisor E2E | Suspensión de emergencia → bundle → `Unverifiable` en todos los verificadores sincronizados; confirmación por la multisig → `compromised` → `Invalid`; y caso de suspensión levantada → la clave vuelve a aceptarse. | REQ-KEY-005, REQ-LEDG-004 |
| F8.T08 | Rotación de firmantes de bundle y de raíz | Raíz nueva encadenada; solapamiento sin interrupción de clientes con distintas versiones; simulacro de avance forzado y recuperación por `bundle_epoch`. | REQ-TRUST-006 |
| F8.T09 | Procedimientos por perfil | Recuperación institucional documentada en cada perfil. | REQ-REC-005, REQ-REC-006 |
| F8.T10 | Robustez | Persistencia, migración y recuperación con inyección de fallos. | REQ-STOR-004 |
| F8.T11 | Revisión del MVP | Ejecución scriptada y reproducible de todos los criterios de §24 con informe. | — |

**Gate G8 / Hito M2:** los nueve criterios de aceptación del MVP (§24) pasan; `docs/STATUS.md` registra la evidencia.

**Riesgos:** baja adopción de la re-vinculación por emisores (mitigación: recuperación institucional siempre disponible; extensión declarada en metadatos).

---

## 14. F9 — SDK público y bindings multiplataforma

**Objetivo:** una API estable disponible y probada en todos los lenguajes y plataformas objetivo.
**Entrada:** G8 cerrado.

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F9.T01 | `pip-sdk` completo | Fachada (iniciada en F1.T13 y ampliada en cada fase) completa según `SDK_API.md`, features, `PipError` con códigos estables, interfaces del host (`KeyStore`, `Clock`, `StorageBackend`, `VerifierStateStore`, `Transport`). | REQ-SDK-001, REQ-SDK-003, REQ-SDK-005 |
| F9.T02 | Revisión y congelación de API | Revisión formal; versión `0.x` congelada para la beta; `cargo-semver-checks` activo. | REQ-SDK-006 |
| F9.T03 | Seguridad FFI | `catch_unwind` en todas las fronteras nativas e instancia envenenada en WASM; prueba de pánico inducido ⇒ `PIP-E9999` en ambos casos; fuzzing a través de la frontera FFI; revisión que confirma que ninguna clave privada del titular cruza FFI. | REQ-SDK-004, REQ-KEY-003 |
| F9.T04 | Kotlin (Android + JVM) | UniFFI + cargo-ndk (todas las ABIs); `KeyStore` Android (StrongBox con alternativa TEE; autenticación de usuario según perfil); KEK en Android Keystore; exclusión de backups; pruebas en emulador y dispositivo físico. | REQ-KEY-002, REQ-STOR-002, REQ-STOR-007 |
| F9.T05 | Swift (iOS + macOS) | XCFramework; `KeyStore` Secure Enclave; KEK en Keychain solo-este-dispositivo; exclusión de backups; pruebas en dispositivo físico (el simulador no tiene Secure Enclave: allí solo keystore software marcado como de prueba). | REQ-KEY-002, REQ-STOR-002, REQ-STOR-007 |
| F9.T06 | JavaScript/TypeScript (WASM) | wasm-bindgen; tipos TypeScript; `KeyStore` WebCrypto no extraíble; `StorageBackend` IndexedDB; pruebas en Node y en Chromium, Firefox y WebKit headless. | REQ-PORT-001 |
| F9.T07 | Python | UniFFI; wheels para Linux, macOS y Windows; pruebas. | REQ-SDK-002 |
| F9.T08 | Dart/Flutter | Según ADR-0006; paquete y pruebas en Android e iOS. | REQ-SDK-002 |
| F9.T09 | C ABI, Go y .NET | `cbindgen`; funciones de liberación de memoria explícitas; envoltorio Go (cgo) y .NET (P/Invoke); pruebas con sanitizadores. | REQ-SDK-002 |
| F9.T10 | Conformidad multi-lenguaje | `conformance/vectors/` ejecutado en cada binding con resultados idénticos. | REQ-SDK-007 |
| F9.T11 | Rendimiento y tamaño | Benchmarks por plataforma; presupuestos numéricos fijados (tiempo de verificación, memoria, arranque, tamaño binario); CI falla ante regresión superior al umbral. | REQ-PERF-002 |
| F9.T12 | Guías de integración | `docs/guides/<lenguaje>.md` con ejemplo ejecutado en CI. | REQ-SDK-009 |
| F9.T13 | Empaquetado previo | Paquetes pre-release en canales de staging de cada registro (no anunciados). | — |
| F9.T14 | Telemetría | Hooks opcionales, desactivados por defecto, sin PII; prueba. | REQ-OBS-003 |

**Gate G9:** todos los bindings pasan la conformidad; presupuestos de rendimiento fijados; claves de hardware probadas en dispositivos físicos; guías ejecutables.

**Riesgos:** inmadurez de generadores de terceros (C#, Go vía UniFFI) (mitigación: C ABI como camino garantizado).

---

## 15. F10 — Protocolos en línea y servicio de emisión

**Objetivo:** emisión y presentación en línea con estándares finales, y un servicio de emisión listo para operar.
**Entrada:** G8 cerrado y F9.T02 completada.

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F10.T01 | OID4VCI (emisor) | Metadatos del emisor, credential offer, flujos pre-authorized code y authorization code con PKCE, endpoint de nonce, endpoint de credencial, prueba de posesión, emisión por lotes. | REQ-ISS-001, REQ-ISS-004 |
| F10.T02 | OID4VCI (wallet) | Cliente en `pip-holder`/`pip-protocol`. | REQ-ISS-001 |
| F10.T03 | Puerto de verificación de identidad | Interfaz `IdentityVerificationPort` para conectar el KYC/proceso propio de cada emisor; adaptador de prueba. | — |
| F10.T04 | Atestación de clave/dispositivo | Android Key Attestation y Apple App Attest verificados en el emisor; obligatorio en perfil financiero. | REQ-ISS-005 |
| F10.T05 | OID4VP (verificador) | Solicitud por referencia, DCQL, modo de respuesta para entre-dispositivos, esquema de identificación del cliente según perfil. | REQ-PRES-008 |
| F10.T06 | OID4VP (wallet) | Cliente con validación de solicitudes y consentimiento. | REQ-PRES-008 |
| F10.T07 | Mismo dispositivo y entre dispositivos | Ambos flujos con pruebas E2E. | REQ-PRES-008 |
| F10.T08 | `pip-issuer-service` completo | OID4VCI, listas de estado, re-vinculación, KMS; desplegable en contenedor o serverless. | REQ-ISS-001..006 |
| F10.T09 | Conformidad OpenID | Ejecución de la suite de conformidad de la OpenID Foundation en la medida en que cubra las versiones finales; brechas documentadas como issues. | REQ-ISS-001, REQ-PRES-008 |
| F10.T10 | Endurecimiento de endpoints | Límites de tasa, validación estricta, CORS mínimo, cabeceras de seguridad, autenticación fuerte para administración. | REQ-SEC-008 |

**Gate G10:** flujos en línea E2E en testnet; suite OpenID ejecutada; servicio de emisión desplegado con KMS.

**Riesgos:** divergencia respecto de perfiles de interoperabilidad externos: HAIP 1.0 (Final) exige `x5c` para la clave del emisor, mientras que PIP la resuelve desde el trust bundle (mitigación: ADR-0003 decide la alineación; perfil propio documentado con mapeo a perfiles externos).

---

## 16. F11 — Aplicaciones de referencia

**Objetivo:** demostrar el protocolo con aplicaciones usables y probadas en campo.
**Entrada:** G9 y G10 cerrados.

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F11.T01 | Diseño de consentimiento | Pantallas que muestran qué, a quién y para qué; claims sensibles destacados; español e inglés. | REQ-PRES-003 |
| F11.T02 | `reference-wallet` | Onboarding con código de recuperación, recepción OID4VCI, listado, presentación offline QR, OID4VP, sincronización, respaldo, recuperación y migración. | REQ-REC-*, REQ-PRES-* |
| F11.T03 | `reference-verifier` | Móvil y web: solicitud, escaneo, resultado con estado y evidencia, configuración de política, actualización de bundle, funcionamiento offline. | REQ-VER-002 |
| F11.T04 | `issuer-console` | Emisión de prueba, revocación/suspensión, estado de listas, monitoreo. | REQ-ISS-003 |
| F11.T05 | E2E automatizados | Escenarios: emisión → presentación offline → revocación → sincronización → `Invalid`; pérdida de dispositivo → recuperación; rotación de claves. | — |
| F11.T06 | Prueba de campo QR | Matriz de dispositivos (gamas, sistemas, iluminación, brillo); presupuesto confirmado o ajustado por ADR. | REQ-PERF-003 |
| F11.T07 | Usabilidad | ≥ 5 participantes por rol; hallazgos como issues y corregidos los críticos. | — |
| F11.T08 | Accesibilidad | WCAG 2.2 AA en web y guías de accesibilidad de cada plataforma móvil. | — |

**Gate G11:** E2E verdes; prueba de campo aprobada; hallazgos críticos de usabilidad cerrados.

---

## 17. F12 — Conformidad, interoperabilidad y beta en testnet → **M3**

**Objetivo:** demostrar que otras implementaciones interoperan y abrir la beta técnica.
**Entrada:** G11 cerrado.

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F12.T01 | Runner de conformidad publicable | `pip-conformance` ejecuta vectores contra cualquier implementación mediante adaptador CLI/JSON; documentado. | REQ-SDK-007 |
| F12.T02 | Interoperabilidad con ≥ 2 implementaciones independientes | Matriz emisor × wallet × verificador en formato y protocolo; informe. | REQ-CRED-001 |
| F12.T03 | Ecosistemas externos | Pruebas con wallets/verificadores compatibles con OID4VC relevantes; informe de compatibilidad y brechas. | REQ-PRES-008 |
| F12.T04 | Especificación v1.0-rc | Congelación de especificación; vectores v1 finales. | REQ-DOC-001 |
| F12.T05 | Despliegue completo en testnet | Contratos, servicios y relays en ≥ 2 regiones o proveedores. | REQ-REL-001 |
| F12.T06 | Beta técnica | Integradores invitados; canal de feedback; todo hallazgo como issue. | — |
| F12.T07 | Pruebas de carga | Emisión, relays y trust service con perfiles de tráfico; capacidad documentada. | REQ-REL-002 |

**Gate G12 / Hito M3:** interoperabilidad demostrada; beta operativa ≥ 4 semanas sin incidentes S0 abiertos.

---

## 18. F13 — Endurecimiento de seguridad y auditorías externas

**Objetivo:** validación independiente de la seguridad antes de producción.
**Entrada:** G12 cerrado (contratación iniciada durante F9).

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F13.T01 | Contratación de auditores | Firmas independientes para criptografía/SDK, contratos y pentest; alcance acordado. | REQ-SEC-007 |
| F13.T02 | Revisión interna previa | Listas OWASP MASVS (móvil) y ASVS (servicios); revisión de todo `unsafe`; revisión completa de dependencias; threat model actualizado. | REQ-SEC-001 |
| F13.T03 | Auditoría criptográfica y del SDK | Informe recibido. | REQ-SEC-007 |
| F13.T04 | Auditoría de contratos | Informe recibido. | REQ-SEC-007 |
| F13.T05 | Pentest | Servicios, apps de referencia y endpoints. | REQ-SEC-008 |
| F13.T06 | Corrección de hallazgos | Cada hallazgo como advisory privado → corrección → prueba de regresión → verificación del auditor. | REQ-SEC-011 |
| F13.T07 | Campaña de fuzzing extendida | Campaña larga (p. ej., OSS-Fuzz si el proyecto es elegible); análisis de cobertura de fuzzing. | REQ-SEC-005 |
| F13.T08 | Publicación de informes | Informes publicados tras corregir. | — |
| F13.T09 | Builds reproducibles y firma | Reproducibilidad verificada de forma independiente; artefactos firmados; SBOM. | REQ-SEC-009 |
| F13.T10 | Modelos formales de protocolo | Modelos Tamarin o ProVerif de presentación, re-vinculación y migración en `docs/specs/models/`; propiedades de autenticación y secreto comprobadas, o desviaciones registradas como issues. | REQ-SEC-007 |

**Gate G13:** cero hallazgos críticos o altos abiertos; medios con plan aceptado y fecha; informes publicados.

---

## 19. F14 — Privacidad, cumplimiento y marco de confianza operativo

**Objetivo:** que el sistema pueda operar legalmente y con una gobernanza real.
**Entrada:** G11 cerrado (en paralelo a F12–F13).

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F14.T01 | Asesoría legal | Análisis de Ley 81 de 2019 y mercados objetivo; rol de cada actor respecto a los datos. | REQ-COMP-001 |
| F14.T02 | DPIA | Evaluación de impacto completa y aprobada. | REQ-PRIV-004 |
| F14.T03 | Validación del perfil financiero | Validación KYC/AML con asesoría y, cuando corresponda, regulador; **sin aprobación, el perfil financiero no entra en producción**. | REQ-COMP-002 |
| F14.T04 | `TRUST_FRAMEWORK.md` v1 | Documento técnico-legal: miembros de la TFA, umbrales, debida diligencia de emisores, bajas, emergencias, disputas, responsabilidades. | REQ-GOV-001 |
| F14.T05 | Constitución de la TFA | Firmantes de organizaciones distintas con monederos hardware; procedimientos probados en testnet. | REQ-GOV-001 |
| F14.T06 | Ceremonias de claves | Guion, ensayo en testnet, testigos y acta; claves de raíz offline y claves de los firmantes de bundle en HSM/KMS de cada operador. | REQ-GOV-002 |
| F14.T07 | Documentos legales de servicio | Términos de uso de servicios operados, políticas de privacidad de apps de referencia, acuerdos con emisores piloto. | REQ-COMP-001 |
| F14.T08 | Proceso de propuestas | Proceso público de propuestas de mejora del protocolo, con plantilla y ciclo de revisión. | REQ-GOV-003 |

**Gate G14:** DPIA aprobada; marco de confianza v1 firmado por los miembros; ceremonia ensayada; estado del perfil financiero documentado (aprobado o excluido del piloto).

---

## 20. F15 — Preparación de producción

**Objetivo:** infraestructura, operación y procesos listos para usuarios reales.
**Entrada:** G13 y G14 cerrados.

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F15.T01 | Infraestructura de producción | IaC; relays multi-región y multi-proveedor; indexador redundante (idealmente ≥ 2 operadores); RPC ≥ 2 proveedores + nodo propio. | REQ-REL-001, REQ-LEDG-006 |
| F15.T02 | Secretos y claves | KMS/HSM para todas las claves de servicio; ninguna clave en variables de entorno en claro. | REQ-ISS-002 |
| F15.T03 | Observabilidad y SLOs | Dashboards, SLOs, alertas, guardias (on-call). | REQ-REL-002, REQ-OBS-002 |
| F15.T04 | Runbooks | Compromiso de clave de emisor, de un firmante de bundle y del rol de emergencia; sustitución de firmantes por raíz nueva; divergencia ledger/bundle, caída de relay o RPC, migración de contrato, restauración de indexador, rotaciones programadas. | REQ-REL-004 |
| F15.T05 | Recuperación ante desastres | Backups, RPO/RTO definidos, simulacro completo de restauración. | REQ-REL-003 |
| F15.T06 | Game day | Ejercicio de incidente con runbooks y guardias. | REQ-REL-003 |
| F15.T07 | Pipeline de release de producción | Firma, SBOM, publicación en crates.io, Maven Central, Swift Package, npm, PyPI, pub.dev, NuGet, proxy Go; notas de release; matriz de compatibilidad. | REQ-SEC-009 |
| F15.T08 | Política de soporte | Versiones soportadas, ventanas de compatibilidad, proceso de deprecación, SLA de parches de seguridad. | REQ-SDK-006 |
| F15.T09 | Contratos en red principal | Despliegue por ceremonia; verificación; direcciones registradas; primer bundle de producción firmado. | REQ-LEDG-003, REQ-GOV-002 |
| F15.T10 | Checklist de go-live | Lista revisada y firmada por responsables técnicos, de seguridad y legales. | — |

**Gate G15:** checklist de go-live firmado; simulacro de DR y game day aprobados.

---

## 21. F16 — Piloto controlado → **M4**

**Objetivo:** validar el sistema con usuarios reales en un alcance limitado.
**Entrada:** G15 cerrado.

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F16.T01 | Selección de participantes | Emisor(es) y verificador(es) piloto, preferiblemente perfiles personal o enterprise; financiero solo con aprobación de F14.T03. | REQ-COMP-002 |
| F16.T02 | Alta del emisor piloto | Alta en el registro de producción vía timelock con debida diligencia documentada. | REQ-GOV-001 |
| F16.T03 | Despliegue del servicio de emisión | En infraestructura del emisor o gestionada, con KMS. | REQ-ISS-002 |
| F16.T04 | Cohorte de usuarios | Cohorte acotada con soporte y métricas acordadas. | — |
| F16.T05 | Operación | SLOs monitoreados; incidentes y hallazgos como issues; postmortems para S0/S1. | REQ-REL-002 |
| F16.T06 | Ejercicios reales | Rotación de clave programada, revocación y recuperación de dispositivo con voluntarios. | REQ-KEY-006, REQ-REC-* |
| F16.T07 | Informe del piloto | Métricas, incidentes, lecciones y ADRs derivados. | — |
| F16.T08 | Release candidata GA | Correcciones integradas; RC publicada. | — |

**Gate G16 / Hito M4:** SLOs cumplidos durante ≥ 4 semanas consecutivas; sin S0/S1 abiertos; informe aprobado.

---

## 22. F17 — Lanzamiento general (GA) → **M5**

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F17.T01 | Especificación v1.0 | Publicada en español e inglés. | REQ-DOC-004 |
| F17.T02 | SDK 1.0.0 | Publicado en todos los registros con firmas y SBOM. | REQ-SDK-006 |
| F17.T03 | Servicios en producción | SLOs vigentes; página de estado pública. | REQ-REL-002 |
| F17.T04 | Programa de recompensas | Bug bounty activo con alcance y reglas. | REQ-SEC-010 |
| F17.T05 | Portal de desarrolladores | Guías, referencia de API, ejemplos, matriz de compatibilidad. | REQ-SDK-009 |
| F17.T06 | Onboarding abierto | Proceso de alta de emisores y verificadores según el marco de confianza. | REQ-GOV-001 |
| F17.T07 | Revisión a 30 días | Informe post-lanzamiento con acciones. | — |

**Gate G17 / Hito M5:** se cumple la Definición de Producción (§23).

---

## 23. Definición de "producto 100 % funcional en producción"

El producto está en producción cuando **todo** lo siguiente es verdad:

1. Todos los requisitos DEBE de `REQUIREMENTS.md` están implementados y trazados a pruebas que pasan.
2. Auditorías externas completadas sin hallazgos críticos o altos abiertos.
3. Especificación v1.0 publicada (ES/EN) y SDK 1.0.0 disponible en todos los registros previstos.
4. Contratos en la red principal desplegados por ceremonia; TFA constituida y operando con multisig.
5. Al menos un emisor y un verificador en producción con usuarios reales tras un piloto aprobado.
6. SLOs cumplidos durante ≥ 4 semanas consecutivas.
7. Runbooks probados, simulacro de DR superado, guardias activas.
8. DPIA aprobada, documentos legales publicados; el perfil financiero solo está habilitado si tiene validación regulatoria (si no, GA se declara para los perfiles personal y enterprise, y el financiero queda documentado como pendiente).
9. Programa de divulgación responsable y bug bounty activos.
10. La verificación funciona offline en todas las plataformas soportadas con claves de hardware donde existan.

---

## 24. Criterios de aceptación del MVP (gate G8)

| # | Criterio | Tareas que lo demuestran |
|---|---|---|
| MVP-01 | Verificación correcta sin acceso a Internet | F4.T06, F4.T10, F5.T12, F5.T14 |
| MVP-02 | Rechazo de credenciales alteradas, firmas incorrectas y emisores no autorizados | F3.T11, F4.T09 |
| MVP-03 | Rechazo de presentaciones repetidas cuando la operación exige protección contra replay | F4.T07, F5.T09 |
| MVP-04 | Comportamiento explícito ante snapshots desactualizados | F4.T02, F4.T04, F7.T11 |
| MVP-05 | Revocación simulada durante periodos offline reflejada tras sincronizar | F7.T11 |
| MVP-06 | Ausencia de datos personales en las transacciones del ledger | F6.T07 |
| MVP-07 | Recuperación y rotación de claves con procedimientos documentados | F8.T01–F8.T09 |
| MVP-08 | Interoperabilidad de formato entre al menos dos implementaciones independientes | F3.T10 |
| MVP-09 | Persistencia, migración y recuperación tras fallos; dependencias revisadas, análisis estático, fuzzing y pruebas de seguridad en verde | F5.T06, F8.T10, F1.T05, F2.T11 |

---

## 25. F18 — Operación continua y evolución (permanente)

| ID | Tarea | Disparador / cadencia |
|---|---|---|
| F18.T01 | Ciclo de releases y parches de seguridad con SLA | Continuo |
| F18.T02 | Rotaciones de claves y ceremonias programadas | Según calendario del marco de confianza |
| F18.T03 | Migración a RFC final de Token Status List y SD-JWT VC | Al publicarse; ADR + nueva versión de perfil criptográfico |
| F18.T04 | ISO 18013-5 (mdoc) y transporte BLE/NFC | Demanda de integradores; ADR |
| F18.T05 | Presentaciones no correlacionables (BBS) | Estándar en Recommendation y bibliotecas auditadas; ADR |
| F18.T06 | Registro de emisión anclado (excepción ante compromiso de clave) | ADR |
| F18.T07 | Preparación post-cuántica | Inventario criptográfico; perfil híbrido con ML-DSA (RFC 9964 ya lo define para JOSE) cuando exista soporte de plataforma para las claves del titular; firma híbrida de la raíz y del bundle como primer paso (el formato multi-firma ya la admite); plan de migración |
| F18.T08 | Nuevos perfiles (p. ej., gubernamental) | Proceso de propuestas |
| F18.T09 | Re-auditorías | Anual o tras cambios mayores |
| F18.T10 | Deprecación y fin de vida de versiones | Según política de soporte |
| F18.T11 | Revisión del threat model y de riesgos | Trimestral |
| F18.T12 | Registro de transparencia con testigos para claves y manifiestos de estado, anclando en cadena solo su raíz | Costo del anclaje por emisor o demanda de auditoría; ADR |
| F18.T13 | Bundle Merkle con deltas y prueba de inclusión adjunta a la presentación | El tamaño del bundle supera el presupuesto móvil; ADR |
| F18.T14 | Propagación de bundles y manifiestos entre dispositivos (wallets como portadoras de datos firmados) | Transporte de proximidad disponible; ADR |
| F18.T15 | Pruebas de conocimiento cero sobre ECDSA P-256 (no correlación compatible con claves de hardware) | Especificación estable y biblioteca auditada; ADR |

---

## 26. Registro de riesgos

| ID | Riesgo | Prob. | Impacto | Mitigación | Dueño |
|---|---|---|---|---|---|
| R-01 | Estándares en borrador cambian (SD-JWT VC, Token Status List) | Media | Medio | Versiones fijadas; ADR para actualizar; vectores por versión | Mantenedores del protocolo |
| R-02 | QR insuficiente para presentaciones reales | Media | Alto | Spike F0, transcodificación binaria, presupuestos, fragmentación, BLE de proximidad adelantable | Protocolo |
| R-03 | Claves de hardware no disponibles en dispositivos de gama baja | Media | Medio | Perfil personal con software cifrado; financiero exige hardware | Bindings |
| R-04 | Compromiso de clave de emisor | Baja | Crítico | HSM, rotación, suspensión de emergencia y confirmación por multisig, runbook | Emisores / TFA |
| R-05 | Captura o parálisis de la gobernanza | Baja | Crítico | Multisig de organizaciones distintas, timelock, rol de emergencia limitado | TFA |
| R-06 | Cambio de costo o de condiciones de la red blockchain | Media | Medio | EVM portable, anclaje por lotes, ADR-0004 revisable | Ledger |
| R-07 | Retraso en auditorías externas | Alta | Alto | Contratación en F9; alcance acordado temprano | Seguridad |
| R-08 | Bloqueo regulatorio del perfil financiero | Media | Alto | GA posible con perfiles personal/enterprise | Legal |
| R-09 | Degradación del proyecto por agentes sin contexto | Media | Alto | `AGENTS.md`, `STATUS.md`, CI estricto, CODEOWNERS | Mantenedores |
| R-10 | Dependencia comprometida en la cadena de suministro | Baja | Crítico | cargo-deny/audit, revisión, builds reproducibles | Seguridad |
| R-11 | Baja adopción de la re-vinculación por emisores | Media | Medio | Recuperación institucional siempre disponible | Producto |
| R-12 | Correlación por reutilización de credenciales SD-JWT | Alta | Medio | Lotes de uso único; BBS en F18 | Protocolo |
| R-13 | Colusión o indisponibilidad de los firmantes de bundle | Baja | Crítico | Operadores de organizaciones distintas, umbral k < n, raíz offline que los sustituye, `bundle_epoch` | TFA |
| R-14 | Mantenedor humano único: la aceptación de ADRs y las revisiones de CODEOWNERS se vuelven cuello de botella | Alta | Medio | Decisión explícita en un issue `type:decision`; ADRs agrupados por revisión; incorporar un segundo revisor humano | Mantenedores |

---

## Anexo A — Plantilla de revisión de gate

```markdown
## Gate G<n> — <nombre de fase>
- Fecha:
- Revisores:
- Criterios:
  - [ ] <criterio 1> — evidencia: <enlace>
  - [ ] <criterio 2> — evidencia: <enlace>
- REQ de la fase trazados (salida de `cargo xtask trace`): <enlace>
- Issues abiertos de la fase (deben ser 0 o diferidos con justificación): <lista>
- Riesgos revisados (§26): <cambios>
- Decisión: CERRADO / NO CERRADO
- Acciones derivadas:
```
