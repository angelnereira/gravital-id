# ROADMAP.md — Hoja de ruta completa hasta producción

> **Estado:** Normativo v0.3 · **Depende de:** `ARCHITECTURE.md`, `REQUIREMENTS.md`, `PROJECT_STRUCTURE.md`
> **Revisión v0.3 (2026-10-15):** incorpora ADR-0021 (**Aceptado**): pista de identidad portable `F19`–`F25`, hitos `MP1`–`MP3` y riesgos `R-15`–`R-23`. El diseño detallado de cada subsistema se cierra en ADR-0022 a ADR-0026 durante `F19`.
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
8. **Los spikes** (PoCs de F0 y F19) son código desechable en `spikes/`. Nada de un spike pasa a `crates/` sin reescribirse con las reglas de `AGENTS.md`.

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
| F19 | Especificación de identidad portable (NFC, tarjeta, código, retrato) | 2–4 semanas (paralela a F4–F5) | — |
| F20 | Núcleo de proximidad (sesión cifrada, independiente del medio) | 3–4 semanas | — |
| F21 | NFC: teléfono Android como tarjeta y lectores multiplataforma | 4–6 semanas | **MP1 · Tap offline** |
| F22 | Tarjeta física Gravital (Java Card) | 6–10 semanas | **MP2 · Tarjeta física** |
| F23 | Códigos numéricos de sesión (y número por emisor opcional) | 3–4 semanas | — |
| F24 | Identidad portable (`pip-identity-v1`) y kit del integrador | 6–8 semanas | **MP3 · Identidad portable** |
| F25 | Formato mdoc e interoperabilidad ISO/IEC 18013-5 (condicional a ADR-0022) | Condicional | — |

**Estimación total orientativa hasta M5:** 14–20 meses con los solapamientos permitidos. El MVP (M2) se alcanza aproximadamente entre los meses 6 y 9. La pista `F19`–`F24` se ejecuta encadenada a `F5`, `F7` y `F10`, entregando los hitos `MP1`, `MP2` y `MP3` antes de la beta técnica (`F12`).

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
    F0 --> F19 --> F20
    F5 -. F5.T08 y F5.T09 .-> F20
    F20 --> F21
    F20 --> F22
    F21 -. lectores .-> F22
    F19 --> F23
    F7 -. relay .-> F23
    F10 -. OID4VP .-> F23
    F21 --> F24
    F22 -. si hay tarjeta .-> F24
    F10 -. servicio de emisión .-> F24
    F24 --> F12
    F19 -. condicional .-> F25
    F25 -.-> F24
```

Solapamientos permitidos: **F6** puede empezar cuando cierra G2 (los contratos no dependen del formato de credencial) y avanzar en paralelo con F3–F5. La tarea F6.T08 (`pip-ledger`) necesita además el modelo de bundle de F4.T03. **F10** puede empezar cuando la API de `pip-sdk` esté congelada (F9.T02). **F14** puede empezar con G11 abierto. La **contratación** de auditores (F13.T01) empieza durante F9. **F19** puede ejecutarse en paralelo a F4–F5 porque solo produce especificaciones, ADRs y spikes. **F20** requiere G19 y las tareas F5.T08–T09 (y su gate G20 espera a G5). Según ADR-0021, **F21** adelanta el subconjunto de frontera FFI y `KeyStore` Kotlin/Swift de F9.T03–T05 requerido para proximidad, y **F24** adelanta el subconjunto de servidor de F9.T06 y F9.T09 (TypeScript/Node, Go y .NET).

---

## 3. Hitos

| Hito | Significado | Demostración mínima |
|---|---|---|
| **M1 · Núcleo offline** | El protocolo funciona sin conectividad. | Emitir credencial de prueba → transferir por QR → verificar en otro dispositivo sin red, con divulgación selectiva y rechazo de replay. |
| **MP1 · Tap offline** | El teléfono Android actúa como tarjeta sin contacto verificable offline. | Emitir → wallet Android (HCE + StrongBox/TEE) → toque NFC → verificación offline en Android, iPhone y lector USB PC/SC con divulgación selectiva y rechazo de replay/sesión cruzada. |
| **MP2 · Tarjeta física** | Tarjeta inteligente Java Card verificable offline con los mismos vectores que el núcleo. | Personalizar tarjeta real con `gid-perso` → verificar offline en Android, iPhone y PC/SC (nivel 0 sin PIN, nivel 1 con PIN; tarjeta revocada ⇒ `Invalid`). |
| **M2 · MVP del protocolo** | Confianza pública, sincronización y recuperación funcionan de extremo a extremo en testnet. | Todos los criterios de aceptación del MVP (§24) pasan en una ejecución scriptada y reproducible. |
| **MP3 · Identidad portable** |Documento de identidad con retrato y kit de servidor listos en teléfono, tarjeta, QR y código numérico. | Emitir `pip-identity-v1` desde SDK de servidor (TS/Go/.NET) con KMS → teléfono y tarjeta → verificar offline por NFC con retrato, por QR sin retrato y por código de sesión en línea. |
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
| F9.T03 | Seguridad FFI | `catch_unwind` en todas las fronteras nativas e instancia envenenada en WASM; prueba de pánico inducido ⇒ `PIP-E9999` en ambos casos; fuzzing a través de la frontera FFI; revisión que confirma que ninguna clave privada del titular cruza FFI. *(Subconjunto de proximidad Kotlin adelantado a F21.T03 según ADR-0021).* | REQ-SDK-004, REQ-KEY-003 |
| F9.T04 | Kotlin (Android + JVM) | UniFFI + cargo-ndk (todas las ABIs); `KeyStore` Android (StrongBox con alternativa TEE; autenticación de usuario según perfil); KEK en Android Keystore; exclusión de backups; pruebas en emulador y dispositivo físico. *(Subconjunto de proximidad y StrongBox/TEE adelantado a F21.T04 según ADR-0021).* | REQ-KEY-002, REQ-STOR-002, REQ-STOR-007 |
| F9.T05 | Swift (iOS + macOS) | XCFramework; `KeyStore` Secure Enclave; KEK en Keychain solo-este-dispositivo; exclusión de backups; pruebas en dispositivo físico (el simulador no tiene Secure Enclave: allí solo keystore software marcado como de prueba). *(Subconjunto mínimo de verificador Core NFC adelantado a F21.T06 según ADR-0021).* | REQ-KEY-002, REQ-STOR-002, REQ-STOR-007 |
| F9.T06 | JavaScript/TypeScript (WASM) | wasm-bindgen; tipos TypeScript; `KeyStore` WebCrypto no extraíble; `StorageBackend` IndexedDB; pruebas en Node y en Chromium, Firefox y WebKit headless. *(Superficie de servidor TS/Node adelantada a F24.T06 según ADR-0021).* | REQ-PORT-001 |
| F9.T07 | Python | UniFFI; wheels para Linux, macOS y Windows; pruebas. | REQ-SDK-002 |
| F9.T08 | Dart/Flutter | Según ADR-0006; paquete y pruebas en Android e iOS. | REQ-SDK-002 |
| F9.T09 | C ABI, Go y .NET | `cbindgen`; funciones de liberación de memoria explícitas; envoltorio Go (cgo) y .NET (P/Invoke); pruebas con sanitizadores. *(Superficie de servidor Go y .NET adelantada a F24.T06 según ADR-0021).* | REQ-SDK-002 |
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
| F18.T04 | ISO 18013-5 (mdoc) (el transporte NFC sobre SD-JWT VC se movió a F21 según ADR-0021; mdoc se adelanta a F25 si ADR-0022 lo decide) | Demanda de integradores; ADR-0022 |
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

## 26. F19 — Especificación de la ampliación (spec-first)

**Objetivo:** cerrar decisiones, requisitos y especificaciones del alcance de identidad portable (NFC, tarjeta física, código numérico y perfil de documento de identidad) antes de escribir código de producción.
**Entrada:** G0 cerrado (avanza en paralelo a F4–F5).

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F19.T01 | ADR-0021: ampliación de alcance y cambio de hoja de ruta | ADR con opciones (incluida "no ampliar"); añade F19–F25, G19–G25, MP1–MP3; adelanta el subconjunto Kotlin de F9.T03/F9.T04 a F21 y el de TS/Go/.NET de F9.T06/F9.T09 a F24; mueve NFC de F18.T04 a F21; `ROADMAP.md` y `ARCHITECTURE.md` actualizados al aceptarse. | — |
| F19.T02 | Registrar discrepancias | Un issue `type:spec-gap` por cada discrepancia detectada en la auditoría inicial (#73–#77). | REQ-DOC-001 |
| F19.T03 | ADR-0022: transporte de proximidad | Compara (a) GID-APDU propio con SD-JWT VC, (b) ISO/IEC 18013-5 con mdoc, (c) BLE con traspaso por NFC; justifica la opción frente a P-04; incluye cambios en `layers.toml`, AID y registro de RID. | REQ-PROX-003 |
| F19.T04 | ADR-0023: cifrado de sesión y transcrito | Suite HPKE (de `CRYPTO_PROFILES.md`), construcción del transcrito, vinculación del KB-JWT, decisión sobre si el QR adopta cifrado. | REQ-PROX-001, REQ-PROX-002 |
| F19.T05 | ADR-0024: tarjeta física | Plataforma y versión Java Card, chips candidatos, soporte AEAD (resultado de F19.T13), ciclo de vida, PIN y su transporte, lotes en tarjeta, certificación del chip, atestación. | REQ-CARD-001, REQ-CARD-002, REQ-CARD-003, REQ-CARD-004, REQ-CARD-005 |
| F19.T06 | ADR-0025: identificadores numéricos | Código de sesión (formato, Damm, TTL, límites) y decisión sobre la opción B con sus contrapartidas; resuelve la tensión con `ARCHITECTURE.md §7.1` (#77). | REQ-CODE-001, REQ-CODE-002, REQ-CODE-003, REQ-CODE-004 |
| F19.T07 | ADR-0026: perfil de identidad y retrato | Variantes oficial/derivada, claims, retrato (formato, tamaño, transportes), parámetros del perfil. | REQ-IDDOC-001, REQ-IDDOC-002, REQ-IDDOC-003 |
| F19.T08 | Requisitos | Familias `PROX`, `CARD`, `CODE`, `IDDOC` incorporadas a `REQUIREMENTS.md` según los ADR aceptados; `cargo xtask trace` en verde. | REQ-DOC-003 |
| F19.T09 | `PROTOCOL.md` §7 Proximidad + `ERROR_CODES.md` familia 8 | Gramática CBOR de los mensajes, tabla APDU, máquinas de estado, errores `GID-E8xxx`; `cargo xtask check-error-codes` en verde. | REQ-PROX-003 |
| F19.T10 | Adenda de `THREAT_MODEL.md` | Amenazas de proximidad, tarjeta física y código numérico con STRIDE/LINDDUN; cada amenaza enlazada a mitigación y REQ. | REQ-SEC-001 |
| F19.T11 | `docs/specs/profiles/pip-identity-v1.md` | Perfil completo con el formato de los perfiles existentes. | REQ-CRED-004, REQ-IDDOC-001 |
| F19.T12 | Spike NFC/HCE (código en `spikes/nfc-hce/`) | App Android HCE mínima + lector Android + lector iPhone + lector PC/SC; payloads de 1, 4 y 20 KB; latencia por APDU, rendimiento con longitud extendida y tasa de éxito al primer toque; script reproducible y datos crudos (CSV) versionados. | REQ-PROX-005 |
| F19.T13 | Spike Java Card (código en `spikes/javacard/`) | Applet mínimo: generar clave P-256, firmar, ECDH y AEAD disponible; en jCardSim y en ≥ 2 modelos de tarjeta reales; tiempos y memoria; datos crudos versionados. | REQ-CARD-001 |
| F19.T14 | Reproducibilidad de spikes existentes | Repetir los spikes QR y keystore con código y datos crudos en `spikes/` (#76); si los resultados difieren de los informes, issue y actualización de ADR-0011 por la vía de ADR. | REQ-PRES-005, REQ-KEY-002 |
| F19.T15 | Adenda legal | Preguntas para F14 en `docs/legal/`: emisión por el Tribunal Electoral o credencial derivada, retrato como dato sensible (Ley 81 de 2019), número por emisor como dato personal, obligaciones del emisor de tarjetas. | REQ-COMP-001 |
| F19.T16 | Revisión cruzada | Cada documento nuevo revisado con la lista de F0.T21. | REQ-DOC-001 |

**Gate G19:** ADR-0021 a ADR-0026 aceptados (o diferidos con fase límite) por el mantenedor humano; especificaciones fusionadas y revisadas; spikes F19.T12–T14 con código y datos crudos; ningún spec-gap abierto del alcance nuevo.

---

## 27. F20 — Núcleo de proximidad (sesión cifrada, independiente del medio)

**Objetivo:** máquinas de estado sans-I/O, cifrado de sesión HPKE y vinculación al transcrito en L4 (`gravital-id-proximity`), reutilizables sobre NFC y BLE.
**Entrada:** G19 cerrado; F5.T08 y F5.T09 completadas (el gate G20 espera a G5).

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F20.T01 | Crate `gravital-id-proximity` (L4) | Crate creado con `#![forbid(unsafe_code)]`, README y lints; `layers.toml` actualizado según ADR-0022; caso negativo de `check-layers`. | REQ-MAINT-002 |
| F20.T02 | Mensajes CBOR | `ProximityRequest`, `ProximityResponse`, `HolderHello`, estado de sesión; parser acotado sobre `gravital-id-codec`; propiedad de ida y vuelta; objetivo de fuzzing por mensaje. | REQ-PROX-003, REQ-PROX-004 |
| F20.T03 | Cifrado de sesión | Clave efímera del verificador (propósito de acuerdo, nunca de firma); sellado y apertura HPKE con AAD = transcrito. Pruebas negativas: clave errónea, texto cifrado alterado, AAD de otra sesión ⇒ fallo cerrado. | REQ-PROX-001 |
| F20.T04 | Transcrito y vinculación | Construcción canónica del transcrito; vinculación del KB-JWT según ADR-0023; prueba: respuesta reenviada a otra sesión o a otro `aud` ⇒ `Invalid`. | REQ-PROX-002 |
| F20.T05 | Fragmentación | Fragmentación por MTU con hash de integridad, compartida por NFC y BLE; reutiliza la transcodificación de F5.T09. | REQ-PROX-003 |
| F20.T06 | Máquinas de estado | Titular y verificador sans-I/O; tiempos de espera como eventos del `Clock` inyectado; sin `std::time`. | REQ-VER-009 |
| F20.T07 | Integración con el verificador | El verificador recibe la presentación reconstruida y llama a `VerifierPipeline::verify`; misma presentación por QR y por proximidad ⇒ mismo `VerificationResult`. Ningún estado nuevo. | REQ-PROX-005 |
| F20.T08 | Vectores de conformidad | `conformance/vectors/proximity/`: positivos y al menos un negativo por regla de rechazo; `cargo xtask conformance` los ejecuta. | REQ-MAINT-003 |
| F20.T09 | Fachada del SDK | Feature `proximity` en `gravital-id-sdk`: iniciar sesión (verificador) y responder (titular) manteniendo preparar/confirmar. | REQ-PRES-003, REQ-SDK-001 |
| F20.T10 | Benchmarks | Tiempo de establecimiento + verificación y tamaños por perfil; resultados en `STATUS.md`. | REQ-PERF-001 |

**Gate G20:** vectores publicados; horas de fuzzing según `TEST_STRATEGY.md`; cobertura ≥ 90 % en `gravital-id-proximity`; demostración con transporte en memoria en la CLI de F4.T12: `Valid`, replay ⇒ `Invalid`, respuesta alterada ⇒ `Invalid`, sesión cruzada ⇒ `Invalid`.

---

## 28. F21 — NFC: teléfono Android como tarjeta y lectores → **MP1 · Tap offline**

**Objetivo:** presentación sin contacto desde teléfono Android (HCE + StrongBox/TEE) y verificación offline en lectores Android, iPhone y USB PC/SC.
**Entrada:** G20 cerrado y ADR-0021 aceptado.

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F21.T01 | Codec GID-APDU | `SELECT`, `ENVELOPE` con encadenamiento, `GET RESPONSE`, `VERIFY`; palabras de estado mapeadas a `GID-E8xxx`; fuzzing de comandos y respuestas. | REQ-PROX-004 |
| F21.T02 | AID | AID propietario de desarrollo definido en un único lugar; decisión de RID documentada (ADR-0022). | — |
| F21.T03 | Frontera FFI mínima (Kotlin) | UniFFI limitado a la superficie de proximidad; `catch_unwind` en cada frontera; pánico inducido ⇒ `GID-E9999`; ninguna clave privada cruza FFI. | REQ-SDK-004, REQ-KEY-003 |
| F21.T04 | Titular Android (HCE) | `HostApduService` que solo reenvía APDU a la máquina Rust (INV-15); `KeyStore` StrongBox con alternativa TEE; modelo de consentimiento de dos toques; prueba en dispositivo físico. | REQ-PROX-006, REQ-PROX-008, REQ-KEY-002 |
| F21.T05 | Verificador Android | Lector `IsoDep` con detección de longitud extendida; verificación offline con trust bundle precargado. | REQ-PROX-005 |
| F21.T06 | Verificador iPhone | Core NFC (ISO 7816) con el AID declarado; binding Swift mínimo; documentar que el iPhone no actúa como titular por NFC. | REQ-PROX-005 |
| F21.T07 | Adaptador PC/SC | `gravital-id-transport-pcsc` (L5) y subcomando de verificación por NFC en la CLI de F4.T12, con lector USB. | REQ-PROX-005 |
| F21.T08 | BLE (condicional) | Solo si F19.T12 muestra que NFC no basta para el retrato o si se exige al titular con iPhone: traspaso NFC → BLE GATT con la misma sesión cifrada. Si no aplica, se cierra con referencia al ADR. | REQ-PROX-003 |
| F21.T09 | Prueba de campo | ≥ 3 Android (gama baja, media, alta) como titulares; ≥ 2 iPhone y 1 lector PC/SC como verificadores; tasa de éxito y latencia con datos crudos versionados; umbral fijado en ADR-0022. | REQ-PROX-005 |
| F21.T10 | Demostración MP1 | Script reproducible: emitir → wallet Android → toque → verificación offline en Android, iPhone y PC/SC con divulgación selectiva, rechazo de replay y de sesión cruzada. | — |

**Gate G21 / Hito MP1:** demostración aprobada; prueba de campo dentro del umbral; logs auditados sin PII (REQ-PROX-007).

---

## 29. F22 — Tarjeta física Gravital (Java Card) → **MP2 · Tarjeta física**

**Objetivo:** tarjeta inteligente física con clave en elemento seguro, niveles de PIN, herramienta de personalización y conformidad idéntica al núcleo Rust.
**Entrada:** G20 cerrado y ADR-0024 aceptado; lectores de F21.T05–T07.

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F22.T01 | Proyecto del applet | `cards/javacard/gid-applet/` con compilación reproducible, pruebas en jCardSim y workflow `cards.yml`; ruta en `CODEOWNERS`. | REQ-MAINT-004 |
| F22.T02 | Clave en la tarjeta | Generación P-256 en la tarjeta; exportación solo de la clave pública; prueba: ningún comando devuelve material privado. | REQ-CARD-001 |
| F22.T03 | Almacenamiento y ciclo de vida | Credencial y divulgaciones con límites; escritura solo en `PERSONALIZACIÓN` autenticada; estados `ACTIVA`, `BLOQUEADA`, `TERMINADA`. | REQ-CARD-002 |
| F22.T04 | Presentación | KB-JWT construido en la tarjeta con `nonce`, `aud`, instante del verificador y `sd_hash`; divulgación según conjunto autorizado; cifrado de sesión según ADR-0024. | REQ-PROX-001, REQ-PROX-002 |
| F22.T05 | PIN | Niveles 0/1; contador con bloqueo; desbloqueo solo por el emisor; transporte del PIN según ADR-0024. | REQ-CARD-003 |
| F22.T06 | Personalización | `apps/gid-perso` (PC/SC + SDK de emisor + `KeyStore` KMS): flujo completo en jCardSim y en tarjeta real. | REQ-CARD-002 |
| F22.T07 | Conformidad del applet | Vectores de `conformance/vectors/proximity/` ejecutados contra el applet en CI: resultados idénticos al núcleo. | REQ-CARD-004 |
| F22.T08 | Tarjeta perdida | Revocación por lista de estado: tras sincronizar el snapshot, el verificador devuelve `Invalid`. | REQ-CARD-005 |
| F22.T09 | Revisión de seguridad del applet | Sin exportación de privadas, sin datos sensibles fuera de la sesión, manejo de errores sin fuga, dependencia de las protecciones del chip documentada. | REQ-SEC-001 |
| F22.T10 | Demostración MP2 | Personalizar una tarjeta real → verificar offline en Android, iPhone y PC/SC; nivel 0 sin PIN, nivel 1 con PIN; tarjeta revocada ⇒ `Invalid`. | — |

**Gate G22 / Hito MP2:** demostración aprobada; conformidad del applet idéntica al núcleo; revisión de seguridad sin hallazgos altos abiertos.

---

## 30. F23 — Códigos numéricos

**Objetivo:** código de sesión efímero de 10 dígitos con dígito de control Damm para presentaciones en línea cuando no hay cámara ni NFC (y número por emisor opcional si ADR-0025 lo aprueba).
**Entrada:** ADR-0025 aceptado; F7.T06 (relay) y F10.T05–T06 (OID4VP) completadas.

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F23.T01 | Newtype `SessionCode` | En `gravital-id-types`: 10 dígitos con control Damm; constructor que rechaza valores inválidos; propiedades y fuzzing del parser. | REQ-CODE-002 |
| F23.T02 | Rendezvous en el relay | Código → solicitud firmada del verificador; TTL por perfil; un solo uso; límites por origen y globales; sin PII en logs. | REQ-CODE-001 |
| F23.T03 | Flujo de la wallet | Introducir código → obtener solicitud → validarla → mostrar quién y qué → consentimiento → respuesta HPKE por el relay. | REQ-CODE-003, REQ-PRES-003 |
| F23.T04 | Flujo del verificador | Crear solicitud y código desde el SDK de servidor; recibir la respuesta (sondeo o webhook); verificar. | REQ-CODE-003 |
| F23.T05 | Pruebas de abuso | Simulación de adivinación dentro del TTL con la cota de probabilidad documentada; carrera entre dos respuestas (gana la primera, el resto se rechaza). | REQ-CODE-001 |
| F23.T06 | Número por emisor (opcional) | Solo si ADR-0025 adopta la opción B: prefijos de emisor en el registro, número como claim, resolución con consentimiento por el relay, límites por número; prueba automatizada de que el número no aparece en ledger, logs ni errores. | REQ-CODE-004 |
| F23.T07 | Guía de atención telefónica | Caso de uso documentado con ejemplo ejecutable en CI. | REQ-SDK-009 |

**Gate G23:** flujos E2E en testnet; pruebas de abuso aprobadas; logs auditados sin PII.

---

## 31. F24 — Identidad portable y kit del integrador → **MP3 · Identidad portable**

**Objetivo:** perfil `pip-identity-v1` con retrato, adaptadores KMS/HSM y SDK de servidor (TS/Node, Go, .NET) listos para emitir y verificar en teléfono, tarjeta, QR y código de sesión.
**Entrada:** G21 cerrado; G22 si se usa tarjeta; F10.T08 (servicio de emisión); para producción, además F14 (legal).

| ID | Tarea | Entregable y criterio de aceptación | REQ |
|---|---|---|---|
| F24.T01 | Esquema `pip-identity-v1` | Esquema incorporado en compilación (como F3.T06); validación en emisión y verificación; variantes oficial/derivada con `vct` distintos. | REQ-IDDOC-001, REQ-CRED-004 |
| F24.T02 | Retrato | Validación estricta de formato y tamaño; rechazo del retrato en transportes no permitidos; el verificador de referencia no lo persiste. | REQ-IDDOC-002 |
| F24.T03 | Emisión derivada | Flujo de un emisor que verificó identidad (`IdentityVerificationPort`) → `pip-identity-v1` derivada. | REQ-IDDOC-001 |
| F24.T04 | Kit para emisor gubernamental | Documento de requisitos para una autoridad de registro civil: HSM, alta en el marco de confianza, personalización de tarjetas. Solo documentación hasta que exista acuerdo. | REQ-GOV-001 |
| F24.T05 | Adaptadores KMS/HSM | `KeyStore` para Azure Key Vault, AWS KMS y PKCS#11 con ES256; pruebas con emuladores o cuentas de prueba; ninguna clave en variables en claro. | REQ-ISS-002 |
| F24.T06 | SDK de servidor | Paquetes para TS/Node, Go y .NET (subconjunto adelantado de F9.T06/F9.T09) con la superficie emisor + verificador; vectores de conformidad en cada lenguaje con resultados idénticos. | REQ-SDK-002, REQ-SDK-007 |
| F24.T07 | API de aprovisionamiento | En `issuer-service`: emisión a teléfono (OID4VCI) y a tarjeta (personalización remota o en punto de atención); imagen de contenedor. | REQ-ISS-001 |
| F24.T08 | Verificador de referencia tipo terminal | App Android o kiosco PC/SC con políticas predefinidas por operación (aceptar offline con estado de hasta N días, o exigir estado fresco). | REQ-VER-005 |
| F24.T09 | Guías de integración | `docs/guides/` para emisor, verificador, wallet y tarjeta, con ejemplos ejecutados en CI. | REQ-SDK-009 |
| F24.T10 | Demostración MP3 | Emitir `pip-identity-v1` → teléfono Android y tarjeta → verificar offline por NFC con retrato, por QR sin retrato y por código de sesión en línea; revocar y comprobar `Invalid` tras sincronizar. | — |

**Gate G24 / Hito MP3:** demostración aprobada; SDK de servidor con conformidad idéntica; guías ejecutables.

---

## 32. F25 — Formato mdoc e interoperabilidad ISO/IEC 18013-5 (condicional)

**Solo si ADR-0022 lo decide** (p. ej. si hay acuerdo con una autoridad de identidad o se exige interoperar con lectores estándar). Adelanta F18.T04. Incluye: formato mdoc (CBOR/COSE), emisión de ambos formatos para el mismo titular, sesión de 18013-5 sobre NFC/BLE, vectores de conformidad oficiales disponibles y pruebas con lectores de terceros. Se planifica en detalle en ADR-0022.

---

## 33. Registro de riesgos

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
| R-15 | iPhone no puede emular tarjeta NFC en Panamá | Alta | Medio | QR/BLE para titulares iOS; Core NFC como lector verificador; reevaluar cuando Apple amplíe mercados | Bindings / Producto |
| R-16 | Chips Java Card sin AEAD nativo para HPKE | Media | Alto | Spike F19.T13 antes de comprar en volumen; ADR-0024 | Tarjetas / Cripto |
| R-17 | Ataques de relay NFC | Media | Alto | Vinculación al transcrito, solicitud firmada, PIN para datos sensibles, ventanas de tiempo cortas | Protocolo / Seguridad |
| R-18 | Tarjeta física rastreable por clave fija | Alta | Medio | Varias copias preaprovisionadas con claves distintas; contrapartida documentada en ADR-0024 | Privacidad |
| R-19 | Validez legal de la cédula portable | Alta | Alto | Distinguir credencial derivada de oficial (`vct` distintos); acuerdo institucional; F14 | Legal / Producto |
| R-20 | Divergencia entre applet Java Card y núcleo Rust | Media | Alto | Vectores de conformidad ejecutados sobre el applet en CI (`jCardSim`, REQ-CARD-004) | Tarjetas / Calidad |
| R-21 | Phishing o ingeniería social con códigos numéricos | Media | Medio | Wallet muestra el verificador; solicitudes firmadas; TTL corto y uso único | Protocolo / UX |
| R-22 | Costo y plazo de certificación de chips y registro de RID | Media | Medio | AID propietario en desarrollo; presupuesto en F15 | Operaciones |
| R-23 | Spikes de F0 sin evidencia reproducible | Media | Alto | Repetición con código y datos crudos en F19.T14 (#76) | Ingeniería |

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
- Riesgos revisados (§33): <cambios>
- Decisión: CERRADO / NO CERRADO
- Acciones derivadas:
```
