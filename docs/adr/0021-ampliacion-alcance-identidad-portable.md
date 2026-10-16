# ADR-0021: Ampliación de alcance y hoja de ruta para identidad portable por NFC, tarjeta física, código numérico y perfil de documento de identidad

- **Estado:** Propuesto
- **Fecha:** 2026-10-15
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira (pendiente de aceptación formal del mantenedor humano)
- **Issue:** #78
- **Requisitos y principios afectados:** REQ-DOC-001, REQ-DOC-002, REQ-KEY-002, REQ-KEY-003, REQ-PRES-001..008, REQ-SDK-001..009, REQ-VER-001..012; candidatos `REQ-PROX-001..008`, `REQ-CARD-001..005`, `REQ-CODE-001..004`, `REQ-IDDOC-001..003`; P-01..P-15; INV-01..INV-16
- **Fase:** F19 (F19.T01)

---

## Contexto

El protocolo Gravital ID cuenta ya con su modelo criptográfico y de confianza offline construido y verificado en las capas L1–L3 (`gravital-id-types`, `gravital-id-codec`, `gravital-id-crypto`, `gravital-id-keys`, `gravital-id-credential`, `gravital-id-status`, `gravital-id-trust`, `gravital-id-issuer` y `gravital-id-verifier`), replicando las garantías de autenticación de datos fuera de línea de **EMV (Visa / Mastercard)**:
- Raíz de confianza (`TrustRoot`) fijada en el terminal verificador y `TrustBundle` cofirmado $k$-de-$n$ por operadores independientes.
- Credenciales SD-JWT VC firmadas por emisores autorizados que ligan la clave pública del titular (`cnf.jwk`).
- Autenticación dinámica por sesión mediante Key Binding JWT (`KB-JWT`) firmado por la clave en hardware del titular sobre el `nonce` e identificador (`aud`) del verificador.
- Verificación 100 % offline contra instantáneas de listas de estado (Token Status List) y política de frescura por operación (`VerificationPolicy`), devolviendo cuatro estados con evidencia completa (`Valid`, `ValidWithStaleStatus`, `Unverifiable`, `Invalid`).

El mantenedor del proyecto ha solicitado ampliar el alcance del producto (`docs/proposals/2026-10-15-alcance-identidad-portable.md`) para cubrir ocho objetivos estratégicos (`OBJ-01` a `OBJ-08`):
1. Guardar datos y perfiles de usuario como credenciales cifradas, portables y verificables (`OBJ-01`).
2. Presentar la identidad sin contacto por **NFC**, como un pago con tarjeta o teléfono, desde móvil o tarjeta física (`OBJ-02`).
3. Presentar la identidad por **QR** (`OBJ-03`, ya previsto en `F5`).
4. Validar mediante un **identificador numérico de 9–10 dígitos** cuando no hay cámara ni lector NFC (`OBJ-04`).
5. Operar **sin conexión a Internet** en la verificación (`OBJ-05`, garantizado por `INV-01`).
6. Ofrecer un **kit integrable de servidor** para que cualquier organización instale el SDK, emita credenciales y aprovisione teléfonos y tarjetas físicas (`OBJ-06`).
7. Portar documentos de identidad, incluida la **cédula** con retrato (`OBJ-07`).
8. Mantener garantías de seguridad de grado alto auditables y demostrables (`OBJ-08`).

En la hoja de ruta actual (`docs/ROADMAP.md` v0.2):
- El transporte NFC solo figuraba como evolución futura post-lanzamiento en `F18.T04` (y con contradicción documental frente a `ADR-0011`, registrada en `#74`).
- No existían fases ni diseño para **tarjetas inteligentes físicas** (Java Card con elemento seguro), **sesiones de proximidad cifradas con HPKE**, **códigos numéricos de sesión**, ni un **perfil de identidad con retrato** (`pip-identity-v1`).
- Los bindings de servidor (TypeScript/Node, Go, .NET) y el binding móvil Kotlin/Android necesario para Host Card Emulation (HCE) estaban agrupados en `F9`, después de `F6`–`F8`.

Al mismo tiempo, el diseño debe respetar **límites técnicos, físicos y legales vinculantes** (`docs/proposals/2026-10-15-alcance-identidad-portable.md §3`):
- **NFC en iOS (Panamá):** Apple restringe la emulación de tarjeta (HCE) en aplicaciones de terceros a jurisdicciones elegibles (EEE y países anunciados en el programa NFC & SE, entre los cuales no figura Panamá). Un iPhone en Panamá **sí puede ser lector verificador** (Core NFC ISO 7816), pero **no tarjeta emulada**; el titular con iPhone presenta por QR o BLE (`R-15`).
- **Imposibilidad de autenticación offline solo con 10 dígitos:** Un número de 9–10 dígitos (~30 bits) carece de firma y de prueba de posesión criptográfica; en línea sí es seguro como **código efímero de sesión** (rendezvous) donde la seguridad recae en la solicitud firmada, el sobre HPKE y el KB-JWT del titular (`#77`).
- **Presupuesto óptico del retrato:** Una fotografía facial JPEG útil excede el presupuesto de un código QR (~800 B útiles), por lo que el retrato solo puede viajar por NFC o BLE.
- **Validez legal de la cédula:** El valor legal de documento público oficial depende del Tribunal Electoral o reconocimiento normativo; sin convenio, el protocolo soporta una **credencial de identidad derivada** emitida por una entidad autorizada que verificó al titular (`R-19`).

---

## Opciones consideradas

### Opción A — Añadir una pista estructurada de ampliación (`F19`–`F24`, más `F25` condicional) encadenada a `F4`–`F5` con tres hitos intermedios (`MP1`, `MP2`, `MP3`) (Recomendada)

Incorporar seis fases nuevas (`F19` a `F24`) y una fase condicional (`F25`) a la hoja de ruta, respetando íntegramente las dependencias existentes (`INV-13`):
- **`F19` — Especificación de la ampliación (spec-first, entrada `G0`):** Redacción y aprobación de `ADR-0021` a `ADR-0026`, registro de discrepancias (`#73`–`#77`), incorporación de requisitos (`REQ-PROX-*`, `REQ-CARD-*`, `REQ-CODE-*`, `REQ-IDDOC-*`), especificación de proximidad (`PROTOCOL.md §7` y errores `GID-E8xxx`), adenda al modelo de amenazas (`THREAT_MODEL.md`), perfil `pip-identity-v1.md`, spikes reproducibles con código y datos crudos (`spikes/nfc-hce/`, `spikes/javacard/` y repetición reproducible de QR/keystore) y adenda legal. Avanza en paralelo a `F4`–`F5` porque no modifica código de producción.
- **`F20` — Núcleo de proximidad (`gravital-id-proximity` en L4 sans-I/O, entrada `G19` + `F5.T08`–`T09`):** Mensajes CBOR acotados, sesión cifrada con HPKE y AAD ligada al transcrito de sesión, fragmentación por MTU, máquinas de estado sans-I/O e integración transparente con `VerifierPipeline::verify` sin añadir estados a `VerificationResult` (`INV-04`).
- **`F21` — NFC en teléfono Android y lectores multiplataforma → Hito `MP1 · Tap offline` (entrada `G20`):** Codec `GID-APDU` (`SELECT`, `ENVELOPE`, `GET RESPONSE`, `VERIFY`), AID, adelanto del subconjunto mínimo de frontera FFI y `KeyStore` Kotlin/Android (`F9.T03`/`F9.T04`) para `HostApduService` (HCE) con StrongBox/TEE y consentimiento en dos toques, lectores verificadores en Android (`IsoDep`), iPhone (`Core NFC`) y terminales de escritorio/kiosco (`gravital-id-transport-pcsc` en L5).
- **`F22` — Tarjeta física Gravital (Java Card) → Hito `MP2 · Tarjeta física` (entrada `G20` + `ADR-0024` + lectores de `F21`):** Applet en `cards/javacard/gid-applet/`, generación interna de clave P-256 no exportable, ciclo de vida (`PERSONALIZACIÓN` → `ACTIVA` → `BLOQUEADA` / `TERMINADA`), niveles de verificación con PIN, herramienta de personalización `apps/gid-perso` y ejecución en CI (jCardSim) de los mismos vectores de conformidad de proximidad que el núcleo Rust.
- **`F23` — Códigos numéricos (entrada `ADR-0025` + `F7.T06` relay + `F10.T05`–`T06` OID4VP):** Newtype `SessionCode` de 10 dígitos con dígito de control Damm, rendezvous de sesión efímera en el relay con límites de abuso y flujo de extremo a extremo (y opción B de número por emisor solo si `ADR-0025` la autoriza).
- **`F24` — Identidad portable y kit del integrador → Hito `MP3 · Identidad portable` (entrada `G21` + `F10.T08`):** Esquema `pip-identity-v1` (variantes oficial y derivada con `vct` distintos), validación y restricción de transporte del retrato, adaptadores KMS/HSM (`Azure Key Vault`, `AWS KMS`, `PKCS#11`), adelanto del SDK de servidor para TypeScript/Node, Go y .NET (`F9.T06`/`F9.T09`), API de aprovisionamiento y demostración integral.
- **`F25` — Formato mdoc e interoperabilidad ISO/IEC 18013-5 (condicional a `ADR-0022`):** Co-emisión y transporte mdoc CBOR/COSE si se requiere interoperabilidad con lectores gubernamentales estándar.

- **Ventajas:**
  - Mantiene intacto el principio **spec-first** (`AGENTS.md §12`) y el orden de fases (`INV-13`): `F4` y `F5` se completan sin interrupciones mientras `F19` cierra el diseño y los spikes de hardware.
  - Reutiliza el 100 % del núcleo criptográfico, credenciales SD-JWT VC, listas de estado, trust bundle y pipeline del verificador ya construidos.
  - Entrega valor tangible y demostrable de forma incremental mediante tres hitos claros (`MP1`, `MP2`, `MP3`).
  - Adelanta de forma controlada solo los subconjuntos de bindings necesarios para `MP1` (Kotlin/Swift de proximidad) y `MP3` (TS/Go/.NET de servidor), sin duplicar el trabajo de `F9`.
- **Inconvenientes:**
  - Incrementa el alcance total del monorepo (un crate L4 nuevo, un adaptador L5 PC/SC, adaptadores KMS, proyecto Java Card y herramienta de personalización).
- **Riesgos:** `R-15` a `R-23` (§Consecuencias), todos con mitigación explícita y validación temprana mediante los spikes `F19.T12`–`T14`.

---

### Opción B — Posponer NFC, tarjeta física, códigos numéricos y perfil de identidad hasta después de GA (`F18`)

Mantener la hoja de ruta v0.2 sin cambios y abordar todo el alcance solicitado como tareas evolutivas dentro de `F18` una vez cerrado `G17` (Producción).

- **Ventajas:** Cero cambios en la planificación actual hasta `M5`.
- **Inconvenientes:** Retrasa entre 14 y 20 meses las capacidades centrales solicitadas por el mantenedor (`OBJ-02`, `OBJ-04`, `OBJ-06`, `OBJ-07`), impidiendo demostrar el uso tipo tarjeta sin contacto (`MP1`/`MP2`) antes del piloto.
- **Riesgo:** El producto llegaría al piloto (`F16`) únicamente con transporte óptico QR y OID4VP en línea, sin cubrir los casos de uso presenciales de alto flujo ni portadores físicos para titulares sin smartphone.

---

### Opción C — No ampliar el alcance (rechazar tarjeta física, NFC y códigos numéricos)

Limitar permanentemente Gravital ID a wallets móviles/web con presentación por QR offline y OID4VP en línea.

- **Ventajas:** Menor superficie de código y sin dependencia de hardware de tarjetas inteligentes ni lectores PC/SC.
- **Inconvenientes:** Incumple directamente los objetivos de producto `OBJ-02`, `OBJ-04`, `OBJ-06` y `OBJ-07` definidos por el mantenedor. Excluye a usuarios sin teléfono inteligente (que requieren tarjeta física) y a canales de atención telefónica o remota sin cámara (que requieren código de sesión).

---

### Opción D — Interrumpir `F4` y `F5` para implementar NFC y tarjeta física inmediatamente

Detener el cierre del verificador (`F4`) y de la wallet/almacenamiento (`F5`) para escribir de inmediato el crate de proximidad y el applet Java Card.

- **Ventajas:** Ninguna real.
- **Inconvenientes:** Viola frontalmente **`INV-13`** ("Ninguna fase de `ROADMAP.md` se salta") y **`P-12`** (spec-first). Además, el transporte de proximidad (`F20`) necesita la preparación/confirmación de presentaciones (`F5.T08`) y la transcodificación binaria compacta (`F5.T09`), por lo que construirlo antes produciría retrabajo y deuda arquitectónica.

---

## Decisión

Se propone adoptar la **Opción A**:

1. **Aprobar la pista de ampliación `F19`–`F24` (y `F25` condicional)** con sus respectivos gates `G19`–`G25` y los tres hitos intermedios:
   - **`MP1 · Tap offline`** (al cerrar `G21`): presentación NFC desde teléfono Android (HCE + StrongBox/TEE) verificada sin red en lectores Android, iPhone y PC/SC.
   - **`MP2 · Tarjeta física`** (al cerrar `G22`): tarjeta inteligente Java Card personalizada con `gid-perso` y verificada offline en los mismos lectores con idénticos vectores de conformidad.
   - **`MP3 · Identidad portable`** (al cerrar `G24`): perfil `pip-identity-v1` (variantes oficial y derivada, retrato por NFC), SDK de servidor (TS/Node, Go, .NET) con KMS/HSM y flujo completo en teléfono, tarjeta, QR y código numérico de sesión.
2. **Preservar el orden y las dependencias de las fases existentes (`INV-13`):**
   - La prioridad inmediata de código sigue siendo cerrar `F4` (`F4.T09`–`F4.T12` → `G4`) y completar `F5` (`F5.T01`–`F5.T14` → `G5` / `M1`).
   - `F19` se ejecuta en paralelo a `F4`–`F5` por ser exclusivamente de especificación, ADRs y spikes.
   - Ningún código de producción de `F20`–`F25` se escribe antes de que este `ADR-0021` esté **Aceptado** y de que se cierren las dependencias de entrada de cada fase.
3. **Reordenar selectivamente subconjuntos de `F9` y `F18`:**
   - Adelantar a `F21` el subconjunto de `F9.T03`/`F9.T04` correspondiente a la frontera FFI mínima UniFFI Kotlin y `KeyStore` Android (StrongBox/TEE) requerido por el servicio HCE.
   - Adelantar a `F24` el subconjunto de `F9.T06`/`F9.T09` correspondiente a la superficie de emisor y verificador en TypeScript/Node (WASM), Go y .NET (C ABI), fijando el orden de prioridad de bindings en: **TypeScript/Node → Go y .NET → Kotlin → Dart/Flutter → Swift → Python**.
   - Mover el transporte NFC sobre credenciales SD-JWT VC desde `F18.T04` a `F21`, dejando en `F25` (condicional) o `F18.T04` la interoperabilidad con el formato mdoc ISO/IEC 18013-5.
4. **Subordinar el diseño detallado de cada subsistema a cinco ADRs específicos en `F19`:**
   - `ADR-0022`: Transporte de proximidad y protocolo `GID-APDU` (`F19.T03`).
   - `ADR-0023`: Cifrado de sesión HPKE y vinculación al transcrito (`F19.T04`).
   - `ADR-0024`: Arquitectura de tarjeta física Java Card y personalización (`F19.T05`).
   - `ADR-0025`: Modelo de identificadores numéricos de 9–10 dígitos (`F19.T06`).
   - `ADR-0026`: Perfil de identidad portable `pip-identity-v1` y tratamiento del retrato (`F19.T07`).

---

## Consecuencias

### Positivas
- **Coherencia con el núcleo existente:** Todos los factores de forma (QR, NFC HCE, tarjeta Java Card y código numérico de sesión) desembocan en el mismo `VerifierPipeline::verify` y producen el mismo `VerificationResult` de cuatro estados (`INV-04`), sin duplicar reglas de validación ni relajar invariantes.
- **Trazabilidad y control de riesgos:** Los riesgos de hardware y plataforma (`R-15` a `R-23`) se aíslan y se validan empíricamente mediante spikes con código y datos crudos (`F19.T12`–`T14`) antes de adquirir hardware en volumen o escribir código de producción.
- **Alineación con estándares:** La sesión cifrada con claves efímeras y transcrito (`F20`) y el encadenamiento `SELECT` / `ENVELOPE` / `GET RESPONSE` (`F21`) se diseñan alineados conceptualmente con ISO/IEC 18013-5 e ISO/IEC 7816-4, facilitando una eventual adopción de mdoc en `F25`.

### Negativas y cómo se mitigan
- **Crecimiento de la superficie a auditar en `F13` y validar en `F14`:** Se suman el crate `gravital-id-proximity`, el applet Java Card y el tratamiento legal del retrato facial y de las tarjetas físicas. *Mitigación:* Los vectores de conformidad de proximidad se ejecutan automáticamente contra el applet en CI (`jCardSim`, `REQ-CARD-004`), y `F19.T10` / `F19.T15` preparan desde el inicio las adendas de amenazas y de cumplimiento legal (Ley 81 de 2019).
- **Limitación de HCE en iOS en Panamá (`R-15`):** Los titulares con iPhone no pueden emular tarjeta NFC hoy. *Mitigación:* El iPhone actúa como lector verificador (`Core NFC`) y como wallet titular mediante QR (y BLE si `ADR-0022` activa `F21.T08`); se documenta de forma transparente desde la especificación.

### Cambios necesarios en documentación (al pasar este ADR a estado Aceptado)
- **`docs/ROADMAP.md`:**
  - `§1 Visión general`: añadir filas `F19` a `F25` con sus duraciones orientativas e hitos `MP1`, `MP2`, `MP3`; actualizar `F18.T04` en `§25`.
  - `§2 Dependencias entre fases`: incorporar el grafo de dependencias de `F19`–`F25` con `F5`, `F7`, `F9`, `F10` y `F12`–`F15`.
  - `§3 Hitos`: añadir `MP1 · Tap offline`, `MP2 · Tarjeta física` y `MP3 · Identidad portable`.
  - Nuevas secciones detalladas para las fases `F19`, `F20`, `F21`, `F22`, `F23`, `F24` y `F25`.
  - `§26 Registro de riesgos`: incorporar los riesgos `R-15` a `R-23`.
- **`docs/ARCHITECTURE.md`:**
  - `§1.1` y `§2`: reflejar los portadores de proximidad (NFC HCE, tarjeta física Java Card) y los límites de viabilidad (iPhone HCE en Panamá, código numérico en línea vs offline, retrato por NFC/BLE, credencial oficial vs derivada).
  - `§6 Vista de capas`: incluir `gravital-id-proximity` en L4 y `gravital-id-transport-pcsc` / adaptadores KMS en L5.
  - `§8.4` y `§9.4`: actualizar la hoja de ruta de proximidad NFC/BLE y el cifrado de sesión.
  - `§16 Perfiles` y `§17.3 Estrategia de bindings`: referenciar el perfil candidato `pip-identity-v1` y la prioridad de bindings acordada.
  - `§22 Decisiones abiertas`: registrar `ADR-0021` a `ADR-0026`.
- **`docs/PROJECT_STRUCTURE.md`:**
  - Registrar `crates/gravital-id-proximity` (L4), `crates/gravital-id-transport-pcsc` (L5), `cards/javacard/gid-applet/`, `apps/gid-perso/`, `conformance/vectors/proximity/` y `.github/workflows/cards.yml`.

### Cambios en código, CI o `layers.toml`
- En `F19`: ningún cambio en `crates/` ni en `xtask/layers.toml` (salvo cuando se acepten `ADR-0021` y `ADR-0022`).
- En `CODEOWNERS` (al aceptar `ADR-0021`): añadir `crates/gravital-id-proximity/` y `cards/` como rutas sensibles bajo revisión obligatoria del mantenedor.
- En `F20.T01` (tras `G19` y `ADR-0022`): añadir `gravital-id-proximity` (L4) y `gravital-id-transport-pcsc` (L5) en `xtask/layers.toml`, manteniendo el aislamiento estricto de `gravital-id-verifier` (que nunca depende de `gravital-id-proximity`).

### Tareas nuevas en `ROADMAP.md`
- `F19.T01` a `F19.T16` (Gate `G19`).
- `F20.T01` a `F20.T10` (Gate `G20`).
- `F21.T01` a `F21.T10` (Gate `G21` / Hito `MP1`).
- `F22.T01` a `F22.T10` (Gate `G22` / Hito `MP2`).
- `F23.T01` a `F23.T07` (Gate `G23`).
- `F24.T01` a `F24.T10` (Gate `G24` / Hito `MP3`).
- `F25` condicional según decisión de `ADR-0022` (Gate `G25`).

---

## Criterios para revisar esta decisión

1. **Resultados de los spikes de hardware (`F19.T12` y `F19.T13`):** Si las pruebas en dispositivos físicos muestran que la latencia APDU o la ausencia de soporte AEAD en los chips Java Card candidatos impiden cumplir el presupuesto de tiempo o el cifrado HPKE en tarjeta (`R-16`), se revisará el alcance de `F22` en `ADR-0024` antes de iniciar su implementación.
2. **Apertura de NFC HCE por Apple en Latinoamérica (`R-15`):** Si Apple habilita la API de emulación HCE o NFC & SE para terceros en Panamá y la región, se añadirá una tarea en `F21` o `F18` para soportar titular NFC en iOS.
3. **Acuerdo institucional con autoridad de registro civil (`R-19`):** Si se formaliza un convenio con el Tribunal Electoral u otra autoridad competente que exija ISO/IEC 18013-5 (mdoc), se activará la fase condicional `F25`.
