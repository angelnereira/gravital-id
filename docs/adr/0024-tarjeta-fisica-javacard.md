# ADR-0024: Arquitectura de tarjeta física Java Card y personalización

- **Estado:** Aceptado
- **Fecha:** 2026-10-15
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira (validado con mediciones en `spikes/javacard/REPORT.md`, `F19.T13`)
- **Issue:** #79
- **Requisitos y principios afectados:** REQ-CARD-001, REQ-CARD-002, REQ-CARD-003, REQ-CARD-004, REQ-CARD-005, REQ-PROX-001, REQ-PROX-002, REQ-KEY-008, REQ-MAINT-004; P-01, P-02, P-05, P-07, P-09, P-11; INV-01, INV-03, INV-05, INV-07, INV-16
- **Fase:** F19 (F19.T05)

---

## Contexto

Uno de los diferenciadores centrales de la ampliación aprobada en **ADR-0021** es permitir que una persona porte su identidad y credenciales verificables en una **tarjeta física sin contacto** ("Tarjeta Gravital", formato ID-1 ISO/IEC 7810 con interfaz sin contacto ISO/IEC 14443-4), capaz de ser verificada 100 % offline igual que una tarjeta EMV (Visa/Mastercard) y sin depender de que el titular tenga un teléfono inteligente o batería.

Diseñar esta tarjeta plantea restricciones severas de hardware y seguridad:
1. **Invariante INV-03 y REQ-CARD-001:** La clave privada de vinculación del titular (`cnf`) debe generarse dentro del elemento seguro de la tarjeta y **nunca** ser exportable ni conocida por el emisor durante la personalización.
2. **Invariante INV-07 y riesgo R-16 (Soporte AEAD en Java Card):** Mientras que las tarjetas Java Card 3.0.4+ modernas soportan ampliamente `ALG_EC_SVDP_DH_PLAIN` (ECDH P-256), `ALG_EC_FP` (`ES256`) y `ALG_SHA_256`, la mayoría de los chips bancarios comerciales **no** incluyen `ChaCha20-Poly1305` en su coprocesador criptográfico, y el soporte de `AES-GCM` (`Cipher.ALG_AES_GCM`) es opcional según el fabricante. **INV-07 prohíbe implementar primitivas criptográficas propias en software dentro del applet.**
3. **Ausencia de reloj interno y de pantalla/teclado en la tarjeta:** La tarjeta no tiene reloj de tiempo real ni interfaz de usuario propia para mostrar quién solicita los datos o para introducir un PIN.
4. **Riesgo de correlación por clave fija (R-18) y pérdida física (`REQ-CARD-005`).**
5. **Riesgo de divergencia de implementación (R-20):** El applet se escribe en el subconjunto de Java para Java Card, por lo que no puede compilar directamente el crate Rust `gravital-id-proximity`.

---

## Opciones consideradas

### Opción A — Tarjeta NFC de memoria estática (NTAG / MIFARE Ultralight / DESFire pasiva sin firma dinámica)

Grabar un SD-JWT estático firmado por el emisor en una etiqueta NFC de solo lectura o protegida por contraseña.

- **Ventajas:** Bajo costo unitario (`< 0.50 USD`) y sin necesidad de desarrollar un applet.
- **Inconvenientes:**
  - **Clonación trivial:** Cualquier lector que lea la etiqueta una vez puede copiar los bytes exactos y emular la tarjeta indefinidamente, ya que no existe un Key Binding JWT (KB-JWT) firmado dinámicamente sobre el `nonce` del verificador.
  - Equivalente a la banda magnética bancaria; viola `REQ-PRES-002` y `REQ-CARD-001`.
- **Riesgos:** Suplantación total tras un solo contacto (rechazada en `ADR-0021`).

---

### Opción B — Implementar `ChaCha20-Poly1305` en bytecode Java dentro del applet Java Card

Para mantener exactamente la misma suite HPKE que en teléfonos móviles en cualquier chip Java Card básico, programar el cifrado de flujo ChaCha20 y el MAC Poly1305 en arreglos de enteros dentro del applet Java Card.

- **Ventajas:** Misma suite binaria en todos los chips.
- **Inconvenientes:**
  - **Viola frontalmente INV-07 ("Ninguna primitiva criptográfica propia").**
  - Una implementación en bytecode Java Card carece de resistencia en hardware contra ataques de canal lateral (*Differential Power Analysis*, DPA, y fallos por inyección electromagnética) y agotaría el presupuesto de tiempo de un toque NFC (`> 1.5 s`).
- **Riesgos:** Vulnerabilidad crítica de canal lateral e incumplimiento de invariantes.

---

### Opción C — Applet Java Card 3.0.5+ con claves P-256 en hardware, ciclo de vida estricto, CVM de dos niveles, conformidad por vectores en CI y selección de cifrado guiada por `F19.T13` (Recomendada)

Construir un applet para **Java Card 3.0.5 Classic Edition (o 3.1+)** en `cards/javacard/gid-applet/` que implemente el extremo titular de `GID-APDU` (ADR-0022) bajo las siguientes reglas arquitectónicas:

1. **Generación de claves en hardware y aprovisionamiento (`gid-perso`):**
   - Ciclo de vida de cuatro estados persistidos en EEPROM/Flash segura: `PERSONALIZACION` (`0x01`) $\to$ `ACTIVA` (`0x02`) $\to$ `BLOQUEADA` (`0x03`) $\to$ `TERMINADA` (`0x04`).
   - En estado `PERSONALIZACION`, la estación `gid-perso` se autentica mediante canal seguro (GlobalPlatform SCP02/SCP03 o clave de personalización del emisor).
   - El comando `GENERATE KEY` ordena al coprocesador de la tarjeta generar el par EC P-256 (`KeyPair.ALG_EC_FP`, 256 bits) y devuelve únicamente el punto público SEC1 (`65 bytes`) más la atestación del fabricante si el chip la provee (`REQ-CARD-001`). Ningún comando APDU existe para leer o exportar escalares privados.
   - `gid-perso` solicita al `issuer-service` la emisión del SD-JWT VC ligado a esa clave pública (`cnf`), inyecta en la tarjeta los componentes pre-separados (cabecera/payload JWS del emisor, divulgaciones individuales con su digest SHA-256 precalculado y metadatos de nivel de acceso), configura el PIN inicial y ejecuta `FINALIZE PERSONALIZATION`, transicionando de forma irreversible a `ACTIVA` (`REQ-CARD-002`).
2. **Construcción eficiente del KB-JWT sin reloj propio:**
   - En estado `ACTIVA`, al recibir `ENVELOPE(ProximityRequest)`, el applet toma `verifier_time` de `ProximityRequest` como valor del claim `iat` del KB-JWT, calcula `transcript_hash` con el motor `MessageDigest.ALG_SHA_256` del chip, ensambla en memoria transitoria (`JCSystem.CLEAR_ON_DESELECT`) el encabezado y payload del KB-JWT con `nonce = Base64UrlNoPad(transcript_hash)`, `aud = ProximityRequest.aud` y `sd_hash` de las divulgaciones seleccionadas, y firma con `Signature.ALG_ECDSA_SHA_256` normalizando `s` a *low-S* (o delegando la normalización del escalar público `s` al lector antes de invocar al verificador, dado que `s` y $n - s$ son públicamente equivalentes y no requieren la clave privada).
3. **Cifrado de sesión en la tarjeta (resolución de R-16 condicionada al spike `F19.T13`):**
   - **Nunca se implementa criptografía en software en el applet (INV-07).**
   - El spike `F19.T13` evaluará en `jCardSim` y en al menos 2 modelos de tarjetas físicas reales (p. ej. NXP JCOP 4 / Infineon Secora ID / Thales IDCore) la disponibilidad y latencia de las primitivas de hardware del chip:
     - **Sub-opción C1 (Preferida si el chip soporta `Cipher.ALG_AES_GCM`):** Utilizar la suite estándar de RFC 9180 **`DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM` (`AEAD ID 0x0001`) o `AES-256-GCM` (`AEAD ID 0x0002`)** ejecutada íntegramente en el coprocesador criptográfico del chip (`KeyAgreement.ALG_EC_SVDP_DH_PLAIN` + `MessageDigest.ALG_SHA_256` para HKDF + `Cipher.ALG_AES_GCM`).
     - **Sub-opción C2 (Si los chips disponibles soportan `AES-CBC` + `HMAC-SHA256` en hardware pero no `AES-GCM`):** Sólo se adoptará si se documenta formalmente tras `F19.T13` como perfil de tarjeta específico con revisión criptográfica (Encrypt-then-MAC con claves separadas derivadas por HKDF sobre `transcript_hash`).
   - La selección definitiva entre C1 y C2 se fijará al cerrar `F19.T13` antes de pasar el Gate `G19`.
4. **Verificación del titular por niveles (CVM de tarjeta, `REQ-CARD-003`):**
   - Cada divulgación almacenada en la tarjeta lleva una etiqueta de nivel de autorización asignada durante la personalización:
     - **Nivel 0 (sin PIN):** Predicados booleanos (`age_over_18`, `age_over_21`) y atributos básicos no sensibles definidos por el perfil. Se liberan en un solo toque.
     - **Nivel 1 (requiere `VERIFY PIN`):** Atributos sensibles (`document_number`, `birth_date`, `portrait`, datos financieros/médicos). Si `ProximityRequest` solicita un claim de Nivel 1 sin que el PIN haya sido verificado en la sesión actual, el applet devuelve `6982` (`Security status not satisfied` $\to$ `GID-E8005`).
   - El `OwnerPIN` de Java Card fija un límite máximo de **3 a 5 intentos fallidos**; al agotarse, la tarjeta pasa a `BLOQUEADA` (`6983` $\to$ `GID-E8006`) para operaciones de Nivel 1 y solo puede desbloquearse mediante un criptograma autenticado por el emisor (`RESET RETRY COUNTER`).
   - Para proteger el PIN frente a escuchas de radio cuando el lector es sin contacto, el comando `VERIFY` para sesiones sin contacto debe enviarse dentro de un canal ligado a la clave efímera de la sesión (o mediante lectura por contacto ISO 7816-3 si el terminal lo exige).
5. **Mitigación de correlación (R-18, `REQ-KEY-008`):**
   - Si la memoria no volátil del chip elegido ($\ge 64\text{ KB}$ EEPROM/Flash) lo permite, `gid-perso` aprovisionará un lote de $N$ ranuras de credencial ($N \in [4, 16]$) con pares de claves P-256 independientes que rotan por sesión. Si la capacidad del chip limita el almacenamiento a una única ranura (p. ej. cuando incluye retrato JPEG), el perfil documenta explícitamente que la tarjeta física tiene el mismo nivel de correlacionabilidad ante verificadores que una tarjeta EMV tradicional.
6. **Conformidad estricta en CI (`REQ-CARD-004`, R-20):**
   - El workflow `.github/workflows/cards.yml` ejecutará en `jCardSim` la suite de vectores de `conformance/vectors/proximity/` contra el applet compilado y verificará que las presentaciones producidas por el applet pasen `VerifierPipeline::verify` en Rust con resultados idénticos al titular móvil.

---

## Decisión

Se adopta la **Opción C**:
1. Desarrollar el applet en **Java Card 3.0.5+ Classic** (`cards/javacard/gid-applet/`) y la herramienta de personalización **`apps/gid-perso`** (sobre `gravital-id-transport-pcsc` y el SDK de emisor).
2. Exigir generación de claves P-256 en hardware dentro de la tarjeta sin posibilidad de exportación (`REQ-CARD-001`), escritura exclusiva en estado `PERSONALIZACION` autenticado por el emisor (`REQ-CARD-002`), PIN con contador de reintentos para claims de Nivel 1 (`REQ-CARD-003`) y revocación remota mediante `Token Status List` en caso de pérdida o robo (`REQ-CARD-005`).
3. Condicionar el AEAD concreto de sesión en la tarjeta (preferentemente `HPKE AES-GCM` en hardware del chip, Sub-opción C1) a las mediciones en hardware real del spike **`F19.T13`**, prohibiendo cualquier implementación de primitivas criptográficas en software dentro del applet (**INV-07**).
4. Exigir que el applet supere en CI (`jCardSim`) los mismos vectores de conformidad de proximidad que el núcleo Rust (`REQ-CARD-004`).

---

## Consecuencias

- **Positivas:**
  - Permite emitir tarjetas físicas de identidad o membresía verificables offline en `< 500 ms` desde teléfonos Android, iPhone y lectores PC/SC sin requerir teléfono ni batería por parte del titular.
  - Garantiza que ni siquiera el emisor o el operador de la estación `gid-perso` conozca jamás la clave privada de la tarjeta.
  - Evita divergencias entre Java Card y Rust gracias a la ejecución cruzada de vectores inmutables en CI.
- **Negativas y cómo se mitigan:**
  - Introduce un segundo lenguaje (Java Card subset) fuera del workspace Cargo en `cards/javacard/gid-applet/`. *Mitigación:* Ruta protegida en `CODEOWNERS`, alcance restringido exclusivamente al lado titular de `GID-APDU`, y validación obligatoria en `.github/workflows/cards.yml`.
  - Requiere adquirir tarjetas Java Card con soporte criptográfico adecuado. *Mitigación:* El spike `F19.T13` valida los chips candidatos antes de iniciar `F22`.
- **Cambios necesarios en documentación (`ARCHITECTURE.md`, `REQUIREMENTS.md`, specs):**
  - Especificación de los comandos de personalización y estados de error `GID-E8005` / `GID-E8006` en `docs/specs/PROTOCOL.md §7` y `docs/specs/ERROR_CODES.md` (`F19.T09`).
- **Cambios en código, CI o `layers.toml`:**
  - Creación de `cards/javacard/gid-applet/`, `apps/gid-perso/` y `.github/workflows/cards.yml` en `F22`.
- **Tareas nuevas en `ROADMAP.md`:**
  - `F19.T13` y `F22.T01`–`F22.T10`.

---

## Criterios para revisar esta decisión

1. Al concluir el spike `F19.T13`, se actualizará este ADR con la tabla de modelos de chips validados, sus tiempos medidos y la confirmación de la suite AEAD de hardware seleccionada (Sub-opción C1 vs C2).
2. Si un fabricante ofrece tarjetas con soporte nativo de `ChaCha20-Poly1305` en hardware, se habilitará sin cambios en el protocolo.
