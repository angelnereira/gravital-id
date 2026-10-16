# ADR-0023: Cifrado de sesión de proximidad y vinculación al transcrito

- **Estado:** Aceptado
- **Fecha:** 2026-10-15
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #79
- **Requisitos y principios afectados:** REQ-PROX-001, REQ-PROX-002, REQ-PROX-003, REQ-PRES-004, REQ-PRES-007, REQ-SEC-002; P-02, P-05, P-07, P-08; INV-01, INV-05, INV-07, INV-08, INV-11
- **Fase:** F19 (F19.T04)

---

## Contexto

En el flujo óptico QR original (`ADR-0011`, `PROTOCOL.md §3`), la presentación transcodificada viaja sin cifrado de capa de transporte porque el canal óptico de corta distancia es direccional y visual. Sin embargo, al introducir canales de radiofrecuencia (**NFC** y **BLE**) en **ADR-0021 / ADR-0022** y la presentación desde **tarjetas físicas** (ADR-0024), aparecen tres vectores de ataque críticos:

1. **Escucha pasiva en el canal de radio (*eavesdropping*):** Una antena oculta cercana al punto de contacto NFC o un receptor BLE pasivo puede capturar los paquetes enviados por el titular y extraer los claims divulgados (PII, retrato, predicados).
2. **Ataques de retransmisión y sesión cruzada (*relay / cross-session replay*):** Un intermediario malicioso puede reenviar la solicitud de un verificador legítimo lejano hacia el dispositivo/tarjeta de la víctima, o intentar reutilizar una respuesta capturada en otra sesión o ante otro verificador.
3. **Fotografía oportunista de códigos QR de respuesta:** Incluso en el flujo óptico QR en dos pasos, si la solicitud del verificador incluye una clave pública efímera, cifrar la respuesta impide que una cámara de vigilancia o un tercero cercano que fotografíe la pantalla del titular obtenga los atributos divulgados.

Cualquier mecanismo de cifrado de sesión debe cumplir **INV-07** (no inventar primitivas criptográficas; usar exclusivamente las fijadas en **ADR-0007** y `gravital-id-crypto`), **INV-08** (perfiles de `CRYPTO_PROFILES.md`) e **INV-11** (aleatoriedad inyectada).

---

## Opciones consideradas

### Opción A — Enviar la presentación SD-JWT+KB en claro sobre NFC/BLE (confiando solo en el alcance físico)

Confiar en que la corta distancia teórica de NFC (~4 cm) protege la confidencialidad y depender únicamente del `nonce` del KB-JWT contra repetición.

- **Ventajas:** Cero sobrecarga criptográfica adicional en el titular y la tarjeta.
- **Inconvenientes:**
  - El tráfico NFC sin cifrar puede capturarse a decenas de centímetros con antenas sintonizadas, y en BLE a varios metros, exponiendo datos personales del titular en claro.
  - Incumple `REQ-PROX-001` y el principio de privacidad por diseño (`P-09`).
- **Riesgos:** Fuga directa de PII por radiofrecuencia (inaceptable).

---

### Opción B — Handshake TLS 1.3 o DTLS sobre APDU

Ejecutar un apretón de manos TLS 1.3 completo encapsulado en comandos APDU entre el lector y el titular.

- **Ventajas:** Protocolo ampliamente conocido en Internet.
- **Inconvenientes:**
  - Requiere múltiples viajes de ida y vuelta (*round-trips*) APDU antes de enviar la consulta, añadiendo cientos de milisegundos a un toque físico que debe completarse en `< 500 ms`.
  - Inviable en tarjetas Java Card por memoria RAM y complejidad de máquina de estados TLS.
  - Introduce dependencias pesadas incompatibles con la simplicidad de `gravital-id-crypto` en capa L1 `no_std`.

---

### Opción C — Respuesta sellada en un paso con HPKE Modo Base (RFC 9180) + AAD ligada al transcrito canónico + KB-JWT vinculado al transcrito (Recomendada)

Reutilizar la implementación **HPKE Modo Base (RFC 9180)** ya disponible y probada en `gravital-id-crypto::hpke` (`DHKEM(P-256, HKDF-SHA256)` `0x0010`, `HKDF-SHA256` `0x0001`, `ChaCha20Poly1305` `0x0003`) junto con un **transcrito de sesión canónico** (`SessionTranscript`):

1. **Par efímero del verificador:**
   - Para cada sesión, el verificador genera un par de claves efímero P-256 de un solo uso con propósito exclusivo de acuerdo de claves (`KeyPurpose::KeyAgreement`, nunca `Signing`).
   - La clave pública efímera en formato SEC1 sin comprimir (`65 bytes`, `0x04 || X || Y`) se incluye en el campo `eph_pub` de `ProximityRequest`.
2. **Construcción canónica del transcrito de sesión (`SessionTranscript`):**
   - El transcrito se define como una estructura CBOR determinista (RFC 8949 §4.2, codificada mediante `gravital-id-codec::cbor`):
     ```text
     SessionTranscript = [
       version: 1,
       transport_type: uint,       ; 1 = NFC (GID-APDU), 2 = BLE, 3 = QR, 4 = SessionCode
       holder_engagement: bstr,    ; bytes exactos de HolderHello (o bstr vacío en QR/SessionCode)
       request_bytes: bstr         ; bytes CBOR canónicos de ProximityRequest
     ]
     transcript_hash = SHA-256(cbor_det(SessionTranscript)) ; 32 bytes
     ```
3. **Vinculación criptográfica doble (HPKE + KB-JWT):**
   - **En el KB-JWT (autenticación del titular):** El titular verifica la vigencia y firma (si aplica) de `ProximityRequest`, y construye el Key Binding JWT firmando con su clave privada de titular (`cnf`). Para ligar de forma irrefutable la firma del titular a toda la negociación de sesión (y no solo a un string aislado), el claim `nonce` del KB-JWT en sesiones de proximidad se verifica contra `Base64UrlNoPad(transcript_hash)` (que compromete transitivamente el `nonce` de 16+ bytes del verificador, `aud`, `verifier_id`, `eph_pub`, `query` y `HolderHello`), y el claim `aud` del KB-JWT debe coincidir exactamente con `ProximityRequest.aud`.
   - **En el sobre HPKE (confidencialidad e integridad de sesión):** El titular transcodifica la presentación SD-JWT+KB resultante (`PROTOCOL.md §3.2`) y la sella mediante `hpke_seal_base_p256_hkdf_sha256_chacha20poly1305` usando:
     - `recipient_public`: `ProximityRequest.eph_pub` (`65 bytes`),
     - `info`: `b"gravital-proximity-v1"`,
     - `aad`: `transcript_hash` (`32 bytes`),
     - `plaintext`: bytes de la presentación transcodificada (`CBOR + DEFLATE`).
   - El mensaje `ProximityResponse` transporta `{ v: 1, enc: bstr(65), ct: bstr }` donde `enc` es la clave encapsulada efímera del titular y `ct` es el texto cifrado más la etiqueta Poly1305 de 16 bytes.
4. **Adopción unificada en QR y Código de Sesión:**
   - Si una solicitud por QR o por código numérico (`SessionCode`, ADR-0025) incluye `eph_pub`, la wallet aplica exactamente el mismo sellado HPKE con `transport_type = 3` (QR) o `transport_type = 4` (`SessionCode`). En QR, esto protege la pantalla del titular frente a cámaras de terceros sin añadir ningún paso interactivo adicional.

---

## Decisión

Se adopta la **Opción C**:
1. Toda respuesta de proximidad (`ProximityResponse` en NFC y BLE, así como en Código de Sesión y en solicitudes QR que incluyan clave efímera) **DEBE** sellarse con **HPKE Modo Base (RFC 9180)** usando la suite de `gravital-id-crypto`:
   - `KEM`: `DHKEM(P-256, HKDF-SHA256)` (`0x0010`),
   - `KDF`: `HKDF-SHA256` (`0x0001`),
   - `AEAD`: `ChaCha20Poly1305` (`0x0003`),
   - etiqueta de dominio `info = b"gravital-proximity-v1"`.
2. Se fija el resumen del transcrito canónico `transcript_hash = SHA-256(cbor_det(SessionTranscript))` como datos asociados autenticados (`aad`) del sobre HPKE y como valor del claim `nonce` (`Base64UrlNoPad(transcript_hash)`) dentro del KB-JWT firmado por el titular (REQ-PROX-001, REQ-PROX-002).
3. Cualquier fallo al desencapsular HPKE, verificar la etiqueta AEAD, recomputar `transcript_hash` o comprobar el `nonce`/`aud` del KB-JWT **DEBE** producir un rechazo inmediato fail-closed (`GID-E8007` en la capa de proximidad o `VerificationResult::Invalid` en el verificador; nunca `Valid`, INV-05).
4. En el caso específico de tarjetas físicas Java Card cuyas limitaciones de hardware impidan ejecutar `ChaCha20Poly1305` dentro del chip, el modo de cifrado aplicable queda regulado por **ADR-0024** sujeto a los resultados empíricos del spike `F19.T13` (R-16), sin relajar nunca la vinculación del KB-JWT a `transcript_hash`.

---

## Consecuencias

- **Positivas:**
  - **Cero primitivas nuevas (INV-07):** Reutiliza al 100 % `gravital-id-crypto::hpke` y `gravital-id-codec::cbor` ya auditados y probados en L1.
  - **Un solo paso de ida y vuelta:** El verificador envía `eph_pub` en `ProximityRequest` y recibe `ProximityResponse` sellada, cumpliendo el presupuesto de latencia de un único toque NFC (`< 500 ms`).
  - **Resistencia a sesión cruzada y *man-in-the-middle*:** Si un atacante altera un solo bit de `HolderHello` o de `ProximityRequest` (p. ej. sustituyendo `eph_pub` por la suya), el `transcript_hash` cambia; si reempaqueta el HPKE hacia el verificador real, el KB-JWT interno (firmado por el hardware del titular sobre el `transcript_hash` alterado) fallará la verificación de firma o de `nonce` en `VerifierPipeline::verify`, devolviendo `Invalid`.
- **Negativas y cómo se mitigan:**
  - Añade 81 bytes de sobrecarga fija al mensaje de respuesta (`65 bytes` de `enc` SEC1 + `16 bytes` de tag Poly1305). *Mitigación:* En NFC y BLE 81 bytes representan menos de 5 ms de transmisión; en QR (si se activa `eph_pub`) caben holgadamente dentro del presupuesto de 1.200 caracteres Base45 para presentaciones estándar.
- **Cambios necesarios en documentación (`ARCHITECTURE.md`, `REQUIREMENTS.md`, specs):**
  - Documentar la estructura exacta de `SessionTranscript`, `ProximityRequest` y `ProximityResponse` en `docs/specs/PROTOCOL.md §7` (`F19.T09`) y referenciar explícitamente la suite RFC 9180 en `docs/specs/CRYPTO_PROFILES.md`.
- **Cambios en código, CI o `layers.toml`:**
  - Implementación en `gravital-id-proximity` (`F20.T02`–`F20.T04`) y publicación de vectores inmutables en `conformance/vectors/proximity/` (`F20.T08`).
- **Tareas nuevas en `ROADMAP.md`:**
  - `F19.T09`, `F20.T02`, `F20.T03`, `F20.T04`, `F20.T08`.

---

## Criterios para revisar esta decisión

1. Si en el futuro el IETF o ISO publica un perfil unificado de HPKE para credenciales verificables con una etiqueta `info` estándar distinta y se requiere interoperabilidad directa a nivel de sobre, se añadirá como versión `v: 2` de `ProximityResponse`.
2. Cuando se aborde la transición post-cuántica en `F18`, se definirá un nuevo perfil criptográfico con KEM híbrido (p. ej. `X25519Kyber768Draft00` / `ML-KEM-768` + P-256) manteniendo la misma estructura de `SessionTranscript`.
