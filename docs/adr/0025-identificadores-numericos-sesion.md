# ADR-0025: Modelo de identificadores numéricos de 9–10 dígitos

- **Estado:** Aceptado
- **Fecha:** 2026-10-15
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #79 (resuelve también #77)
- **Requisitos y principios afectados:** REQ-CODE-001, REQ-CODE-002, REQ-CODE-003, REQ-CODE-004, REQ-PRES-003, REQ-PRES-007, REQ-LEDG-001; P-02, P-05, P-08, P-09; INV-01, INV-02, INV-05
- **Fase:** F19 (F19.T06)

---

## Contexto

El objetivo de producto **OBJ-04** (`ADR-0021`) solicita permitir la validación de un titular mediante un **identificador numérico de 9–10 dígitos**, pensado para canales donde no es posible usar NFC ni escanear un código QR (p. ej. atención telefónica en un *call center*, ventanillas sin lector óptico/NFC, o formularios web de escritorio cuando la wallet está en otro dispositivo).

Como se registró en el issue `type:spec-gap` **#77**, este requisito presenta dos restricciones fundamentales que el diseño debe resolver sin ambigüedad:
1. **Imposibilidad matemática de verificación offline segura solo con 10 dígitos:** Un número de 10 dígitos con 1 dígito de control tiene $10^9 \approx 2^{29.9}$ combinaciones (~30 bits de entropía) y carece de firma criptográfica dinámica sobre un desafío del verificador. Aceptar un número dictado como prueba de identidad sin conexión equivaldría a aceptar el número impreso de una tarjeta de crédito sin chip ni autorización en línea: cualquiera que haya visto u oído el número una vez podría suplantar al titular indefinidamente.
2. **Tensión con el principio de no correlación (`P-09`) y `ARCHITECTURE.md §7.1`:** La arquitectura de Gravital ID establece que *"no existe un identificador global del titular en el protocolo"*. Asignar un número persistente global del protocolo a cada ser humano convertiría a Gravital ID en un vector de correlación universal.

Es necesario distinguir claramente tres conceptos distintos (el número de documento civil como claim, el código efímero de sesión y el número opcional por emisor) y fijar la arquitectura normativa para `F23`.

---

## Opciones consideradas

### Opción A — Identificador numérico global y persistente por titular validado offline

Asignar a cada titular un número fijo de 10 dígitos y permitir que los verificadores lo consulten en una lista local descargada previamente.

- **Ventajas:** Funciona sin conexión a Internet.
- **Inconvenientes:**
  - **Cero autenticación (S0 — Crítica):** Dictar un número estático no prueba posesión de ninguna clave privada (`INV-05`, `REQ-PRES-002`).
  - **Violación de INV-02 y P-09:** Distribuir una lista de números de titulares a todos los verificadores offline filtraría el censo de usuarios y permitiría correlacionar globalmente a las personas.
- **Riesgos:** Suplantación trivial y fuga masiva de datos personales (rechazada de plano).

---

### Opción B — Código efímero de sesión (`SessionCode`, 10 dígitos con control Damm) resuelto en línea vía Relay + Número por emisor estrictamente opcional y desactivado por defecto (Recomendada)

Separar la funcionalidad numérica en tres mecanismos con garantías explícitas:

#### 1. Número de documento oficial (p. ej. cédula) $\to$ Claim de divulgación selectiva (`document_number`)
- Ya existe en `pip-personal-v1` y se incluye en `pip-identity-v1` (ADR-0026).
- Viaja **dentro** de la credencial firmada por el emisor, siempre oculto tras una sal de 128 bits (`_sd`) y solo se revela cuando el titular consiente divulgarlo (`REQ-IDDOC-003`). **Nunca** se usa como clave de enrutamiento del protocolo.

#### 2. Mecanismo primario (por defecto): Código efímero de sesión (`SessionCode`, 10 dígitos)
- **Qué identifica:** Identifica una **sesión de presentación**, nunca a una persona (`REQ-CODE-001`).
- **Formato (`SessionCode` en `gravital-id-types`):** Exactamente **10 dígitos decimales** (`D₁ D₂ ... D₉ C`), donde los primeros 9 dígitos son generados aleatoriamente con CSPRNG en el relay/verificador y el décimo dígito `C` es el **dígito de control de Damm** (cuasigrupo antisimétrico de orden 10 que detecta el 100 % de los errores de transcripción de un solo dígito y el 100 % de las transposiciones de dígitos adyacentes, superando al algoritmo de Luhn; `REQ-CODE-002`). Para legibilidad humana se formatea como `XXX-XXX-XXXX` (ignorando guiones y espacios al parsear).
- **Flujo en línea (equivalente a una transacción *Card-Not-Present* con 3-D Secure):**
  1. El verificador (en línea) construye una solicitud firmada (`ProximityRequest` con su certificado/clave en el trust bundle, `REQ-PRES-007`, y su clave pública efímera `eph_pub` para HPKE) y la registra en el servicio de *rendezvous* del relay (`F7.T06` / `F23.T02`), obteniendo un `SessionCode` con un **TTL corto ($\le 180\text{ segundos}$)**.
  2. El verificador muestra o dicta el código de 10 dígitos al titular (p. ej. por teléfono o en pantalla web).
  3. El titular introduce los 10 dígitos en su wallet. La wallet valida localmente el dígito Damm antes de hacer cualquier llamada de red, descarga del relay la `ProximityRequest`, **verifica criptográficamente la firma del verificador contra su trust bundle local**, y muestra en pantalla: *"¿Deseas compartir [atributos] con [Nombre verificado del Verificador]?"* (`REQ-PRES-003`).
  4. Al aceptar el titular, la wallet construye la presentación SD-JWT+KB ligada al `transcript_hash` (`transport_type = 4`, ADR-0023), la sella con **HPKE** hacia `eph_pub` del verificador y la deposita en el relay.
  5. El código se marca inmediatamente como **consumido al primer uso** (`REQ-CODE-001`). El verificador descarga el sobre HPKE, lo abre y ejecuta `VerifierPipeline::verify`.
- **Por qué la seguridad NO depende del secreto del código (`REQ-CODE-003`):**
  - El código solo localiza una solicitud pública firmada por el verificador. Si un atacante intenta adivinar un código activo, lo único que obtiene es la solicitud de presentación del verificador; no puede leer la respuesta de ningún titular (porque el primer envío válido consume el buzón y viaja cifrado con HPKE hacia la clave efímera privada del verificador) ni puede suplantar al titular esperado (porque carece de su credencial firmada por el emisor y de su clave privada en hardware).
  - Adicionalmente, el relay aplica limitación estricta de tasa (*rate limiting*) por IP/origen y global, y destruye la sesión tras un número acotado de intentos fallidos (`REQ-CODE-002`).

#### 3. Mecanismo secundario (opcional, desactivado por defecto): Número Gravital por emisor
- Si una organización integradora requiere indispensablemente que el usuario dicte un número fijo "tipo número de cuenta/tarjeta" en lugar de que el operador le dicte el `SessionCode`:
  - **Alcance:** El número es **específico de un emisor**, nunca global del protocolo (`P-09`, `ARCHITECTURE.md §7.1`).
  - **Estructura de 10 dígitos:** `P₁ P₂ A₁ A₂ A₃ A₄ A₅ A₆ A₇ C` (2 dígitos de prefijo de emisor `01`–`99` reservando `00` para códigos de sesión cuando se distingan por prefijo, 7 dígitos de cuenta = $10^7$ titulares por emisor, y 1 dígito de control Damm `C`). Los prefijos de 2 dígitos pertenecen al emisor (no son PII) y pueden asociarse al `IssuerId` en los metadatos del emisor.
  - **Privacidad y consentimiento (`REQ-CODE-004`):** El número completo se trata como **dato personal (PII)**: jamás va al ledger, a logs, a métricas ni a mensajes de error (`INV-02`). Su resolución sigue un flujo *push* con consentimiento idéntico a 3-D Secure: el verificador envía la solicitud firmada al endpoint del emisor dueño del prefijo $\to$ el emisor encamina una notificación cifrada a la wallet del titular vía relay $\to$ el titular ve quién solicita qué y consiente en su dispositivo $\to$ la wallet responde con HPKE directamente al verificador.
  - **Contrapartidas explícitas:** En este flujo opcional, el emisor participa en el enrutamiento de la solicitud (lo que relaja la propiedad de "cero *phone-home*" de `P-09` únicamente para las credenciales cuyo perfil habilite explícitamente esta opción) y existe riesgo de notificaciones no deseadas (*push bombing*) si terceros conocen el número, por lo que requiere límites estrictos por número, solicitud firmada obligatoria del verificador y botón de bloqueo en la wallet (`R-21`). Por estas razones, **está desactivado por defecto en todos los perfiles estándar**.

---

## Decisión

Se adopta la **Opción B**:
1. Establecer **`SessionCode`** (código efímero de 10 dígitos: 9 aleatorios + 1 dígito de control Damm, TTL $\le 180\text{ s}$, un solo uso) como el mecanismo estándar de Gravital ID para cumplir `OBJ-04` en canales sin cámara ni NFC (`REQ-CODE-001`, `REQ-CODE-002`, `REQ-CODE-003`).
2. Documentar como límite físico vinculante (`ARCHITECTURE.md §2`) que la validación mediante código numérico **requiere conexión en línea** (al servicio de *rendezvous* del relay) y nunca puede realizarse 100 % offline.
3. Prohibir cualquier identificador numérico persistente global del titular en el protocolo (`ARCHITECTURE.md §7.1`, `P-09`).
4. Permitir el **Número por emisor** (`F23.T06`) únicamente como extensión opcional desactivada por defecto, tratada como dato personal bajo `INV-02` y sujeta a consentimiento interactivo del titular con solicitud firmada del verificador (`REQ-CODE-004`).

---

## Consecuencias

- **Positivas:**
  - Resuelve el caso de uso de atención telefónica y remota (`OBJ-04`) con seguridad criptográfica completa (solicitud firmada del verificador + cifrado HPKE + firma KB-JWT en hardware del titular), haciendo imposible la suplantación aunque un tercero escuche el código de 10 dígitos.
  - El dígito de control de Damm detecta errores humanos al teclear o dictar el número antes de realizar tráfico de red.
  - Preserva intactos `INV-02` (cero PII en ledger/logs) y `P-09` (sin identificador global del titular).
- **Negativas y cómo se mitigan:**
  - No funciona sin Internet. *Mitigación:* En escenarios offline presenciales el titular utiliza NFC (teléfono o tarjeta física) o QR.
  - Riesgo de ingeniería social donde un estafador telefónico dicta un `SessionCode` a la víctima. *Mitigación (`R-21`):* La solicitud debe ir firmada por un verificador registrado (`REQ-PRES-007`) y la wallet muestra de forma prominente la identidad verificada del solicitante y los claims exactos antes de permitir firmar (`REQ-PRES-003`).
- **Cambios necesarios en documentación (`ARCHITECTURE.md`, `REQUIREMENTS.md`, specs):**
  - `ARCHITECTURE.md` (§2, §7.3) y `REQUIREMENTS.md` (`REQ-CODE-001..004`) ya incorporan esta distinción; `docs/specs/PROTOCOL.md §7` y `docs/specs/ERROR_CODES.md` especificarán el formato y errores en `F19.T09`.
  - Se cierra el issue `type:spec-gap` `#77`.
- **Cambios en código, CI o `layers.toml`:**
  - Creación del newtype `SessionCode` con algoritmo de Damm y objetivo de fuzzing en `gravital-id-types` (`F23.T01`) y endpoints de *rendezvous* en el relay (`F23.T02`).
- **Tareas nuevas en `ROADMAP.md`:**
  - `F23.T01`–`F23.T07`.

---

## Criterios para revisar esta decisión

1. Si ningún integrador solicita el flujo opcional de Número por emisor (`F23.T06`) antes de finalizar `F23`, dicha tarea podrá mantenerse diferida para evitar complejidad innecesaria en el relay y en el servicio de emisión.
2. Si las pruebas de usabilidad muestran que un TTL de 180 segundos es insuficiente para atención telefónica asistida, el perfil podrá parametrizar el TTL hasta un máximo de 300 segundos manteniendo el límite de intentos y el consumo al primer uso.
