# ADR-0022: Transporte de proximidad y protocolo GID-APDU

- **Estado:** Propuesto
- **Fecha:** 2026-10-15
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira (pendiente de validación formal del mantenedor)
- **Issue:** #79 (resuelve también #74)
- **Requisitos y principios afectados:** REQ-PROX-003, REQ-PROX-004, REQ-PROX-005, REQ-PROX-006, REQ-PROX-007, REQ-PROX-008, REQ-MAINT-002; P-02, P-04, P-05, P-11, P-14; INV-01, INV-04, INV-05, INV-15
- **Fase:** F19 (F19.T03)

---

## Contexto

Con la aceptación de **ADR-0021**, Gravital ID incorpora la presentación de credenciales sin contacto (*tap*) mediante **NFC** desde teléfonos Android (Host Card Emulation, HCE) y desde tarjetas físicas con elemento seguro (Java Card), verificables offline desde teléfonos Android (`IsoDep`), iPhone (Core NFC ISO 7816) y terminales con lectores USB/embebidos (`PC/SC`).

Para materializar este canal sin romper el modelo de confianza ni la arquitectura del núcleo (`gravital-id-verifier`), es necesario decidir:
1. **El protocolo de transporte y formato de carga útil en proximidad**, evaluando la tensión con el principio **P-04 (Estándares primero)** dado que en el ecosistema internacional (p. ej. EUDI Wallet ARF y mDL) el transporte de proximidad suele asociarse a **ISO/IEC 18013-5 (`mdoc`)**.
2. **La ubicación en la arquitectura por capas (`layers.toml`)** de las máquinas de estado de proximidad y de los adaptadores de lectores.
3. **La estrategia de identificador de aplicación (AID) ISO/IEC 7816-4** para desarrollo y producción, así como el rol de Bluetooth Low Energy (BLE).
4. **La armonización con ADR-0011 §Decisión.5** (registrada en el issue `#74`), que mencionaba originalmente los canales BLE/NFC como extensiones para una fase genérica anterior.

---

## Opciones consideradas

### Opción A — Adoptar exclusivamente ISO/IEC 18013-5 (`mdoc` CBOR/COSE) para proximidad

Reemplazar o duplicar de inmediato el formato de credencial en proximidad utilizando estructuras `MobileSecurityObject` (MSO) firmadas con `COSE_Sign1` (RFC 9052) y el transporte de sesión/engagement de ISO/IEC 18013-5 sobre NFC y BLE.

- **Ventajas:**
  - Alineación directa con lectores de licencias de conducir móviles (mDL) y el perfil de proximidad de EUDI Wallet.
- **Inconvenientes:**
  - **Ruptura del formato único del núcleo (ADR-0003):** Todo el núcleo construido y verificado en F1–F4 (`gravital-id-credential`, `gravital-id-status`, `gravital-id-trust`, `gravital-id-verifier`) opera sobre **SD-JWT VC (RFC 9901)** con firmas JWS `ES256` y listas de estado `Token Status List`. Introducir `mdoc` como requisito para el primer hito de NFC (MP1) obligaría a implementar COSE, CBOR MSO, validación de certificados X.509 de emisor para mdoc y una segunda tubería de verificación antes de tener un solo toque NFC operativo.
  - **Complejidad excesiva en tarjeta física Java Card:** Construir estructuras COSE/CBOR dinámicas en una tarjeta Java Card con 2–4 KB de RAM incrementa drásticamente el riesgo de desbordamiento y divergencia respecto al núcleo Rust.
- **Riesgos:** Duplicación prematura del motor de verificación y retraso severo de los hitos MP1 y MP2.

---

### Opción B — Transporte BLE obligatorio con traspaso (*handover*) por NFC

Usar NFC únicamente para el *engagement* estático o dinámico (NDEF) y transferir siempre la presentación por Bluetooth Low Energy (GATT).

- **Ventajas:**
  - Mayor ancho de banda para credenciales con retrato en dispositivos móviles, incluido iPhone actuando como titular frente a lectores BLE.
- **Inconvenientes:**
  - **Incompatible con tarjetas físicas sin batería (Java Card):** Una tarjeta pasiva ISO/IEC 14443-4 carece de radio BLE; solo se alimenta del campo magnético del lector NFC y se comunica mediante comandos APDU ISO/IEC 7816-4.
  - **Fricción operativa y latencia:** El emparejamiento/conexión BLE suele añadir entre 800 ms y 2.5 s de latencia e inconsistencias entre pilas Bluetooth de distintos fabricantes Android/iOS, frente a un toque puro APDU de `< 400 ms`.
- **Riesgos:** Imposibilita el objetivo OBJ-02/OBJ-06 para tarjetas físicas ("funcionar como una tarjeta Visa/Mastercard").

---

### Opción C — Protocolo `GID-APDU` sobre ISO/IEC 7816-4 transportando la presentación SD-JWT+KB transcodificada + BLE condicional + `mdoc` diferido a F25 (Recomendada)

Definir un protocolo de comandos APDU estándar **ISO/IEC 7816-4** denominado **`GID-APDU`** en un crate sans-I/O de capa L4 (`gravital-id-proximity`), transportando la misma presentación **SD-JWT+KB transcodificada** (`PROTOCOL.md §3.2`) sellada dentro de una sesión cifrada (`ProximityRequest` / `ProximityResponse`, ADR-0023):

1. **Comandos ISO/IEC 7816-4 reutilizando los códigos de instrucción de ISO/IEC 18013-5:**
   - `SELECT` por nombre de aplicación (AID) (`CLA=00, INS=A4, P1=04, P2=00`): selecciona el applet/servicio HCE y devuelve `HolderHello` (CBOR acotado con versión de protocolo, tamaño máximo de APDU soportado, capacidades de PIN y transporte, **cero PII**).
   - `ENVELOPE` (`CLA=00/10, INS=C3, P1=00, P2=00`): envía `ProximityRequest` desde el lector al titular (con encadenamiento en el bit 4 de `CLA` o APDU de longitud extendida si `HolderHello` lo declara).
   - `GET RESPONSE` (`CLA=00, INS=C0, P1=00, P2=00`): recupera los fragmentos de `ProximityResponse` cuando el titular responde `61xx` (bytes disponibles).
   - `VERIFY` (`CLA=00, INS=20, P1=00, P2=80`): presenta el PIN del titular (en tarjetas físicas para claims de Nivel 1, según ADR-0024).
2. **Justificación frente a P-04 (Estándares primero):**
   - El encuadramiento de comandos (`SELECT`, `ENVELOPE`, `GET RESPONSE`, `VERIFY` y palabras de estado `9000`, `61xx`, `63Cx`, `6983`, `6A82`) **sigue estrictamente ISO/IEC 7816-4** y adopta el mismo patrón de encapsulación (`ENVELOPE` / `GET RESPONSE`) que ISO/IEC 18013-5 §8.3.3.1.2.
   - El contenido de la presentación reutiliza sin cambios el estándar **IETF RFC 9901 (SD-JWT) + SD-JWT VC** (ADR-0003) y la transcodificación binaria CBOR + DEFLATE de `PROTOCOL.md §3.2`.
   - De este modo, **todos los transportes (QR, NFC HCE, Tarjeta Java Card y BLE)** alimentan el **mismo** `VerifierPipeline::verify` en `gravital-id-verifier` y producen exactamente el mismo `VerificationResult` de cuatro estados (INV-04, REQ-PROX-005).
   - La compatibilidad nativa con el formato `mdoc` (ISO/IEC 18013-5 completo con COSE) no se descarta: se aísla en la fase condicional **F25** (que adelanta `F18.T04` si un acuerdo gubernamental o de interoperabilidad internacional lo exige).
3. **Separación de capas (`layers.toml`):**
   - `gravital-id-proximity` se ubica en **Capa L4 (sans-I/O)**: depende únicamente de `gravital-id-types`, `gravital-id-codec`, `gravital-id-crypto`, `gravital-id-keys` y `gravital-id-credential`. No realiza I/O ni depende de `std::time` ni de `tokio` (INV-01, INV-11).
   - **`gravital-id-verifier` NO depende de `gravital-id-proximity`** (preserva la regla 3 de `PROJECT_STRUCTURE.md §4`): la capa de proximidad abre el sobre cifrado, reconstruye la cadena SD-JWT+KB compacta y la entrega al verificador.
   - `gravital-id-transport-pcsc` se ubica en **Capa L5 (Adaptadores de plataforma/transporte)**: envuelve lectores USB/contacto/sin contacto PC/SC y alimenta la máquina de estados de `gravital-id-proximity`.
4. **Estrategia de AID (ISO/IEC 7816-5):**
   - En desarrollo, pruebas y pilotos cerrados se utiliza el AID propietario: `F0 47 52 41 56 49 54 41 4C 01` (`"F0" + ASCII("GRAVITAL") + 0x01`, 10 bytes). Conforme a ISO/IEC 7816-5, el prefijo `F` designa el rango propietario no registrado y evita colisiones con esquemas EMV o gubernamentales.
   - Antes de la salida a producción general (`F15` / `G15`), si el despliegue abarca terminales de múltiples organizaciones no coordinadas, se tramitará el registro de un **RID (Registered Application Provider Identifier)** oficial de 5 bytes ante la autoridad de registro ISO/IEC 7816-5 (R-22), manteniendo soporte dual en los lectores durante la transición.
5. **Papel de BLE (`F21.T08`):**
   - NFC (`GID-APDU`) es el canal primario para teléfonos Android y tarjetas físicas.
   - BLE GATT (transportando exactamente los mismos mensajes `ProximityRequest` / `ProximityResponse` fragmentados por MTU) se activa de forma condicional en `F21.T08` para dos casos: (a) titulares con iPhone en mercados donde Apple no habilita HCE para terceros (como Panamá, R-15), y (b) presentaciones con retrato en lectores donde el spike `F19.T12` demuestre que el tiempo de transferencia APDU supera el umbral ergonómico de un toque (`> 600 ms`).

---

## Decisión

Se adopta la **Opción C**:
1. Definir el protocolo **`GID-APDU`** basado en comandos ISO/IEC 7816-4 (`SELECT`, `ENVELOPE`, `GET RESPONSE`, `VERIFY`) dentro del crate L4 sans-I/O **`gravital-id-proximity`**, transportando presentaciones SD-JWT+KB transcodificadas y cifradas en sesión (ADR-0023).
2. Fijar el AID propietario de desarrollo en `F0475241564954414C01` en una única constante canónica de `gravital-id-proximity`, planificando la evaluación/registro de RID ISO/IEC 7816-5 para `F15` (R-22).
3. Incorporar el adaptador L5 **`gravital-id-transport-pcsc`** para lectores de escritorio, kioscos y estación de personalización de tarjetas.
4. Mantener `gravital-id-verifier` libre de dependencias hacia `gravital-id-proximity`: la verificación por proximidad desemboca en el mismo `VerifierPipeline::verify` sin red (INV-01, REQ-PROX-005).
5. Actualizar **ADR-0011 §Decisión.5** para reflejar que el transporte NFC/BLE se especifica en `F19` y se implementa en `F20`–`F21` (con `mdoc` ISO/IEC 18013-5 en `F25`/`F18`), cerrando el hueco `#74`.
6. Establecer como umbral de aceptación de campo (`F21.T09`) una tasa de éxito $\ge 95\,\%$ al primer toque y una latencia total de intercambio APDU + verificación $\le 500\,\text{ms}$ para credenciales sin retrato ($\le 900\,\text{ms}$ con retrato de hasta 16 KB en lectores con APDU extendido).

---

## Consecuencias

- **Positivas:**
  - Un único formato de credencial (SD-JWT VC) y un único motor de verificación (`VerifierPipeline`) sirven a QR, NFC en Android, tarjeta física Java Card y BLE.
  - Los adaptadores de plataforma (`HostApduService` en Kotlin, `NFCTagReaderSession` en Swift, `pcsc` en Rust) carecen de lógica de protocolo (INV-15, REQ-PROX-008): solo reenvían buffers APDU hacia/desde la máquina de estado Rust.
  - El uso de `ENVELOPE` y `GET RESPONSE` facilita la futura incorporación de ISO/IEC 18013-5 en `F25`.
- **Negativas y cómo se mitigan:**
  - Un verificador que solo implemente ISO/IEC 18013-5 (`mdoc`) puro no entenderá el payload SD-JWT VC de `GID-APDU` sin el SDK de Gravital ID. *Mitigación:* Fase condicional `F25` lista para activarse cuando se requiera interoperabilidad con lectores `mdoc` de terceros.
  - En iOS (Panamá), el iPhone puede leer tarjetas y teléfonos Android por Core NFC (`F21.T06`), pero no emular tarjeta por HCE (R-15). *Mitigación:* El titular con iPhone presenta mediante QR (F5) o BLE (`F21.T08`).
- **Cambios necesarios en documentación (`ARCHITECTURE.md`, `REQUIREMENTS.md`, specs):**
  - `docs/ARCHITECTURE.md` (§6, §8.4, §9.4, §22) y `docs/REQUIREMENTS.md` (`REQ-PROX-003..008`) ya reflejan la estructura general; `docs/specs/PROTOCOL.md §7` y `docs/specs/ERROR_CODES.md` (familia `GID-E8000..E8999`) detallarán la gramática binaria y los códigos de estado en `F19.T09`.
  - Actualización de `docs/adr/0011-transporte-offline.md` para cerrar `#74`.
- **Cambios en código, CI o `layers.toml`:**
  - En `F20.T01` y `F21.T07` se añadirán `gravital-id-proximity` (L4) y `gravital-id-transport-pcsc` (L5) a `layers.toml`, junto con pruebas negativas de `cargo xtask check-layers`.
- **Tareas nuevas en `ROADMAP.md`:**
  - `F19.T09`, `F19.T12`, `F20.T01`–`F20.T10`, `F21.T01`–`F21.T10` y `F25` (incorporadas en `ROADMAP.md` v0.3).

---

## Criterios para revisar esta decisión

1. Si el spike `F19.T12` muestra que el encadenamiento APDU estándar en lectores comerciales introduce latencias superiores a 800 ms para presentaciones sin retrato, se ajustará el tamaño de fragmento o se activará obligatoriamente la negociación de longitud extendida.
2. Si Apple habilita las APIs de HCE / NFC & SE Platform para Panamá y Latinoamérica, se planificará el adaptador de emulación para iOS.
3. Si una entidad gubernamental exige interoperabilidad directa con lectores ISO/IEC 18013-5 de terceros antes de `F24`, se activará la Fase `F25`.
