# ADR-0029: Política de ranura única por clase de dispositivo (Móvil, Tarjeta tipo Visa, Otro) y atestación de hardware/IMEI

- **Estado:** Aceptado
- **Fecha:** 2026-10-18
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira (2026-10-18)
- **Issue:** #101
- **Requisitos y principios afectados:** REQ-DEVSLOT-001, REQ-DEVSLOT-002, REQ-DEVSLOT-003, REQ-DEVSLOT-004, REQ-KEY-002, REQ-CARD-001, REQ-CARD-005, REQ-ISS-005; P-01, P-03, P-08, P-09; INV-01, INV-02, INV-03, INV-05
- **Fase:** F19 / F8 / F10 / F22

---

## Contexto

Para mantener la integridad de la identidad del titular y evitar que una misma credencial Gravital ID sea clonada, compartida o utilizada simultáneamente por varias personas en dispositivos del mismo tipo, se establece la siguiente regla de negocio fundamental:

> **Regla de Exclusión por Tipo de Dispositivo:** Un titular puede portar su Gravital ID simultáneamente en **diferentes clases de dispositivos compatibles** —por ejemplo, en **un (1) teléfono móvil**, en **una (1) tarjeta física inteligente tipo Visa** y en **un (1) dispositivo de otra clase compatible**—, pero **NUNCA en dos dispositivos de la misma clase al mismo tiempo** (nunca en 2 teléfonos móviles simultáneamente, ni en 2 tarjetas tipo Visa simultáneamente).

El planteamiento original sugiere utilizar el registro del código **IMEI** cuando el dispositivo sea un teléfono móvil, y un control equivalente en tarjetas tipo Visa. Al analizar las restricciones de los sistemas operativos móviles modernos (`ARCHITECTURE.md §2`), encontramos tres hechos técnicos determinantes:
1. **Bloqueo del IMEI en Android 10+ (API 29+) e iOS:**
   - En **iOS**, Apple prohíbe a todas las aplicaciones de terceros leer el IMEI o el UDID del dispositivo desde iOS 7.
   - En **Android 10+ (2019–presente)**, Google restringió `TelephonyManager.getImei()` exclusivamente a aplicaciones del sistema firmadas por el fabricante (OEM) o aplicaciones de administración corporativa (*Device Owner* / MDM) con el permiso privilegiado `READ_PRIVILEGED_PHONE_STATE`. Una app instalada por un ciudadano desde Google Play recibe una `SecurityException` al invocar `getImei()`.
2. **Vulnerabilidad de un IMEI leído por software:** En un teléfono Android rooteado o en un emulador, un atacante puede interceptar la llamada de software e inyectar cualquier IMEI falso (*IMEI spoofing*).
3. **Privacidad bajo la Ley 81 de 2019 e `INV-02`:** El IMEI en claro es un identificador permanente de hardware vinculado a una persona natural, por lo que nunca debe almacenarse en claro ni tocar el ledger ni los logs.

Por tanto, necesitamos un diseño que:
- **Use el IMEI firmado por hardware (*Key ID Attestation*)** en los escenarios donde el sistema operativo lo permite de forma criptográfica (dispositivos corporativos/institucionales Android *Device Owner* / OEM), y
- **Garantice exactamente la misma unicidad infalsificable en todos los teléfonos de ciudadanos (Android Play Store e iPhone) y en las tarjetas físicas tipo Visa**, sin depender de llamadas de software bloqueadas por Android/iOS.

---

## Opciones consideradas

### Opción A — Leer `TelephonyManager.getImei()` por software y enviarlo en texto plano al servidor

- **Ventajas:** Ninguna en sistemas operativos actuales.
- **Inconvenientes:**
  - **Falla en el 100 % de los iPhone y en el 100 % de los Android 10+ de usuarios finales** (`SecurityException`).
  - Trivial de falsificar desde un emulador o cliente HTTP modificado.
- **Riesgos:** Inviabilidad técnica en tiendas de aplicaciones y vulnerabilidad de suplantación (rechazada).

---

### Opción B — Modelo de Ranura Única por Clase de Dispositivo (`DeviceFactorClass`) + Atestación Criptográfica de Silicio (StrongBox/TEE, Secure Enclave, CPLC de Java Card e IMEI Atestado en MDM/OEM) + Revocación Atómica por Ranura (Recomendada)

Implementar la regla *"máximo 1 dispositivo activo por clase de factor de forma"* combinando tres mecanismos criptográficos y de protocolo:

#### 1. Taxonomía Normativa de Clases de Dispositivo (`DeviceFactorClass`)
Cada credencial emitida por un emisor para un Gravital ID se asocia a una **ranura de clase de dispositivo (`device_class`)**:

| Clase (`DeviceFactorClass`) | Valor en Claim / Metadatos | Máximo Activo por Titular | Identificador Criptográfico de Hardware |
|---|---|---|---|
| **Teléfono Móvil** | `"mobile"` (`DeviceFactorClass::MobilePhone`) | **1** | Clave `cnf.jwk` inexportable en **Android StrongBox/TEE** o **iOS Secure Enclave** + Certificado de **Hardware Key Attestation / App Attest** (+ **IMEI atestado por el TEE** en dispositivos *Device Owner* / OEM). |
| **Tarjeta Física Tipo Visa** | `"card"` (`DeviceFactorClass::SmartCard`) | **1** | Clave `cnf.jwk` inexportable generada dentro del chip **Java Card 3.0.5+** (`REQ-CARD-001`) + **Serial de Silicio CPLC (*Card Production Life Cycle* / IC Fabricator + IC Serial Number)** leído y verificado durante `gid-perso` (`ADR-0024`). |
| **Otro Dispositivo Compatible** | `"other"` (`DeviceFactorClass::AuxiliaryHardware`, p. ej. llave de seguridad FIDO2/PKCS#11 o quiosco dedicado) | **1** por subclase | Clave `cnf.jwk` en TPM 2.0 / HSM / Token PKCS#11 + certificado de atestación del fabricante. |

#### 2. Registro de Huella de Hardware (`HardwareDeviceTag`) y Tratamiento del IMEI
- **En Teléfonos Móviles (`DeviceFactorClass::MobilePhone`):**
  1. Durante la emisión o re-vinculación (`OID4VCI` / `F10.T04`), el dispositivo genera la clave privada P-256 dentro de su chip seguro (`StrongBox`/`TEE` o `Secure Enclave`). Como la clave privada **jamás sale del chip (`INV-03`, `REQ-KEY-002`)**, es físicamente imposible copiar el Gravital ID de un teléfono a otro.
  2. El teléfono presenta al emisor la **cadena de certificados X.509 de atestación de hardware**:
     - **Modo Ciudadano Estándar (Android 10+ Play Store / iOS):** Se verifica la cadena de `Android Key Attestation` (anclada en la raíz de hardware de Google) o `Apple App Attest`, extrayendo la huella del módulo de hardware para ese emisor.
     - **Modo Institucional / MDM (*Device Owner* / OEM con `ID Attestation`):** El chip TEE de Android incluye la extensión `AttestationRecord` (OID `1.3.6.1.4.1.11129.2.1.17`) con el **IMEI verificado y firmado directamente por el silicio del teléfono** (no por software falsificable).
  3. El emisor calcula un compromiso ciego con clave en HSM (`HardwareDeviceTag = HMAC_HSM(device_hardware_id_or_attested_imei)`) y verifica que ese aparato físico no esté siendo usado simultáneamente para suplantar múltiples identidades.
- **En Tarjetas Físicas Tipo Visa (`DeviceFactorClass::SmartCard`):**
  1. En la estación de personalización `gid-perso` (`F22.T06`), antes de inyectar la credencial, se lee el registro **CPLC (`APDU 80 CA 9F 7F`)** grabado de fábrica en la máscara ROM/EEPROM del chip seguro (NXP JCOP / Infineon / Thales), que contiene el `IC Fabricator`, `IC Type`, `IC Batch Identifier` y `IC Serial Number` únicos en el mundo.
  2. El applet genera su par de claves ECDSA P-256 dentro del chip (`REQ-CARD-001`).
  3. El emisor registra `HardwareDeviceTag = HMAC_HSM(CPLC_Bytes)` junto con el `cnf.jwk` de la tarjeta:
     - **Ninguna tarjeta física puede clonarse** (la clave privada no es exportable).
     - **Un mismo chip físico no puede personalizarse dos veces** sin revocar su asignación previa.

#### 3. Invariante de Ranura Única y Revocación Selectiva Independiente (`REQ-DEVSLOT-001`, `REQ-DEVSLOT-003`)
Cada ranura (`mobile`, `card`, `other`) posee **su propia clave `cnf.jwk`** y **su propio índice independiente en la `Token Status List` del emisor**:
- **Caso 1 — Coexistencia permitida (1 Móvil + 1 Tarjeta tipo Visa):**
  - El usuario tiene activa su ranura `mobile` (en su teléfono, con `status_index = 10452`) y solicita personalizar su tarjeta física tipo Visa.
  - Como la ranura `card` está libre, el emisor emite la credencial para la tarjeta (`device_class = "card"`, `status_index = 88319`). Ambos dispositivos funcionan offline y online de forma simultánea.
- **Caso 2 — Prohibición de duplicidad en la misma clase (Intento de tener 2 Teléfonos Móviles o 2 Tarjetas):**
  - Si el usuario intenta activar su Gravital ID en un **Teléfono Móvil 2** mientras el **Teléfono Móvil 1** está activo en la ranura `mobile`:
    - El servidor detecta que la ranura `DeviceFactorClass::MobilePhone` ya está ocupada.
    - Si no es un flujo autorizado de reemplazo/migración (`F8.T04`/`F8.T05`), rechaza el alta con `GID-E2011 DuplicateDeviceClassActive`.
    - Si el usuario confirma la migración o reemplazo al Teléfono Móvil 2 (autenticado con SAS + biometría o código de recuperación), el emisor **revoca atómicamente en la `Token Status List` el índice del Teléfono Móvil 1 (`status_index = 10452 -> 01 Revoked`)** en el mismo acto transaccional en que activa el Teléfono Móvil 2, **dejando la Tarjeta Física (`status_index = 88319`) intacta y 100 % operativa**.
  - De igual forma, si el usuario reemplaza su Tarjeta Física tipo Visa por pérdida o deterioro, el emisor revoca únicamente el índice de la Tarjeta Física 1 (`88319 -> 01 Revoked`) y activa la Tarjeta Física 2, **sin desconectar su Teléfono Móvil**.

---

## Decisión

Se adopta la **Opción B**:
1. Establecer la **Política de Ranura Única por Clase de Dispositivo (`DeviceFactorClass`: `mobile`, `card`, `other`)**: cada titular puede mantener como máximo **un (1) dispositivo activo por clase**, cada uno con su clave privada en hardware inexportable y su propio índice en la `Token Status List`.
2. En teléfonos móviles, utilizar **Android Hardware Key Attestation (StrongBox/TEE)** y **Apple App Attest (Secure Enclave)** como mecanismo universal, incorporando la extracción del **IMEI firmado por hardware (`ID Attestation`)** cuando el dispositivo opere en modo corporativo/institucional (*Device Owner* / OEM), y guardando solo su compromiso `HMAC_HSM` (`INV-02`).
3. En tarjetas físicas tipo Visa (`Java Card`), utilizar la clave generada en el chip (`REQ-CARD-001`) más la huella única de silicio **CPLC (`IC Serial Number`)** durante la personalización (`gid-perso`).
4. Garantizar que el alta de un nuevo dispositivo en una clase ya ocupada exija el flujo de reemplazo/re-vinculación y **revoque atómicamente el dispositivo anterior de esa misma clase**, sin afectar los dispositivos activos del titular en otras clases.

---

## Consecuencias

- **Positivas:**
  - Cumple al 100 % la regla de negocio (*"se puede tener el Gravital ID en una tarjeta, teléfono u otro dispositivo compatible, pero nunca en dos del mismo tipo"*).
  - Funciona en el 100 % de los teléfonos Android 10–17 y en el 100 % de los iPhone sin ser bloqueado por las restricciones de permisos de Google Play o App Store, a la vez que aprovecha la atestación de IMEI en hardware cuando el teléfono es gestionado (*Device Owner*).
  - Si un usuario pierde su tarjeta física, la revoca al instante sin quedarse sin su teléfono móvil; y si cambia de teléfono móvil, el teléfono viejo queda invalidado automáticamente sin inutilizar su tarjeta física.
- **Negativas y cómo se mitigan:**
  - Consume una entrada de `Token Status List` por cada clase de dispositivo activa del titular (p. ej. 1 para el móvil y 1 para la tarjeta). *Mitigación:* Las listas tienen capacidad $\ge 131.072$ entradas (`REQ-STAT-002`) con un costo de solo 2 bits por dispositivo.
- **Cambios necesarios en documentación:**
  - Actualizar `docs/ARCHITECTURE.md` (§2, §12, §15), `docs/REQUIREMENTS.md` (`REQ-DEVSLOT-001..004`), `docs/specs/ERROR_CODES.md` (`GID-E2010`, `GID-E2011`) y `docs/specs/profiles/pip-identity-v1.md`.
