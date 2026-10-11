# ADR-0003: Formato de credencial v1 (SD-JWT VC + HAIP 1.0)

- **Estado:** Aceptado
- **Fecha:** 2026-10-11
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #8
- **Requisitos y principios afectados:** REQ-CRED-001; REQ-CRED-004; P-02; P-04; P-09
- **Fase:** F0 (F0.T11)

---

## Contexto

El protocolo Gravital ID requiere un formato estándar de credenciales verificables que permita:
1. **Divulgación selectiva (Selective Disclosure):** El titular debe poder revelar únicamente los atributos requeridos por el verificador (p. ej. mayor de 18 años) sin exponer información confidencial adicional (número de documento, nombre completo).
2. **Vinculación de clave criptográfica (Key Binding):** Garantizar que la presentación de la credencial esté demostrada criptográficamente por la clave privada del titular, impidiendo la transferencia ilegítima o robo de la credencial si los datos son interceptados.
3. **Verificación offline y portabilidad:** Funcionar de forma autónoma en entornos sin conexión y compilar de manera eficiente en navegadores y dispositivos móviles sin requerir suites criptográficas experimentales no soportadas por hardware nativo (Secure Enclave / StrongBox).
4. **Interoperabilidad global:** Alinearse con la evolución de estándares internacionales (OpenID Foundation y Unión Europea / eIDAS 2.0).

---

## Opciones consideradas

### Opción A — W3C Verifiable Credentials con Data Integrity BBS+ Cryptosuites
- **Ventajas:** Prueba de conocimiento cero (ZKP) con firmas indetectables de divulgación selectiva y emisión con clave única.
- **Inconvenientes:**
  - Requiere curvas elípticas emparejadas (BLS12-381) que carecen de soporte en Secure Enclave (Apple) y StrongBox (Android).
  - Alto consumo computacional y complejidad de implementación en Rust `no_std` y WebAssembly.
  - Madurez incipiente en implementaciones industriales móviles.

### Opción B — ISO/IEC 18013-5 mdoc / mDL (COSE/CBOR)
- **Ventajas:** Estándar maduro adoptado por gobiernos para licencias de conducir digitales; soporta BLE y NFC de proximidad.
- **Inconvenientes:**
  - Formato rígido centrado en documentos de identidad físicos.
  - Complejidad en la integración web (HTTP/JSON) y flujos basados en navegadores.
  - Modelo de gobernanza y perfiles estrechamente acoplados al transporte de corto alcance.

### Opción C — SD-JWT VC (RFC 9901 + IETF SD-JWT VC) con alineación HAIP 1.0 (Recomendada)
- **Ventajas:**
  - Basado en primitivas JSON/JWT y JOSE (RFC 7515/7519) ampliamente soportadas en la industria.
  - Estandarizado en el RFC 9901 del IETF y el borrador fijado `draft-ietf-oauth-sd-jwt-vc-08`.
  - Soporta vinculación de clave (SD-JWT+KB) mediante curvas NIST estándar (P-256 / ES256) directamente ejecutables dentro del hardware seguro móvil.
  - Totalmente alineado con el perfil OpenID4VC High Assurance Interoperability Profile (HAIP) 1.0 (diciembre de 2025) y las especificaciones de billeteras digitales europeas e internacionales.
- **Inconvenientes:** Las divulgaciones intermedias revelan el hash de los atributos ocultos (mitigado mediante sales criptográficas de 128 bits generadas por el emisor).

---

## Decisión

Se adopta la **Opción C**:
1. El formato canónico de credenciales en la versión 1.0 del protocolo es **SD-JWT VC** (RFC 9901 y borrador IETF fijado en `CRYPTO_PROFILES.md`).
2. Toda presentación interactiva utiliza **SD-JWT+KB** (Key Binding JWT) firmado por la clave de vinculación del titular (ES256).
3. Se incorpora alineación con **HAIP 1.0**:
   - Soporte de cabecera `x5c` opcional en las credenciales cuando el emisor esté respaldado por una infraestructura PKI complementaria, validada contra la `TrustStore` local.
   - Algoritmo de firma mandatorio ES256 (NIST P-256 con SHA-256).
4. El tipo de credencial se declara de forma inequívoca en el claim normativo `vct`.

---

## Consecuencias

- Las especificaciones normativas `PROTOCOL.md`, `CRYPTO_PROFILES.md` y `SDK_API.md` implementan de forma estricta las estructuras SD-JWT y SD-JWT+KB.
- La evaluación de crear o reutilizar un crate SD-JWT se reserva para la tarea F3.T01 bajo ADR-0015.
