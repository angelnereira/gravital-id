# ADR-0005: Mecanismo de estado y revocación (Token Status List)

- **Estado:** Aceptado
- **Fecha:** 2026-10-11
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #10
- **Requisitos y principios afectados:** REQ-STAT-001; REQ-STAT-002; REQ-STAT-008; P-02; P-09
- **Fase:** F0 (F0.T11)

---

## Contexto

El protocolo requiere un mecanismo escalable y que preserve la privacidad para verificar si una credencial emitida sigue activa, ha sido suspendida temporalmente o ha sido revocada de forma definitiva.
Restricciones clave:
1. **Preservación de la privacidad:** La comprobación de estado no puede requerir una consulta en línea dirigida al emisor sobre una credencial específica (prohibición de "phone home", que permitiría al emisor rastrear dónde y cuándo el titular presenta su credencial).
2. **Capacidad offline:** Un verificador desconectado debe poder comprobar el estado de una credencial si dispone de un snapshot reciente y firmado de la lista de estado.
3. **Eficiencia en ancho de banda:** El formato debe ser lo bastante compacto como para descargarse rápidamente en redes móviles y almacenarse en caché local.
4. **Distinción de estados:** Ciertos perfiles (como el perfil financiero) exigen distinguir entre los estados *Activo*, *Suspendido* (reversible) y *Revocado* (irreversible).

---

## Opciones consideradas

### Opción A — OCSP (Online Certificate Status Protocol) adaptado a credenciales
- **Ventajas:** Consulta en tiempo real.
- **Inconvenientes:** Viola el principio de no-phone home; revela patrones de actividad del titular al emisor; imposible de operar sin conexión continua a Internet.

### Opción B — Acumuladores criptográficos (Cryptographic Accumulators / Merkle Trees dinámicos)
- **Ventajas:** Pruebas criptográficas individuales de pertenencia o no-pertenencia sin revelar la lista completa.
- **Inconvenientes:** Requiere actualización continua del testigo (*witness*) por parte del titular en cada revocación de terceros; alta complejidad matemática y coste computacional elevado en clientes móviles.

### Opción C — Token Status List (IETF draft-ietf-oauth-status-list) (Recomendada)
- **Ventajas:**
  - Estándar emergente del IETF ampliamente respaldado por la industria de identidad descentralizada y las especificaciones europeas de billeteras digitales.
  - El emisor publica un vector de bits comprimido con DEFLATE/zlib codificado en Base64URL.
  - Soporta codificación de **1 bit por entrada** (0 = válido, 1 = revocado) o **2 bits por entrada** (00 = válido, 01 = suspendido, 10 = revocado).
  - Al descargarse la lista completa, el emisor desconoce qué entrada específica está consultando el verificador, protegiendo totalmente la privacidad del titular.
  - Un snapshot de 100,000 credenciales ocupa apenas unos 12 KB comprimidos.
- **Inconvenientes:** El verificador descarga la lista completa en lugar de una prueba puntual (perfectamente asumible dado el reducido tamaño comprimido).

---

## Decisión

Se adopta la **Opción C**:
1. El mecanismo oficial de estado de credenciales de Gravital ID es **Token Status List** conforme al borrador IETF fijado en `CRYPTO_PROFILES.md`.
2. Las credenciales declaran su estado mediante el claim `status` conteniendo un objeto `status_list` con la URI de la lista (`uri`) y el índice de la credencial (`idx`).
3. Se admite codificación de 1 bit para perfiles generales (`pip-personal-v1`) y de 2 bits para perfiles regulados que soportan suspensión reversible (`pip-financial-v1` y `pip-enterprise-v1`).
4. Para evitar la equivocación del emisor, los hashes SHA-256 de los snapshots de listas se enumeran en el **Manifiesto de Estado** del emisor (ADR-0017) y se anclan periódicamente en el contrato inteligente `StatusAnchor.sol` (INV-02).

---

## Consecuencias

- Las especificaciones normativas `PROTOCOL.md`, `CRYPTO_PROFILES.md` y `CONTRACTS.md` articulan la resolución de Token Status Lists.
- El verificador almacena en caché local las listas de estado descargadas, respetando el tiempo de frescura máximo fijado por cada perfil.
