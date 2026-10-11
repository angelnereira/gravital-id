# ADR-0009: Modelo de recuperación, migración y re-vinculación

- **Estado:** Aceptado
- **Fecha:** 2026-10-11
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #14
- **Requisitos y principios afectados:** REQ-REC-001; REQ-REC-002; REQ-REC-005; P-04; P-08; P-09
- **Fase:** F0 (F0.T11)

---

## Contexto

En los sistemas de identidad soberana y billeteras digitales, la pérdida o sustracción del dispositivo móvil suele provocar la pérdida irrevocable de las credenciales o forzar el uso de custodios centralizados que destruyen la soberanía del usuario.
Requisitos críticos de recuperación en Gravital ID:
1. **Sin dependencia exclusiva de un custodio ni SMS/Email:** La recuperación no puede depender de un tercero de confianza centralizado ni de mecanismos no autenticados criptográficamente.
2. **Protección contra la correlación de emisores:** Si un titular utiliza una clave de recuperación compartida ante múltiples emisores, el hash de dicha clave actuaría como un identificador global único permanente, permitiendo la vigilancia masiva y correlación de la actividad del usuario entre distintas entidades.
3. **Migración segura entre dispositivos (SAS con compromiso previo):** Cuando un usuario cambia voluntariamente de teléfono móvil, la transferencia directa de credenciales mediante canales de corto alcance (QR/Wi-Fi/Bluetooth) debe ser inmune a ataques de intermediario (*Man-in-the-Middle* / MitM).
4. **No exportabilidad de claves hardware:** Las claves privadas ligadas a Secure Enclave o StrongBox nunca pueden extraerse; por tanto, la recuperación de credenciales en un nuevo dispositivo exige un protocolo de **re-vinculación** criptográfica con cada emisor.

---

## Opciones consideradas

### Opción A — Custodia centralizada de claves o respaldo en la nube del emisor
- **Ventajas:** Experiencia de usuario idéntica a una cuenta web convencional ("olvidé mi contraseña").
- **Inconvenientes:** Viola los principios de soberanía de datos (P-08); crea almacenes masivos de datos (*honeypots*); sujeta a órdenes judiciales y filtraciones.

### Opción B — Simple frase semilla BIP-39 sin claves por emisor
- **Ventajas:** Modelo ampliamente conocido en Web3.
- **Inconvenientes:** Si la misma clave pública derivada se registra ante todos los emisores para autorizar re-vinculaciones, se crea un identificador global permanente del titular, violando flagrantemente INV-02 y el principio P-09 de privacidad.

### Opción C — Arquitectura de recuperación en 3 niveles con SAS de compromiso previo y derivación de claves por emisor (Recomendada)
- **Ventajas:**
  - **Nivel 1 (Migración dispositivo a dispositivo):** Canal efímero ECDH P-256 protegido por **compromiso criptográfico previo** (`Commitment = SHA256(EphemeralPubKey)`). Al enviar el compromiso antes de revelar la clave efímera, ningún atacante puede forzar la colisión del código SAS de 6 dígitos que ambos usuarios comparan visualmente.
  - **Nivel 2 (Respaldo cifrado del titular):** Respaldo cifrado con frase de alta entropía ($\ge 128$ bits) con soporte opcional de partición secreta de Shamir ($k$-de-$n$). El respaldo contiene el *secreto de recuperación*, a partir del cual se derivan **claves de recuperación independientes para cada emisor**:
    $$\text{RecoveryKey}_{\text{Issuer}} = \text{HKDF}(\text{RecoverySecret}, \text{IssuerId})$$
    El protocolo de **re-vinculación** envía una solicitud firmada con dicha clave para revocar la credencial vieja y emitir una nueva ligada al nuevo hardware.
  - **Nivel 3 (Recuperación institucional):** Para perfiles financieros estrictos, el emisor repite la verificación de identidad institucional (KYC) y emite una nueva credencial (sin restaurar claves anteriores).
- **Inconvenientes:** La re-vinculación en el Nivel 2 requiere conectividad con el emisor.

---

## Decisión

Se adopta la **Opción C**:
1. La migración entre dispositivos implementa el protocolo de **compromiso previo y código SAS** documentado normativamente en `PROTOCOL.md §7`.
2. Las claves de recuperación registradas ante los emisores se derivan de forma determinista y aislada para cada emisor utilizando HKDF, impidiendo cualquier correlación cruzada de identidad.
3. Las claves privadas ligadas a hardware nunca se exportan; la restauración en un nuevo dispositivo genera un nuevo par de claves hardware y ejecuta el protocolo de **re-vinculación** ante cada emisor.
4. El respaldo del titular se exporta como un paquete cifrado con AEAD conforme a `STORAGE_FORMAT.md`.

---

## Consecuencias

- Las especificaciones `PROTOCOL.md`, `CRYPTO_PROFILES.md` y `SDK_API.md` incorporan la máquina de estados de migración y el objeto `RecoveryClient`.
- Se mitiga el ataque de colisión SAS documentado en `THREAT_MODEL.md`.
