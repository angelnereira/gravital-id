# Perfil PIP: Personal v1 (`pip-personal-v1`)

> **Identificador normativo:** `pip-personal-v1`  
> **Versión:** `1.0.0` (Fase F8 / Tarea `F8.T09`)  
> **Estado:** Normativo  
> **Trazabilidad:** REQ-CRED-004, REQ-REC-005, REQ-REC-006, REQ-DEVSLOT-001..004, REQ-REC-002, REQ-REC-003, REQ-REC-004, REQ-REC-007; ADR-0009, ADR-0029; `ARCHITECTURE.md §16`

---

## 1. Alcance y Casos de Uso

El perfil `pip-personal-v1` está diseñado para credenciales cotidianas de personas naturales donde la privacidad del titular, la minimización de atributos y la facilidad de uso sin hardware especializado son primordiales:
* Verificación de mayoría de edad (predicados como `age_over_18` o `age_over_21` sin revelar fecha de nacimiento).
* Títulos y certificaciones académicas.
* Licencias deportivas, culturales y carnets de membresía.
* Tarjetas cívicas o de transporte público.

---

## 2. Parámetros Técnicos del Perfil

| Parámetro | Valor Normativo | Justificación |
|---|---|---|
| **Formato de Credencial** | SD-JWT VC (`typ: dc+sd-jwt`) | RFC 9901 y `draft-ietf-oauth-sd-jwt-vc-19`. |
| **Algoritmo de Firma** | `ES256` (P-256 + SHA-256) | Compatibilidad universal y rendimiento. |
| **Almacenamiento de Clave de Titular** | Preferido en Hardware (TEE); permitido en software cifrado | Inclusión para dispositivos de gama baja sin TEE. |
| **Exportación de Clave en Migración** | Permitida (cifrada en tránsito con ECDH + compromiso) | Facilidad de cambio de teléfono para el usuario común. |
| **Frescura Máxima de Estado** | 7 días (604,800 segundos) | Tolerancia operativa en comunidades desconectadas. |
| **Modo de Token Status List** | 1 bit por entrada (`0 = activo`, `1 = revocado`) | Eficiencia máxima en tamaño de lista de estado. |
| **Protección contra Replay** | Obligatoria en presentaciones interactivas (KB-JWT con `nonce`) | Mitigación de repetición de presentaciones interceptadas. |
| **Solicitud de Verificador Firmada** | Opcional | Permite verificadores independientes sin registro previo. |
| **Emisión por Lotes** | Recomendada | Reducción de coste y soporte de lotes para copias de credencial. |

---

## 3. Esquema JSON Canónico de Referencia

Ejemplo para credencial cívica / mayoría de edad:
* `vct`: `https://credentials.gravital.io/vct/personal/id-v1`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "given_name": { "type": "string" },
    "family_name": { "type": "string" },
    "birth_date": { "type": "string", "format": "date" },
    "age_over_18": { "type": "boolean" },
    "age_over_21": { "type": "boolean" },
    "nationality": { "type": "string", "pattern": "^[A-Z]{3}$" },
    "document_number": { "type": "string" }
  },
  "required": ["given_name", "family_name", "age_over_18"]
}
```

---

## 4. Política de Retención y Privacidad del Verificador

1. **Minimización Estricta:** El verificador debe solicitar exclusivamente los claims indispensables para la interacción inmediata (p. ej., `age_over_18` en lugar de `birth_date`).
2. **Retención Cero:** Salvo consentimiento explícito del titular fundamentado en una base legal válida, el verificador no almacenará en disco ningún claim personal recibido tras concluir la comprobación criptográfica.
3. **Registro de Auditoría:** El verificador almacena únicamente el registro abstracto:
   $$\text{AuditRecord} = (\text{timestamp}, \text{vct}, \text{issuer\_id}, \text{verification\_result}, \text{proof\_hash})$$

---

## 5. Procedimientos Normativos de Respaldo, Recuperación Institucional y Re-vinculación (`REQ-REC-005`, `REQ-REC-006`, `ADR-0009`, `ADR-0029`)

### 5.1 Nivel 2: Respaldo Cifrado del Titular y Custodia Social (`REQ-REC-002`, `REQ-REC-003`, `REQ-REC-004`, `REQ-REC-007`)

1. **Código de Recuperación Autónomo:** Mnemónico estándar de $\ge 128$ bits de entropía (12 palabras) con verificación de suma de control (`SPEC-PIP-BACKUP-001`, `STORAGE_FORMAT.md §7`).
2. **Cifrado de Sobre del Almacén:** Paquete binario autónomo cifrado con `XChaCha20-Poly1305` utilizando la clave derivada mediante `HKDF-SHA256` y sal criptográfica de 128 bits.
3. **Claves de Recuperación Aisladas por Emisor (`REQ-REC-004`, `REQ-REC-007`):**
   - El titular deriva una clave de recuperación asimétrica P-256 única para este emisor:
     $$\text{RecoveryKey}_{\text{Issuer}} = \text{HKDF}(\text{RecoverySecret}, \text{IssuerId})$$
   - El registro de la huella `cnf.rec` en el momento de la emisión (`PROTOCOL.md §2.2`) permite solicitar re-vinculaciones directas sin exponer una identidad global permanente (`INV-02`, `P-09`).
4. **Custodia Social Distribuida Opcional (`REQ-REC-003`, `P-10`):**
   - El titular puede dividir su secreto de recuperación en $n$ fragmentos mediante el esquema Shamir $k$-de-$n$ en $\text{GF}(2^8)$ (`SPEC-PIP-SHAMIR-001`, `STORAGE_FORMAT.md §8`).
   - Ningún custodio individual posee información sobre el secreto maestro ni puede actuar unilateralmente (`REQ-REC-006`, `INV-16`).

### 5.2 Nivel 3: Procedimiento Normativo de Recuperación Institucional (`REQ-REC-005`, `REQ-REC-006`)

Cuando el titular pierde su dispositivo físico y carece de respaldo cifrado o clave de recuperación funcional, el emisor aplica el procedimiento institucional normativo:

1. **Canal de Identificación Fuera de Banda:**
   - El titular debe identificarse fehacientemente ante el emisor (o su red de delegaciones autorizadas) mediante un canal seguro fuera de banda:
     - Cotejo presencial en punto de atención / ventanilla con documento civil oficial válido, O
     - Verificación de identidad federada de alto nivel de seguridad con prueba de vida biométrica activa.
2. **Prohibición Estricta de Correo Electrónico o Custodio Único (`REQ-REC-006`):**
   - **Regla Inviolable:** La recuperación institucional **NUNCA DEBE depender exclusivamente de un mensaje o enlace a correo electrónico (*magic link* / email OTP) ni de SMS.** Un canal de mensajería no autenticado criptográficamente carece de prueba de posesión de identidad y es vulnerable a ataques de intermediario y secuestro de cuenta.
   - La recuperación no puede depender de un único operador o custodio con privilegios discrecionales ilimitados (`P-10`).
3. **Re-emisión y Revocación Atómica por Clase de Dispositivo (`REQ-DEVSLOT-001..004`, `ADR-0029`):**
   - **Identificación de Ranura:** El emisor determina la clase de factor del dispositivo que se reporta como extraviado o sustituido (`device_class`: `mobile`, `card` u `other`).
   - **Revocación Atómica:** El emisor revoca de forma atómica e inmediata el índice anterior (`status_list_index`) de esa clase específica en la `TokenStatusList` (marcando `01 = revocado`), sin alterar las ranuras de otras clases de dispositivo activas para el mismo titular (`REQ-DEVSLOT-003`).
   - **Generación de Nuevas Claves:** El nuevo dispositivo genera un nuevo par de claves P-256 en hardware y presenta su prueba de posesión.
   - **Re-emisión y Anclaje:** El emisor emite la credencial de reemplazo vinculada a la nueva clave pública `cnf` con un nuevo índice de estado, publica el `IssuerStatusManifest` actualizado y ancla la raíz en el registro de confianza (`TrustLedger`) con estricta observancia de `INV-01` e `INV-02`.
