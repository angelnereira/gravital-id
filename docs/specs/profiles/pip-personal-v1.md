# Perfil PIP: Personal v1 (`pip-personal-v1`)

> **Identificador normativo:** `pip-personal-v1`  
> **Versión:** `1.0.0-draft` (Fase F0 / Tarea `F0.T15`)  
> **Estado:** Normativo / En revisión  
> **Trazabilidad:** REQ-CRED-004, REQ-REC-005; `ARCHITECTURE.md §16`

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

## 5. Procedimiento de Respaldo y Recuperación (Nivel 2)

* **Código de Recuperación:** Mnemónico BIP-39 de 12 palabras (128 bits de entropía).
* **Cifrado de Respaldo:** El almacén se cifra con `XChaCha20-Poly1305` utilizando una clave derivada con `Argon2id` ($m=32\,\text{MiB}, t=2, p=2$).
* **Re-vinculación con Emisor:** Opcional. El titular puede registrar una clave de recuperación derivada del secreto maestro ante el emisor en el momento de la emisión.
