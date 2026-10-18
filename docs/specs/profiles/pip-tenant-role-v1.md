# Perfil PIP: Autenticación Multi-Inquilino, Portabilidad y Roles por Aplicación v1 (`pip-tenant-role-v1`)

> **Identificador normativo:** `pip-tenant-role-v1`  
> **Versión:** `1.0.0`  
> **Estado:** Normativo  
> **Fecha:** 2026-10-18  
> **Trazabilidad:** REQ-TENANT-001, REQ-TENANT-002, REQ-TENANT-003, REQ-TENANT-004, REQ-UNIQ-001..004, REQ-DEVSLOT-001..004, REQ-REC-005, REQ-REC-006, REQ-REC-004, REQ-REC-007, REQ-CRED-004, REQ-PRES-003; ADR-0009, ADR-0027, ADR-0028, ADR-0029; `ARCHITECTURE.md §7, §16, §18`

---

## 1. Alcance y Propósito

El perfil `pip-tenant-role-v1` define cómo otros servicios, plataformas SaaS, aplicaciones móviles/web y sistemas institucionales consumen **Gravital ID** como llave unificada de identificación de usuarios, alojamiento de inquilinos (*multi-tenancy*), portabilidad consentida de atributos y asignación de roles verificables:

1. **Identificación consistente de usuario por inquilino (`TenantSubjectId`):** Permite que un sistema reconozca siempre al mismo titular de forma determinista e íntegra, independientemente de si ingresa con su teléfono móvil o con su tarjeta física tipo Visa.
2. **Portabilidad controlada por el titular:** El usuario decide qué datos verificados de su Gravital ID comparte con cada aplicación al iniciar sesión o vincularse a un inquilino.
3. **Credenciales de Rol y Autorización por Aplicación (`urn:gravital-id:vct:pip-tenant-role-v1`):** Permite que el sistema anfitrión emita al usuario una credencial verificable con sus roles, permisos y alcances en esa aplicación, verificable tanto en línea como **100 % offline**.
4. **Servicio Auto-alojable (`Tenant Gateway`) con Flujo Dual:** Permite a cualquier servidor o app alojar el módulo de Gravital ID para aceptar usuarios con Gravital ID previo o registrar usuarios nuevos validando la no-duplicidad ciudadana ante el organismo nacional correspondiente (p. ej. el **Tribunal Electoral de Panamá** vía SVI, `ADR-0028`).

---

## 2. Parámetros Técnicos del Perfil

| Parámetro | Valor Normativo | Justificación |
|---|---|---|
| **Identificador `vct`** | `urn:gravital-id:vct:pip-tenant-role-v1` | Distingue inequívocamente una credencial de rol/membresía de inquilino de una credencial de identidad civil (`pip-identity-v1`). |
| **Formato de Credencial** | SD-JWT VC (`typ: dc+sd-jwt`) | RFC 9901 + `draft-ietf-oauth-sd-jwt-vc`. |
| **Algoritmo de Firma** | `ES256` (ECDSA P-256 + SHA-256) | Estándar universal en HSM/KMS de servidores y chips seguros móviles/tarjetas. |
| **Vinculación del Titular (`cnf`)** | Clave P-256 en hardware de la ranura activa (`mobile`, `card` u `other`, `ADR-0029`) | Garantiza prueba de posesión en cada acceso. |
| **Derivación de `tenant_subject_id`** | `Base64UrlNoPad(HMAC-SHA256(holder_root_secret, "gid-tenant-sub-v1" \|\| tenant_id))` | Mantiene el mismo sujeto dentro del inquilino sin permitir correlación cruzada no autorizada entre inquilinos distintos (`P-09`). |
| **Modo de Token Status List** | 2 bits (`00 = activo`, `01 = revocado`, `10 = suspendido`) | Permite revocar o suspender el acceso/rol de un usuario en un inquilino al instante sin afectar su identidad ciudadana base ni sus roles en otras apps. |
| **Frescura Máxima de Estado** | $\le 4\text{ horas}$ (operaciones estándar de app) · En línea o $\le 15\text{ min}$ (operaciones administrativas críticas) | Control ágil de bajas de permisos en sistemas empresariales. |
| **Solicitud Firmada del Verificador** | **Obligatoria (`REQ-PRES-007`)** | La wallet valida criptográficamente qué aplicación/inquilino solicita los datos antes de mostrar la hoja de consentimiento. |

---

## 3. Esquema JSON Canónico (`urn:gravital-id:vct:pip-tenant-role-v1`)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "tenant_id": { "type": "string", "format": "uri" },
    "tenant_name": { "type": "string" },
    "app_id": { "type": "string" },
    "tenant_subject_id": { "type": "string" },
    "device_class": {
      "type": "string",
      "enum": ["mobile", "card", "other"]
    },
    "roles": {
      "type": "array",
      "items": { "type": "string" },
      "minItems": 1
    },
    "permissions": {
      "type": "array",
      "items": { "type": "string" }
    },
    "work_zones": {
      "type": "array",
      "items": { "type": "string" }
    },
    "organization_unit": { "type": "string" },
    "shared_attributes_manifest": {
      "type": "array",
      "items": { "type": "string" }
    }
  },
  "required": [
    "tenant_id",
    "tenant_name",
    "app_id",
    "tenant_subject_id",
    "device_class",
    "roles"
  ]
}
```

---

## 4. Flujo Dual del Servicio Auto-alojado (`Tenant Gateway`)

Cuando una aplicación o servidor integra Gravital ID (`gravital-id-sdk` / `pip-issuer-service`), expone en su puerta de entrada dos flujos normativos:

### 4.1 Flujo A: Usuario con Gravital ID Previamente Creado (`SignIn & Port Data`)
1. La app genera una `VerificationRequest` firmada con su `tenant_id` pidiendo los claims requeridos por el sistema (vía QR, NFC, OID4VP o `SessionCode` de 10 dígitos).
2. La wallet del titular verifica la firma de la app contra su `TrustBundle` local y presenta al usuario la hoja de consentimiento (`GxDisclosureConsentSheet`), indicando qué atributos se solicitan y qué roles se asociarán.
3. El usuario selecciona qué datos comparte y confirma con biometría/PIN (`confirm_presentation`).
4. El servidor de la app verifica localmente el `SD-JWT+KB` (`VerifierPipeline::verify`), asocia los datos recibidos al `tenant_subject_id` del usuario en el inquilino y emite (o actualiza) su credencial `pip-tenant-role-v1` con los roles asignados en esa aplicación.

### 4.2 Flujo B: Creación de Nuevo Usuario con Prevención de Duplicidad (`Create Gravital ID`)
1. El usuario indica su país y documento de identidad (p. ej. Cédula de Identidad Personal en Panamá) y realiza la captura biométrica con prueba de vida.
2. El servidor valida el formato canónico según el `NationalIdProfile` del país y consulta el `IdentityVerificationPort` (en Panamá: el **Servicio de Verificación de Identidad - SVI** del **Tribunal Electoral**, cumpliendo el Decreto N.° 43 de 2024).
3. El sistema calcula el `UniquenessTag` mediante el módulo HSM/VOPRF (`ADR-0028`):
   - **Si ya existe un Gravital ID para ese ciudadano:** se bloquea la creación duplicada (`GID-E2010 CitizenIdentityAlreadyRegistered`) y se ofrece al usuario iniciar sesión con su Gravital ID existente o ejecutar la recuperación/re-vinculación (`F8.T04`).
   - **Si no existe:** se verifica la atestación de hardware del dispositivo para la ranura correspondiente (`mobile`, `card` u `other`, `ADR-0029`), se emite la credencial de identidad (`pip-identity-derived-v1` o `pip-identity-official-v1`) y se vincula al inquilino.

---

## 5. Procedimiento Normativo de Recuperación Institucional y Re-vinculación de Inquilino (`REQ-REC-005`, `REQ-REC-006`, `REQ-DEVSLOT-003`, `ADR-0009`, `ADR-0029`)

Cuando un usuario pierde o reemplaza su soporte físico, la restitución de sus roles y permisos en aplicaciones hospedadas se rige por el siguiente procedimiento normativo:

### 5.1 Soberanía del Inquilino sin Custodio Central (`REQ-REC-006`, `P-10`)

1. **Gestión Descentralizada:** La emisión, suspensión, revocación y re-vinculación de credenciales `pip-tenant-role-v1` es administrada de forma autónoma por cada inquilino a través de su propio módulo emisor (`Tenant Gateway` / `pip-issuer-service`).
2. **Sin Custodia Global:** Ningún operador de red, relay ni tercero centralizado posee claves ni facultades para alterar o transferir roles dentro de un inquilino privado (`INV-03`, `INV-16`).

### 5.2 Prohibición Expresa de Correo Electrónico como Factor Único (`REQ-REC-006`)

1. **Prohibición de Reseteo por Email:**
   - **Regla Inviolable:** La re-vinculación de roles de un inquilino **NUNCA DEBE depender exclusivamente de un mensaje o enlace a correo electrónico (*magic link* / email OTP) ni de SMS.** Un correo electrónico no autentica criptográficamente la posesión del titular y es vulnerable a secuestro de buzón y ataques de ingeniería social.
2. **Factores Autorizados de Re-vinculación:**
   - Para vincular un nuevo dispositivo a su cuenta en el inquilino, el titular debe proporcionar:
     1. **Prueba de Posesión de Identidad Civil:** Presentación de su credencial oficial (`pip-identity-v1`) con firma KB-JWT autenticada en un factor de hardware alternativo activo (p. ej. su tarjeta física tipo Visa o quiosco presencial), O
     2. **Protocolo Criptográfico de Re-vinculación:** Desafío firmado con la clave de recuperación exclusiva del inquilino:
        $$\text{RecoveryKey}_{\text{Tenant}} = \text{HKDF}(\text{RecoverySecret}, \text{TenantId})$$
        registrada ante el inquilino en la emisión inicial (`REQ-REC-004`, `REQ-REC-007`), O
     3. **Aprobación Dual Delegada:** Co-autorización del Administrador del Inquilino y un supervisor de seguridad institucional asignado.

### 5.3 Aislamiento y Revocación Atómica por Ranura (`REQ-DEVSLOT-001..004`, `ADR-0029`)

1. **Aislamiento por Ranura:**
   - Si el usuario sustituye su teléfono móvil (`device_class = "mobile"`), el Tenant Gateway revoca atómicamente el `status_list_index` asignado a esa ranura en la `TokenStatusList` de 2 bits del inquilino (`01 = revocado`).
   - Las credenciales y ranuras del titular en otros dispositivos (p. ej. tarjeta física `"card"`) o en otros inquilinos permanecen totalmente válidas y operativas (`REQ-DEVSLOT-003`).

### 5.4 Continuidad Determinista de Identidad de Inquilino (`TenantSubjectId`, `INV-02`, `P-09`)

1. **Preservación del Sujeto en el Inquilino:**
   - La nueva credencial `pip-tenant-role-v1` re-emitida para el nuevo dispositivo conserva de manera estricta y determinista el mismo:
     $$\text{tenant\_subject\_id} = \text{Base64UrlNoPad}(\text{HMAC-SHA256}(\text{holder\_root\_secret}, \text{"gid-tenant-sub-v1"} \parallel \text{tenant\_id}))$$
   - Esto asegura que los historiales, autorizaciones de base de datos y auditorías internas del sistema anfitrión continúen funcionando sin interrupciones ni desajustes de identidad.
2. **No Correlación Cruzada:**
   - Como $\text{tenant\_subject\_id}$ depende criptográficamente de $\text{tenant\_id}$, dos inquilinos diferentes nunca obtienen el mismo identificador para un mismo titular, preservando la no-correlación (`P-09`) y la ausencia total de datos personales en el registro (`INV-02`).
