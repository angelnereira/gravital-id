# Perfil PIP: Empresarial v1 (`pip-enterprise-v1`)

> **Identificador normativo:** `pip-enterprise-v1`  
> **Versión:** `1.0.0-draft` (Fase F0 / Tarea `F0.T15`)  
> **Estado:** Normativo / En revisión  
> **Trazabilidad:** REQ-CRED-004, REQ-REC-005; `ARCHITECTURE.md §16`

---

## 1. Alcance y Casos de Uso

El perfil `pip-enterprise-v1` está diseñado para la gestión de accesos corporativos, autorización entre servicios (S2S), control de presencia física e interoperabilidad B2B:
* Credenciales de empleado y pases de acceso físico (torniquetes / puertas con lectores offline).
* Delegación de roles y permisos de administración de infraestructura en la nube.
* Tokens de servicio máquina-a-máquina (M2M / S2S) integrables con microservicios y gateways (Band-All, Gravital-Talk).
* Acreditaciones de contratistas y proveedores auditados.

---

## 2. Parámetros Técnicos del Perfil

| Parámetro | Valor Normativo | Justificación |
|---|---|---|
| **Formato de Credencial** | SD-JWT VC (`typ: dc+sd-jwt`) | RFC 9901 y `draft-ietf-oauth-sd-jwt-vc-19`. |
| **Algoritmo de Firma** | `ES256` (P-256 + SHA-256) | Estándar de infraestructura. |
| **Almacenamiento de Clave de Titular** | Hardware preferido en puestos de trabajo; HSM/software en servidores | Adaptabilidad a entornos de servidor, microservicios y móviles corporativos. |
| **Exportación de Clave en Migración** | Según política interna corporativa (MDM / IAM) | Control centralizado de la flota de dispositivos. |
| **Frescura Máxima de Estado** | 8 horas (duración estándar de turno laboral) | Bloqueo ágil de accesos en caso de despido o incidente de seguridad. |
| **Modo de Token Status List** | 2 bits (`00 = activo`, `01 = revocado`, `10 = suspendido`) | Soporte para suspensiones laborales o vacaciones. |
| **Protección contra Replay** | Obligatoria (KB-JWT con `nonce` e `iat`) | Prevención de clonación y ataques de repetición en lectores físicos. |
| **Solicitud de Verificador Firmada** | **Obligatoria** | Los puntos de acceso deben identificarse como lectores autorizados. |
| **Emisión por Lotes** | Opcional | Típicamente gestionado por aprovisionamiento continuo SCIM / IdP. |

---

## 3. Esquema JSON Canónico de Referencia

Ejemplo para credencial de acceso corporativo / empleado:
* `vct`: `https://credentials.gravital.io/vct/enterprise/employee-v1`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "employee_id": { "type": "string" },
    "organization_id": { "type": "string" },
    "department": { "type": "string" },
    "job_title": { "type": "string" },
    "security_clearance": { "type": "string", "enum": ["confidential", "secret", "top_secret"] },
    "authorized_zones": {
      "type": "array",
      "items": { "type": "string" }
    },
    "valid_until": { "type": "string", "format": "date-time" }
  },
  "required": ["employee_id", "organization_id", "security_clearance", "authorized_zones"]
}
```

---

## 4. Política de Retención y Auditoría Corporativa

1. **Lectores de Acceso Físico (Puntos de Entrada Desconectados):** Verifican la credencial contra el `TrustBundle` local en milisegundos sin llamadas de red; registran el evento de acceso con firma y timestamp en una cola local protegida con AEAD.
2. **Sincronización Periódica:** Los eventos de acceso se vuelcan al sistema SIEM corporativo mediante sincronización de sobres cifrados HPKE cuando se restablece la conectividad.

---

## 5. Procedimiento de Recuperación y Ciclo de Vida

* **Aprovisionamiento y Baja:** La gestión del ciclo de vida se integra con los directorios corporativos de la organización (Active Directory, Okta, LDAP).
* **Baja Inmediata:** La revocación de un empleado actualiza la Token Status List corporativa en el CDN/relay y emite un nuevo `IssuerStatusManifest`.
* **Reemplazo de Dispositivo:** El administrador empresarial invalida la credencial anterior y aprovisiona una nueva credencial al dispositivo enrolado en el MDM.
