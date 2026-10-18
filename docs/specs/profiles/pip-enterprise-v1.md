# Perfil PIP: Empresarial v1 (`pip-enterprise-v1`)

> **Identificador normativo:** `pip-enterprise-v1`  
> **Versión:** `1.0.0` (Fase F8 / Tarea `F8.T09`)  
> **Estado:** Normativo  
> **Trazabilidad:** REQ-CRED-004, REQ-REC-005, REQ-REC-006, REQ-DEVSLOT-001..004, REQ-REC-004, REQ-REC-007; ADR-0009, ADR-0029; `ARCHITECTURE.md §16`

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

## 5. Procedimiento Normativo de Recuperación Institucional Corporativa (`REQ-REC-005`, `REQ-REC-006`, `REQ-DEVSLOT-003`, `ADR-0009`, `ADR-0029`)

En organizaciones corporativas e infraestructuras críticas, la sustitución de credenciales de acceso físico y lógico no puede depender de decisiones discrecionales ni de factores vulnerables de autoservicio. La re-emisión se gobierna mediante el siguiente procedimiento normativo:

### 5.1 Protocolo de Aprobación Dual Obligatoria (Four-Eyes Principle, `REQ-REC-005`, `REQ-REC-006`)

1. **Doble Autorización Independiente:**
   - La re-emisión y re-vinculación de una credencial `pip-enterprise-v1` tras la pérdida, robo o renovación de soporte exige la aprobación concurrente de **dos entidades corporativas independientes**:
     1. **Administrador de Identidad Corporativa (IAM / Directorio):** Valida la identidad corporativa del empleado en el directorio central (Active Directory, Okta, SCIM), su estado laboral activo y la matrícula del nuevo dispositivo.
     2. **Supervisor Directo o Responsable de Seguridad (CISO / SOC):** Autoriza expresamente la concesión de los niveles de autorización (`security_clearance`) y zonas de acceso (`authorized_zones`).
2. **Mitigación de Amenazas Internas (`P-10`):**
   - Esta regla de doble control impide que una única credencial administrativa comprometida o un operador interno desleal pueda emitir unilateralmente credenciales de acceso físico o permisos de infraestructura a dispositivos no autorizados (`INV-16`).

### 5.2 Prohibición Expresa de Correo Electrónico como Factor Único (`REQ-REC-006`)

1. **Prohibición de Reseteo por Email:**
   - **Regla Inviolable:** Queda **estrictamente prohibida la recuperación desasistida o re-vinculación de credenciales corporativas mediante enlaces web enviados al correo electrónico corporativo (*magic links* / email OTP) ni mediante SMS.** La cuenta de correo no constituye una prueba criptográfica de posesión de identidad y suele ser el primer vector comprometido ante ataques de ingeniería social o compromiso de cuenta (*business email compromise*).

### 5.3 Gestión de Dispositivos MDM y Atestación de Silicio Institucional (`ADR-0029`)

1. **Enrolamiento en MDM/EDR Corporativo:**
   - El nuevo dispositivo debe estar registrado y validado en la plataforma de gestión de movilidad corporativa (MDM).
2. **Atestación de Hardware de Dispositivo:**
   - En teléfonos móviles gestionados (*Device Owner*), el dispositivo presenta la cadena de atestación de hardware (`Key Attestation`) extrayendo el **IMEI verificado por silicio en el TEE** (`AttestationRecord`).
   - El emisor corporativo registra el compromiso ciego `HardwareDeviceTag = HMAC_HSM(attested_imei_or_key_id)` para asegurar que el silicio pertenece a la flota corporativa (`INV-02`).
   - En estaciones de trabajo o servidores, la clave reside en TPM 2.0 o HSM corporativo.

### 5.4 Revocación Atómica y Propagación Inmediata a Lectores Offline (`REQ-DEVSLOT-001..004`, `REQ-STAT-004`)

1. **Revocación Atómica de Ranura:**
   - El emisor corporativo revoca inmediatamente el índice anterior (`status_list_index`) asignado al soporte extraviado en la `TokenStatusList` corporativa (marcando `01 = revocado`), sin invalidar las ranuras de otras clases de soporte (`mobile`, `card`, `other`) si el empleado cuenta con una tarjeta física de acceso (`REQ-DEVSLOT-003`).
2. **Despliegue Inmediato en Relays Locales:**
   - El emisor publica de inmediato un nuevo `IssuerStatusManifest` y lo distribuye a los puntos de acceso, torniquetes y cerraduras electrónicas desconectadas vía relay local.
   - En cuanto los lectores perimetrales actualizan el snapshot, cualquier intento de acceso con el soporte anterior produce `VerificationResult::Invalid` (`GID-E4005`), protegiendo el perímetro de la organización de forma autónoma y sin conexión a Internet centralizada (`INV-01`).
3. **Re-emisión:**
   - Se emite la nueva credencial `pip-enterprise-v1` vinculada a la nueva clave pública `cnf` de hardware y se entrega al dispositivo corporativo.
