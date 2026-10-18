# ADR-0027: Autenticación multi-inquilino (Multi-Tenant), portabilidad consentida de datos y credenciales de rol por aplicación

- **Estado:** Aceptado
- **Fecha:** 2026-10-18
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira (2026-10-18)
- **Issue:** #101
- **Requisitos y principios afectados:** REQ-TENANT-001, REQ-TENANT-002, REQ-TENANT-003, REQ-TENANT-004, REQ-PRES-001, REQ-PRES-003, REQ-PRES-007, REQ-CRED-004; P-01, P-02, P-03, P-05, P-09, P-11; INV-01, INV-02, INV-03, INV-04, INV-05
- **Fase:** F19 / F10 / F24

---

## Contexto

Gravital ID debe poder ser consumido por múltiples aplicaciones, sistemas empresariales, plataformas SaaS y servicios gubernamentales como la **llave unificada de acceso e identificación de usuarios**, permitiendo:
1. **Reutilización y portabilidad de identidad entre sistemas (Multi-Tenancy):** Un usuario que ya posee un Gravital ID puede ingresar a cualquier aplicación o sistema compatible y portar únicamente los atributos verificados que decida compartir con ese sistema, sin rellenar formularios manuales ni pasar por un proceso KYC repetido.
2. **Integridad consistente del sujeto dentro de cada inquilino (`Tenant`):** Cuando un mismo usuario vuelve a iniciar sesión en el sistema $X$ (ya sea desde su teléfono móvil o desde su tarjeta física tipo Visa, o tras haber recuperado su dispositivo), el sistema $X$ debe poder reconocer de forma determinista y criptográfica que se trata exactamente del mismo usuario titular de su cuenta e historial en dicho inquilino.
3. **Gestión de roles y permisos por aplicación o sistema:** Un usuario tiene distintos roles y niveles de autorización según la aplicación o inquilino (p. ej. `admin` en el sistema ERP de la Empresa A, `paciente` en el portal de la Clínica B, `cajero` en el POS del Comercio C). El usuario debe poder ver en su billetera a qué aplicaciones está vinculado, qué datos les ha compartido y qué roles ostenta en cada una, pudiendo incluso demostrar esos roles offline ante terminales del inquilino.
4. **Auto-alojamiento del servicio en el backend de la aplicación integradora (`Tenant Gateway`):** Cualquier servidor o aplicación debe poder alojar entre sus propios servicios el módulo de Gravital ID para:
   - Permitir el ingreso y portabilidad a usuarios que **ya tienen un Gravital ID creado**.
   - Permitir **crear un nuevo Gravital ID** a usuarios que aún no lo tienen, verificando previamente su documento nacional contra duplicidades (`ADR-0028`).

Existe una tensión aparente entre esta necesidad y `ARCHITECTURE.md §1.2` (*"PIP no es un IdP centralizado"*) y `§7.1` (*"No existe un identificador global del titular"*). Si un servidor central en la nube autenticara cada login de cada app, rompería `INV-01` (operación offline), `P-09` (sin *phone-home*) y `P-10` (sin puntos únicos de fallo).

---

## Opciones consideradas

### Opción A — Convertir Gravital ID en un servidor OAuth2/OIDC centralizado único con un UUID global por persona en la blockchain

- **Ventajas:** Fácil de entender como un login social tradicional ("Login with Google/Auth0").
- **Inconvenientes:**
  - **Viola frontalmente `INV-01`, `INV-02`, `P-01`, `P-02`, `P-09` y `P-10`:** Requiere conexión permanente al servidor central, impide verificar accesos o roles offline, y publica o expone un identificador global correlacionable entre todas las organizaciones sin control del usuario.
- **Riesgos:** Punto único de fallo y vulneración de la Ley 81 de 2019 (rechazada).

---

### Opción B — Centralización en el portador del titular + `TenantSubjectId` consistente por inquilino + Credenciales de Rol (`pip-tenant-role-v1`) + Módulo Auto-alojable (`Tenant Gateway`) (Recomendada)

Resolver la necesidad manteniendo el 100 % de los invariantes del protocolo mediante cuatro mecanismos:

1. **Identidad centralizada en el Titular, verificada localmente en cada Sistema (`Tenant Gateway`):**
   - La "centralización" de la identidad ocurre en la **bóveda portable del usuario** (su teléfono móvil y su tarjeta física sincronizados), nunca en una base de datos central ajena.
   - Cada aplicación, sistema o servidor aloja su propia instancia del SDK/servicio de Gravital ID (`gravital-id-sdk` / `pip-issuer-service` en modo `TenantGateway`), que verifica presentaciones localmente (offline u online) contra el `TrustBundle` sin llamar a servidores centrales.
2. **Integridad consistente de usuario por inquilino (`TenantSubjectId`):**
   - Para que una aplicación o inquilino (`tenant_id` / `verifier_id`) identifique de manera inequívoca y consistente al mismo usuario a través del tiempo y entre sus dispositivos autorizados (móvil y tarjeta física, `ADR-0029`):
     - La wallet deriva o presenta un identificador seudónimo específico de ese inquilino (`tenant_subject_id`), calculado deterministamente como:
       $$\text{tenant\_subject\_id} = \text{Base64Url}(\text{HMAC-SHA256}(\text{holder\_root\_secret},\ \text{"gid-tenant-sub-v1"} \parallel \text{tenant\_id}))$$
       o bien respaldado por el vínculo criptográfico de re-vinculación del emisor para ese `tenant_id`.
     - **Resultado:** Para el Sistema $X$ (`tenant_id = "https://app.sistema-x.pa"`), el usuario tiene siempre el mismo `tenant_subject_id` inmutable (manteniendo la integridad de su cuenta, inquilino y datos en ese sistema incluso si presenta desde su tarjeta o tras recuperar su teléfono). Al mismo tiempo, dos aplicaciones independientes sin relación no pueden correlacionar silenciosamente sus bases de datos a espaldas del usuario (`P-09`).
3. **Consentimiento por Aplicación y Registro de Portabilidad en la Wallet (`REQ-TENANT-002`):**
   - Cuando una app solicita acceso o portabilidad de datos, envía una consulta `DCQL` firmada con su clave de verificador/inquilino registrada.
   - El titular elige exactamente qué atributos compartir (`given_name`, `family_name`, `document_number`, `email`, etc.).
   - La wallet guarda en su almacenamiento local cifrado (`gravital-id-storage`) el **registro de relación con el inquilino (`TenantRelationshipRecord`)**: qué app es, cuándo se conectó, cuál es su `tenant_subject_id`, qué atributos consintió compartirle y qué roles tiene en ella, permitiendo al usuario auditar o revocar el vínculo desde su app Flutter.
4. **Credenciales Verificables de Rol y Membresía por Inquilino (`pip-tenant-role-v1`, `REQ-TENANT-003`):**
   - Se define el perfil/esquema `urn:gravital-id:vct:pip-tenant-role-v1` (especificado en `docs/specs/profiles/pip-tenant-role-v1.md`).
   - Una vez que un usuario ingresa a un sistema/inquilino con su Gravital ID, el servidor de ese sistema puede emitir a la wallet del usuario una credencial firmada de rol que contiene:
     - `tenant_id`, `tenant_name`, `app_id`, `tenant_subject_id`
     - `roles`: lista de roles en ese sistema (p. ej. `["tenant_admin", "approver", "operator"]`)
     - `permissions` / `scopes`: permisos granulares (p. ej. `["invoices:write", "vault:read"]`)
     - `authorized_resources` / `zones`: recursos o zonas físicas/lógicas autorizadas
     - `status`: puntero a la `Token Status List` del inquilino para revocación o suspensión inmediata del rol.
   - Así, el usuario no solo usa su Gravital ID para iniciar sesión en línea, sino que puede presentar su credencial de rol **100 % offline** ante cualquier microservicio, lector NFC o terminal del inquilino.
5. **Flujo Dual en el Servicio Auto-alojable (`REQ-TENANT-004`):**
   - El módulo auto-alojado en el servidor de la app expone dos flujos estándar:
     - **Flujo `SignInWithGravitalId` (Usuario existente):** Verifica la presentación del Gravital ID existente (vía **NFC `GID-APDU`**, **Passkey / WebAuthn CTAP2**, QR offline, OID4VP o `SessionCode` de 10 dígitos), recibe los atributos portados con consentimiento y activa la sesión del usuario en el inquilino.
     - **Flujo `CreateOrRecoverGravitalId` (Usuario nuevo):** Invoca el validador de identidad nacional del país correspondiente (`ADR-0028`), comprueba en el registro de unicidad que ese documento nacional no tenga ya un Gravital ID activo (si ya lo tiene, redirige a recuperación/re-vinculación para evitar duplicados) y, si es nuevo, emite y aprovisiona el Gravital ID en el dispositivo del usuario.
6. **Transmisión de Credenciales vía NFC (`GID-APDU`) y vía Passkey (`FIDO2 / WebAuthn`):**
   - **Vía NFC (`GID-APDU` ISO/IEC 7816-4, `ADR-0022`, `PROTOCOL.md §7.4`):** La aplicación móvil transmite la presentación SD-JWT+KB-JWT cifrada con HPKE sobre APDU (`AID = F0475241564954414C01`, comandos `SELECT`, `VERIFY PIN`, `ENVELOPE`, `GET RESPONSE`) operando tanto en modo **Emulación de Tarjeta (Android HCE)** frente a terminales de acceso físico como en modo **Lector/Transceptor ISO 14443-4** para interactuar con tarjetas físicas tipo Visa Java Card.
   - **Vía Passkey (`FIDO2 / WebAuthn Level 3` + `CTAP2`):** La aplicación permite presentar y transmitir credenciales vinculadas a una **Passkey (`ES256` P-256)** mediante `CredentialManager` (Android), `ASAuthorizationPlatformPublicKeyCredentialProvider` (iOS/macOS) o llaves de seguridad FIDO2 por NFC/USB/BLE. La aserción WebAuthn (`AuthenticatorAssertionResponse`) fija `clientDataJSON.challenge = Base64UrlNoPad(SHA-256(transcript_hash || sd_hash))`, ligando criptográficamente la autenticación sin contraseña del navegador/sistema con las divulgaciones selectivas `_sd` y el `KB-JWT` de Gravital ID.

---

## Decisión

Se adopta la **Opción B**:
1. Incorporar el modelo de **Identificación Multi-Inquilino con `TenantSubjectId` consistente**, **Registro de Portabilidad por App en la Wallet**, **Credenciales de Rol por Aplicación (`pip-tenant-role-v1`)** y **Transmisión nativa vía NFC (`GID-APDU`) y Passkey (`FIDO2 / WebAuthn`)**.
2. Definir el modo de despliegue auto-alojable (`Tenant Gateway` sobre `gravital-id-sdk` y `pip-issuer-service`) con el flujo dual de **ingreso con Gravital ID existente** y **creación verificada sin duplicidad**.
3. Incorporar los requisitos `REQ-TENANT-001` a `REQ-TENANT-004` en `docs/REQUIREMENTS.md`.

---

## Consecuencias

- **Positivas:**
  - Convierte a Gravital ID en una llave universal de acceso y portabilidad para cualquier ecosistema de apps, SaaS o gobierno, manteniendo la integridad del usuario en cada sistema sin crear un punto único de fallo ni exponer PII en la blockchain.
  - Los roles emitidos como credenciales SD-JWT VC permiten control de acceso basado en roles (RBAC) verificable tanto en línea (vía Passkey/OID4VP) como **sin conexión a Internet** (vía NFC `GID-APDU` o QR).
- **Negativas y cómo se mitigan:**
  - Requiere que la wallet almacene el `holder_root_secret` en su respaldo cifrado para que el `tenant_subject_id` se mantenga idéntico tras recuperar un dispositivo perdido. *Mitigación:* Ya contemplado en el respaldo cifrado de `ADR-0009` (`F8.T01`).
- **Cambios necesarios en documentación:**
  - Actualizar `docs/ARCHITECTURE.md`, `docs/REQUIREMENTS.md`, `docs/ROADMAP.md`, `docs/specs/PROTOCOL.md` y crear `docs/specs/profiles/pip-tenant-role-v1.md`.

