# `apps/reference-wallet` — Gravital ID Reference Wallet & Multi-Tenant Hub (Flutter)

> **Sistema de diseño obligatorio:** [`docs/specs/GRAVITAL_EXPERIENCE_UI.md`](../../docs/specs/GRAVITAL_EXPERIENCE_UI.md) (`Gravital-Experience-UI`, `ADR-0030`)  
> **Arquitectura multi-inquilino, unicidad ciudadana y ranuras por dispositivo:** `ADR-0027`, `ADR-0028`, `ADR-0029`  
> **Trazabilidad:** `REQ-UI-001..004`, `REQ-TENANT-001..004`, `REQ-UNIQ-001..004`, `REQ-DEVSLOT-001..004`, `REQ-PRES-003`, `REQ-IDDOC-001..003`, `REQ-CODE-002`

Aplicación multiplataforma en **Flutter** que permite al titular:

1. **Ver y gestionar su bóveda de credenciales (`Credenciales`)**:
   - Cédula de Identidad Personal Oficial (`urn:gravital-id:vct:pip-identity-official-v1`, Tribunal Electoral de Panamá — Decreto N.° 43 de 2024),
   - Identidad Derivada Verificada por SVI (`urn:gravital-id:vct:pip-identity-derived-v1`),
   - Credencial Financiera KYC (`urn:gravital-id:vct:pip-financial-v1`),
   - Credenciales de Rol y Acceso por Inquilino (`urn:gravital-id:vct:pip-tenant-role-v1`).
   - Registro / Onboarding con validación del formato canónico de cédula panameña y detección de duplicidad mediante etiqueta ciega `UniquenessTag` (**VOPRF RFC 9497**, rechazo `GID-E2010` sin exponer PII en ledger).
2. **Presentar, compartir y acreditar accesos (`Presentar`)**:
   - Código QR Offline (`Base45 + DEFLATE`, bloqueando automáticamente el retrato en QR con `GID-E8002`),
   - Proximidad NFC (`GID-APDU` + sobre cifrado HPKE),
   - Código Numérico de Sesión de 10 dígitos con dígito verificador **Damm** (`SessionCode`, `ADR-0025`, rechazo `GID-E8010`).
   - Consentimiento interactivo en dos pasos (`prepare_presentation` $\to$ `confirm_presentation`) y visor de los **4 estados** de `VerificationResult` (`Valid`, `ValidWithStaleStatus`, `Unverifiable`, `Invalid`).
3. **Centralizar el acceso a sistemas e inquilinos, portar datos y gestionar roles (`Apps y Roles`)**:
   - Flujo dual **"Ingresar con Gravital ID existente"** vs **"Crear nuevo Gravital ID"**,
   - Identificador seudónimo consistente por inquilino (`TenantSubjectId`),
   - Control granular por el usuario de qué atributos comparte y porta entre aplicaciones, y visualización de roles/permisos verificables (`pip-tenant-role-v1`).
4. **Gestionar soportes físicos bajo la regla de ranura única por clase (`Soportes`)**:
   - Máximo **1 Teléfono Móvil** (`StrongBox`/`Secure Enclave` + `Key Attestation` / `IMEI` en modo MDM),
   - Máximo **1 Tarjeta Física Tipo Visa** (`Java Card 3.0.5+` con número de serie `CPLC` y PIN de Nivel 1),
   - Máximo **1 Otro Dispositivo Compatible** (`FIDO2` / `PKCS#11`),
   - Rechazo inmediato de un segundo dispositivo del mismo tipo (`GID-E2011`) y reemplazo atómico con revocación independiente en `Token Status List`.
