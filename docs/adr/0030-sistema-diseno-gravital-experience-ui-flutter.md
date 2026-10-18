# ADR-0030: Sistema de diseño propio "Gravital-Experience-UI" y arquitectura de aplicaciones Flutter

- **Estado:** Aceptado
- **Fecha:** 2026-10-18
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira (2026-10-18)
- **Issue:** #101
- **Requisitos y principios afectados:** REQ-UI-001, REQ-UI-002, REQ-UI-003, REQ-UI-004, REQ-PRES-003, REQ-PORT-001; P-05, P-09, P-11, P-12; INV-02, INV-04, INV-15
- **Fase:** F11 / F19

---

## Contexto

El ecosistema Gravital ID incluye aplicaciones de cara al usuario y al operador (`apps/reference-wallet`, `apps/reference-verifier`, `apps/issuer-console`) y debe integrarse visualmente con toda la suite de aplicaciones de la organización. Para garantizar coherencia absoluta, accesibilidad WCAG 2.2 AA, rendimiento de 60/120 Hz y cero deuda visual, el mantenedor ha definido un plano normativo de diseño de interfaces en Flutter basado en la geometría, color tonal HCT, tipografía `Google Sans Flex` y física de resortes de Material 3 Expressive, y ha instruido institucionalizarlo bajo el nombre propio **"Gravital-Experience-UI"**.

Asimismo, se requiere construir la aplicación Flutter de Gravital ID (`apps/reference-wallet`) que permita al usuario:
- **Ver** todas sus credenciales verificables (Cédula/Identidad oficial o derivada con retrato, Financiera, Empresarial, Personal) y los detalles de cada una.
- **Compartir y mostrar** sus credenciales para accesos presenciales o remotos mediante **QR offline**, **Toque sin contacto NFC (`GID-APDU`)** y **Código numérico efímero de 10 dígitos (`SessionCode` Damm)**, con consentimiento de divulgación selectiva en dos pasos (`REQ-PRES-003`).
- **Portar** su identidad y datos hacia otros servicios, aplicaciones e inquilinos (*tenants*), visualizando qué datos comparte con cada aplicación y **qué roles y permisos** ostenta en cada sistema (`ADR-0027`).
- **Gestionar y visualizar sus dispositivos vinculados por clase (`ADR-0029`)**: su Teléfono Móvil activo, su Tarjeta Física tipo Visa activa y otros dispositivos compatibles, garantizando que nunca existan dos dispositivos activos del mismo tipo, además del estado de verificación de unicidad ciudadana ante el **Tribunal Electoral de Panamá** (`ADR-0028`).

---

## Decisión

1. **Institucionalizar el sistema de diseño "Gravital-Experience-UI" (`SPEC-PIP-UI-001`):**
   - Incorporar la especificación normativa completa en `docs/specs/GRAVITAL_EXPERIENCE_UI.md`.
   - Añadir la regla obligatoria en `AGENTS.md §9.5` y los requisitos `REQ-UI-001` a `REQ-UI-004` en `docs/REQUIREMENTS.md`: toda interfaz Flutter del repositorio **DEBE** construirse exclusivamente sobre el paquete compartido `gravital_experience_ui` (`packages/gravital_experience_ui/`), sin colores, radios, espaciados ni duraciones literales en las pantallas.
2. **Crear el paquete compartido `packages/gravital_experience_ui/`:**
   - **Capa 1 (`tokens/`):** `GxSpace` (retícula de 4 dp), `GxShape` (10 tokens de radio de esquina de `0` a `48 dp` y `full`), `GxMotion` (resortes `Expressive` y `Standard` con `SpringDescription.withDampingRatio`), y `WindowClass` (`compact`, `medium`, `expanded`, `large`, `extraLarge`).
   - **Capa 2 (`theme/`):** `GxTheme` con semilla de marca fija (`#0B57D0`), tipografía `Google Sans Flex` con ejes variables (`wght`, `opsz`) y cifras tabulares, `EmphasizedTextTheme` y `SemanticColors` armonizados en espacio HCT (mapeados también a los 4 estados de `VerificationResult` de `INV-04`).
   - **Capa 3 (`adapters/` y `components/`):** adaptadores expresivos (`GxSplitButton`, `GxButtonGroup`, `GxFloatingToolbar`, `GxLoadingIndicator`, `GxSpringScale`) y componentes de dominio (`MoneyText`, `StatusChip`, `GxCredentialCard`, `GxDisclosureConsentSheet`, `GxDeviceSlotCard`, `GxTenantAccessCard`, `GxVerificationResultCard`).
   - **Capa 4 (`patterns/`):** `GxAdaptiveScaffold` (que conmuta automáticamente entre `NavigationBar` inferior en `compact`, `NavigationRail` en `medium` y doble/triple panel en `expanded+`), `GxEmptyState`, `GxErrorState`, `GxOfflineBanner`.
   - **Capa 5 (`app/`):** `GxApp` con configuración `edgeToEdge`, soporte de temas claro, oscuro y alto contraste (`contrastLevel: 0.0 / 0.5 / 1.0`), y localización español (`es_PA`) / inglés (`en`).
3. **Construir la aplicación Flutter `apps/reference-wallet/` sobre `gravital_experience_ui`:**
   - **Destino 1 — Bóveda (`Credenciales`):** visualización adaptativa (lista + detalle en pantallas anchas) de todas las credenciales del titular (`pip-identity-official-v1` del Tribunal Electoral de Panamá con retrato, `pip-identity-derived-v1`, `pip-financial-v1`, `pip-enterprise-v1`), inspección de claims ocultos con sales `_sd`, estado en la `Token Status List` y flujo para crear/importar credencial con verificación anti-duplicidad SVI.
   - **Destino 2 — Presentar y Accesos (`Compartir / Mostrar`):** selector expresivo de modo de presentación (**QR Offline Base45**, **Toque NFC `GID-APDU`**, **Código de Sesión de 10 dígitos Damm**), hoja de consentimiento de dos pasos (`prepare_presentation` $\to$ selección de atributos $\to$ autenticación biométrica/PIN Nivel 0/1 $\to$ `confirm_presentation`) y simulador del resultado de verificación en los 4 estados (`Valid`, `ValidWithStaleStatus`, `Unverifiable`, `Invalid`).
   - **Destino 3 — Inquilinos, Portabilidad y Roles (`Apps y Roles`):** panel central donde el usuario ve todas las aplicaciones y sistemas a los que ha ingresado con su Gravital ID, su `TenantSubjectId` consistente, qué atributos consintió portar a cada app, qué **roles y permisos** (`pip-tenant-role-v1`) tiene en cada sistema, y flujo para conectar un nuevo servicio/inquilino o revocar acceso.
   - **Destino 4 — Dispositivos y Seguridad (`Soportes y Confianza`):** gestión de la regla de **Ranura Única por Clase de Dispositivo (`ADR-0029`)** mostrando las 3 ranuras (`Teléfono Móvil` con StrongBox/IMEI Attestation, `Tarjeta Física Gravital tipo Visa` con chip Java Card CPLC y PIN, y `Otro Dispositivo Compatible`), demostración interactiva del bloqueo de duplicidad dentro del mismo tipo de dispositivo y reemplazo atómico, estado del `TrustBundle` $k$-de-$n$ y respaldo de recuperación.

---

## Consecuencias

- **Positivas:**
  - Unifica el diseño visual y de interacción de todas las aplicaciones bajo **Gravital-Experience-UI**, con pruebas automatizadas de widgets y accesibilidad en `flutter test`.
  - Materializa de inmediato en una aplicación ejecutable e interactiva todos los flujos de credenciales, accesos, portabilidad multi-inquilino, roles, validación ante el Tribunal Electoral y exclusión de duplicidad por clase de dispositivo.
- **Negativas y cómo se mitigan:**
  - Añade código Dart/Flutter en `packages/gravital_experience_ui/` y `apps/reference-wallet/`. *Mitigación:* Reside en la capa superior `L7` (`PROJECT_STRUCTURE.md §2`), completamente aislado del workspace Cargo de Rust, de modo que `cargo xtask check-layers` y las garantías `no_std` de `L1`–`L3` permanecen intactas.
