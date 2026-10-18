# `gravital_experience_ui` — Sistema de Diseño Propio Gravital-Experience-UI

> **Especificación normativa:** `docs/specs/GRAVITAL_EXPERIENCE_UI.md` (`SPEC-PIP-UI-001`)  
> **Decisión arquitectónica:** `docs/adr/0030-sistema-diseno-gravital-experience-ui-flutter.md` (`ADR-0030`)  
> **Requisitos trazados:** `REQ-UI-001`, `REQ-UI-002`, `REQ-UI-003`, `REQ-UI-004`

Paquete compartido de interfaz de usuario Flutter basado en **Material 3 Expressive (M3E)** para el ecosistema **Gravital ID**.

## Arquitectura de 5 Capas

1. **Capa 5 — Pantallas de aplicación (`apps/reference-wallet/`)**: importan exclusivamente `package:gravital_experience_ui/gravital_experience_ui.dart`.
2. **Capa 4 — Componentes y patrones de dominio**: `GxCredentialCard`, `GxDisclosureConsentSheet`, `GxVerificationResultCard`, `GxDeviceSlotCard`, `GxTenantAccessCard`, `GxAdaptiveScaffold`, `StatusChip`, `MoneyText`.
3. **Capa 3 — Fábrica de tema (`GxTheme`, `SemanticColors`, `EmphasizedTextTheme`)**: armonización tonal HCT (`#0B57D0`), 6 roles semánticos de dominio y mapeo inmutable de los 4 estados de `VerificationResult`.
4. **Capa 2 — Adaptadores expresivos M3E**: `GxSplitButton`, `GxButtonGroup`, `GxFloatingToolbar`, `GxLoadingIndicator`, `GxSpringScale`.
5. **Capa 1 — Tokens fundacionales**: `GxSpace`, `GxShape` (10 niveles), `GxMotion` (`SpringDescription.withDampingRatio`) y `WindowClass`.
