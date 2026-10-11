# Especificaciones normativas

Estas especificaciones detallan lo que `ARCHITECTURE.md` define a alto nivel. Se redactan en la fase F0 (`ROADMAP.md §5`) y son requisito del gate G0. Hasta entonces, **no existe autorización para implementar** el área correspondiente.

| Especificación | Contenido | Tarea | Estado |
|---|---|---|---|
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Activos, actores, fronteras, STRIDE, LINDDUN, mitigaciones ↔ REQ | F0.T05 | Redactada (v0.1.0-draft) |
| [`CRYPTO_PROFILES.md`](CRYPTO_PROFILES.md) | Algoritmos, versiones fijadas de estándares, parámetros y límites | F0.T06 | Redactada (v0.1.0-draft) |
| [`PROTOCOL.md`](PROTOCOL.md) | Flujos, mensajes, máquinas de estado, errores de protocolo | F0.T12 | Redactada (v0.1.0-draft) |
| [`TRUST_BUNDLE.md`](TRUST_BUNDLE.md) | Raíz de confianza, bundle multi-firma, derivación determinista, manifiesto de estado, validación, anti-rollback, rotación | F0.T13 | Redactada (v0.1.0-draft) |
| [`CONTRACTS.md`](CONTRACTS.md) | Funciones, roles, eventos, invariantes, migración | F0.T14 | Redactada (v0.1.0-draft) |
| [`profiles/pip-personal-v1.md`](profiles/pip-personal-v1.md) | Perfil personal | F0.T15 | Redactada (v1.0.0-draft) |
| [`profiles/pip-financial-v1.md`](profiles/pip-financial-v1.md) | Perfil financiero | F0.T15 | Redactada (v1.0.0-draft) |
| [`profiles/pip-enterprise-v1.md`](profiles/pip-enterprise-v1.md) | Perfil empresarial | F0.T15 | Redactada (v1.0.0-draft) |
| [`SDK_API.md`](SDK_API.md) | API pública e interfaces del host | F0.T16 | Redactada (v0.1.0-draft) |
| [`ERROR_CODES.md`](ERROR_CODES.md) | Catálogo de códigos `PIP-Exxxx` | F0.T16 | Redactada (v0.1.0-draft) |
| [`STORAGE_FORMAT.md`](STORAGE_FORMAT.md) | Formato de almacenamiento local y migraciones | F0.T17 | Redactada (v0.1.0-draft) |
| [`TRUST_FRAMEWORK.md`](TRUST_FRAMEWORK.md) | Gobernanza técnica (v0.1) y legal (v1, F14) | F0.T18 / F14.T04 | Redactada técnica v0.1 (legal F14) |
| [`TEST_STRATEGY.md`](TEST_STRATEGY.md) | Estrategia de pruebas y umbrales por gate | F0.T19 | Redactada (v0.1.0-draft) |

Reglas: cada especificación declara versión, estado y requisitos que concreta; los cambios siguen `AGENTS.md §12`.
