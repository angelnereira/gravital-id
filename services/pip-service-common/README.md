# pip-service-common

> **Capa:** Servicios / Infraestructura backend · **Fase:** F7 (F7.T02) · **Requisitos:** `REQ-OBS-001`, `REQ-PRIV-003`, `REQ-REL-001`, `INV-02`

Módulo común compartido para los servicios backend del ecosistema Gravital ID (`pip-indexer`, `pip-trust-service`, `pip-relay`, `pip-issuer-service`).

---

## 1. Responsabilidades

- **Configuración tipada (`config`):** Carga y validación estructurada de parámetros de servidor, base de datos, endpoints EVM y telemetría a partir de variables de entorno y archivos de configuración.
- **Observabilidad y OpenTelemetry (`telemetry`, `REQ-OBS-001`):** Inicialización de `tracing`, propagación de identificadores de traza y métricas estructuradas compatibles con OpenTelemetry Collector.
- **Capa de redacción de logs (`redaction`, `REQ-PRIV-003`, `INV-02`):** Interceptación y sanitización determinista antes de emitir cualquier línea de log o traza. Redacta de forma preventiva:
  - Tokens JWT/JWS completos (`[REDACTED_TOKEN]`).
  - Claves privadas y secretos criptográficos (`[REDACTED_SECRET]`).
  - Correos electrónicos (`[REDACTED_EMAIL]`).
  - Números de teléfono y números de identificación personal (`[REDACTED_PHONE]`, `[REDACTED_ID]`).
- **Comprobaciones de salud (`health`):** Registro de componentes (`HealthRegistry`) y endpoints estándar de monitoreo:
  - `/healthz`: Liveness probe (indica si el proceso está vivo).
  - `/readyz`: Readiness probe (evalúa conectividad activa a base de datos PostgreSQL, nodo RPC o almacenamiento S3).
- **Apagado ordenado (`shutdown`):** Coordinación de señales `SIGINT` / `SIGTERM` con tiempo de gracia para finalizar peticiones en curso.
- **Servidor HTTP integrado (`server`):** Servidor HTTP minimalista y sin dependencias externas pesadas para exponer endpoints de salud y métricas.

---

## 2. Invariantes

- **`INV-02` / `REQ-PRIV-003`:** Ningún dato personal (PII), identificador de titular, credencial en claro o secreto cruza la capa de redacción ni se persiste en logs o métricas.
- **`INV-09`:** `#![forbid(unsafe_code)]` absoluto.
- **`INV-10`:** Sin `unwrap`, `expect`, `panic!`, `todo!` ni indexaciones que puedan fallar en rutas de ejecución.
