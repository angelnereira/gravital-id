# pip-indexer

`pip-indexer` es el servicio de indexación y mantenimiento de proyecciones relacionales del protocolo Gravital ID (Capa L5, F7.T03, `REQ-LEDG-005`, `ADR-0013`).

## 1. Misión y Responsabilidades

1. **Ingesta de bloques finalizados (`REQ-LEDG-005`):**
   Consume únicamente eventos confirmados en bloques finalizados (`finalized_head`) de redes EVM, garantizando tolerancia ante reorganizaciones y split-views.
2. **Persistencia e idempotencia:**
   Persiste eventos en PostgreSQL (o almacenamiento relacional determinista) con inserciones estrictamente idempotentes (`ON CONFLICT DO NOTHING`) y cursor atómico por cadena.
3. **Mantenimiento de proyecciones:**
   Actualiza de manera continua y secuencial las proyecciones relacionales de emisores, claves criptográficas SEC-1, raíces de confianza, firmantes de bundles y anclajes de manifiestos de estado (`StatusAnchor.sol`).
4. **Reprocesamiento determinista:**
   Permite rebobinar y reprocesar el estado a partir de cualquier altura de bloque previa (`reprocess_from_block`), reconstruyendo de forma consistente las vistas.
5. **Detección de divergencias RPC (`REQ-LEDG-006`):**
   Compara múltiples proveedores RPC independientes y alerta/detiene la ingesta ante inconsistencias de bloques o bifurcaciones.
6. **Métricas de retraso (Lag):**
   Expone métricas cuantitativas de desfase entre la cabeza finalizada de la red y el cursor indexado (`finalized_block - indexed_block`).
7. **Observabilidad y salud (`REQ-OBS-001`, `REQ-PRIV-003`):**
   Integra OpenTelemetry estructurado, redacción de PII/secretos sin fugas en logs (`pip-service-common`) y endpoints `/healthz` y `/readyz`.

## 2. Variables de Configuración

| Variable | Tipo | Por defecto | Descripción |
|---|---|---|---|
| `PIP_INDEXER_RPC_ENDPOINTS` | String (csv) | `http://127.0.0.1:8545` | URLs de nodos RPC EVM separadas por coma |
| `PIP_INDEXER_CHAIN_ID` | u64 | `31337` (local anvil) | Identificador de la cadena EVM |
| `PIP_INDEXER_TRUST_REGISTRY` | String | `0x00...` | Dirección del contrato `TrustRegistry.sol` |
| `PIP_INDEXER_STATUS_ANCHOR` | String | `0x00...` | Dirección del contrato `StatusAnchor.sol` |
| `PIP_INDEXER_DATABASE_URL` | String | `postgres://pip:pip@localhost:5432/pip_indexer` | URL de conexión a la base de datos PostgreSQL |
| `PIP_INDEXER_CHUNK_SIZE` | u64 | `500` | Tamaño de ventana de bloques por consulta `eth_getLogs` |
| `PIP_INDEXER_POLL_INTERVAL_MS` | u64 | `2000` | Intervalo de polling en milisegundos |
| `PIP_INDEXER_START_BLOCK` | u64 | `0` | Bloque inicial si no existe checkpoint previo |
| `PIP_INDEXER_MAX_ALLOWED_LAG` | u64 | `100` | Umbral de bloques de retraso para marcar estado degradado |
| `PIP_SERVER_PORT` | u16 | `8081` | Puerto del servidor de salud HTTP (`/healthz`, `/readyz`) |
