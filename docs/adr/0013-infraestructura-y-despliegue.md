# ADR-0013: Infraestructura, despliegue y proveedor de nube inicial

- **Estado:** Aceptado
- **Fecha:** 2026-10-17
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #94
- **Requisitos y principios afectados:** REQ-REL-001, REQ-REL-002, REQ-REL-004, REQ-OBS-001, REQ-PRIV-003, REQ-ISS-002, REQ-LEDG-006, P-01, P-02, P-10
- **Fase:** F7 (F7.T01)

---

## Contexto

El ecosistema de Gravital ID entra en la Fase F7 (Servicios y sincronización), requiriendo el despliegue del plano de servicios backend de soporte a la confianza y sincronización:

1. **`pip-indexer`:** Ingesta continua y procesamiento idempotente de eventos finalizados de los contratos en el ledger EVM (`TrustRegistry` y `StatusAnchor`), persistencia en PostgreSQL de las vistas de estado y detección de divergencias entre RPCs proveedores. Proceso de larga duración.
2. **`pip-trust-service`:** Derivación determinista del trust bundle a partir de los datos indexados por su propio indexador, cofirma por umbral $k$-de-$n$ con operadores institucionales independientes, y publicación del bundle resultante en almacenamiento de objetos / CDN.
3. **`pip-relay`:** Caché direccionada por contenido para snapshots de listas de revocación y manifiestos de estado, buzón de sobres cifrados HPKE para sincronización entre dispositivos de un titular, y punto de encuentro (*rendezvous*) para flujos de sesión numérica efímera (`SessionCode` de 10 dígitos, F23/ADR-0025). Servicio stateless con TTL estricto y límites de tasa y tamaño.
4. **`pip-issuer-service`:** Implementación del protocolo de emisión OpenID4VCI (RFC 9901 / SD-JWT VC), gestión del ciclo de vida de listas de estado (asignación de bits aleatorios, firmas de listas) y endpoints de re-vinculación de credenciales, con custodia de claves en KMS/HSM.
5. **Nodos RPC de Ledger:** Múltiples proveedores RPC EVM independientes (Arbitrum Sepolia en testnet) consumidos a través de `MultiRpcClient` (`gravital-id-ledger-evm`).

### Restricciones e Invariantes Fundamentales

- **`INV-01` (Sans-I/O en el núcleo):** Los crates del núcleo (L1–L4) se mantienen estrictamente libres de red y I/O; los servicios backend viven en la capa L5 y capa de aplicaciones, orquestando el I/O sin contaminar las bibliotecas criptográficas y de validación.
- **`INV-02` / `REQ-PRIV-003` (Cero datos personales):** Ningún dato personal (PII), ni hash reversible de baja entropía, ni credenciales en claro transitan por los relays o indexadores, ni se persisten en bases de datos compartidas, ni se registran en logs, métricas o trazas de telemetría.
- **`REQ-REL-001` (Ausencia de puntos únicos de fallo):** La verificación de credenciales siempre opera de manera 100% desconectada y autónoma en los dispositivos terminales. Ningún servicio o proveedor en la nube puede constituir un punto único de fallo para validar credenciales o restaurar identidades.
- **Neutralidad de proveedor (*Vendor Neutrality*):** La arquitectura de despliegue no debe generar dependencia cautiva (*lock-in*) con ningún proveedor de nube comercial. Diferentes operadores del marco de confianza (`TFA`) deben poder operar sus componentes en proveedores heterogéneos (AWS, GCP, Azure, servidores dedicados u operadores de nube soberana).
- **Higiene estricta de secretos:** Cero secretos, tokens, contraseñas o claves privadas en el repositorio git (`INV-02`, políticas de CI). La configuración sensible se inyecta exclusivamente en tiempo de ejecución desde gestores de secretos o variables de entorno del sistema host.

---

## Opciones consideradas

### Opción A — Proveedor propietario único y servicios serverless propietarios (AWS Lambda / Google Cloud Functions)
- **Ventajas:** Escalabilidad automática inmediata a coste casi nulo en fases tempranas.
- **Inconvenientes:** Acoplamiento severo a APIs propietarias; inadecuado para procesos de larga duración e ingesta continua en tiempo real (`pip-indexer`); difícil adopción por parte de operadores independientes del Trust Framework que operen infraestructuras alternativas; riesgo de lock-in tecnológico.

### Opción B — Neutralidad basada en contenedores OCI, OpenTofu/Terraform modular, servicios desacoplados y stack local Docker Compose (Recomendada)
- **Ventajas:**
  - **Imágenes OCI estándar:** Empaquetado de cada servicio mediante Dockerfiles reproducibles con multi-stage builds en Rust 1.99.0, imagen base mínima de ejecución (`distroless` o `alpine`/`debian-slim`) y ejecución con usuario sin privilegios (`non-root`, UID 10001).
  - **Infraestructura como Código (IaC) neutral:** Manifiestos OpenTofu / Terraform organizados en módulos desacoplados para aprovisionar entornos `dev`, `testnet`, `pilot` y `production`.
  - **Proveedor de referencia inicial:** AWS seleccionado para el entorno de testnet gestionado por el proyecto (ECS Fargate para indexador y servicios, RDS PostgreSQL 16 para almacenamiento relacional, S3 + CloudFront para distribución pública de bundles y listas de estado, y AWS KMS para las claves de los servicios gestionados), manteniendo interfaces compatibles estándar que permitan a cualquier operador desplegar en GCP (Cloud Run / GCS), Azure o Hetzner / Kubernetes.
  - **Almacenamiento de confianza S3-compatible:** Publicación pública y lectura anónima de trust bundles y listas de estado a través de HTTP/HTTPS estándar mediante endpoints direccionados por contenido protegidos por CDN.
  - **Gestión estricta de secretos:** Módulos de IaC configurados para referenciar KMS y Secrets Manager en entornos remotos, e inyección mediante variables de entorno y archivos `.env.example` sanitizados para desarrollo local.
  - **Entorno local de desarrollo y CI:** Configuración completa en `deploy/docker/docker-compose.yml` que orquesta PostgreSQL, nodo EVM local (Anvil), almacenamiento local S3 (MinIO) y los servicios de Gravital ID en una red privada aislada para pruebas automatizadas de integración de extremo a extremo sin red externa.
- **Inconvenientes:** Requiere mantener Dockerfiles y módulos IaC declarativos.

### Opción C — Plataforma Kubernetes obligatoria para todos los entornos
- **Ventajas:** Máxima portabilidad entre nubes en entornos corporativos masivos.
- **Inconvenientes:** Complejidad operativa excesiva para las fases F7–F8 y requerimientos de recursos desproporcionados para desarrolladores individuales y pruebas locales de integración.

---

## Decisión

Se adopta la **Opción B**:

1. **Empaquetado y Ejecución:** Todos los servicios de Gravital ID (`pip-indexer`, `pip-trust-service`, `pip-relay`, `pip-issuer-service`) se distribuyen como imágenes de contenedor conformes a la especificación OCI, compiladas en Rust 1.99.0, con usuario `non-root` y sin privilegios de sistema.
2. **Proveedor de Referencia:** Se fija **AWS** como proveedor de nube inicial de referencia para los despliegues oficiales de `testnet` (ECS Fargate + RDS PostgreSQL + S3/CloudFront + KMS), empleando **OpenTofu / Terraform** para la definición declarativa de toda la infraestructura (`deploy/iac/`).
3. **Distribución de Confianza:** La publicación de Trust Bundles (`pip-trust-service`) y Listas de Revocación (`Status Lists`) se realiza sobre almacenamiento de objetos compatible con la API de S3 (AWS S3, Cloudflare R2, MinIO), expuestos para lectura pública y sin autenticación a través de CDN, asegurando alta disponibilidad global y latencias mínimas para wallets y verificadores.
4. **Base de Datos del Indexador:** PostgreSQL versión 16 o superior como motor de persistencia relacional estándar, con conexiones TLS forzadas y aislamiento por roles de base de datos con privilegios mínimos.
5. **Cero Secretos en Repositorio:** Ninguna clave, contraseña o secreto reside en el repositorio. En entornos de producción y testnet, las claves de firma y cifrado residen en KMS/HSM (`REQ-ISS-002`). En entornos locales, se usan variables de entorno documentadas en plantillas `.env.example`.
6. **Entorno Local Reproducible:** Se establece `deploy/docker/docker-compose.yml` como entorno canónico local para pruebas integradas de la Fase F7 (PostgreSQL + MinIO + Anvil local + servicios).

---

## Consecuencias

- **Positivas:**
  - Cumplimiento estricto de `REQ-REL-001` (sin puntos únicos de fallo) y `REQ-PRIV-003` (cero PII en logs y bases de datos).
  - Operadores independientes del Trust Framework pueden implementar el nodo de cofirma en cualquier proveedor o infraestructura propia sin restricciones de vendor lock-in.
  - La suite de integración local puede probar el plano de servicios completo de manera determinista sin dependencias externas.
- **Negativas y mitigación:**
  - Mantenimiento de módulos IaC para AWS y Docker Compose local: se mitiga estandarizando variables y configuración mediante `deploy/environments/`.
- **Cambios en documentación:**
  - `docs/adr/README.md` actualizado con ADR-0013 en estado Aceptado.
  - `docs/ARCHITECTURE.md §18 y §22` actualizados.
  - `deploy/README.md` ampliado con la guía de arquitectura IaC y Docker.

---

## Criterios para revisar esta decisión

- Incorporación de operadores de la TFA con requisitos regulatorios que demanden despliegues en nubes soberanas o hardware dedicado on-premise exclusivo.
- Emergencia de estándares de orquestación descentralizada que reemplacen la necesidad de almacenamiento S3-compatible.
