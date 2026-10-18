# pip-trust-service

Servicio de derivación determinista de **Trust Bundles**, cofirma multi-operador $k$-de-$n$ y publicación de confianza para Gravital ID (Fase **F7.T04**, **REQ-TRUST-003**, **REQ-TRUST-005**, **REQ-TRUST-008**).

---

## 1. Misión y Responsabilidades

`pip-trust-service` es un microservicio en capa **L5** que orquesta la generación y distribución descentralizada del **Trust Bundle** institucional:

1. **Derivación determinista (`REQ-TRUST-003`, `REQ-TRUST-008`):** Deriva el documento `TrustBundle` canónico a partir del estado finalizado del ledger (`finalized_head`) proyectado por su propio `pip-indexer`. La serialización sigue estrictamente JSON Canónico (**RFC 8785** / JCS), garantizando que operadores independientes que lean la misma cabeza obtengan **exactamente los mismos bytes**.
2. **Cofirma institucional multi-operador (`REQ-TRUST-001`, `INV-16`):** Cada operador firma de forma aislada e independiente el hash SHA-256 del bundle derivado utilizando su clave ES256 (`P-256`). Ningún operador firma a ciegas datos provistos por terceros.
3. **Agregador no confiable (`aggregator.rs`):** Un nodo agregador recopila firmas individuales de $N$ operadores, valida la concordancia del digest del payload, **detecta y aísla operadores divergentes** (que hayan calculado un estado o bloque diferente), y verifica que se alcance el umbral mínimo $k$ de operadores distintos.
4. **Ensamblado JWS multi-firma (`RFC 7515 §7.2`):** Construye la serialización JSON general de JWS con el array `signatures` que contiene cada cabecera protegida (`kid`) y firma válida.
5. **Publicación en almacenamiento de objetos / CDN (`REQ-REL-001`, `ADR-0013`):** Publica el bundle multi-firmado en almacenamiento compatible con S3 (AWS S3, MinIO, Cloudflare R2) con cabeceras inmutables y URLs canónicas (`bundles/current.json`, `bundles/{epoch}/{version}.json`).

---

## 2. Invariantes Clave

- **INV-01 (Verificación sans-I/O):** Los clientes (wallets y verificadores) descargan el bundle publicado y lo verifican 100% offline contra la raíz de confianza inyectada (`TrustRoot`), sin consultar la red ni el ledger.
- **INV-02 (Cero PII):** El trust bundle contiene únicamente identificadores criptográficos institucionales (`issuer_id`, `kid`, JWKs públicos, estados de clave, perfiles y anclajes). Ningún dato personal viaja ni se almacena en el servicio.
- **INV-05 (Fail-closed):** Si menos de $k$ operadores distintos firman el bundle, o si se detecta divergencia que impida alcanzar el quórum, el servicio rechaza la publicación y reporta estado degradado/unhealthy.
- **INV-16 (Umbral k-de-n):** Ninguna clave única decide la validez de un bundle; se exige siempre el umbral $k$-de-$n$ de firmantes independientes registrados en la raíz.

---

## 3. Variables de Entorno

| Variable | Tipo | Por defecto | Descripción |
|---|---|---|---|
| `PIP_SERVER_PORT` | `u16` | `8082` | Puerto HTTP para endpoints `/healthz` y `/readyz`. |
| `PIP_LOG_LEVEL` | `string` | `info` | Nivel de logging estructurado (`info`, `debug`, `warn`). |
| `PIP_TRUST_FRAMEWORK_ID` | `string` | `"pip-global-mainnet"` | Identificador normativo del marco de confianza. |
| `PIP_TRUST_CHAIN_ID` | `u64` | `31337` | Identificador de la cadena blockchain. |
| `PIP_TRUST_BUNDLE_EPOCH` | `u64` | `1` | Época activa de la raíz de confianza. |
| `PIP_TRUST_BUNDLE_VERSION` | `u64` | `1` | Versión monotónica incremental del bundle. |
| `PIP_TRUST_VALIDITY_SECONDS` | `u64` | `604800` | Vigencia nominal del bundle (7 días). |
| `PIP_TRUST_THRESHOLD` | `u32` | `2` | Umbral $k$ mínimo de operadores distintos requeridos. |
| `PIP_TRUST_OPERATOR_ID` | `string` | `"operator-local"` | Identificador único del operador local. |
| `PIP_TRUST_OPERATOR_KID` | `string` | `"urn:pip:signer:local"` | Key ID del firmante del operador local. |
| `PIP_TRUST_OPERATOR_PRIVATE_KEY_HEX` | `string` | `""` | Clave privada P-256 en hexadecimal (para dev/test). |
| `PIP_TRUST_STORAGE_BACKEND` | `string` | `"memory"` | Backend de publicación: `"memory"`, `"filesystem"`, `"s3"`. |
| `PIP_TRUST_STORAGE_LOCAL_DIR` | `string` | `"/var/data/pip/bundles"` | Directorio local si se usa `"filesystem"`. |
| `PIP_TRUST_S3_BUCKET` | `string` | `""` | Nombre del bucket si se usa `"s3"`. |
| `PIP_TRUST_S3_ENDPOINT` | `string` | `""` | Endpoint S3 compatible (ej. MinIO `http://127.0.0.1:9000`). |
