# `pip-relay`

Servicio stateless de retransmisión y sincronización en capa L5 para el protocolo Gravital ID (`F7.T06`, `REQ-SYNC-004`, `REQ-SYNC-006`, `REQ-CODE-001..004`).

## Responsabilidades

1. **Almacenamiento de objetos direccionados por contenido (`REQ-SYNC-004`):**
   - Distribución inmutable indexada por hash SHA-256 (`/v1/objects/{sha256}`).
   - Verificación de integridad `sha256(payload) == hash` antes de almacenar.
   - Cache con TTL configurable.
2. **Buzón efímero de sobres cifrados HPKE (`REQ-SYNC-006`):**
   - Buzón indexado por identificador ciego (`inbox_id`).
   - Sobres cifrados con HPKE (RFC 9180) entre dispositivos de un titular.
   - Descarte idempotente de duplicados por `idempotency_key`.
   - Recuperación y acuse de recibo / borrado atómico.
3. **Punto de encuentro efímero (`SessionCode`, `ADR-0025`, `PROTOCOL.md §7.7`):**
   - Canal de proximidad para verificación asistida por código numérico de 10 dígitos con dígito de control de Damm.
   - Indexado por `sha256("gid-session-code-v1" || session_code)`.
   - TTL estricto de máximo 180 segundos.
   - Consumo atómico de un solo uso de la respuesta.
4. **Higiene de seguridad y privacidad (`INV-02`, `REQ-PRIV-003`):**
   - Sin registro de payloads, nonces ni datos personales en logs.
   - Límites de tasa (`RateLimiter`) y tamaño máximo de payload (`128 KiB`).
   - Servicio completamente en memoria con límites estrictos de capacidad.
