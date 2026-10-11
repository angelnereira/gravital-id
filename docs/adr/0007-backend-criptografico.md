# ADR-0007: Backend criptográfico y soporte FIPS

- **Estado:** Aceptado
- **Fecha:** 2026-10-11
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #12
- **Requisitos y principios afectados:** REQ-PORT-002; REQ-SEC-001; P-04; P-07
- **Fase:** F0 (F0.T11)

---

## Contexto

El protocolo Gravital ID requiere primitivas criptográficas robustas para:
- Firmas y verificación digital ES256 (NIST P-256 / secp256r1 con SHA-256).
- Hashing criptográfico (SHA-256).
- Derivación de claves HKDF (RFC 5869).
- Cifrado autenticado de datos en reposo y sobres de transporte: XChaCha20-Poly1305 y AES-256-GCM.
- Intercambio de claves y cifrado híbrido HPKE (RFC 9180 con DHKEM(P-256)).

Requisitos determinantes:
1. **Compatibilidad `no_std`:** Las capas L1 a L3 del protocolo deben poder ejecutarse en entornos embebidos y WebAssembly puro sin soporte del sistema operativo (ADR-0019).
2. **Operaciones en tiempo constante:** Mitigación de canales laterales en comparaciones y operaciones de clave mediante crates auditados y comparaciones seguras (`subtle`).
3. **Cumplimiento FIPS 140-3 opcional:** Determinados integradores institucionales (sector bancario, gubernamental y empresarial) requieren el uso de módulos criptográficos validados bajo FIPS 140-3 en entornos de servidor.
4. **Higiene de dependencias de Cargo:** La selección de backends no debe realizarse mediante *Cargo features* mutuamente excluyentes que contaminen el árbol de dependencias de los consumidores de la biblioteca.

---

## Opciones consideradas

### Opción A — `ring` como único backend criptográfico
- **Ventajas:** Rendimiento optimizado en ensamblador para x86_64 y aarch64.
- **Inconvenientes:**
  - Código en C y ensamblador complejo de compilar a `wasm32-unknown-unknown` sin emulación de entornos UNIX.
  - No soporta `no_std` puro en microcontroladores sin asignador estándar.
  - Carece de validación FIPS 140-3 nativa empaquetada.

### Opción B — `RustCrypto` exclusivo
- **Ventajas:** Implementado en 100 % Rust seguro, soporte completo de `no_std` + `alloc`, compila de forma trivial a WebAssembly, excelente auditoría comunitaria y soporte de tiempo constante con `subtle`.
- **Inconvenientes:** No dispone de certificación formal FIPS 140-3 para licitaciones gubernamentales de alta seguridad.

### Opción C — Proveedor desacoplado por tipos con RustCrypto por defecto y aws-lc-rs para FIPS (Recomendada)
- **Ventajas:**
  - **RustCrypto** (`p256`, `sha2`, `chacha20poly1305`, `aes-gcm`, `hkdf`) actúa como implementación de referencia por defecto para todas las plataformas, navegadores móviles y entornos `no_std`.
  - Para entornos de infraestructura y servidores que exigen FIPS 140-3, se provee el adaptador `aws-lc-rs` (módulo criptográfico de AWS validado por NIST FIPS).
  - La selección se realiza en tiempo de compilación a través de tipos genéricos y el trait `CryptoProvider`, sin recurrir a flags booleanas de Cargo que rompan la composición de crates dependientes.
- **Inconvenientes:** Mantenimiento de la capa de abstracción del trait `CryptoProvider`.

---

## Decisión

Se adopta la **Opción C**:
1. Se establece el ecosistema **RustCrypto** como el backend criptográfico canónico y predeterminado del protocolo en todas las plataformas de cliente (Android, iOS, Web, Flutter y Desktop).
2. La suite criptográfica v1 se restringe taxativamente a los algoritmos fijados en `docs/specs/CRYPTO_PROFILES.md` (rechazo total de `none`, algoritmos obsoletos o parámetros no auditados).
3. En la capa de infraestructura y adaptadores (L5), se ofrece soporte opcional para **aws-lc-rs (FIPS)** implementando el trait `CryptoProvider` para emisores e indexadores empresariales que lo requieran.

---

## Consecuencias

- Las pruebas unitarias y de integración de L2 (`pip-crypto`) se ejecutan contra RustCrypto asegurando compatibilidad `no_std`.
- El spike técnico `spikes/wasm/REPORT.md` (F0.T09) evalúa el tamaño de binario y el rendimiento de RustCrypto en WebAssembly.
