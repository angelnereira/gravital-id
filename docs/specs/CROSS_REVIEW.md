# Informe de Revisión Cruzada de Especificaciones Normativas (F0.T21)

- **Identificador de tarea:** F0.T21
- **Fecha de ejecución:** 2026-10-11
- **Revisores:** Angel Nereira (mantenedor líder) y Antigravity (agente de arquitectura)
- **Requisitos cubiertos:** REQ-DOC-001, REQ-DOC-002, Invariantes INV-01 a INV-16
- **Estado de la revisión:** Aprobado — Lista para cierre de Gate G0

---

## 1. Alcance de la Revisión

Se ha llevado a cabo una auditoría cruzada sistemática de consistencia, trazabilidad, ausencia de ambigüedades y rigor normativo sobre la totalidad de los documentos producidos durante la Fase F0:

1. **[`docs/specs/PROTOCOL.md`](PROTOCOL.md)** (v0.1.0-draft / F0.T12): Flujos de emisión OID4VCI, presentación offline QR en 2 pasos con transcodificación binaria (CBOR + DEFLATE + Base45), sobres HPKE y sincronización diferida.
2. **[`docs/specs/TRUST_BUNDLE.md`](TRUST_BUNDLE.md)** (v0.1.0-draft / F0.T13): Raíz encadenada de confianza, JWS JSON multi-firma con canonización JCS (RFC 8785), límites estrictos y anti-rollback monotónico con `bundle_epoch`.
3. **[`docs/specs/CONTRACTS.md`](CONTRACTS.md)** (v0.1.0-draft / F0.T14): Interfaces Solidity para `TrustRegistry` y `StatusAnchor`, timelock de 48-72h y rol de emergencia de suspensión (14 días).
4. **[`docs/specs/profiles/`](profiles/)** (v1.0.0-draft / F0.T15): Perfiles normativos `pip-personal-v1`, `pip-financial-v1` (con atestación hardware mandatoria) y `pip-enterprise-v1`.
5. **[`docs/specs/SDK_API.md`](SDK_API.md)** y **[`docs/specs/ERROR_CODES.md`](ERROR_CODES.md)** (v0.1.0-draft / F0.T16): Contratos abstractos de host (`KeyStore`, `Clock`, `VerifierStateStore`, `StorageBackend`, `Transport`) y catálogo unificado de errores `GID-Exxxx` / `PIP-Exxxx`.
6. **[`docs/specs/STORAGE_FORMAT.md`](STORAGE_FORMAT.md)** (v0.1.0-draft / F0.T17): Cifrado de sobre DEK/KEK con XChaCha20-Poly1305, índices ciegos HMAC y SQLite WAL.
7. **[`docs/specs/TRUST_FRAMEWORK.md`](TRUST_FRAMEWORK.md)** (v0.1.0-draft / F0.T18): Gobernanza técnica de la TFA, umbrales multisig $k$-de-$n$, timelock y ciclo de vida de emisores.
8. **[`docs/specs/TEST_STRATEGY.md`](TEST_STRATEGY.md)** (v0.1.0-draft / F0.T19): Pirámide de pruebas, horas mínimas de fuzzing por gate, cobertura $\ge 85\%$ y trazabilidad REQ.
9. **[`docs/specs/THREAT_MODEL.md`](THREAT_MODEL.md)** (v0.1.0-draft / F0.T05): Modelado STRIDE por componente + análisis de privacidad LINDDUN.
10. **[`docs/legal/2026-analisis-regulatorio-preliminar.md`](../legal/2026-analisis-regulatorio-preliminar.md)** (v0.1.0-draft / F0.T20): Análisis de cumplimiento con la Ley 81 de 2019 de Panamá (Protección de Datos Personales) y Ley 23 de 2015 (KYC/AML).
11. **ADRs 0001 a 0012, 0016 a 0020** en [`docs/adr/`](../adr/): Decisiones de arquitectura vinculantes.
12. **Informes de Spikes** en [`spikes/`](../../spikes/): Viabilidad empírica de QR (F0.T07), Keystore (F0.T08), WASM (F0.T09) y Ledger (F0.T10).

---

## 2. Lista de Verificación de Invariantes Normativas (`AGENTS.md §2`)

| Invariante | Descripción | Estado | Evidencia de Cumplimiento en Especificaciones |
|---|---|---|---|
| **INV-01** | L1–L4 cero I/O de red; L1–L3 `no_std`; L4 sans-I/O. | **Conforme** | Modelado en `SDK_API.md §4`, `PROTOCOL.md §8` y `ADR-0019`. |
| **INV-02** | Cero PII ni hashes de PII en blockchain, logs o métricas. | **Conforme** | Validado en `CONTRACTS.md §8`, `THREAT_MODEL.md §6`, `spikes/ledger/REPORT.md` y `legal/2026-analisis-regulatorio-preliminar.md`. |
| **INV-03** | Claves privadas nunca cruzan FFI a Rust. | **Conforme** | Verificado en `SDK_API.md §4.1`, `ADR-0006` y `spikes/keystore/REPORT.md`. |
| **INV-04** | Dependencias criptográficas fijadas y auditadas. | **Conforme** | Lista cerrada en `CRYPTO_PROFILES.md §2` y `ADR-0007`. |
| **INV-05** | Comprobaciones críticas fallan cerrado (*fail-closed*). | **Conforme** | Especificado en `SDK_API.md §3.2` y `ADR-0020`. |
| **INV-06** | Claves de emisor resueltas exclusivamente desde `TrustStore`. | **Conforme** | `TRUST_BUNDLE.md §5` y `PROTOCOL.md §5.5` ignoran `jku`/`jwk`/`x5u`. |
| **INV-07** | Nonces interactivos de uso único con caché persistente. | **Conforme** | Definido en `SDK_API.md §4.3` (`VerifierStateStore`) y `PROTOCOL.md §5.2`. |
| **INV-08** | Piso de tiempo monotónico confiable. | **Conforme** | Modelado en `SDK_API.md §4.3` y `TRUST_BUNDLE.md §5.3`. |
| **INV-09** | Cifrado en reposo con sobre (DEK/KEK) y datos asociados (AAD). | **Conforme** | Detallado bit a bit en `STORAGE_FORMAT.md §3`. |
| **INV-10** | Canales efímeros (ECDH) con compromiso previo y SAS. | **Conforme** | Formalizado en `PROTOCOL.md §7` y `ADR-0009`. |
| **INV-11** | Códigos de error numéricos normalizados `GID-Exxxx` / `PIP-Exxxx`. | **Conforme** | Catálogo exhaustivo en `ERROR_CODES.md`. |
| **INV-12** | Límites estrictos en deserialización (tamaño, profundidad, duplicados). | **Conforme** | Parametrizado en `CRYPTO_PROFILES.md §6` y `TRUST_BUNDLE.md §4.3`. |
| **INV-13** | Trazabilidad completa REQ $\rightarrow$ spec $\rightarrow$ prueba. | **Conforme** | Matriz de trazabilidad en `TEST_STRATEGY.md §7`. |
| **INV-14** | Contratos inmutables con timelock de 48-72h. | **Conforme** | Interfaces y tiempos en `CONTRACTS.md §5` y `TRUST_FRAMEWORK.md §3`. |
| **INV-15** | Rol de emergencia limitado a suspensión temporal ($\le 14$ días). | **Conforme** | Restricciones estrictas en `CONTRACTS.md §6`, `ADR-0018` y `ADR-0012`. |
| **INV-16** | Confianza offline por umbral $k$-de-$n$ obligatoria. | **Conforme** | Especificado en `TRUST_BUNDLE.md §3` y `ADR-0016`. |

---

## 3. Matriz de Coherencia Cruzada entre Especificaciones

1. **Alineación Criptográfica (`CRYPTO_PROFILES.md` vs resto):**
   - Se verificó que todas las especificaciones utilicen exactamente los mismos algoritmos fijados: firmas ES256 (NIST P-256 / SHA-256), curvas SEC1 no comprimidas (65 bytes), firmas IEEE P1363 (64 bytes), hashing SHA-256, AEAD XChaCha20-Poly1305 y cifrado híbrido HPKE DHKEM(P-256).
   - Ningún documento menciona curvas o algoritmos deprecados.
2. **Consistencia de Perfiles (`profiles/` vs `PROTOCOL.md` y `STORAGE_FORMAT.md`):**
   - El perfil `pip-financial-v1` exige atestación hardware mandatoria, coincidente con la interfaz `KeyStore::get_key_attestation` de `SDK_API.md` y con los hallazgos de `spikes/keystore/REPORT.md`.
   - La retención y almacenamiento definidos en los perfiles coinciden con las políticas de índices ciegos de `STORAGE_FORMAT.md`.
3. **Consistencia de Gobernanza (`TRUST_FRAMEWORK.md` vs `CONTRACTS.md` vs `TRUST_BUNDLE.md`):**
   - Los umbrales multisig ($k$-de-$n$), las duraciones de timelock (48 a 72 horas) y la caducidad máxima del rol de emergencia (14 días naturales) coinciden en los tres documentos sin discrepancias numéricas.
   - El flujo de revocación y suspensión refleja idénticos estados: `active`, `suspended`, `retired` y `compromised`.

---

## 4. Hallazgos Menores Resueltos

Durante la revisión cruzada se detectaron y unificaron dos detalles menores:
- **Nomenclatura de prefijos de error:** Se ratificó que el espacio de error numérico `0000`–`9999` es idéntico entre `PIP-Exxxx` y `GID-Exxxx`, sirviendo este último como alias canónico tras la adopción de `ADR-0001`.
- **Límites de descompresión:** Se confirmó que el límite de descompresión de 500 KB para Token Status Lists aplica de forma uniforme tanto en verificación online como en verificación offline.

---

## 5. Dictamen Final de Revisión

Todas las especificaciones normativas de la versión v0.1.0-draft cumplen con los estándares de rigor matemático, claridad de ingeniería y preservación de la privacidad exigidos por el proyecto Gravital ID.

**Recomendación:** Se aprueba formalmente la revisión cruzada F0.T21 y se declara satisfecha la totalidad de requisitos previos para el cierre del **Gate G0** (Fundación, gobierno y especificación).
