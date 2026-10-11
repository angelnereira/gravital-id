# ADR-0010: Formato del trust bundle y derivación determinista

- **Estado:** Aceptado
- **Fecha:** 2026-10-11
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #15
- **Requisitos y principios afectados:** REQ-TRUST-001; REQ-TRUST-002; REQ-TRUST-003; REQ-TRUST-004; P-01; P-04
- **Fase:** F0 (F0.T11)

---

## Contexto

El Trust Bundle es el artefacto que empaqueta el estado verificado del ecosistema (emisores autorizados, sus claves públicas, estados y metadatos) para permitir la verificación completamente desconectada (offline) de credenciales.
Requisitos esenciales:
1. **Multi-firma por umbral ($k$-de-$n$):** El bundle no puede depender de una única entidad; debe estar firmado por al menos $k$ operadores independientes autorizados por la Raíz de Confianza (TFA), conforme a ADR-0016.
2. **Derivación determinista idéntica:** Cada operador independiente deriva el contenido del bundle a partir de los eventos finalizados en la blockchain. Para que las firmas individuales coincidan sobre el mismo resumen criptográfico (*digest*), la serialización del payload JSON debe ser 100 % idéntica bit a bit en cualquier lenguaje o plataforma.
3. **Resistencia a denegación de servicio:** Los límites del documento deben estar acotados (tamaño, profundidad, claves duplicadas) para evitar ataques de agotamiento de memoria o inconsistencias de parseo.
4. **Anti-rollback:** Mecanismo estricto de números de secuencia monotónicos y épocas de bundle (`bundle_epoch`) para impedir que un atacante fuerce al verificador a aceptar bundles antiguos.

---

## Opciones consideradas

### Opción A — Archivo XML con firmas XMLDSig
- **Ventajas:** Estándar histórico utilizado en SAML.
- **Inconvenientes:** Complejidad extrema de canonización (C14N), vulnerabilidades históricas recurrentes de inyección XML y parseo no determinista.

### Opción B — Bloque binario ASN.1 DER / CMS (Cryptographic Message Syntax)
- **Ventajas:** Serialización binaria canónica estricta.
- **Inconvenientes:** Dificultad de inspección e interoperabilidad en clientes web y herramientas modernas basadas en JSON.

### Opción C — JWS JSON Signature General (RFC 7515) con canonización JCS (RFC 8785) (Recomendada)
- **Ventajas:**
  - **JWS JSON General:** Formato JSON nativo que soporta un array de firmas independientes (`signatures: [...]`) sobre un mismo payload Base64URL.
  - **RFC 8785 (JSON Canonicalization Scheme - JCS):** Algoritmo estándar que normaliza el orden lexicográfico UTF-8 de las claves, formato de números en punto flotante y espacios en blanco. Garantiza que cualquier operador independiente genere exactamente los mismos bytes a firmar.
  - Firmas digitales ES256 (NIST P-256) estándar.
  - Compatible con parsers seguros en Rust `no_std`, WebAssembly y herramientas web.
- **Inconvenientes:** Requiere implementar o validar el canonizador RFC 8785.

---

## Decisión

Se adopta la **Opción C**:
1. El Trust Bundle se distribuye como un objeto **JWS JSON con firmas múltiples** conforme al RFC 7515 §7.2.1.
2. La serialización canónica del payload se realiza estrictamente mediante **RFC 8785 (JCS)**.
3. Límites normativos estrictos del bundle:
   - Tamaño máximo total del documento: 2 MB.
   - Profundidad máxima de anidamiento JSON: 16 niveles.
   - Prohibición expresa de claves JSON duplicadas (rechazo inmediato si se detectan).
4. El payload incluye el campo monotónico `bundle_version`, el identificador de época `bundle_epoch` y el período de validez temporal (`valid_from` y `valid_until`).
5. La validación exige que al menos $k$ de los firmantes correspondan a operadores válidos registrados en la Raíz de Confianza vigente.

---

## Consecuencias

- La especificación normativa `docs/specs/TRUST_BUNDLE.md` define la estructura detallada de esquemas, derivación determinista y ejemplos canónicos.
- Las funciones de validación en `pip-core` / `pip-verifier` rechazan cualquier bundle que viole las restricciones sintácticas o no alcance el umbral $k$.
