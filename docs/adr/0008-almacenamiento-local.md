# ADR-0008: Almacenamiento local, cifrado de sobre e índices ciegos

- **Estado:** Aceptado
- **Fecha:** 2026-10-11
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #13
- **Requisitos y principios afectados:** REQ-STOR-001; REQ-STOR-002; REQ-STOR-003; P-03; P-09
- **Fase:** F0 (F0.T11)

---

## Contexto

Tanto la billetera del titular (`Wallet`) como el verificador (`Verifier`) requieren persistencia local para almacenar:
- Credenciales emitidas y sus metadatos.
- Raíces de confianza, trust bundles y manifiestos de estado.
- Caché de nonces de verificación y piso de tiempo monotónico confiable (`VerifierStateStore`).
- Cola cifrada de sincronización diferida.

Requisitos de seguridad y privacidad:
1. **Resistencia a ataques forenses y volcados de memoria:** La base de datos no debe contener datos personales ni identificadores en texto claro en el disco físico.
2. **Cifrado de sobre (Envelope Encryption):** Uso de una clave de cifrado de datos (DEK) generada aleatoriamente y protegida por una clave de cifrado de claves (KEK) residente en el hardware seguro del host (Secure Enclave, StrongBox, Keychain, WebCrypto).
3. **Imposibilidad de intercambio de registros:** Los datos asociados autenticados (AAD) deben vincular criptográficamente el identificador de registro y el tipo de objeto para impedir ataques de sustitución entre filas.
4. **Búsqueda sin revelar metadatos:** Las consultas locales por emisor o tipo de credencial (`vct`) deben realizarse mediante índices ciegos deterministas basados en HMAC sin filtrar texto claro a la capa de almacenamiento.
5. **Backend intercambiable y desacoplado:** El núcleo criptográfico de almacenamiento (`pip-storage`) debe ser puro y libre de I/O, delegando la persistencia transaccional a un trait inyectable (`StorageBackend`).

---

## Opciones consideradas

### Opción A — Base de datos relacional estándar sin cifrar (SQLite plano / CoreData)
- **Ventajas:** Facilidad de integración y consultas SQL directas.
- **Inconvenientes:** Cualquier volcado de copia de seguridad del sistema operativo, acceso de root o fallo de aislamiento de sandbox expondría las credenciales y el historial del titular en texto claro.

### Opción B — SQLCipher para toda la base de datos
- **Ventajas:** Cifra la totalidad de las páginas de disco de SQLite.
- **Inconvenientes:**
  - Requiere compilación de código C nativo complejo de mantener y enlazar en Rust.
  - No es compatible de forma natural con WebAssembly (IndexedDB) ni microcontroladores.
  - La clave de cifrado de SQLCipher permanece en la memoria del proceso durante toda la sesión.

### Opción C — Cifrado de sobre por registro en Rust puro + Índices ciegos HMAC + SQLite WAL / IndexedDB (Recomendada)
- **Ventajas:**
  - **`pip-storage` (capa L3):** Implementa el cifrado de sobre y los índices ciegos en Rust puro (`no_std` + `alloc`). Cada registro se cifra con XChaCha20-Poly1305 vinculando el `record_id` en los datos asociados (AAD).
  - La DEK se zeroiza inmediatamente al salir del ámbito de uso (`zeroize`).
  - Los índices ciegos permiten búsquedas exactas eficientes (`HMAC-SHA256(BlindKey, Term)`) sin que el motor de almacenamiento subyacente conozca los términos buscados.
  - **Desacoplamiento total:** El motor de almacenamiento subyacente es un adaptador L5 (`pip-storage-sqlite` con modo WAL para iOS/Android/Desktop, o adaptador IndexedDB para navegador Web).
- **Inconvenientes:** Las búsquedas por rangos o texto parcial requieren desencriptar en memoria los registros relevantes (perfectamente aceptable para carteras personales con cientos de credenciales).

---

## Decisión

Se adopta la **Opción C**:
1. El almacenamiento local de Gravital ID utiliza **cifrado de sobre a nivel de registro** con XChaCha20-Poly1305 conforme a `docs/specs/STORAGE_FORMAT.md`.
2. Las búsquedas de registros por emisor (`issuer_id`) y tipo de credencial (`vct`) se ejecutan mediante **índices ciegos HMAC-SHA256**.
3. La capa de persistencia se modela mediante el trait **`StorageBackend`**, suministrando `pip-storage-sqlite` (SQLite con journaling Write-Ahead Logging - WAL y transacciones ACID) como adaptador predeterminado en entornos con sistema operativo, y adaptadores en memoria para tests.
4. Las copias de seguridad automáticas del sistema operativo (iCloud Backup, Android Cloud Backup) deben excluir los archivos de la base de datos mediante flags del sistema, confiando la recuperación al protocolo criptográfico de Gravital ID (ADR-0009).

---

## Consecuencias

- La especificación normativa `docs/specs/STORAGE_FORMAT.md` documenta los esquemas de tablas, versión de base de datos y reglas de migración de esquema.
- El crate `pip-storage` se implementa en L3 sin dependencias de I/O de red o disco.
