# gravital-id-sync

> **Capa:** L4 (Sans-I/O y Flujos de Dominio) · **Ambiente:** `std` sin I/O de red ni runtimes asincrónicos

## Propósito

Máquina de estados de sincronización sans-I/O para el protocolo Gravital ID (`PIP`). Orquesta la persistencia, cifrado en reposo, transmisión y recepción asíncrona de operaciones de sincronización entre billeteras de titulares y servicios relay, con garantías estrictas de idempotencia, resiliencia y cero conocimiento.

Cumple con **F7.T07** y verifica los requisitos normativos **REQ-SYNC-001** a **REQ-SYNC-007**.

## Invariantes Aplicables

- **INV-01:** La sincronización en L4 es estrictamente sans-I/O. El crate no realiza llamadas de red directas ni depende de runtimes asíncronos (`tokio`, `async-std`). La comunicación se desacopla mediante el trait inyectado `Transport`.
- **INV-02:** Ningún dato personal, identificador persistente de titular ni información en claro se transmite en los sobres de sincronización ni se almacena sin cifrado de sobre.
- **INV-03:** Sin custodia de claves privadas de titulares. Las firmas y aperturas de sobres se delegan a las claves autorizadas del titular.
- **INV-04:** Integridad y trazabilidad de los estados de entrega de cada operación (`Pending`, `InFlight`, `Delivered`, `Failed`).
- **INV-05:** Fail-closed ante cualquier corrupción de sobre o fallo criptográfico.
- **INV-07:** Uso exclusivo de suites criptográficas auditadas mediante `gravital-id-crypto`.
- **INV-09:** Sin código `unsafe` (`#![forbid(unsafe_code)]`).
- **INV-10:** Sin `unwrap`, `expect`, `panic!`, `todo!` ni indexaciones que puedan causar pánico en código de biblioteca.
- **INV-11:** El reloj y el generador de números aleatorios se inyectan explícitamente mediante traits (`Clock`, `Rng`) para determinismo total y pruebas reproducibles.

## Arquitectura y Componentes Clave

1. **Cola de Operaciones Cifrada en Reposo (`EncryptedOperationQueue`, REQ-SYNC-001):**
   Las operaciones pendientes se serializan y cifran utilizando cifrado de sobre DEK/KEK (`gravital-id-storage::envelope`) antes de persistir en `StorageBackend`. La clave de cifrado se obtiene del proveedor KEK del titular.

2. **Idempotencia Estricta y Desduplicación (`REQ-SYNC-001`, `REQ-SYNC-002`):**
   Cada operación posee un identificador único determinista de 32 bytes (`OperationId`). La inserción de operaciones duplicadas es detectada y rechazada sin efectos secundarios.

3. **Cálculo Determinista de Backoff con Jitter (`BackoffCalculator`, REQ-SYNC-003, INV-11):**
   Algoritmo exponencial de reintentos basado exclusivamente en aritmética de enteros (sin números de coma flotante, cumpliendo con la regla estricta del workspace), con límite superior de retardo y fluctuación aleatoria (*jitter*) acotada inyectada desde el CSPRNG determinista.

4. **Verificación Íntegra de Contenido Recibido (`REQ-SYNC-004`):**
   Todo contenido público o descargado de un relay se verifica obligatoriamente mediante su digest SHA-256 o firma criptográfica antes de ser procesado o incorporado al estado del titular.

5. **Descargas Públicas Anónimas (`REQ-SYNC-005`, INV-02, P-09):**
   La descarga de objetos inmutables de sincronización (trust bundles, listas de estado, esquemas) se realiza de forma anónima referenciando únicamente el digest SHA-256, sin cabeceras de autorización ni identificadores de usuario.

6. **Sobres Cifrados de Extremo a Extremo con HPKE (`REQ-SYNC-006`):**
   Las operaciones dirigidas a un destinatario específico se empaquetan en sobres cifrados con HPKE (RFC 9180: DHKEM P-256 + HKDF-SHA256 + ChaCha20-Poly1305), garantizando confidencialidad y autenticidad frente al relay intermediario.

7. **Soporte Multi-Relay con Failover Transparente (`REQ-SYNC-007`):**
   La máquina de estados mantiene una lista priorizada de relays disponibles y conmuta automáticamente al siguiente proveedor ante caídas, tiempos de espera o errores de red.

8. **Resolución de Conflictos LWW (`LwwConflictResolver`, REQ-SYNC-002):**
   Resolución determinista de conflictos basada en Last-Write-Wins (marca temporal monotónica con desempate determinista por digest SHA-256 de la operación).

## Abstracción de Transporte

```text
+--------------------------------------------------------------+
|             SyncStateMachine (L4 - sans-I/O)                 |
+--------------------------------------------------------------+
                               |
                               v
+--------------------------------------------------------------+
|                   Trait Transport (L4)                       |
+--------------------------------------------------------------+
                               |
                               v
+--------------------------------------------------------------+
|     gravital-id-transport-http / Adaptador Host (L5)         |
+--------------------------------------------------------------+
```
