# Especificación PIP: Contratos Inteligentes del Registro y Gobernanza

> **Identificador normativo:** `SPEC-PIP-CONTRACTS-001`  
> **Versión:** `1.0.0` (Fase F6 / Tarea `F6.T01`)  
> **Estado:** Normativo  
> **Fecha:** 2026-10-16  
> **Trazabilidad:** REQ-LEDG-001, REQ-LEDG-002, REQ-LEDG-003, REQ-LEDG-004, REQ-LEDG-007, REQ-TRUST-001, REQ-TRUST-005, REQ-TRUST-007, REQ-TRUST-008, REQ-TRUST-009, REQ-STAT-006; ADR-0004, ADR-0016, ADR-0018; P-02, P-04, P-08, P-10, P-14, P-15; Invariantes INV-01, INV-02, INV-06, INV-16.

---

## 1. Alcance y Arquitectura de Contratos

Esta especificación detalla las interfaces, máquinas de estado, eventos, control de acceso basado en roles (RBAC) y reglas de inmutabilidad para los contratos inteligentes desplegados en redes compatibles con EVM (Ethereum L1 o red L2 de finalidad comprobada, conforme a ADR-0004):

1. **`TrustRegistry`**: Contrato principal que mantiene la verdad autorizada y auditable sobre:
   - Emisores institucionales autorizados y sus perfiles (`pip-personal-v1`, etc.).
   - Claves públicas P-256 de emisores y sus estados operativos (`active`, `retired`, `suspended`, `compromised`).
   - Verificadores registrados y sus perfiles autorizados (`REQ-TRUST-007`).
   - Claves públicas autorizadas de los operadores firmantes de bundles (`BundleSigner`).
   - Compromiso criptográfico (hash SHA-256) y versión de la raíz de confianza activa (`TrustRoot`).
2. **`StatusAnchor`**: Contrato para el anclaje periódico de raíces Merkle de manifiestos de estado (`IssuerStatusManifest`), garantizando la detección y prevención de bifurcaciones fraudulentas (*split-view attacks*, `REQ-STAT-006`).
3. **`Governance & Timelock`**: Módulo de administración descentralizado basado en una multisig de umbral k-de-n (Safe) controlada por la Autoridad del Marco de Confianza (TFA), acoplado a un `TimelockController` de retardo obligatorio (48–72 horas) para operaciones estructurales, y un rol restringido de respuesta rápida a emergencias sin timelock (`EMERGENCY_ROLE`, ADR-0018).

```text
    ┌───────────────────────────────────────────────────────────┐
    │           Multisig de la TFA (Safe k-de-n)                │
    └─────────────┬───────────────────────────────┬─────────────┘
                  │                               │
                  ▼                               ▼
    ┌───────────────────────────┐   ┌───────────────────────────┐
    │    TimelockController     │   │      EMERGENCY_ROLE       │
    │     (Retardo: 48-72h)     │   │  (Sin Timelock / TTL 14d) │
    └─────────────┬─────────────┘   └─────────────┬─────────────┘
                  │ Altas, bajas,                 │ Solo suspensiones
                  │ rotaciones ordinarias         │ temporales
                  ▼                               ▼
    ┌───────────────────────────────────────────────────────────┐
    │                      TrustRegistry                        │
    │  (Inmutable, sin proxies, eventos tipados deterministas)  │
    └───────────────────────────────────────────────────────────┘
                                  ▲
                                  │ Registro de manifiestos
    ┌─────────────────────────────┴─────────────────────────────┐
    │                       StatusAnchor                        │
    │     (Anclaje de raíces Merkle monotónicas por emisor)     │
    └───────────────────────────────────────────────────────────┘
```

---

## 2. Invariantes No Negociables del Ledger

| Invariante | Descripción | Cumplimiento Técnico |
|---|---|---|
| **INV-02 / REQ-LEDG-001** | **Ningún dato personal**, ni hash de dato personal, ni identificador de titular va al ledger. | Todos los parámetros son tipos primitivos cerrados (`bytes32`, `uint64`, `address`, `bytes` de claves públicas o `string` de URIs institucionales públicas). Emisores personas naturales usan identificadores seudónimos (`REQ-LEDG-007`). |
| **REQ-LEDG-003** | **Sin proxies actualizables.** Los contratos son estrictamente inmutables. | Queda prohibido el uso de patrones ERC-1967 (UUPS), Transparent Proxies o Beacon Proxies. Todo cambio mayor requiere despliegue de una nueva versión y rotación de raíz encadenada. |
| **REQ-LEDG-004** | **Gobernanza con separación de poderes.** Altas con timelock, emergencias limitadas a suspensiones con caducidad fija. | `TimelockController` obligatorio para operaciones de alta o rotación. El rol de emergencia solo puede suspender (TTL 14 días) y no puede renovar su propia suspensión. |
| **INV-16** | **Umbrales multi-firma.** Ninguna clave única decide la confianza. | La administración requiere la multisig de la TFA; las raíces y bundles offline se verifican por umbrales k-de-n independientes del ledger. |

---

## 3. Contrato `TrustRegistry`

### 3.1 Estructuras de Datos y Enums

```solidity
// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity 0.8.28;

/// @notice Estado operativo del emisor institucional en el registro.
enum IssuerState {
    None,        // 0: Emisor inexistente o dado de baja
    Active,      // 1: Emisor plenamente autorizado y vigente
    Suspended    // 2: Emisor temporalmente suspendido (preventivo o sanción)
}

/// @notice Ciclo de vida y estado de seguridad de una clave pública de emisor.
enum KeyState {
    None,        // 0: Clave inexistente
    Active,      // 1: Clave autorizada para firmar credenciales
    Retired,     // 2: Clave retirada ordenadamente; credenciales emitidas antes siguen vigentes
    Suspended,   // 3: Clave suspendida preventivamente por sospecha de incidente
    Compromised  // 4: Clave comprometida; invalida toda credencial firmada con ella (terminal)
}

/// @notice Estado de autorización de un verificador registrado.
enum VerifierState {
    None,        // 0: Verificador inexistente
    Active,      // 1: Verificador activo con clave autorizada
    Suspended    // 2: Verificador suspendido temporalmente
}

/// @notice Registro individual de clave pública de un emisor.
struct IssuerKey {
    bytes32 kid;                 // JWK Thumbprint SHA-256 canónico (RFC 7638)
    bytes publicKey;             // Clave pública P-256 SEC-1 (33 bytes comprimida o 65 bytes no comprimida)
    KeyState state;              // Estado actual de la clave
    uint64 stateSince;           // Instante Unix del último cambio de estado
    uint64 suspensionExpiresAt;  // Timestamp de caducidad automática si state == Suspended
    address suspendedBy;         // Dirección que ordenó la suspensión (control de no-renovación de emergencia)
}

/// @notice Registro institucional del emisor en la blockchain.
struct IssuerRecord {
    string uri;                  // URI HTTPS canónica del emisor (ej. "https://issuer.example.gov")
    bytes32[] profiles;          // Identificadores de perfiles autorizados (ej. keccak256("pip-personal-v1"))
    bytes32[] allowedVcts;       // Hashes de VCTs autorizados para emisión
    uint64 validFrom;            // Timestamp Unix de inicio de vigencia de la autorización
    uint64 validUntil;           // Timestamp Unix de expiración de la autorización
    IssuerState state;           // Estado operativo actual
    uint64 suspensionExpiresAt;  // Timestamp de caducidad automática de la suspensión (si aplica)
    bytes32[] keyIds;            // Lista de kids registrados para este emisor
}

/// @notice Registro de verificador autorizado para perfiles que exigen registro (REQ-PRES-007, REQ-TRUST-007).
struct VerifierRecord {
    string uri;                  // URI o identificador del verificador (ej. "https://verifier.example.com")
    bytes32[] profiles;          // Perfiles autorizados a auditar
    bytes publicKey;             // Clave pública P-256 SEC-1 del verificador para validar solicitudes firmadas
    VerifierState state;         // Estado del verificador
    uint64 validFrom;            // Inicio de vigencia
    uint64 validUntil;           // Expiración de vigencia
}

/// @notice Operador autorizado para cofirmar trust bundles offline.
struct BundleSigner {
    bytes32 kid;                 // Identificador de clave del firmante
    bytes publicKey;             // Clave pública P-256 SEC-1
    bool authorized;             // Estado de autorización (true = activo, false = revocado)
    uint64 authorizedSince;      // Timestamp Unix de autorización
}

/// @notice Compromiso criptográfico de la raíz de confianza.
struct TrustRootCommitment {
    bytes32 rootHash;            // Hash SHA-256 del documento TrustRoot canónico
    uint64 rootVersion;          // Versión monotónica de la raíz
    uint64 updatedAt;            // Timestamp Unix de actualización
}
```

---

### 3.2 Máquina de Estados y Reglas de Transición

#### Transiciones de `IssuerState`
- `None` $\rightarrow$ `Active`: Exclusivamente mediante `registerIssuer` a través de `TimelockController`.
- `Active` $\rightarrow$ `Suspended`: Vía `emergencySuspendIssuer` (rol de emergencia, TTL fijo 14 días) o `suspendIssuer` (timelock/multisig ordinaria).
- `Suspended` $\rightarrow$ `Active`:
  - Por expiración automática: cuando `block.timestamp >= suspensionExpiresAt`.
  - Por rehabilitación explícita: vía `liftIssuerSuspension` o ratificación por timelock.
- `Active` / `Suspended` $\rightarrow$ `None`: Baja definitiva vía `deregisterIssuer` (timelock).

#### Transiciones de `KeyState`
```text
           ┌──────────────┐
           │     None     │
           └──────┬───────┘
                  │ registerKey (Timelock)
                  ▼
         ┌───────────────────┐
         │      Active       │◄─────────────┐
         └──┬──────────────┬─┘              │
            │              │                │
suspendKey  │   retireKey  │                │ liftSuspension /
(Emergency/ │   (Timelock) │                │ Expiración TTL
Timelock)   │              │                │
            ▼              ▼                │
    ┌───────────────┐  ┌───────────────┐    │
    │   Suspended   │  │    Retired    │    │
    └──┬────────────┘  └───────┬───────┘    │
       │       │               │            │
       │       └───────────────┼────────────┘
       │                       │
       │ markCompromised       │ markCompromised
       │ (Multisig Plena)      │ (Multisig Plena)
       ▼                       ▼
    ┌──────────────────────────────────┐
    │           Compromised            │  (ESTADO TERMINAL ABSOLUTO)
    └──────────────────────────────────┘
```

**Reglas Críticas de Transición:**
1. **Inmutabilidad de Compromiso:** Un estado `Compromised` es **terminal e irreversible**. Una clave marcada como comprometida jamás puede transicionar a ningún otro estado bajo ninguna circunstancia.
2. **Inmutabilidad de Retiro:** Un estado `Retired` es **terminal respecto a operatividad activa**. Una clave retirada no puede reactivarse ni suspenderse; únicamente puede transicionar a `Compromised` si se detecta compromiso retroactivo de su material privado.
3. **Prohibición de Auto-Renovación de Emergencia:** Si una clave o emisor fue suspendido por el `EMERGENCY_ROLE`, el `EMERGENCY_ROLE` tiene **estrictamente prohibido** extender o renovar dicha suspensión. La suspensión expirará tras 14 días salvo que la multisig apruebe una extensión ordinaria a través del `TimelockController`.

---

### 3.3 Interfaz `ITrustRegistry`

```solidity
// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity 0.8.28;

interface ITrustRegistry {
    // --- ERRORES PERSONALIZADOS (Gas-efficient) ---
    error Unauthorized();
    error ZeroAddress();
    error IssuerAlreadyExists(bytes32 issuerId);
    error IssuerNotFound(bytes32 issuerId);
    error IssuerNotActive(bytes32 issuerId);
    error KeyAlreadyExists(bytes32 issuerId, bytes32 kid);
    error KeyNotFound(bytes32 issuerId, bytes32 kid);
    error KeyAlreadyCompromised(bytes32 issuerId, bytes32 kid);
    error KeyAlreadyRetired(bytes32 issuerId, bytes32 kid);
    error InvalidKeyTransition(KeyState from, KeyState to);
    error InvalidTimestamps();
    error SuspensionNotActive();
    error SuspensionExpired();
    error EmergencyRenewalForbidden();
    error InvalidPublicKeyLength(uint256 length);
    error VerifierAlreadyExists(bytes32 verifierId);
    error VerifierNotFound(bytes32 verifierId);
    error InvalidRootVersion(uint64 current, uint64 proposed);

    // --- FUNCIONES DE LECTURA (Views) ---
    function getIssuer(bytes32 issuerId) external view returns (IssuerRecord memory);
    function getIssuerKey(bytes32 issuerId, bytes32 kid) external view returns (IssuerKey memory);
    function getIssuerKeyIds(bytes32 issuerId) external view returns (bytes32[] memory);
    function isIssuerAuthorized(bytes32 issuerId, bytes32 profile) external view returns (bool);
    function isKeyAuthorized(bytes32 issuerId, bytes32 kid) external view returns (bool);
    function getVerifier(bytes32 verifierId) external view returns (VerifierRecord memory);
    function isVerifierAuthorized(bytes32 verifierId, bytes32 profile) external view returns (bool);
    function getTrustRootCommitment() external view returns (TrustRootCommitment memory);
    function isBundleSigner(address signerAddress) external view returns (bool);

    // --- MUTACIONES ORDINARIAS (Vía TIMELOCK_ROLE) ---
    function registerIssuer(
        bytes32 issuerId,
        string calldata uri,
        bytes32[] calldata profiles,
        bytes32[] calldata vcts,
        uint64 validFrom,
        uint64 validUntil
    ) external;

    function deregisterIssuer(bytes32 issuerId) external;

    function addIssuerKey(
        bytes32 issuerId,
        bytes32 kid,
        bytes calldata publicKey
    ) external;

    function retireIssuerKey(bytes32 issuerId, bytes32 kid) external;

    function suspendIssuer(bytes32 issuerId, uint64 durationSeconds) external;

    function liftIssuerSuspension(bytes32 issuerId) external;

    function suspendKey(bytes32 issuerId, bytes32 kid, uint64 durationSeconds) external;

    function liftKeySuspension(bytes32 issuerId, bytes32 kid) external;

    function registerVerifier(
        bytes32 verifierId,
        string calldata uri,
        bytes32[] calldata profiles,
        bytes calldata publicKey,
        uint64 validFrom,
        uint64 validUntil
    ) external;

    function deregisterVerifier(bytes32 verifierId) external;

    function updateTrustRootHash(bytes32 newRootHash, uint64 newRootVersion) external;

    function setBundleSigner(
        address signerAddress,
        bytes32 kid,
        bytes calldata publicKey,
        bool authorized
    ) external;

    // --- MUTACIONES DE ALTA SEGURIDAD (Multisig Plena / DEFAULT_ADMIN_ROLE) ---
    function markKeyCompromised(bytes32 issuerId, bytes32 kid) external;

    // --- MUTACIONES DE EMERGENCIA (EMERGENCY_ROLE, Sin Timelock, TTL = 14 días) ---
    function emergencySuspendIssuer(bytes32 issuerId) external;

    function emergencySuspendKey(bytes32 issuerId, bytes32 kid) external;

    function emergencyLiftSuspension(bytes32 issuerId, bytes32 kid) external;
}
```

---

## 4. Contrato `StatusAnchor`

### 4.1 Propósito
El contrato `StatusAnchor` actúa como testigo descentralizado de alta disponibilidad para el anclaje periódico de los compromisos de estado emitidos en los `IssuerStatusManifest` (ADR-0005, ADR-0017). Impide que un emisor malicioso o comprometido bifurque el historial de revocaciones para presentar un estado revocado a un integrador y un estado no revocado a otro (*split-view attack*, `REQ-STAT-006`).

### 4.2 Interfaz `IStatusAnchor`

```solidity
// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity 0.8.28;

interface IStatusAnchor {
    // --- ESTRUCTURAS ---
    struct StatusCommitment {
        bytes32 manifestHash;   // SHA-256 del IssuerStatusManifest canónico
        uint64 manifestVersion; // Versión monotónica incremental del manifiesto
        uint64 anchoredAt;      // Timestamp Unix de inclusión en bloque
        uint64 blockNumber;     // Altura de bloque de la inclusión
    }

    // --- ERRORES ---
    error Unauthorized();
    error VersionNotMonotonic(uint64 current, uint64 proposed);
    error InvalidManifestHash();

    // --- FUNCIONES ---
    function getLatestCommitment(bytes32 issuerId) external view returns (StatusCommitment memory);

    function getCommitmentByVersion(
        bytes32 issuerId,
        uint64 manifestVersion
    ) external view returns (StatusCommitment memory);

    /// @notice Ancla un nuevo compromiso de estado.
    /// @dev Solo invocable por cuentas con ANCHOR_ROLE asociadas al emisor.
    /// Exige manifestVersion > latestVersion.
    function anchorStatusManifest(
        bytes32 issuerId,
        uint64 manifestVersion,
        bytes32 manifestHash,
        string calldata uriHint
    ) external;
}
```

---

## 5. Control de Acceso y Gobernanza (RBAC)

Se implementa el control de acceso desacoplado con roles basados en `bytes32`:

| Rol | Titular de la Clave / Contrato | Propósito y Privilegios |
|---|---|---|
| `DEFAULT_ADMIN_ROLE` | Multisig Safe de la TFA (umbral k-de-n) | Administración de roles, configuración del retardo del timelock y ejecución de `markKeyCompromised`. |
| `TIMELOCK_ROLE` | Dirección del contrato `TimelockController` | Único autorizado para operaciones ordinarias de alta, baja, retiro de claves y actualización de raíz de confianza. |
| `EMERGENCY_ROLE` | Multisig operativa de respuesta a incidentes | Privilegio exclusivo para ejecutar `emergencySuspendIssuer`, `emergencySuspendKey` y `emergencyLiftSuspension` sin ventana de espera. |
| `ANCHOR_ROLE` | Cuentas autorizadas de emisión de estado | Autorizado para ejecutar `anchorStatusManifest` en `StatusAnchor`. |

### Parámetros de Seguridad del Timelock
- **Retardo mínimo (`minDelay`):** 172.800 segundos (48 horas).
- **Retardo máximo de emergencia preventiva:** Las acciones de emergencia no esperan timelock pero su efecto está acotado por contrato a `EMERGENCY_SUSPENSION_DURATION = 14 days` (1.209.600 segundos).

---

## 6. Catálogo de Eventos para Indexación (`pip-ledger` y `pip-indexer`)

Todas las funciones mutadoras emiten eventos estructurados con campos indexados (`indexed`), garantizando que la reconstrucción del estado en Rust sea 100% determinista (`REQ-TRUST-008`):

```solidity
// Eventos de Emisores
event IssuerRegistered(
    bytes32 indexed issuerId,
    string uri,
    uint64 validFrom,
    uint64 validUntil
);
event IssuerSuspended(
    bytes32 indexed issuerId,
    uint64 expiresAt,
    address indexed initiatedBy
);
event IssuerReinstated(bytes32 indexed issuerId);
event IssuerDeregistered(bytes32 indexed issuerId);

// Eventos de Claves
event KeyAdded(
    bytes32 indexed issuerId,
    bytes32 indexed kid,
    bytes publicKey
);
event KeyRetired(
    bytes32 indexed issuerId,
    bytes32 indexed kid,
    uint64 stateSince
);
event KeySuspended(
    bytes32 indexed issuerId,
    bytes32 indexed kid,
    uint64 expiresAt,
    address indexed initiatedBy
);
event KeyCompromised(
    bytes32 indexed issuerId,
    bytes32 indexed kid,
    uint64 stateSince
);

// Eventos de Verificadores
event VerifierRegistered(
    bytes32 indexed verifierId,
    string uri,
    bytes publicKey,
    uint64 validFrom,
    uint64 validUntil
);
event VerifierDeregistered(bytes32 indexed verifierId);

// Eventos de Confianza y Operadores
event TrustRootUpdated(
    bytes32 indexed rootHash,
    uint64 indexed rootVersion,
    uint64 updatedAt
);
event BundleSignerUpdated(
    address indexed signerAddress,
    bytes32 indexed kid,
    bytes publicKey,
    bool authorized
);

// Eventos de Anclaje de Estado
event StatusManifestAnchored(
    bytes32 indexed issuerId,
    uint64 indexed manifestVersion,
    bytes32 manifestHash,
    string uriHint
);
```

### Determinismo en la Reconstrucción
Los eventos en el ledger forman una secuencia monotónica y estrictamente ordenada por la tupla:
$$\text{Orden} = (\text{blockNumber}, \text{transactionIndex}, \text{logIndex})$$
El adaptador `pip-ledger` procesa esta secuencia aplicando los eventos en el mismo orden que ocurrieron en los bloques finalizados, derivando el `TrustBundle` canónico con bytes idénticos en cualquier implementación (`REQ-TRUST-008`).

---

## 7. Procedimiento de Verificación "Sin Datos Personales" (REQ-LEDG-001, REQ-LEDG-007)

1. **Auditoría de Tipos en ABIs:**  
   Se ejecutará un script automatizado en CI (`cargo xtask check-contracts-privacy`) sobre los ficheros ABI JSON generados por el compilador. La comprobación fallará de inmediato si algún evento o función expone parámetros con nombres o semánticas asociadas a PII (`name`, `email`, `holder`, `subject`, `document`, `ssn`, `tax_id`, `birthdate`, `address`, etc.).
2. **Uso de Seudónimos para Emisores Particulares (`REQ-LEDG-007`):**  
   Cualquier emisor que constituya una persona natural (por ejemplo, notarios o inspectores independientes) deberá registrarse utilizando una URI con seudónimo opaco (ej. `https://issuer.example.gov/p/d3b07384d113edec`) y clave pública P-256, sin publicar jamás su nombre civil en la blockchain.

---

## 8. Inmutabilidad y Migración de Contratos (REQ-LEDG-003)

Ante la necesidad de evolucionar la lógica o actualizar dependencias normativas:
1. Se despliega una nueva instancia independiente del contrato (ej. `TrustRegistryV2`).
2. La multisig de la TFA inicializa el nuevo contrato migrando el estado consolidado de emisores activos.
3. Se publica y firma una nueva `TrustRoot` encadenada cofirmada por el umbral de claves de raíz anteriores y nuevas (`REQ-TRUST-009`).
4. La nueva `TrustRoot` actualiza el campo `registry_address`.
5. Los verificadores offline adoptan automáticamente la nueva dirección al sincronizar el bundle derivado sin alterar su binario.

---

## 9. Parámetros del Compilador y Estándares de Implementación

- **Compilador:** Solidity `0.8.28`.
- **EVM Target:** `cancun` o `shanghai` (conforme a la red de despliegue).
- **Optimizador:** Habilitado con `runs = 200` y `via_ir = true`.
- **Herramienta de Construcción y Pruebas:** Foundry (`forge`, `cast`, `anvil`).
- **Análisis Estático:** Slither sin hallazgos altos o críticos (`REQ-SEC-007`).
- **Artefacto de Despliegue:** `deploy/environments/<network>/contracts.json` con esquema normalizado.
