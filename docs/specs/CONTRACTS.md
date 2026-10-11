# Especificación PIP: Contratos Inteligentes del Registro y Gobernanza

> **Identificador normativo:** `SPEC-PIP-CONTRACTS-001`  
> **Versión:** `0.1.0-draft` (Fase F0 / Tarea `F0.T14`)  
> **Estado:** Normativo / En revisión  
> **Fecha:** 2026-10-10  
> **Trazabilidad:** REQ-LEDG-001..005, REQ-TRUST-001, 005, 008, 009; ADR-0004, ADR-0016, ADR-0018; P-02, P-04, P-08, P-10, P-14, P-15; INV-02.

---

## 1. Alcance y Arquitectura de Contratos

Esta especificación detalla las interfaces, máquinas de estado, eventos, control de acceso basado en roles (RBAC) y reglas de inmutabilidad para los contratos inteligentes desplegados en redes compatibles con EVM (Ethereum / L2 madura):

1. **`TrustRegistry`**: Contrato principal que mantiene la verdad autorizada sobre emisores admitidos, claves públicas de firma, verificadores registrados, firmantes de bundles y el hash de la raíz de confianza activa.
2. **`StatusAnchor`**: Contrato para el anclaje periódico de raíces Merkle de manifiestos de estado, garantizando la detección de bifurcaciones fraudulentas (*split-view attacks*).
3. **`Governance & Timelock`**: Módulo de administración basado en multisig corporativa (Safe) acoplado a un `TimelockController`, con un rol restringido de emergencia sin timelock (ADR-0018).

### Invariantes No Negociables
* **INV-02 / REQ-LEDG-001:** Ningún parámetro, evento, hash ni dato que contenga o derive de datos personales de titulares tocará la blockchain. Los identificadores de emisor son URIs públicas o seudónimos institucionales.
* **REQ-LEDG-003:** **Sin proxies actualizables.** Los contratos son estrictamente inmutables. Toda evolución se despliega como una nueva instancia y se enlaza mediante una nueva versión de `TrustRoot`.

---

## 2. Contrato `TrustRegistry`

### 2.1 Estructuras de Datos y Enums

```solidity
enum IssuerState {
    None,
    Active,
    Suspended
}

enum KeyState {
    None,
    Active,
    Retired,
    Suspended,
    Compromised
}

struct IssuerKey {
    bytes32 kid;          // JWK Thumbprint SHA-256 (RFC 7638)
    bytes publicKey;      // Clave pública P-256 SEC-1 (65 bytes no comprimida o 33 comprimida)
    KeyState state;       // Estado operativo
    uint64 stateSince;    // Timestamp Unix de cambio de estado
    uint64 suspensionExpiresAt; // 0 salvo en estado Suspended
}

struct IssuerRecord {
    string issuerUri;     // URI oficial del emisor (https://...)
    bytes32[] profiles;   // Perfiles autorizados (pip-personal-v1, etc.)
    bytes32[] allowedVcts;// Hashes de los VCTs que puede emitir
    uint64 validFrom;     // Timestamp inicio de autorización
    uint64 validUntil;    // Timestamp expiración
    IssuerState state;    // Estado administrativo
    uint64 suspensionExpiresAt; // Caducidad de suspensión si aplica
}
```

---

### 2.2 Funciones Principales

#### Gobernanza Ordinaria (Vía Timelock Obligatorio)
* `registerIssuer(string calldata uri, bytes32[] calldata profiles, bytes32[] calldata vcts, uint64 validFrom, uint64 validUntil)`:  
  Registra un nuevo emisor institucional tras vencer la ventana de observación del timelock.
* `addIssuerKey(bytes32 issuerId, bytes32 kid, bytes calldata publicKey)`:  
  Asocia una nueva clave pública activa para el emisor indicado.
* `retireIssuerKey(bytes32 issuerId, bytes32 kid)`:  
  Pasa una clave activa al estado `Retired` a partir de `block.timestamp`.
* `markKeyCompromised(bytes32 issuerId, bytes32 kid)`:  
  Marca una clave irrevocablemente como `Compromised`. Requiere aprobación unánime/plena de la multisig.
* `updateTrustRootHash(bytes32 newRootHash, uint64 rootVersion)`:  
  Actualiza el compromiso de la raíz de confianza tras una ceremonia de rotación.
* `setBundleSigner(address signerAddress, bytes32 kid, bool authorized)`:  
  Gestiona la lista autorizada de operadores firmantes de bundles.

#### Gobernanza de Emergencia (Sin Timelock / ADR-0018)
* `emergencySuspendIssuer(bytes32 issuerId)`:  
  Suspende inmediatamente al emisor por un plazo fijo e inmutable ($\Delta T_{\text{suspensión}} = 14$ días). Al expirar el plazo, el estado revierte automáticamente a `Active` salvo ratificación de la multisig.
* `emergencySuspendKey(bytes32 issuerId, bytes32 kid)`:  
  Suspende cautelarmente una clave sospechosa de compromiso por 14 días.
* `emergencyLiftSuspension(bytes32 issuerId, bytes32 kid)`:  
  Cancela prematuramente una suspensión si se demuestra falsa alarma.

---

### 2.3 Eventos Emitidos (Fuente para Indexadores)

Todas las mutaciones emiten eventos tipados, los cuales son consumidos por los indexadores de los operadores de bundle (REQ-LEDG-005):

```solidity
event IssuerRegistered(bytes32 indexed issuerId, string uri, uint64 validFrom, uint64 validUntil);
event IssuerSuspended(bytes32 indexed issuerId, uint64 expiresAt, address initiatedBy);
event IssuerReinstated(bytes32 indexed issuerId);
event IssuerDeregistered(bytes32 indexed issuerId);

event KeyAdded(bytes32 indexed issuerId, bytes32 indexed kid, bytes publicKey);
event KeyRetired(bytes32 indexed issuerId, bytes32 indexed kid, uint64 stateSince);
event KeySuspended(bytes32 indexed issuerId, bytes32 indexed kid, uint64 expiresAt);
event KeyCompromised(bytes32 indexed issuerId, bytes32 indexed kid, uint64 stateSince);

event TrustRootUpdated(bytes32 indexed rootHash, uint64 rootVersion);
event BundleSignerUpdated(address indexed signer, bytes32 kid, bool authorized);
```

---

## 3. Contrato `StatusAnchor`

### 3.1 Propósito y Función
Garantiza que un emisor no pueda emitir listas de revocación contradictorias para distintos usuarios o verificadores.

```solidity
struct StatusCommitment {
    bytes32 manifestHash;  // SHA-256 del IssuerStatusManifest canónico
    uint64 manifestVersion;// Versión monotónica
    uint64 anchoredAt;     // Timestamp de inclusión
    uint64 blockNumber;    // Altura de bloque
}

mapping(bytes32 => mapping(uint64 => StatusCommitment)) public issuerCommitments;

event StatusManifestAnchored(
    bytes32 indexed issuerId,
    uint64 indexed manifestVersion,
    bytes32 manifestHash,
    string uriHint
);
```

* `anchorStatusManifest(bytes32 issuerId, uint64 manifestVersion, bytes32 manifestHash, string calldata uriHint)`:  
  Invocado por el emisor autenticado o por el servicio de confianza en su nombre. Verifica que `manifestVersion > lastVersion[issuerId]`.

---

## 4. Control de Acceso y Timelock (RBAC)

```text
    ┌────────────────────────┐
    │     Multisig (Safe)    │
    │ (TFA - Umbral k-de-n)  │
    └───────────┬────────────┘
                │
                ▼
    ┌────────────────────────┐         ┌────────────────────────┐
    │   TimelockController   │         │     Emergency Role     │
    │    (Ventana 48-72h)    │         │  (Sin Timelock / 14d)  │
    └───────────┬────────────┘         └───────────┬────────────┘
                │ Acciones                         │ Solo
                │ Estructurales                    │ Suspender
                ▼                                  ▼
    ┌───────────────────────────────────────────────────────────┐
    │                       TrustRegistry                       │
    └───────────────────────────────────────────────────────────┘
```

1. **`TIMELOCK_ROLE`:** Asignado exclusivamente a la dirección del `TimelockController`. Autorizado para altas, revocaciones definitivas, bajas y rotaciones de raíz.
2. **`EMERGENCY_ROLE`:** Asignado a un contrato o multisig operativa de respuesta a incidentes. Posee permisos acotados exclusivamente a funciones `emergencySuspend*`.
3. **`ANCHOR_ROLE`:** Permite a emisores verificados registrar compromisos en `StatusAnchor`.

---

## 5. Procedimiento de Migración de Contratos

Al no existir proxies actualizables (garantía de inmutabilidad):
1. Se despliega una nueva versión del contrato (p. ej. `TrustRegistryV2`).
2. La multisig de la TFA inicializa el nuevo contrato migrando el estado consolidado de emisores activos.
3. Se publica una nueva **`TrustRoot` encadenada** (RFC 7515 multi-firma con umbral $R_N$ y $R_{N+1}$) que actualiza el campo `registry_address`.
4. Los clientes de verificación adoptan automáticamente la nueva dirección al procesar la rotación de raíz sin requerir parches de software ni cambios de configuración.
