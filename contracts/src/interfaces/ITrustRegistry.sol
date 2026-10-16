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

/// @title Interfaz ITrustRegistry
/// @notice Interfaz canónica para el registro de emisores, claves, verificadores y confianza (SPEC-PIP-CONTRACTS-001).
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

    // --- EVENTOS ---
    event IssuerRegistered(bytes32 indexed issuerId, string uri, uint64 validFrom, uint64 validUntil);
    event IssuerSuspended(bytes32 indexed issuerId, uint64 expiresAt, address indexed initiatedBy);
    event IssuerReinstated(bytes32 indexed issuerId);
    event IssuerDeregistered(bytes32 indexed issuerId);

    event KeyAdded(bytes32 indexed issuerId, bytes32 indexed kid, bytes publicKey);
    event KeyRetired(bytes32 indexed issuerId, bytes32 indexed kid, uint64 stateSince);
    event KeySuspended(bytes32 indexed issuerId, bytes32 indexed kid, uint64 expiresAt, address indexed initiatedBy);
    event KeyCompromised(bytes32 indexed issuerId, bytes32 indexed kid, uint64 stateSince);

    event VerifierRegistered(bytes32 indexed verifierId, string uri, bytes publicKey, uint64 validFrom, uint64 validUntil);
    event VerifierDeregistered(bytes32 indexed verifierId);

    event TrustRootUpdated(bytes32 indexed rootHash, uint64 indexed rootVersion, uint64 updatedAt);
    event BundleSignerUpdated(address indexed signerAddress, bytes32 indexed kid, bytes publicKey, bool authorized);

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
