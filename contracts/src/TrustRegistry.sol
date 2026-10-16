// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity 0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {
    ITrustRegistry,
    IssuerState,
    KeyState,
    VerifierState,
    IssuerKey,
    IssuerRecord,
    VerifierRecord,
    BundleSigner,
    TrustRootCommitment
} from "./interfaces/ITrustRegistry.sol";

/// @title TrustRegistry
/// @notice Contrato inteligente central para la gestión inmutable de emisores, claves, verificadores y confianza (SPEC-PIP-CONTRACTS-001).
/// @dev Inmutable (sin proxies, REQ-LEDG-003), sin datos personales (REQ-LEDG-001, INV-02), con RBAC desacoplado (REQ-LEDG-004).
contract TrustRegistry is AccessControl, ITrustRegistry {
    // --- CONSTANTES DE ROLES (RBAC) ---
    bytes32 public constant TIMELOCK_ROLE = keccak256("TIMELOCK_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    // --- PARÁMETROS NORMATIVOS ---
    uint64 public constant EMERGENCY_SUSPENSION_DURATION = 14 days;

    // --- ALMACENAMIENTO (PRIVADO / INTERNO) ---
    mapping(bytes32 => IssuerRecord) private _issuers;
    mapping(bytes32 => mapping(bytes32 => IssuerKey)) private _issuerKeys;
    mapping(bytes32 => VerifierRecord) private _verifiers;
    mapping(address => BundleSigner) private _bundleSigners;
    TrustRootCommitment private _trustRootCommitment;

    /// @notice Inicializa el contrato con los roles de administración, timelock y emergencia.
    /// @param admin Cuenta o multisig Safe de la TFA (DEFAULT_ADMIN_ROLE).
    /// @param timelock Dirección del contrato TimelockController (TIMELOCK_ROLE).
    /// @param emergency Cuenta o multisig operativa de respuesta a incidentes (EMERGENCY_ROLE).
    constructor(address admin, address timelock, address emergency) {
        if (admin == address(0) || timelock == address(0) || emergency == address(0)) {
            revert ZeroAddress();
        }

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(TIMELOCK_ROLE, timelock);
        _grantRole(EMERGENCY_ROLE, emergency);
    }

    // =========================================================================
    // FUNCIONES DE LECTURA (VIEWS)
    // =========================================================================

    /// @inheritdoc ITrustRegistry
    function getIssuer(bytes32 issuerId) external view override returns (IssuerRecord memory) {
        IssuerRecord memory record = _issuers[issuerId];
        if (record.state == IssuerState.None) {
            revert IssuerNotFound(issuerId);
        }
        return record;
    }

    /// @inheritdoc ITrustRegistry
    function getIssuerKey(bytes32 issuerId, bytes32 kid) external view override returns (IssuerKey memory) {
        IssuerKey memory key = _issuerKeys[issuerId][kid];
        if (key.state == KeyState.None) {
            revert KeyNotFound(issuerId, kid);
        }
        return key;
    }

    /// @inheritdoc ITrustRegistry
    function getIssuerKeyIds(bytes32 issuerId) external view override returns (bytes32[] memory) {
        if (_issuers[issuerId].state == IssuerState.None) {
            revert IssuerNotFound(issuerId);
        }
        return _issuers[issuerId].keyIds;
    }

    /// @inheritdoc ITrustRegistry
    function isIssuerAuthorized(bytes32 issuerId, bytes32 profile) public view override returns (bool) {
        IssuerRecord storage record = _issuers[issuerId];
        if (record.state == IssuerState.None) {
            return false;
        }

        // Comprobación de vigencia temporal
        if (block.timestamp < record.validFrom || block.timestamp > record.validUntil) {
            return false;
        }

        // Si está suspendido, verificar si la suspensión ya expiró
        if (record.state == IssuerState.Suspended) {
            if (record.suspensionExpiresAt == 0 || block.timestamp < record.suspensionExpiresAt) {
                return false;
            }
        }

        // Si profile es 0, solo se verifica si el emisor está activo
        if (profile == bytes32(0)) {
            return true;
        }

        // Comprobar coincidencia de perfil autorizado
        for (uint256 i = 0; i < record.profiles.length; i++) {
            if (record.profiles[i] == profile) {
                return true;
            }
        }
        return false;
    }

    /// @inheritdoc ITrustRegistry
    function isKeyAuthorized(bytes32 issuerId, bytes32 kid) external view override returns (bool) {
        if (!isIssuerAuthorized(issuerId, bytes32(0))) {
            return false;
        }

        IssuerKey storage key = _issuerKeys[issuerId][kid];
        if (key.state == KeyState.Active) {
            return true;
        }

        if (key.state == KeyState.Suspended) {
            // Caducidad automática de suspensión
            return key.suspensionExpiresAt != 0 && block.timestamp >= key.suspensionExpiresAt;
        }

        // Retired, Compromised o None no son claves autorizadas para nuevas firmas
        return false;
    }

    /// @inheritdoc ITrustRegistry
    function getVerifier(bytes32 verifierId) external view override returns (VerifierRecord memory) {
        VerifierRecord memory record = _verifiers[verifierId];
        if (record.state == VerifierState.None) {
            revert VerifierNotFound(verifierId);
        }
        return record;
    }

    /// @inheritdoc ITrustRegistry
    function isVerifierAuthorized(bytes32 verifierId, bytes32 profile) external view override returns (bool) {
        VerifierRecord storage record = _verifiers[verifierId];
        if (record.state != VerifierState.Active) {
            return false;
        }

        if (block.timestamp < record.validFrom || block.timestamp > record.validUntil) {
            return false;
        }

        if (profile == bytes32(0)) {
            return true;
        }

        for (uint256 i = 0; i < record.profiles.length; i++) {
            if (record.profiles[i] == profile) {
                return true;
            }
        }
        return false;
    }

    /// @inheritdoc ITrustRegistry
    function getTrustRootCommitment() external view override returns (TrustRootCommitment memory) {
        return _trustRootCommitment;
    }

    /// @inheritdoc ITrustRegistry
    function isBundleSigner(address signerAddress) external view override returns (bool) {
        return _bundleSigners[signerAddress].authorized;
    }

    // =========================================================================
    // MUTACIONES ORDINARIAS (Vía TIMELOCK_ROLE o DEFAULT_ADMIN_ROLE)
    // =========================================================================

    /// @inheritdoc ITrustRegistry
    function registerIssuer(
        bytes32 issuerId,
        string calldata uri,
        bytes32[] calldata profiles,
        bytes32[] calldata vcts,
        uint64 validFrom,
        uint64 validUntil
    ) external override {
        _checkTimelockOrAdmin();
        if (issuerId == bytes32(0)) revert Unauthorized();
        if (_issuers[issuerId].state != IssuerState.None) revert IssuerAlreadyExists(issuerId);
        if (validFrom >= validUntil) revert InvalidTimestamps();

        IssuerRecord storage rec = _issuers[issuerId];
        rec.uri = uri;
        rec.profiles = profiles;
        rec.allowedVcts = vcts;
        rec.validFrom = validFrom;
        rec.validUntil = validUntil;
        rec.state = IssuerState.Active;
        rec.suspensionExpiresAt = 0;

        emit IssuerRegistered(issuerId, uri, validFrom, validUntil);
    }

    /// @inheritdoc ITrustRegistry
    function deregisterIssuer(bytes32 issuerId) external override {
        _checkTimelockOrAdmin();
        if (_issuers[issuerId].state == IssuerState.None) revert IssuerNotFound(issuerId);

        _issuers[issuerId].state = IssuerState.None;
        emit IssuerDeregistered(issuerId);
    }

    /// @inheritdoc ITrustRegistry
    function addIssuerKey(
        bytes32 issuerId,
        bytes32 kid,
        bytes calldata publicKey
    ) external override {
        _checkTimelockOrAdmin();
        if (_issuers[issuerId].state == IssuerState.None) revert IssuerNotFound(issuerId);
        if (_issuerKeys[issuerId][kid].state != KeyState.None) revert KeyAlreadyExists(issuerId, kid);
        if (publicKey.length != 33 && publicKey.length != 65) revert InvalidPublicKeyLength(publicKey.length);

        IssuerKey storage key = _issuerKeys[issuerId][kid];
        key.kid = kid;
        key.publicKey = publicKey;
        key.state = KeyState.Active;
        key.stateSince = uint64(block.timestamp);
        key.suspensionExpiresAt = 0;
        key.suspendedBy = address(0);

        _issuers[issuerId].keyIds.push(kid);

        emit KeyAdded(issuerId, kid, publicKey);
    }

    /// @inheritdoc ITrustRegistry
    function retireIssuerKey(bytes32 issuerId, bytes32 kid) external override {
        _checkTimelockOrAdmin();
        IssuerKey storage key = _issuerKeys[issuerId][kid];
        if (key.state == KeyState.None) revert KeyNotFound(issuerId, kid);
        if (key.state == KeyState.Compromised) revert KeyAlreadyCompromised(issuerId, kid);
        if (key.state == KeyState.Retired) revert KeyAlreadyRetired(issuerId, kid);

        key.state = KeyState.Retired;
        key.stateSince = uint64(block.timestamp);
        key.suspensionExpiresAt = 0;
        key.suspendedBy = address(0);

        emit KeyRetired(issuerId, kid, uint64(block.timestamp));
    }

    /// @inheritdoc ITrustRegistry
    function suspendIssuer(bytes32 issuerId, uint64 durationSeconds) external override {
        _checkTimelockOrAdmin();
        IssuerRecord storage rec = _issuers[issuerId];
        if (rec.state == IssuerState.None) revert IssuerNotFound(issuerId);

        rec.state = IssuerState.Suspended;
        rec.suspensionExpiresAt = durationSeconds == 0 ? 0 : uint64(block.timestamp + durationSeconds);

        emit IssuerSuspended(issuerId, rec.suspensionExpiresAt, msg.sender);
    }

    /// @inheritdoc ITrustRegistry
    function liftIssuerSuspension(bytes32 issuerId) external override {
        _checkTimelockOrAdmin();
        IssuerRecord storage rec = _issuers[issuerId];
        if (rec.state != IssuerState.Suspended) revert SuspensionNotActive();

        rec.state = IssuerState.Active;
        rec.suspensionExpiresAt = 0;

        emit IssuerReinstated(issuerId);
    }

    /// @inheritdoc ITrustRegistry
    function suspendKey(bytes32 issuerId, bytes32 kid, uint64 durationSeconds) external override {
        _checkTimelockOrAdmin();
        IssuerKey storage key = _issuerKeys[issuerId][kid];
        if (key.state == KeyState.None) revert KeyNotFound(issuerId, kid);
        if (key.state == KeyState.Compromised) revert KeyAlreadyCompromised(issuerId, kid);
        if (key.state == KeyState.Retired) revert KeyAlreadyRetired(issuerId, kid);

        key.state = KeyState.Suspended;
        key.stateSince = uint64(block.timestamp);
        key.suspensionExpiresAt = durationSeconds == 0 ? 0 : uint64(block.timestamp + durationSeconds);
        key.suspendedBy = msg.sender;

        emit KeySuspended(issuerId, kid, key.suspensionExpiresAt, msg.sender);
    }

    /// @inheritdoc ITrustRegistry
    function liftKeySuspension(bytes32 issuerId, bytes32 kid) external override {
        _checkTimelockOrAdmin();
        IssuerKey storage key = _issuerKeys[issuerId][kid];
        if (key.state != KeyState.Suspended) revert SuspensionNotActive();

        key.state = KeyState.Active;
        key.stateSince = uint64(block.timestamp);
        key.suspensionExpiresAt = 0;
        key.suspendedBy = address(0);

        emit KeyAdded(issuerId, kid, key.publicKey);
    }

    /// @inheritdoc ITrustRegistry
    function registerVerifier(
        bytes32 verifierId,
        string calldata uri,
        bytes32[] calldata profiles,
        bytes calldata publicKey,
        uint64 validFrom,
        uint64 validUntil
    ) external override {
        _checkTimelockOrAdmin();
        if (verifierId == bytes32(0)) revert Unauthorized();
        if (_verifiers[verifierId].state != VerifierState.None) revert VerifierAlreadyExists(verifierId);
        if (validFrom >= validUntil) revert InvalidTimestamps();
        if (publicKey.length != 33 && publicKey.length != 65) revert InvalidPublicKeyLength(publicKey.length);

        VerifierRecord storage ver = _verifiers[verifierId];
        ver.uri = uri;
        ver.profiles = profiles;
        ver.publicKey = publicKey;
        ver.state = VerifierState.Active;
        ver.validFrom = validFrom;
        ver.validUntil = validUntil;

        emit VerifierRegistered(verifierId, uri, publicKey, validFrom, validUntil);
    }

    /// @inheritdoc ITrustRegistry
    function deregisterVerifier(bytes32 verifierId) external override {
        _checkTimelockOrAdmin();
        if (_verifiers[verifierId].state == VerifierState.None) revert VerifierNotFound(verifierId);

        _verifiers[verifierId].state = VerifierState.None;
        emit VerifierDeregistered(verifierId);
    }

    /// @inheritdoc ITrustRegistry
    function updateTrustRootHash(bytes32 newRootHash, uint64 newRootVersion) external override {
        _checkTimelockOrAdmin();
        if (newRootVersion <= _trustRootCommitment.rootVersion) {
            revert InvalidRootVersion(_trustRootCommitment.rootVersion, newRootVersion);
        }

        _trustRootCommitment.rootHash = newRootHash;
        _trustRootCommitment.rootVersion = newRootVersion;
        _trustRootCommitment.updatedAt = uint64(block.timestamp);

        emit TrustRootUpdated(newRootHash, newRootVersion, _trustRootCommitment.updatedAt);
    }

    /// @inheritdoc ITrustRegistry
    function setBundleSigner(
        address signerAddress,
        bytes32 kid,
        bytes calldata publicKey,
        bool authorized
    ) external override {
        _checkTimelockOrAdmin();
        if (signerAddress == address(0)) revert ZeroAddress();

        BundleSigner storage signer = _bundleSigners[signerAddress];
        signer.kid = kid;
        signer.publicKey = publicKey;
        signer.authorized = authorized;
        signer.authorizedSince = uint64(block.timestamp);

        emit BundleSignerUpdated(signerAddress, kid, publicKey, authorized);
    }

    // =========================================================================
    // MUTACIONES DE ALTA SEGURIDAD (Multisig Plena / DEFAULT_ADMIN_ROLE)
    // =========================================================================

    /// @inheritdoc ITrustRegistry
    function markKeyCompromised(bytes32 issuerId, bytes32 kid) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        IssuerKey storage key = _issuerKeys[issuerId][kid];
        if (key.state == KeyState.None) revert KeyNotFound(issuerId, kid);
        if (key.state == KeyState.Compromised) revert KeyAlreadyCompromised(issuerId, kid);

        key.state = KeyState.Compromised;
        key.stateSince = uint64(block.timestamp);
        key.suspensionExpiresAt = 0;
        key.suspendedBy = address(0);

        emit KeyCompromised(issuerId, kid, uint64(block.timestamp));
    }

    // =========================================================================
    // MUTACIONES DE EMERGENCIA (EMERGENCY_ROLE, Sin Timelock, TTL 14 días)
    // =========================================================================

    /// @inheritdoc ITrustRegistry
    function emergencySuspendIssuer(bytes32 issuerId) external override onlyRole(EMERGENCY_ROLE) {
        IssuerRecord storage rec = _issuers[issuerId];
        if (rec.state == IssuerState.None) revert IssuerNotFound(issuerId);

        // Si ya está suspendido por emergencia y no ha caducado, prohibir auto-renovación
        if (rec.state == IssuerState.Suspended && block.timestamp < rec.suspensionExpiresAt) {
            revert EmergencyRenewalForbidden();
        }

        rec.state = IssuerState.Suspended;
        rec.suspensionExpiresAt = uint64(block.timestamp + EMERGENCY_SUSPENSION_DURATION);

        emit IssuerSuspended(issuerId, rec.suspensionExpiresAt, msg.sender);
    }

    /// @inheritdoc ITrustRegistry
    function emergencySuspendKey(bytes32 issuerId, bytes32 kid) external override onlyRole(EMERGENCY_ROLE) {
        IssuerKey storage key = _issuerKeys[issuerId][kid];
        if (key.state == KeyState.None) revert KeyNotFound(issuerId, kid);
        if (key.state == KeyState.Compromised) revert KeyAlreadyCompromised(issuerId, kid);
        if (key.state == KeyState.Retired) revert KeyAlreadyRetired(issuerId, kid);

        // Prohibición estricta de auto-renovación si fue suspendido por emergencia
        if (key.state == KeyState.Suspended && key.suspendedBy == msg.sender && block.timestamp < key.suspensionExpiresAt) {
            revert EmergencyRenewalForbidden();
        }

        key.state = KeyState.Suspended;
        key.stateSince = uint64(block.timestamp);
        key.suspensionExpiresAt = uint64(block.timestamp + EMERGENCY_SUSPENSION_DURATION);
        key.suspendedBy = msg.sender;

        emit KeySuspended(issuerId, kid, key.suspensionExpiresAt, msg.sender);
    }

    /// @inheritdoc ITrustRegistry
    function emergencyLiftSuspension(bytes32 issuerId, bytes32 kid) external override onlyRole(EMERGENCY_ROLE) {
        IssuerKey storage key = _issuerKeys[issuerId][kid];
        if (key.state != KeyState.Suspended) revert SuspensionNotActive();

        key.state = KeyState.Active;
        key.stateSince = uint64(block.timestamp);
        key.suspensionExpiresAt = 0;
        key.suspendedBy = address(0);

        emit KeyAdded(issuerId, kid, key.publicKey);
    }

    // =========================================================================
    // AUXILIARES PRIVADOS
    // =========================================================================

    function _checkTimelockOrAdmin() internal view {
        if (!hasRole(TIMELOCK_ROLE, msg.sender) && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert Unauthorized();
        }
    }
}
