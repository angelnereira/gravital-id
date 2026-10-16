// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity 0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IStatusAnchor} from "./interfaces/IStatusAnchor.sol";

/// @title StatusAnchor
/// @notice Contrato descentralizado para el anclaje periódico de raíces Merkle de listas de revocación (SPEC-PIP-CONTRACTS-001 §4, REQ-STAT-006).
/// @dev Inmutable, sin proxies (REQ-LEDG-003) y sin datos personales (REQ-LEDG-001, INV-02).
contract StatusAnchor is AccessControl, IStatusAnchor {
    // --- CONSTANTES DE ROLES (RBAC) ---
    bytes32 public constant ANCHOR_ROLE = keccak256("ANCHOR_ROLE");

    // --- ALMACENAMIENTO ---
    mapping(bytes32 => StatusCommitment) private _latestCommitments;
    mapping(bytes32 => mapping(uint64 => StatusCommitment)) private _commitmentsByVersion;

    /// @notice Inicializa el contrato con el administrador inicial.
    /// @param admin Cuenta administradora o multisig de la TFA.
    constructor(address admin) {
        if (admin == address(0)) {
            revert Unauthorized();
        }
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ANCHOR_ROLE, admin);
    }

    // =========================================================================
    // FUNCIONES DE LECTURA (VIEWS)
    // =========================================================================

    /// @inheritdoc IStatusAnchor
    function getLatestCommitment(bytes32 issuerId) external view override returns (StatusCommitment memory) {
        return _latestCommitments[issuerId];
    }

    /// @inheritdoc IStatusAnchor
    function getCommitmentByVersion(
        bytes32 issuerId,
        uint64 manifestVersion
    ) external view override returns (StatusCommitment memory) {
        return _commitmentsByVersion[issuerId][manifestVersion];
    }

    // =========================================================================
    // FUNCIONES DE MUTACIÓN
    // =========================================================================

    /// @inheritdoc IStatusAnchor
    function anchorStatusManifest(
        bytes32 issuerId,
        uint64 manifestVersion,
        bytes32 manifestHash,
        string calldata uriHint
    ) external override {
        if (!hasRole(ANCHOR_ROLE, msg.sender) && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert Unauthorized();
        }

        if (manifestHash == bytes32(0)) {
            revert InvalidManifestHash();
        }

        uint64 currentVersion = _latestCommitments[issuerId].manifestVersion;
        if (manifestVersion <= currentVersion) {
            revert VersionNotMonotonic(currentVersion, manifestVersion);
        }

        StatusCommitment memory commitment = StatusCommitment({
            manifestHash: manifestHash,
            manifestVersion: manifestVersion,
            anchoredAt: uint64(block.timestamp),
            blockNumber: uint64(block.number)
        });

        _latestCommitments[issuerId] = commitment;
        _commitmentsByVersion[issuerId][manifestVersion] = commitment;

        emit StatusManifestAnchored(issuerId, manifestVersion, manifestHash, uriHint);
    }
}
