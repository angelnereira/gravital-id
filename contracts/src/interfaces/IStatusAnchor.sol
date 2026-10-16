// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity 0.8.28;

/// @title Interfaz IStatusAnchor
/// @notice Anclaje periódico descentralizado de compromisos de listas de revocación (SPEC-PIP-CONTRACTS-001 §4).
interface IStatusAnchor {
    // --- ESTRUCTURAS ---
    struct StatusCommitment {
        bytes32 manifestHash;   // SHA-256 del IssuerStatusManifest canónico
        uint64 manifestVersion; // Versión monotónica incremental del manifiesto
        uint64 anchoredAt;      // Timestamp Unix de inclusión en bloque
        uint64 blockNumber;     // Altura de bloque de la inclusión
    }

    // --- ERRORES PERSONALIZADOS ---
    error Unauthorized();
    error VersionNotMonotonic(uint64 current, uint64 proposed);
    error InvalidManifestHash();

    // --- EVENTOS ---
    event StatusManifestAnchored(
        bytes32 indexed issuerId,
        uint64 indexed manifestVersion,
        bytes32 manifestHash,
        string uriHint
    );

    // --- FUNCIONES DE LECTURA ---
    function getLatestCommitment(bytes32 issuerId) external view returns (StatusCommitment memory);

    function getCommitmentByVersion(
        bytes32 issuerId,
        uint64 manifestVersion
    ) external view returns (StatusCommitment memory);

    // --- FUNCIONES DE MUTACIÓN ---
    /// @notice Ancla un nuevo compromiso de estado para el emisor.
    /// @dev Requiere que manifestVersion sea estrictamente superior a la última versión registrada.
    function anchorStatusManifest(
        bytes32 issuerId,
        uint64 manifestVersion,
        bytes32 manifestHash,
        string calldata uriHint
    ) external;
}
