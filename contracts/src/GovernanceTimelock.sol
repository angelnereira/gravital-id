// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity 0.8.28;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @title GovernanceTimelock
/// @notice Controlador de timelock normativo para la gobernanza ordinaria de Gravital ID (SPEC-PIP-CONTRACTS-001 §5, REQ-LEDG-004).
/// @dev Exige un retardo mínimo de 48 horas (172.800 segundos) para proteger el registro de confianza ante compromisos de claves individuales.
contract GovernanceTimelock is TimelockController {
    uint256 public constant MINIMUM_TIMELOCK_DELAY = 48 hours;

    error DelayTooShort(uint256 provided, uint256 minimum);

    /// @notice Constructor que valida el retardo mínimo de 48h.
    /// @param minDelay Retardo en segundos antes de poder ejecutar una propuesta (>= 48h).
    /// @param proposers Cuentas autorizadas para proponer (multisig Safe TFA).
    /// @param executors Cuentas autorizadas para ejecutar propuestas cumplidas.
    /// @param admin Administrador inicial del timelock (revocado o asignado a la multisig).
    constructor(
        uint256 minDelay,
        address[] memory proposers,
        address[] memory executors,
        address admin
    ) TimelockController(minDelay, proposers, executors, admin) {
        if (minDelay < MINIMUM_TIMELOCK_DELAY) {
            revert DelayTooShort(minDelay, MINIMUM_TIMELOCK_DELAY);
        }
    }
}
