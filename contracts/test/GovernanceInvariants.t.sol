// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {
    TrustRegistry,
    ITrustRegistry,
    IssuerState,
    KeyState,
    IssuerKey
} from "../src/TrustRegistry.sol";
import {GovernanceTimelock} from "../src/GovernanceTimelock.sol";

contract GovernanceInvariantsTest is Test {
    TrustRegistry public registry;
    GovernanceTimelock public timelockContract;

    address public admin = address(0xAD01);
    address public emergency = address(0xE911);
    address public attacker = address(0xBAAD);

    bytes32 public issuerId = keccak256("https://gov.example.com");
    bytes32 public kid = keccak256("key-01");
    bytes public pubKey = hex"024479f6eb079c6d595be5d36e788c6e781190fd83935398246cb32cfcb6e2df40";

    function setUp() public {
        address[] memory proposers = new address[](1);
        proposers[0] = admin;
        address[] memory executors = new address[](1);
        executors[0] = admin;

        timelockContract = new GovernanceTimelock(48 hours, proposers, executors, admin);
        registry = new TrustRegistry(admin, address(timelockContract), emergency);

        bytes32[] memory profiles = new bytes32[](1);
        profiles[0] = keccak256("pip-personal-v1");
        bytes32[] memory vcts = new bytes32[](0);

        vm.prank(admin);
        registry.registerIssuer(issuerId, "https://gov.example.com", profiles, vcts, uint64(block.timestamp), uint64(block.timestamp + 365 days));

        vm.prank(admin);
        registry.addIssuerKey(issuerId, kid, pubKey);
    }

    /// @notice Invariante 1: Una clave comprometida jamás puede volver a estado Active ni ser retirada o suspendida.
    function test_Invariant_CompromisedKeyNeverReturnsToActive() public {
        // Marcar clave como comprometida
        vm.prank(admin);
        registry.markKeyCompromised(issuerId, kid);

        IssuerKey memory key = registry.getIssuerKey(issuerId, kid);
        assertEq(uint8(key.state), uint8(KeyState.Compromised));
        assertFalse(registry.isKeyAuthorized(issuerId, kid));

        // Intento 1: Retirar clave comprometida revierte
        vm.prank(address(timelockContract));
        vm.expectRevert(abi.encodeWithSelector(ITrustRegistry.KeyAlreadyCompromised.selector, issuerId, kid));
        registry.retireIssuerKey(issuerId, kid);

        // Intento 2: Suspender clave comprometida revierte
        vm.prank(address(timelockContract));
        vm.expectRevert(abi.encodeWithSelector(ITrustRegistry.KeyAlreadyCompromised.selector, issuerId, kid));
        registry.suspendKey(issuerId, kid, 30 days);

        // Intento 3: Suspensión de emergencia sobre clave comprometida revierte
        vm.prank(emergency);
        vm.expectRevert(abi.encodeWithSelector(ITrustRegistry.KeyAlreadyCompromised.selector, issuerId, kid));
        registry.emergencySuspendKey(issuerId, kid);

        // Intento 4: Levantamiento de suspensión revierte porque no está suspendida
        vm.prank(emergency);
        vm.expectRevert(ITrustRegistry.SuspensionNotActive.selector);
        registry.emergencyLiftSuspension(issuerId, kid);

        // Intento 5: Transcurrir 100 años no altera el estado terminal
        vm.warp(block.timestamp + 36500 days);
        assertFalse(registry.isKeyAuthorized(issuerId, kid));
        key = registry.getIssuerKey(issuerId, kid);
        assertEq(uint8(key.state), uint8(KeyState.Compromised));
    }

    /// @notice Invariante 2: Solo TIMELOCK_ROLE o DEFAULT_ADMIN_ROLE pueden registrar emisores o claves.
    function test_Invariant_OnlyTimelockCanRegister() public {
        bytes32 rogueIssuer = keccak256("https://rogue.example.com");
        bytes32[] memory profiles = new bytes32[](0);
        bytes32[] memory vcts = new bytes32[](0);

        // Atacante falla
        vm.prank(attacker);
        vm.expectRevert(ITrustRegistry.Unauthorized.selector);
        registry.registerIssuer(rogueIssuer, "https://rogue.example.com", profiles, vcts, 100, 200);

        // EMERGENCY_ROLE falla (no tiene rol de alta)
        vm.prank(emergency);
        vm.expectRevert(ITrustRegistry.Unauthorized.selector);
        registry.registerIssuer(rogueIssuer, "https://rogue.example.com", profiles, vcts, 100, 200);
    }

    /// @notice Invariante 3: EMERGENCY_ROLE solo puede suspender y levantar suspensiones cautelares.
    function test_Invariant_EmergencyRoleRestrictedPrivileges() public {
        // EMERGENCY_ROLE no puede marcar clave como comprometida
        vm.prank(emergency);
        vm.expectRevert();
        registry.markKeyCompromised(issuerId, kid);

        // EMERGENCY_ROLE no puede retirar claves
        vm.prank(emergency);
        vm.expectRevert(ITrustRegistry.Unauthorized.selector);
        registry.retireIssuerKey(issuerId, kid);

        // EMERGENCY_ROLE no puede dar de baja emisores
        vm.prank(emergency);
        vm.expectRevert(ITrustRegistry.Unauthorized.selector);
        registry.deregisterIssuer(issuerId);

        // EMERGENCY_ROLE no puede actualizar la raíz de confianza
        vm.prank(emergency);
        vm.expectRevert(ITrustRegistry.Unauthorized.selector);
        registry.updateTrustRootHash(keccak256("new-root"), 2);
    }

    /// @notice Invariante 4: EMERGENCY_ROLE no puede auto-renovar una suspensión activa (mitigación DoS persistente).
    function test_Invariant_EmergencyRoleCannotRenewActiveSuspension() public {
        vm.prank(emergency);
        registry.emergencySuspendKey(issuerId, kid);

        // Mientras no haya expirado, auto-renovación revierte
        vm.prank(emergency);
        vm.expectRevert(ITrustRegistry.EmergencyRenewalForbidden.selector);
        registry.emergencySuspendKey(issuerId, kid);
    }

    /// @notice Invariante 5: Toda suspensión cautelar caduca automáticamente tras el TTL de 14 días.
    function test_Invariant_EmergencySuspensionAlwaysExpires() public {
        vm.prank(emergency);
        registry.emergencySuspendKey(issuerId, kid);

        IssuerKey memory key = registry.getIssuerKey(issuerId, kid);
        assertEq(key.suspensionExpiresAt, block.timestamp + 14 days);
        assertFalse(registry.isKeyAuthorized(issuerId, kid));

        // Al cumplirse el plazo de 14 días + 1 segundo:
        vm.warp(block.timestamp + 14 days + 1);
        assertTrue(registry.isKeyAuthorized(issuerId, kid));
    }

    /// @notice Invariante 6: El timelock exige un retardo mínimo no inferior a 48 horas.
    function test_Invariant_TimelockMinimumDelayEnforced() public {
        address[] memory proposers = new address[](0);
        address[] memory executors = new address[](0);

        // Intentar instanciar timelock con retardo de 24 horas debe revertir
        vm.expectRevert(abi.encodeWithSelector(GovernanceTimelock.DelayTooShort.selector, 24 hours, 48 hours));
        new GovernanceTimelock(24 hours, proposers, executors, admin);
    }
}
