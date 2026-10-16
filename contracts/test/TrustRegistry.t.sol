// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {
    TrustRegistry,
    ITrustRegistry,
    IssuerState,
    KeyState,
    VerifierState,
    IssuerKey,
    IssuerRecord,
    VerifierRecord,
    TrustRootCommitment
} from "../src/TrustRegistry.sol";

contract TrustRegistryTest is Test {
    TrustRegistry public registry;

    address public admin = address(0xAD01);
    address public timelock = address(0x710E);
    address public emergency = address(0xE911);
    address public attacker = address(0xBAAD);

    bytes32 public issuerId1 = keccak256("https://issuer.cedula.example.gov");
    bytes32 public kid1 = keccak256("key-2026-issuer-01");
    bytes32 public profilePersonal = keccak256("pip-personal-v1");
    bytes32 public vctId1 = keccak256("https://credentials.gravital.io/vct/personal/id-v1");

    bytes public pubKeyP256Compressed = hex"024479f6eb079c6d595be5d36e788c6e781190fd83935398246cb32cfcb6e2df40";
    bytes public pubKeyP256Uncompressed = hex"044479f6eb079c6d595be5d36e788c6e781190fd83935398246cb32cfcb6e2df4090dc2e9c22c07fc11c1d428bfd5ab9eb6fc9b44bb0e0d5dbce584ebfa8827988";

    function setUp() public {
        registry = new TrustRegistry(admin, timelock, emergency);
    }

    // =========================================================================
    // PRUEBAS DE REGISTRO DE EMISORES
    // =========================================================================

    function test_RegisterIssuer_Success() public {
        bytes32[] memory profiles = new bytes32[](1);
        profiles[0] = profilePersonal;
        bytes32[] memory vcts = new bytes32[](1);
        vcts[0] = vctId1;

        uint64 validFrom = uint64(block.timestamp);
        uint64 validUntil = uint64(block.timestamp + 365 days);

        vm.prank(timelock);
        vm.expectEmit(true, false, false, true);
        emit ITrustRegistry.IssuerRegistered(issuerId1, "https://issuer.cedula.example.gov", validFrom, validUntil);

        registry.registerIssuer(issuerId1, "https://issuer.cedula.example.gov", profiles, vcts, validFrom, validUntil);

        IssuerRecord memory rec = registry.getIssuer(issuerId1);
        assertEq(rec.uri, "https://issuer.cedula.example.gov");
        assertEq(uint8(rec.state), uint8(IssuerState.Active));
        assertTrue(registry.isIssuerAuthorized(issuerId1, profilePersonal));
        assertTrue(registry.isIssuerAuthorized(issuerId1, bytes32(0)));
    }

    function test_RegisterIssuer_Unauthorized_Reverts() public {
        bytes32[] memory profiles = new bytes32[](0);
        bytes32[] memory vcts = new bytes32[](0);

        vm.prank(attacker);
        vm.expectRevert(ITrustRegistry.Unauthorized.selector);
        registry.registerIssuer(issuerId1, "https://attacker.org", profiles, vcts, 100, 200);
    }

    function test_RegisterIssuer_Duplicate_Reverts() public {
        bytes32[] memory profiles = new bytes32[](0);
        bytes32[] memory vcts = new bytes32[](0);

        vm.prank(timelock);
        registry.registerIssuer(issuerId1, "https://issuer.cedula.example.gov", profiles, vcts, 100, 200);

        vm.prank(timelock);
        vm.expectRevert(abi.encodeWithSelector(ITrustRegistry.IssuerAlreadyExists.selector, issuerId1));
        registry.registerIssuer(issuerId1, "https://issuer.cedula.example.gov", profiles, vcts, 100, 200);
    }

    function test_RegisterIssuer_InvalidTimestamps_Reverts() public {
        bytes32[] memory profiles = new bytes32[](0);
        bytes32[] memory vcts = new bytes32[](0);

        vm.prank(timelock);
        vm.expectRevert(ITrustRegistry.InvalidTimestamps.selector);
        registry.registerIssuer(issuerId1, "https://issuer.cedula.example.gov", profiles, vcts, 200, 100);
    }

    // =========================================================================
    // PRUEBAS DE CLAVES DE EMISOR Y MÁQUINA DE ESTADOS
    // =========================================================================

    function _registerDefaultIssuer() internal {
        bytes32[] memory profiles = new bytes32[](1);
        profiles[0] = profilePersonal;
        bytes32[] memory vcts = new bytes32[](1);
        vcts[0] = vctId1;
        vm.prank(timelock);
        registry.registerIssuer(issuerId1, "https://issuer.cedula.example.gov", profiles, vcts, uint64(block.timestamp), uint64(block.timestamp + 365 days));
    }

    function test_AddIssuerKey_CompressedAndUncompressed() public {
        _registerDefaultIssuer();

        vm.prank(timelock);
        registry.addIssuerKey(issuerId1, kid1, pubKeyP256Compressed);

        IssuerKey memory key = registry.getIssuerKey(issuerId1, kid1);
        assertEq(key.kid, kid1);
        assertEq(key.publicKey, pubKeyP256Compressed);
        assertEq(uint8(key.state), uint8(KeyState.Active));
        assertTrue(registry.isKeyAuthorized(issuerId1, kid1));

        bytes32 kid2 = keccak256("key-2026-issuer-02");
        vm.prank(timelock);
        registry.addIssuerKey(issuerId1, kid2, pubKeyP256Uncompressed);

        assertTrue(registry.isKeyAuthorized(issuerId1, kid2));
        bytes32[] memory keys = registry.getIssuerKeyIds(issuerId1);
        assertEq(keys.length, 2);
    }

    function test_AddIssuerKey_InvalidLength_Reverts() public {
        _registerDefaultIssuer();

        bytes memory invalidKey = hex"0211223344"; // 5 bytes
        vm.prank(timelock);
        vm.expectRevert(abi.encodeWithSelector(ITrustRegistry.InvalidPublicKeyLength.selector, 5));
        registry.addIssuerKey(issuerId1, kid1, invalidKey);
    }

    function test_RetireKey_Success() public {
        _registerDefaultIssuer();
        vm.prank(timelock);
        registry.addIssuerKey(issuerId1, kid1, pubKeyP256Compressed);

        vm.prank(timelock);
        vm.expectEmit(true, true, false, true);
        emit ITrustRegistry.KeyRetired(issuerId1, kid1, uint64(block.timestamp));
        registry.retireIssuerKey(issuerId1, kid1);

        IssuerKey memory key = registry.getIssuerKey(issuerId1, kid1);
        assertEq(uint8(key.state), uint8(KeyState.Retired));
        assertFalse(registry.isKeyAuthorized(issuerId1, kid1));

        // Reintentar retirar una clave ya retirada debe revertir
        vm.prank(timelock);
        vm.expectRevert(abi.encodeWithSelector(ITrustRegistry.KeyAlreadyRetired.selector, issuerId1, kid1));
        registry.retireIssuerKey(issuerId1, kid1);
    }

    function test_EmergencySuspendKey_TTL14Days_AndAutoExpiration() public {
        _registerDefaultIssuer();
        vm.prank(timelock);
        registry.addIssuerKey(issuerId1, kid1, pubKeyP256Compressed);

        uint64 suspendTime = uint64(block.timestamp);
        uint64 expectedExpiresAt = suspendTime + registry.EMERGENCY_SUSPENSION_DURATION();

        vm.prank(emergency);
        vm.expectEmit(true, true, false, true);
        emit ITrustRegistry.KeySuspended(issuerId1, kid1, expectedExpiresAt, emergency);
        registry.emergencySuspendKey(issuerId1, kid1);

        IssuerKey memory key = registry.getIssuerKey(issuerId1, kid1);
        assertEq(uint8(key.state), uint8(KeyState.Suspended));
        assertEq(key.suspensionExpiresAt, expectedExpiresAt);
        assertEq(key.suspendedBy, emergency);

        // Clave no está autorizada mientras la suspensión está activa
        assertFalse(registry.isKeyAuthorized(issuerId1, kid1));

        // Prohibición estricta de auto-renovación por EMERGENCY_ROLE
        vm.prank(emergency);
        vm.expectRevert(ITrustRegistry.EmergencyRenewalForbidden.selector);
        registry.emergencySuspendKey(issuerId1, kid1);

        // Al avanzar el tiempo pasado el TTL (14 días + 1 segundo):
        vm.warp(expectedExpiresAt + 1);
        // Debe auto-recuperar autorización automáticamente
        assertTrue(registry.isKeyAuthorized(issuerId1, kid1));
    }

    function test_EmergencyLiftSuspension_Success() public {
        _registerDefaultIssuer();
        vm.prank(timelock);
        registry.addIssuerKey(issuerId1, kid1, pubKeyP256Compressed);

        vm.prank(emergency);
        registry.emergencySuspendKey(issuerId1, kid1);
        assertFalse(registry.isKeyAuthorized(issuerId1, kid1));

        // Levantamiento anticipado por emergencia
        vm.prank(emergency);
        registry.emergencyLiftSuspension(issuerId1, kid1);

        IssuerKey memory key = registry.getIssuerKey(issuerId1, kid1);
        assertEq(uint8(key.state), uint8(KeyState.Active));
        assertEq(key.suspensionExpiresAt, 0);
        assertTrue(registry.isKeyAuthorized(issuerId1, kid1));
    }

    function test_MarkKeyCompromised_IsTerminal() public {
        _registerDefaultIssuer();
        vm.prank(timelock);
        registry.addIssuerKey(issuerId1, kid1, pubKeyP256Compressed);

        // Solo el admin pleno (multisig) puede marcar comprometida
        vm.prank(emergency);
        vm.expectRevert();
        registry.markKeyCompromised(issuerId1, kid1);

        vm.prank(admin);
        vm.expectEmit(true, true, false, true);
        emit ITrustRegistry.KeyCompromised(issuerId1, kid1, uint64(block.timestamp));
        registry.markKeyCompromised(issuerId1, kid1);

        IssuerKey memory key = registry.getIssuerKey(issuerId1, kid1);
        assertEq(uint8(key.state), uint8(KeyState.Compromised));
        assertFalse(registry.isKeyAuthorized(issuerId1, kid1));

        // Una clave comprometida no puede ser retirada ni suspendida
        vm.prank(timelock);
        vm.expectRevert(abi.encodeWithSelector(ITrustRegistry.KeyAlreadyCompromised.selector, issuerId1, kid1));
        registry.retireIssuerKey(issuerId1, kid1);

        vm.prank(emergency);
        vm.expectRevert(abi.encodeWithSelector(ITrustRegistry.KeyAlreadyCompromised.selector, issuerId1, kid1));
        registry.emergencySuspendKey(issuerId1, kid1);
    }

    // =========================================================================
    // PRUEBAS DE VERIFICADORES REGISTRADOS (REQ-TRUST-007)
    // =========================================================================

    function test_RegisterVerifier_Success() public {
        bytes32 verifierId = keccak256("https://verifier.example.com");
        bytes32[] memory profiles = new bytes32[](1);
        profiles[0] = profilePersonal;

        vm.prank(timelock);
        registry.registerVerifier(
            verifierId,
            "https://verifier.example.com",
            profiles,
            pubKeyP256Compressed,
            uint64(block.timestamp),
            uint64(block.timestamp + 180 days)
        );

        VerifierRecord memory ver = registry.getVerifier(verifierId);
        assertEq(ver.uri, "https://verifier.example.com");
        assertEq(uint8(ver.state), uint8(VerifierState.Active));
        assertTrue(registry.isVerifierAuthorized(verifierId, profilePersonal));
        assertFalse(registry.isVerifierAuthorized(verifierId, keccak256("pip-financial-v1")));
    }

    // =========================================================================
    // PRUEBAS DE RAÍZ DE CONFIANZA Y FIRMANTES DE BUNDLE
    // =========================================================================

    function test_UpdateTrustRootHash_Monotonic() public {
        bytes32 rootHash1 = keccak256("canonical-root-hash-v1");
        vm.prank(timelock);
        registry.updateTrustRootHash(rootHash1, 1);

        TrustRootCommitment memory c1 = registry.getTrustRootCommitment();
        assertEq(c1.rootHash, rootHash1);
        assertEq(c1.rootVersion, 1);

        // Actualizar a versión igual o menor debe revertir
        vm.prank(timelock);
        vm.expectRevert(abi.encodeWithSelector(ITrustRegistry.InvalidRootVersion.selector, 1, 1));
        registry.updateTrustRootHash(keccak256("same-version"), 1);

        // Actualizar a versión mayor tiene éxito
        bytes32 rootHash2 = keccak256("canonical-root-hash-v2");
        vm.prank(timelock);
        registry.updateTrustRootHash(rootHash2, 2);

        TrustRootCommitment memory c2 = registry.getTrustRootCommitment();
        assertEq(c2.rootHash, rootHash2);
        assertEq(c2.rootVersion, 2);
    }

    function test_SetBundleSigner_Success() public {
        address signerAddr = address(0x5164);
        bytes32 signerKid = keccak256("bundle-signer-operator-01");

        assertFalse(registry.isBundleSigner(signerAddr));

        vm.prank(timelock);
        registry.setBundleSigner(signerAddr, signerKid, pubKeyP256Compressed, true);

        assertTrue(registry.isBundleSigner(signerAddr));

        // Revocar
        vm.prank(timelock);
        registry.setBundleSigner(signerAddr, signerKid, pubKeyP256Compressed, false);

        assertFalse(registry.isBundleSigner(signerAddr));
    }

    // =========================================================================
    // FUZZ TESTING
    // =========================================================================

    function testFuzz_UpdateTrustRootVersion(uint32 v1, uint32 delta) public {
        vm.assume(v1 > 0);
        vm.assume(delta > 0);
        uint64 ver1 = uint64(v1);
        uint64 ver2 = ver1 + uint64(delta);

        vm.prank(timelock);
        registry.updateTrustRootHash(keccak256(abi.encode(ver1)), ver1);

        vm.prank(timelock);
        registry.updateTrustRootHash(keccak256(abi.encode(ver2)), ver2);

        TrustRootCommitment memory c = registry.getTrustRootCommitment();
        assertEq(c.rootVersion, ver2);
    }
}
