// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {StatusAnchor, IStatusAnchor} from "../src/StatusAnchor.sol";

contract StatusAnchorTest is Test {
    StatusAnchor public anchor;

    address public admin = address(0xAD01);
    address public issuerOperator = address(0x1550);
    address public unauthorizedUser = address(0xBAAD);

    bytes32 public issuerId = keccak256("https://issuer.cedula.example.gov");
    bytes32 public manifestHash1 = keccak256("status-manifest-2026-10-v1");
    bytes32 public manifestHash2 = keccak256("status-manifest-2026-10-v2");

    function setUp() public {
        anchor = new StatusAnchor(admin);
        bytes32 role = anchor.ANCHOR_ROLE();
        vm.prank(admin);
        anchor.grantRole(role, issuerOperator);
    }

    function test_AnchorStatusManifest_Success() public {
        vm.prank(issuerOperator);
        vm.expectEmit(true, true, false, true);
        emit IStatusAnchor.StatusManifestAnchored(
            issuerId,
            1,
            manifestHash1,
            "https://status.cedula.example.gov/manifests/v1.json"
        );

        anchor.anchorStatusManifest(
            issuerId,
            1,
            manifestHash1,
            "https://status.cedula.example.gov/manifests/v1.json"
        );

        IStatusAnchor.StatusCommitment memory c = anchor.getLatestCommitment(issuerId);
        assertEq(c.manifestHash, manifestHash1);
        assertEq(c.manifestVersion, 1);
        assertEq(c.anchoredAt, block.timestamp);
        assertEq(c.blockNumber, block.number);

        IStatusAnchor.StatusCommitment memory cVer = anchor.getCommitmentByVersion(issuerId, 1);
        assertEq(cVer.manifestHash, manifestHash1);
    }

    function test_AnchorStatusManifest_NonMonotonic_Reverts() public {
        vm.prank(issuerOperator);
        anchor.anchorStatusManifest(issuerId, 5, manifestHash1, "hint");

        // Intentar anclar con versión igual (5) debe revertir
        vm.prank(issuerOperator);
        vm.expectRevert(abi.encodeWithSelector(IStatusAnchor.VersionNotMonotonic.selector, 5, 5));
        anchor.anchorStatusManifest(issuerId, 5, manifestHash2, "hint");

        // Intentar anclar con versión inferior (4) debe revertir
        vm.prank(issuerOperator);
        vm.expectRevert(abi.encodeWithSelector(IStatusAnchor.VersionNotMonotonic.selector, 5, 4));
        anchor.anchorStatusManifest(issuerId, 4, manifestHash2, "hint");
    }

    function test_AnchorStatusManifest_Unauthorized_Reverts() public {
        vm.prank(unauthorizedUser);
        vm.expectRevert(IStatusAnchor.Unauthorized.selector);
        anchor.anchorStatusManifest(issuerId, 1, manifestHash1, "hint");
    }

    function test_AnchorStatusManifest_ZeroHash_Reverts() public {
        vm.prank(issuerOperator);
        vm.expectRevert(IStatusAnchor.InvalidManifestHash.selector);
        anchor.anchorStatusManifest(issuerId, 1, bytes32(0), "hint");
    }

    function testFuzz_AnchorMonotonicProgression(uint32 startVer, uint16 delta) public {
        vm.assume(startVer > 0);
        vm.assume(delta > 0);

        uint64 v1 = uint64(startVer);
        uint64 v2 = v1 + uint64(delta);

        vm.prank(issuerOperator);
        anchor.anchorStatusManifest(issuerId, v1, keccak256(abi.encode(v1)), "hint1");

        vm.prank(issuerOperator);
        anchor.anchorStatusManifest(issuerId, v2, keccak256(abi.encode(v2)), "hint2");

        IStatusAnchor.StatusCommitment memory latest = anchor.getLatestCommitment(issuerId);
        assertEq(latest.manifestVersion, v2);
    }
}
