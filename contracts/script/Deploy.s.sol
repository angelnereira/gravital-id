// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {TrustRegistry} from "../src/TrustRegistry.sol";
import {StatusAnchor} from "../src/StatusAnchor.sol";
import {GovernanceTimelock} from "../src/GovernanceTimelock.sol";

/// @title DeployScript - Despliegue reproducible de contratos para Gravital ID (F6.T11, REQ-LEDG-003)
contract DeployScript is Script {
    function run() external returns (
        GovernanceTimelock timelock,
        TrustRegistry registry,
        StatusAnchor anchor
    ) {
        // Llave de despliegue: leída de variable de entorno o fallback seguro de desarrollo (Anvil key 0)
        uint256 deployerPrivateKey = vm.envOr(
            "DEPLOYER_PRIVATE_KEY",
            uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80)
        );

        address deployer = vm.addr(deployerPrivateKey);
        address admin = vm.envOr("TFA_ADMIN_MULTISIG", deployer);
        address emergencyAdmin = vm.envOr("EMERGENCY_MULTISIG", deployer);

        uint256 minDelay = vm.envOr("TIMELOCK_DELAY_SECONDS", uint256(48 hours));

        address[] memory proposers = new address[](1);
        proposers[0] = admin;

        // address(0) como executor permite que cualquier operador o servicio ejecute propuestas ya cumplidas
        address[] memory executors = new address[](1);
        executors[0] = address(0);

        vm.startBroadcast(deployerPrivateKey);

        // 1. Desplegar GovernanceTimelock (minDelay >= 48 hours inmutable)
        timelock = new GovernanceTimelock(
            minDelay,
            proposers,
            executors,
            admin
        );

        // 2. Desplegar TrustRegistry con roles segregados
        registry = new TrustRegistry(
            admin,
            address(timelock),
            emergencyAdmin
        );

        // 3. Desplegar StatusAnchor
        anchor = new StatusAnchor(admin);

        vm.stopBroadcast();

        console.log("=== DESPLIEGUE GRAVITAL ID / PIP COMPLETADO ===");
        console.log("Chain ID: ", block.chainid);
        console.log("Deployer: ", deployer);
        console.log("TFA Admin: ", admin);
        console.log("GovernanceTimelock: ", address(timelock));
        console.log("TrustRegistry: ", address(registry));
        console.log("StatusAnchor: ", address(anchor));
    }
}
