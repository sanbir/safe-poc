// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../lib/forge-std/src/Vm.sol";
import "../src/P2pEigenLayerModule.sol";
import {Script} from "forge-std/Script.sol";

contract Deploy is Script {

    function run()
        external
        returns (P2pEigenLayerModule module)
    {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerKey);
        P2pEigenLayerModule module = new P2pEigenLayerModule();
        vm.stopBroadcast();

        return (module);
    }
}
