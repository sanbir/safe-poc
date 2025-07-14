// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../src/@safe/ISafe_1_4_1.sol";
import "../src/@safe/proxies/SafeProxyFactory.sol";
import "../src/P2pEigenLayerModule.sol";
import {Test, console} from "forge-std/Test.sol";
import "../lib/modulekit/src/module-bases/utils/ERC7579Constants.sol";

contract Erc7579Test is Test {
    address private clientAddress;
    uint256 private clientPrivateKey;

    address private p2pOperatorAddress;
    uint256 private p2pOperatorPrivateKey;

    address public ClientSWAInstance;
    address public Module;

    bytes public eigenPodCalldata;

    function setUp() public {
        vm.createSelectFork("mainnet", 22572464);

        // (clientAddress, clientPrivateKey) = makeAddrAndKey("client");
        clientAddress = 0xE99A946A20f0e08e78F3F140905650432d069aA4;
        (p2pOperatorAddress, p2pOperatorPrivateKey) = makeAddrAndKey("p2pOperator");

        eigenPodCalldata = abi.encodeCall(IEigenPod.startCheckpoint, (false));
    }

    function test_ERC7579Module() public {
        ClientSWAInstance = 0xe73c8CcB5A9727B2f9fe5D0e0f87F7999b983fc8;
        Module = _deployP2pEigenLayerModule();
        _enableERC7579Module();

        address pod = address(P2pEigenLayerModule(Module).s_EigenPodOf(ClientSWAInstance));
        vm.startPrank(p2pOperatorAddress);
        P2pEigenLayerModule(Module).execERC7579(ClientSWAInstance, pod, eigenPodCalldata);
        vm.stopPrank();
    }

    function _enableERC7579Module() private {
        vm.startPrank(clientAddress);

        bytes memory initData = abi.encodePacked(
            // first exactly 20 bytes = hook address
            bytes20(address(1)),
            // then a *proper* abi encoding of the two dynamic fields
            abi.encode(
                bytes(""),  // executorData
                bytes("")   // hookData
            )
        );

        IERC7579Account(ClientSWAInstance).installModule(
            MODULE_TYPE_EXECUTOR,
            Module,
            initData
        );
        vm.stopPrank();
    }

    function _deployP2pEigenLayerModule() private returns(address) {
        vm.startPrank(p2pOperatorAddress);
        P2pEigenLayerModule module = new P2pEigenLayerModule();
        vm.stopPrank();

        return address(module);
    }
}
