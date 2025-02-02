// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../src/@safe/ISafe_1_4_1.sol";
import "../src/@safe/proxies/SafeProxyFactory.sol";
import {Test, console} from "forge-std/Test.sol";

contract SafeTest is Test {
    address public constant SafeProxyFactoryAddress = 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67;
    SafeProxyFactory public constant SafeProxyFactoryInstance = SafeProxyFactory(SafeProxyFactoryAddress);

    address public constant Safe_1_4_1_Address = 0x41675C099F32341bf84BFc5382aF534df5C7461a;

    address private clientAddress;
    uint256 private clientPrivateKey;

    address private p2pOperatorAddress;
    uint256 private p2pOperatorPrivateKey;

    address public ClientSafeInstance;

    function setUp() public {
        vm.createSelectFork("mainnet", 21308893);

        (clientAddress, clientPrivateKey) = makeAddrAndKey("client");
        (p2pOperatorAddress, p2pOperatorPrivateKey) = makeAddrAndKey("p2pOperator");
    }

    function test_Safe() public {
        ClientSafeInstance = _deploySafe();

        console.log(ClientSafeInstance);
    }

    function _deploySafe() private returns(address) {
        address[] memory _owners = new address[](2);
        _owners[0] = clientAddress;
        _owners[1] = p2pOperatorAddress;

        uint256 _threshold = 1;
        address to = address(0);
        bytes memory data = "";
        address fallbackHandler = address(0);
        address paymentToken = address(0);
        uint256 payment = 0;
        address payable paymentReceiver = payable(address(0));

        bytes memory initializer = abi.encodeCall(ISafe_1_4_1.setup, (
            _owners,
            _threshold,
            to,
            data,
            fallbackHandler,
            paymentToken,
            payment,
            paymentReceiver
        ));

        vm.startPrank(p2pOperatorAddress);
        SafeProxy proxy = SafeProxyFactoryInstance.createProxyWithNonce(
            Safe_1_4_1_Address,
            initializer,
            0
        );
        vm.stopPrank();

        return address(proxy);
    }
}
