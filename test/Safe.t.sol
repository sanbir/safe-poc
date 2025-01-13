// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../src/@safe/proxies/SafeProxyFactory.sol";
import {Test, console} from "forge-std/Test.sol";

contract SafeTest is Test {
    address public constant SafeProxyFactoryAddress = 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67;
    SafeProxyFactory public constant SafeProxyFactoryInstance = SafeProxyFactory(SafeProxyFactoryAddress);

    function setUp() public {
        vm.createSelectFork("mainnet", 21308893);
    }

    function test_Increment() public {
        uint256 chainId = SafeProxyFactoryInstance.getChainId();
        console.log(chainId);
    }
}
