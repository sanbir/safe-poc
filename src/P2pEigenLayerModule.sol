// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "./@eigenlayer/interfaces/IEigenPod.sol";
import "./@safe/common/Enum.sol";

interface ISafe {
    /// @dev Allows a Module to execute a Safe transaction without any further confirmations.
    /// @param to Destination address of module transaction.
    /// @param value Ether value of module transaction.
    /// @param data Data payload of module transaction.
    /// @param operation Operation type of module transaction.
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation
    ) external returns (bool success);
}

contract P2pEigenLayerModule {
    IEigenPodManager public constant EigenPodManager = IEigenPodManager(0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338);

    /// @dev maps each Safe to its configured EigenPod
    mapping(ISafe => IEigenPod) private eigenPodOf;

    function setup(bytes calldata) external {
        IEigenPod eigenPod = EigenPodManager.getPod(msg.sender);
        require(address(eigenPod).code.length > 0, "Invalid EigenPod address");
        eigenPodOf[ISafe(msg.sender)] = eigenPod;
    }

    function getEigenPodVersion(ISafe safe) private {
        bytes memory data = abi.encodeCall(ISemVerMixin.version, ());
        address eigenPod = address(eigenPodOf[safe]);

        require(safe.execTransactionFromModule(eigenPod, 0, data, Enum.Operation.Call), "Could not getEigenPodVersion");
    }
}

