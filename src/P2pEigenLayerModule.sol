// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../lib/modulekit/src/module-bases/ERC7579ExecutorBase.sol";
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

contract P2pEigenLayerModule is ERC7579ExecutorBase {
    event P2pEigenLayerModule__Setup(address eigenPod, address eigenPodOwner);

    IEigenPodManager public constant EigenPodManager = IEigenPodManager(0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338);

    /// @dev maps each SWA to its configured EigenPod
    mapping(address => IEigenPod) private eigenPodOf;

    // Safe

    function setup(bytes calldata) external {
        IEigenPod eigenPod = EigenPodManager.getPod(msg.sender);
        ISafe safe = ISafe(msg.sender);

        if (address(eigenPod).code.length == 0) {
            bytes memory data = abi.encodeCall(EigenPodManager.createPod, ());
            require(safe.execTransactionFromModule(address(EigenPodManager), 0, data, Enum.Operation.Call), "Could not createPod");
        }

        eigenPodOf[msg.sender] = eigenPod;
        emit P2pEigenLayerModule__Setup(address(eigenPod), msg.sender);
    }

    function getEigenPodVersion(address safeAddress) external {
        bytes memory data = abi.encodeCall(ISemVerMixin.version, ());
        address eigenPod = address(eigenPodOf[safeAddress]);

        require(ISafe(safeAddress).execTransactionFromModule(eigenPod, 0, data, Enum.Operation.Call), "Could not getEigenPodVersion");
    }

    function startCheckpoint(address safeAddress) external {
        bytes memory data = abi.encodeCall(IEigenPod.startCheckpoint, (false));
        address eigenPod = address(eigenPodOf[safeAddress]);

        require(ISafe(safeAddress).execTransactionFromModule(eigenPod, 0, data, Enum.Operation.Call), "Could not startCheckpoint");
    }

    // ERC-7579

    function onInstall(bytes calldata) external override {
        IEigenPod eigenPod = EigenPodManager.getPod(msg.sender);

        if (address(eigenPod).code.length == 0) {
            bytes memory data = abi.encodeCall(EigenPodManager.createPod, ());
            _execute(address(EigenPodManager), 0, data);
        }

        eigenPodOf[msg.sender] = eigenPod;
        emit P2pEigenLayerModule__Setup(address(eigenPod), msg.sender);
    }

    function onUninstall(bytes calldata) external override { }

    function startCheckpointERC7579(address swa) external {
        bytes memory data = abi.encodeCall(IEigenPod.startCheckpoint, (false));
        address eigenPod = address(eigenPodOf[swa]);
        _execute(swa, eigenPod, 0, data);
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == TYPE_EXECUTOR;
    }

    function isInitialized(
        address smartAccount
    )
    external
    view
    returns (bool)
    {
        return address(eigenPodOf[smartAccount]) != address(0);
    }
}

