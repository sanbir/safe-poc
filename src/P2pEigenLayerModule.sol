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
    mapping(address => IEigenPod) public eigenPodOf;

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

    function execSafe(address safeAddress, address eigenLayerContract, bytes memory data) external {
        bool isAllowed = _isAllowedEigenLayerContract(eigenLayerContract);
        if (!isAllowed) {
            address eigenPod = address(eigenPodOf[safeAddress]);
            require(eigenLayerContract == eigenPod, "Contract not allowed");
        }
        require(ISafe(safeAddress).execTransactionFromModule(
            eigenLayerContract,
            0,
            data,
            Enum.Operation.Call
        ), "Could not execSafe");
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

    function execERC7579(address swa, address eigenLayerContract, bytes memory data) external {
        bool isAllowed = _isAllowedEigenLayerContract(eigenLayerContract);
        if (!isAllowed) {
            address eigenPod = address(eigenPodOf[swa]);
            require(eigenLayerContract == eigenPod, "Contract not allowed");
        }
        _execute(swa, eigenLayerContract, 0, data);
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

    function _isAllowedEigenLayerContract(address _contract) private view returns(bool) {
        bool isAllowed;
        address[] memory allowedEigenLayerContracts = _getAllowedEigenLayerContracts();
        for (uint256 i = 0; i < allowedEigenLayerContracts.length; ++i) {
            if (_contract == allowedEigenLayerContracts[i]) {
                isAllowed = true;
            }
        }
        return isAllowed;
    }

    function _getAllowedEigenLayerContracts() private view returns(address[] memory) {
        if (block.chainid == 1) {
            address[] memory allowedEigenLayerContracts = new address[](12);
            allowedEigenLayerContracts[0] = 0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A;
            allowedEigenLayerContracts[1] = 0x858646372CC42E1A627fcE94aa7A7033e7CF075A;
            allowedEigenLayerContracts[2] = 0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338;
            allowedEigenLayerContracts[3] = 0x135DDa560e946695d6f155dACaFC6f1F25C1F5AF;
            allowedEigenLayerContracts[4] = 0x7750d328b314EfFa365A0402CcfD489B80B0adda;

            allowedEigenLayerContracts[5] = 0x25E5F8B1E7aDf44518d35D5B2271f114e081f0E5;
            allowedEigenLayerContracts[6] = 0x948a420b8CC1d6BFd0B6087C2E7c344a2CD0bc39;
            allowedEigenLayerContracts[7] = 0x5e4C39Ad7A3E881585e383dB9827EB4811f6F647;
            allowedEigenLayerContracts[8] = 0x0ed6703C298d28aE0878d1b28e88cA87F9662fE9;
            allowedEigenLayerContracts[9] = 0xaCB55C530Acdb2849e6d4f36992Cd8c9D50ED8F7;

            allowedEigenLayerContracts[10] = 0xec53bF9167f50cDEB3Ae105f56099aaaB9061F83;
            allowedEigenLayerContracts[11] = 0x83E9115d334D248Ce39a6f36144aEaB5b3456e75;
            return allowedEigenLayerContracts;
        } else if (block.chainid == 560048) {
            address[] memory allowedEigenLayerContracts = new address[](12);
            allowedEigenLayerContracts[0] = 0x867837a9722C512e0862d8c2E15b8bE220E8b87d;
            allowedEigenLayerContracts[1] = 0xeE45e76ddbEDdA2918b8C7E3035cd37Eab3b5D41;
            allowedEigenLayerContracts[2] = 0xcd1442415Fc5C29Aa848A49d2e232720BE07976c;
            allowedEigenLayerContracts[3] = 0xD58f6844f79eB1fbd9f7091d05f7cb30d3363926;
            allowedEigenLayerContracts[4] = 0x29e8572678e0c272350aa0b4B8f304E47EBcd5e7;

            allowedEigenLayerContracts[5] = 0x95a7431400F362F3647a69535C5666cA0133CAA0;
            allowedEigenLayerContracts[6] = 0xdcCF401fD121d8C542E96BC1d0078884422aFAD2;
            allowedEigenLayerContracts[7] = 0x885C0CC8118E428a2C04de58A93eB15Ed4F0e064;
            allowedEigenLayerContracts[8] = 0x8ae2520954db7D80D66835cB71E692835bbA45bf;
            allowedEigenLayerContracts[9] = 0x6e60888132Cc7e637488379B4B40c42b3751f63a;

            allowedEigenLayerContracts[10] = 0xfB7d94501E4d4ACC264833Ef4ede70a11517422B;
            allowedEigenLayerContracts[11] = 0x6d28cEC1659BC3a9BC814c3EFc1412878B406579;
            return allowedEigenLayerContracts;
        } else {
            revert("Not supported chain");
        }
    }
}

