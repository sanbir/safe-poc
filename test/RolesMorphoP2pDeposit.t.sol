// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../lib/p2p-lending-proxy/src/@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../lib/p2p-lending-proxy/src/adapters/morpho/p2pMorphoProxyFactory/P2pMorphoProxyFactory.sol";
import "../lib/p2p-lending-proxy/src/@permit2/libraries/Permit2Lib.sol";
import "../lib/safe-contracts/contracts/GnosisSafe.sol";
import "../lib/safe-contracts/contracts/base/ModuleManager.sol";
import "../lib/safe-contracts/contracts/base/FallbackManager.sol";
import "../lib/safe-contracts/contracts/proxies/GnosisSafeProxyFactory.sol";
import "../lib/zodiac-modifier-roles/packages/evm/contracts/Roles.sol" as ZodiacRoles;
import "../lib/zodiac-modifier-roles/packages/evm/contracts/Types.sol";
import "../lib/zodiac/contracts/factory/ModuleProxyFactory.sol";
import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console.sol";
import "forge-std/console2.sol";

// Simple ERC-1271 handler compatible with Solidity 0.8.30
contract SimpleERC1271Handler {
    address public immutable safe;
    address public immutable owner;
    
    constructor(address _safe, address _owner) {
        safe = _safe;
        owner = _owner;
    }
    
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        // For a single-owner Safe, verify the signature against the owner
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := mload(add(signature, 32))
                s := mload(add(signature, 64))
                v := byte(0, mload(add(signature, 96)))
            }
            
            address signer = ecrecover(hash, v, r, s);
            if (signer == owner) {
                return 0x1626ba7e; // EIP1271 magic value
            }
        }
        
        return 0xffffffff; // Invalid signature
    }
}

contract MainnetIntegration is Test {
    using SafeERC20 for IERC20;

    address constant P2pTreasury = 0x6Bb8b45a1C6eA816B70d76f83f7dC4f0f87365Ff;
    P2pMorphoProxyFactory private factory;

    // Roles and Safe related
    GnosisSafe private userSafe;
    ZodiacRoles.Roles private roles;
    GnosisSafeProxyFactory private safeFactory;
    ModuleProxyFactory private moduleFactory;
    SimpleERC1271Handler private fallbackHandler;
    address private relayer;
    bytes32 constant ROLE_RELAYER = keccak256("RELAYER");

    address private clientAddress;
    uint256 private clientPrivateKey;

    address private p2pSignerAddress;
    uint256 private p2pSignerPrivateKey;

    address private p2pOperatorAddress;
    address private nobody;

    address constant MorphoEthereumBundlerV2 = 0x4095F064B8d3c3548A3bebfd0Bbfd04750E30077;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant VaultUSDC = 0x8eB67A509616cd6A7c1B3c8C21D48FF57df3d458;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant VaultUSDT = 0xbEef047a543E45807105E51A8BBEFCc5950fcfBa;

    address asset;
    address vault;

    uint256 constant SigDeadline = 1734464723;
    uint96 constant ClientBasisPoints = 8700; // 13% fee
    uint256 constant DepositAmount = 10000000;

    address proxyAddress;

    uint48 nonce;

    function setUp() public {
        vm.createSelectFork("https://eth.drpc.org", 21308893);

        (clientAddress, clientPrivateKey) = makeAddrAndKey("client");
        (p2pSignerAddress, p2pSignerPrivateKey) = makeAddrAndKey("p2pSigner");
        p2pOperatorAddress = makeAddr("p2pOperator");
        nobody = makeAddr("nobody");
        relayer = makeAddr("relayer");

        vm.startPrank(p2pOperatorAddress);
        factory = new P2pMorphoProxyFactory(
            MorphoEthereumBundlerV2,
            p2pSignerAddress,
            P2pTreasury
        );
        vm.stopPrank();

        _setRules();
        _setupSafeAndRoles();
        
        // Update proxy address to use Safe address
        proxyAddress = factory.predictP2pLendingProxyAddress(address(userSafe), ClientBasisPoints);

        asset = USDC;
        vault = VaultUSDC;
    }

    function test_Roles_happy_path() external {
        asset = USDT;
        vault = VaultUSDT;
        _rolesHappyPath();
    }

    function test_transferP2pSigner_Mainnet() public {
        vm.startPrank(nobody);
        vm.expectRevert(abi.encodeWithSelector(P2pOperator.P2pOperator__UnauthorizedAccount.selector, nobody));
        factory.transferP2pSigner(nobody);

        address oldSigner = factory.getP2pSigner();
        assertEq(oldSigner, p2pSignerAddress);

        vm.startPrank(p2pOperatorAddress);
        factory.transferP2pSigner(nobody);

        address newSigner = factory.getP2pSigner();
        assertEq(newSigner, nobody);
    }







    function test_getHashForP2pSigner_Mainnet() public view {
        bytes32 expectedHash = keccak256(abi.encode(
            clientAddress,
            ClientBasisPoints,
            SigDeadline,
            address(factory),
            block.chainid
        ));

        bytes32 actualHash = factory.getHashForP2pSigner(
            clientAddress,
            ClientBasisPoints,
            SigDeadline
        );

        assertEq(actualHash, expectedHash);
    }

    function test_getPermit2HashTypedData_Mainnet() public view {
        // Create a permit single struct
        IAllowanceTransfer.PermitSingle memory permitSingle = IAllowanceTransfer.PermitSingle({
            details: IAllowanceTransfer.PermitDetails({
            token: asset,
            amount: uint160(DepositAmount),
            expiration: uint48(SigDeadline),
                nonce: 0
            }),
            spender: proxyAddress,
            sigDeadline: SigDeadline
        });

        // Get the permit hash
        bytes32 permitHash = factory.getPermitHash(permitSingle);

        // Get the typed data hash
        bytes32 actualTypedDataHash = factory.getPermit2HashTypedData(permitHash);

        // Calculate expected hash
        bytes32 expectedTypedDataHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                Permit2Lib.PERMIT2.DOMAIN_SEPARATOR(),
                permitHash
            )
        );

        assertEq(actualTypedDataHash, expectedTypedDataHash);

        // Test the overloaded function that takes PermitSingle directly
        bytes32 actualTypedDataHashFromPermitSingle = factory.getPermit2HashTypedData(permitSingle);
        assertEq(actualTypedDataHashFromPermitSingle, expectedTypedDataHash);
    }

    function test_supportsInterface_Mainnet() public view {
        // Test IP2pLendingProxyFactory interface support
        bool supportsP2pLendingProxyFactory = factory.supportsInterface(type(IP2pLendingProxyFactory).interfaceId);
        assertTrue(supportsP2pLendingProxyFactory);

        // Test IERC165 interface support
        bool supportsERC165 = factory.supportsInterface(type(IERC165).interfaceId);
        assertTrue(supportsERC165);

        // Test non-supported interface
        bytes4 nonSupportedInterfaceId = bytes4(keccak256("nonSupportedInterface()"));
        bool supportsNonSupported = factory.supportsInterface(nonSupportedInterfaceId);
        assertFalse(supportsNonSupported);
    }


    function test_acceptP2pOperator_Mainnet() public {
        // Initial state check
        assertEq(factory.getP2pOperator(), p2pOperatorAddress);

        // Only operator can initiate transfer
        vm.startPrank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(
                P2pOperator.P2pOperator__UnauthorizedAccount.selector,
                nobody
            )
        );
        factory.transferP2pOperator(nobody);
        vm.stopPrank();

        // Operator initiates transfer
        address newOperator = makeAddr("newOperator");
        vm.startPrank(p2pOperatorAddress);
        factory.transferP2pOperator(newOperator);

        // Check pending operator is set
        assertEq(factory.getPendingP2pOperator(), newOperator);
        // Check current operator hasn't changed yet
        assertEq(factory.getP2pOperator(), p2pOperatorAddress);
        vm.stopPrank();

        // Wrong address cannot accept transfer
        vm.startPrank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(
                P2pOperator.P2pOperator__UnauthorizedAccount.selector,
                nobody
            )
        );
        factory.acceptP2pOperator();
        vm.stopPrank();

        // New operator accepts transfer
        vm.startPrank(newOperator);
        factory.acceptP2pOperator();

        // Check operator was updated
        assertEq(factory.getP2pOperator(), newOperator);
        // Check pending operator was cleared
        assertEq(factory.getPendingP2pOperator(), address(0));
        vm.stopPrank();

        // Old operator can no longer call operator functions
        vm.startPrank(p2pOperatorAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                P2pOperator.P2pOperator__UnauthorizedAccount.selector,
                p2pOperatorAddress
            )
        );
        factory.transferP2pOperator(p2pOperatorAddress);
        vm.stopPrank();
    }


    function _setRules() private {
        // allowed calldata for factory
        bytes4 multicallSelector = IMorphoBundler.multicall.selector;

        P2pStructs.Rule memory rule0Deposit = P2pStructs.Rule({ // approve2
            ruleType: P2pStructs.RuleType.StartsWith,
            index: 0,
            allowedBytes: hex"000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000022000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000184af504202"
        });
        P2pStructs.Rule memory rule1Deposit = P2pStructs.Rule({ // spender in approve2 must be MorphoEthereumBundlerV2
            ruleType: P2pStructs.RuleType.StartsWith,
            index: 336,
            allowedBytes: abi.encodePacked(MorphoEthereumBundlerV2)
        });
        P2pStructs.Rule memory rule2Deposit = P2pStructs.Rule({ // transferFrom2
            ruleType: P2pStructs.RuleType.StartsWith,
            index: 640,
            allowedBytes: hex"54c53ef0"
        });
        P2pStructs.Rule memory rule3Deposit = P2pStructs.Rule({ // erc4626Deposit
            ruleType: P2pStructs.RuleType.StartsWith,
            index: 768,
            allowedBytes: hex"6ef5eeae"
        });
        P2pStructs.Rule[] memory rulesDeposit = new P2pStructs.Rule[](4);
        rulesDeposit[0] = rule0Deposit;
        rulesDeposit[1] = rule1Deposit;
        rulesDeposit[2] = rule2Deposit;
        rulesDeposit[3] = rule3Deposit;

        vm.startPrank(p2pOperatorAddress);
        factory.setCalldataRules(
            P2pStructs.FunctionType.Deposit,
            MorphoEthereumBundlerV2,
            multicallSelector,
            rulesDeposit
        );
        vm.stopPrank();

        P2pStructs.Rule memory rule0Withdrawal = P2pStructs.Rule({ // erc4626Redeem
            ruleType: P2pStructs.RuleType.StartsWith,
            index: 0,
            allowedBytes: hex"00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000a4a7f6e606"
        });

        P2pStructs.Rule[] memory rulesWithdrawal = new P2pStructs.Rule[](1);
        rulesWithdrawal[0] = rule0Withdrawal;

        vm.startPrank(p2pOperatorAddress);
        factory.setCalldataRules(
            P2pStructs.FunctionType.Withdrawal,
            MorphoEthereumBundlerV2,
            multicallSelector,
            rulesWithdrawal
        );
        vm.stopPrank();
    }

    function _getMulticallDataAndPermitSingleForP2pLendingProxy() private returns(bytes memory, IAllowanceTransfer.PermitSingle memory) {
        // morpho approve2
        IAllowanceTransfer.PermitDetails memory permitDetails = IAllowanceTransfer.PermitDetails({
            token: asset,
            amount: uint160(DepositAmount),
            expiration: uint48(SigDeadline),
            nonce: nonce
        });
        nonce++;
        IAllowanceTransfer.PermitSingle memory permitSingle = IAllowanceTransfer.PermitSingle({
            details: permitDetails,
            spender: MorphoEthereumBundlerV2,
            sigDeadline: SigDeadline
        });
        bytes32 permitSingleHash = factory.getPermit2HashTypedData(PermitHash.hash(permitSingle));
        (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(clientPrivateKey, permitSingleHash);
        bytes memory signatureForApprove2 = abi.encodePacked(r0, s0, v0);
        bytes memory approve2CallData = abi.encodeCall(IMorphoBundler.approve2, (
            permitSingle,
            signatureForApprove2,
            true
        ));

        // morpho transferFrom2
        bytes memory transferFrom2CallData = abi.encodeCall(IMorphoBundler.transferFrom2, (
            asset,
            DepositAmount
        ));

        // morpho erc4626Deposit
        uint256 shares = IERC4626(vault).convertToShares(DepositAmount);
        bytes memory erc4626Deposit2CallData = abi.encodeCall(IMorphoBundler.erc4626Deposit, (
            vault,
            DepositAmount,
            (shares * 100) / 102,
            proxyAddress
        ));

        // morpho multicall
        bytes[] memory dataForMulticall = new bytes[](3);
        dataForMulticall[0] = approve2CallData;
        dataForMulticall[1] = transferFrom2CallData;
        dataForMulticall[2] = erc4626Deposit2CallData;
        bytes memory multicallCallData = abi.encodeCall(IMorphoBundler.multicall, (dataForMulticall));

        // data for factory
        IAllowanceTransfer.PermitSingle memory permitSingleForP2pLendingProxy = IAllowanceTransfer.PermitSingle({
            details: permitDetails,
            spender: proxyAddress,
            sigDeadline: SigDeadline
        });

        return (multicallCallData, permitSingleForP2pLendingProxy);
    }

    function _getMulticallDataAndPermitSingleForSafe() private returns(bytes memory, IAllowanceTransfer.PermitSingle memory) {
        // Get the current nonce for the Safe from Permit2
        (, , uint48 currentNonce) = Permit2Lib.PERMIT2.allowance(address(userSafe), asset, proxyAddress);
        
        // morpho approve2
        IAllowanceTransfer.PermitDetails memory permitDetails = IAllowanceTransfer.PermitDetails({
            token: asset,
            amount: uint160(DepositAmount),
            expiration: uint48(SigDeadline),
            nonce: uint48(currentNonce)
        });
        
        IAllowanceTransfer.PermitSingle memory permitSingle = IAllowanceTransfer.PermitSingle({
            details: permitDetails,
            spender: MorphoEthereumBundlerV2,
            sigDeadline: SigDeadline
        });
        bytes32 permitSingleHash = factory.getPermit2HashTypedData(PermitHash.hash(permitSingle));
        (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(clientPrivateKey, permitSingleHash);
        bytes memory signatureForApprove2 = abi.encodePacked(r0, s0, v0);
        bytes memory approve2CallData = abi.encodeCall(IMorphoBundler.approve2, (
            permitSingle,
            signatureForApprove2,
            true
        ));

        // morpho transferFrom2
        bytes memory transferFrom2CallData = abi.encodeCall(IMorphoBundler.transferFrom2, (
            asset,
            DepositAmount
        ));

        // morpho erc4626Deposit
        uint256 shares = IERC4626(vault).convertToShares(DepositAmount);
        bytes memory erc4626Deposit2CallData = abi.encodeCall(IMorphoBundler.erc4626Deposit, (
            vault,
            DepositAmount,
            (shares * 100) / 102,
            proxyAddress
        ));

        // morpho multicall
        bytes[] memory dataForMulticall = new bytes[](3);
        dataForMulticall[0] = approve2CallData;
        dataForMulticall[1] = transferFrom2CallData;
        dataForMulticall[2] = erc4626Deposit2CallData;
        bytes memory multicallCallData = abi.encodeCall(IMorphoBundler.multicall, (dataForMulticall));

        // data for factory
        IAllowanceTransfer.PermitSingle memory permitSingleForP2pLendingProxy = IAllowanceTransfer.PermitSingle({
            details: permitDetails,
            spender: proxyAddress,
            sigDeadline: SigDeadline
        });

        return (multicallCallData, permitSingleForP2pLendingProxy);
    }

    function _getPermit2SignatureForP2pLendingProxy(IAllowanceTransfer.PermitSingle memory permitSingleForP2pLendingProxy) private view returns(bytes memory) {
        bytes32 permitSingleForP2pLendingProxyHash = factory.getPermit2HashTypedData(PermitHash.hash(permitSingleForP2pLendingProxy));
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(clientPrivateKey, permitSingleForP2pLendingProxyHash);
        bytes memory permit2SignatureForP2pLendingProxy = abi.encodePacked(r1, s1, v1);
        return permit2SignatureForP2pLendingProxy;
    }

    function _getPermit2SignatureForSafe(IAllowanceTransfer.PermitSingle memory permitSingleForP2pLendingProxy) private view returns(bytes memory) {
        bytes32 permitSingleForP2pLendingProxyHash = factory.getPermit2HashTypedData(PermitHash.hash(permitSingleForP2pLendingProxy));
        
        // For Safe signature verification, we need to create a signature in the Safe's expected format
        // Generate signature with the Safe owner's private key
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(clientPrivateKey, permitSingleForP2pLendingProxyHash);
        
        // For Gnosis Safe, the signature format for a single owner with threshold 1 should be:
        // abi.encodePacked(r, s, v)
        // The Safe should be able to verify this against its owner
        bytes memory permit2SignatureForP2pLendingProxy = abi.encodePacked(r1, s1, v1);
        return permit2SignatureForP2pLendingProxy;
    }

    function _getP2pSignerSignature(
        address _clientAddress,
        uint96 _clientBasisPoints,
        uint256 _sigDeadline
    ) private view returns(bytes memory) {
        // p2p signer signing
        bytes32 hashForP2pSigner = factory.getHashForP2pSigner(
            _clientAddress,
            _clientBasisPoints,
            _sigDeadline
        );
        bytes32 ethSignedMessageHashForP2pSigner = ECDSA.toEthSignedMessageHash(hashForP2pSigner);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(p2pSignerPrivateKey, ethSignedMessageHashForP2pSigner);
        bytes memory p2pSignerSignature = abi.encodePacked(r2, s2, v2);
        return p2pSignerSignature;
    }


    function _getMulticallWithdrawalCallData(uint256 sharesToWithdraw) private view returns(bytes memory) {
        // morpho erc4626Redeem
        uint256 assets = IERC4626(vault).convertToAssets(sharesToWithdraw);
        bytes memory erc4626RedeemCallData = abi.encodeCall(IMorphoBundler.erc4626Redeem, (
            vault,
            sharesToWithdraw,
            (assets * 100) / 102,
            proxyAddress,
            proxyAddress
        ));

        // morpho multicall
        bytes[] memory dataForMulticallWithdrawal = new bytes[](1);
        dataForMulticallWithdrawal[0] = erc4626RedeemCallData;
        bytes memory multicallWithdrawalCallData = abi.encodeCall(IMorphoBundler.multicall, (dataForMulticallWithdrawal));

        return multicallWithdrawalCallData;
    }



    function _rolesHappyPath() private {
        // Set up Roles permissions for the relayer
        _setupRolesPermissions();

        // Fund the Safe with USDT for testing
        deal(asset, address(userSafe), 10000e18);

        uint256 assetBalanceBefore = IERC20(asset).balanceOf(address(userSafe));
        uint256 sharesBalanceBefore = IERC20(vault).balanceOf(proxyAddress);
        assertEq(sharesBalanceBefore, 0);

        // Execute deposit through Roles
        _doDepositThroughRoles();

        uint256 assetBalanceAfter1 = IERC20(asset).balanceOf(address(userSafe));
        uint256 sharesBalanceAfter1 = IERC20(vault).balanceOf(proxyAddress);
        assertNotEq(sharesBalanceAfter1, 0);
        assertEq(assetBalanceBefore - assetBalanceAfter1, DepositAmount);

        // Execute another deposit through Roles
        _doDepositThroughRoles();

        uint256 assetBalanceAfter2 = IERC20(asset).balanceOf(address(userSafe));
        uint256 sharesBalanceAfter2 = IERC20(vault).balanceOf(proxyAddress);

        assertEq(assetBalanceAfter1 - assetBalanceAfter2, DepositAmount);
        assertEq(sharesBalanceAfter2 - sharesBalanceAfter1, sharesBalanceAfter1);

        // Execute more deposits
        _doDepositThroughRoles();
        _doDepositThroughRoles();

        uint256 assetBalanceAfterAllDeposits = IERC20(asset).balanceOf(address(userSafe));

        // Execute withdrawals through Roles
        _doWithdrawThroughRoles(10);

        uint256 assetBalanceAfterWithdraw1 = IERC20(asset).balanceOf(address(userSafe));

        assertApproxEqAbs(assetBalanceAfterWithdraw1 - assetBalanceAfterAllDeposits, DepositAmount * 4 / 10, 1);

        _doWithdrawThroughRoles(5);
        _doWithdrawThroughRoles(3);
        _doWithdrawThroughRoles(2);
        _doWithdrawThroughRoles(1);

        uint256 assetBalanceAfterAllWithdrawals = IERC20(asset).balanceOf(address(userSafe));
        uint256 sharesBalanceAfterAfterAllWithdrawals = IERC20(vault).balanceOf(proxyAddress);

        assertApproxEqAbs(assetBalanceAfterAllWithdrawals, assetBalanceBefore, 1);
        assertEq(sharesBalanceAfterAfterAllWithdrawals, 0);
    }

    function _setupRolesPermissions() private {
        // Assign relayer to ROLE_RELAYER
        bytes32[] memory roleKeys = new bytes32[](1);
        roleKeys[0] = ROLE_RELAYER;
        bool[] memory memberOf = new bool[](1);
        memberOf[0] = true;
        
        roles.assignRoles(relayer, roleKeys, memberOf);

        // Set default role to none (no default privileges)
        roles.setDefaultRole(relayer, bytes32(0));

        // Scope target: Allow function-level access to factory contract
        roles.scopeTarget(ROLE_RELAYER, address(factory));

        // Allow the deposit function (0xa6c26af4) for the relayer
        roles.allowFunction(ROLE_RELAYER, address(factory), bytes4(0xa6c26af4), ExecutionOptions.None);

        // Also allow approve function on the asset token for Permit2
        roles.scopeTarget(ROLE_RELAYER, asset);
        roles.allowFunction(ROLE_RELAYER, asset, bytes4(0x095ea7b3), ExecutionOptions.None); // approve function

        // Allow withdraw function on the proxy
        roles.scopeTarget(ROLE_RELAYER, proxyAddress);
        roles.allowFunction(ROLE_RELAYER, proxyAddress, bytes4(0x0872d9cd), ExecutionOptions.None); // withdraw function
    }

    function _doDepositThroughRoles() private {
        (
            bytes memory multicallCallData,
            IAllowanceTransfer.PermitSingle memory permitSingleForP2pLendingProxy
        ) = _getMulticallDataAndPermitSingleForSafe();
        bytes memory permit2SignatureForP2pLendingProxy = _getPermit2SignatureForSafe(permitSingleForP2pLendingProxy);
        bytes memory p2pSignerSignature = _getP2pSignerSignature(
            address(userSafe), // Use Safe address instead of clientAddress
            ClientBasisPoints,
            SigDeadline
        );

        // Approve Permit2 if needed
        if (IERC20(asset).allowance(address(userSafe), address(Permit2Lib.PERMIT2)) == 0) {
            bytes memory approveData = abi.encodeWithSelector(
                IERC20.approve.selector,
                address(Permit2Lib.PERMIT2),
                type(uint256).max
            );
            
            vm.prank(relayer);
            roles.execTransactionWithRole(
                asset, // to
                0, // value
                approveData, // data
                Enum.Operation.Call, // operation
                ROLE_RELAYER, // roleKey
                false // shouldRevert
            );
        }

        // Prepare deposit call data
        bytes memory depositData = abi.encodeWithSelector(
            P2pMorphoProxyFactory.deposit.selector,
            MorphoEthereumBundlerV2,
            multicallCallData,
            permitSingleForP2pLendingProxy,
            permit2SignatureForP2pLendingProxy,
            ClientBasisPoints,
            SigDeadline,
            p2pSignerSignature
        );

        // Execute deposit through Roles
        vm.prank(relayer);
        bool success = roles.execTransactionWithRole(
            address(factory), // to
            0, // value
            depositData, // data
            Enum.Operation.Call, // operation
            ROLE_RELAYER, // roleKey
            false // shouldRevert
        );

        require(success, "Roles deposit execution failed");
    }

    function _doWithdrawThroughRoles(uint256 denominator) private {
        uint256 sharesBalance = IERC20(vault).balanceOf(proxyAddress);
        uint256 sharesToWithdraw = sharesBalance / denominator;
        bytes memory multicallWithdrawalCallData = _getMulticallWithdrawalCallData(sharesToWithdraw);

        // Prepare withdraw call data
        bytes memory withdrawData = abi.encodeWithSelector(
            P2pMorphoProxy.withdraw.selector,
            MorphoEthereumBundlerV2,
            multicallWithdrawalCallData,
            vault,
            sharesToWithdraw
        );

        // Execute withdraw through Roles
        vm.prank(relayer);
        bool success = roles.execTransactionWithRole(
            proxyAddress, // to
            0, // value
            withdrawData, // data
            Enum.Operation.Call, // operation
            ROLE_RELAYER, // roleKey
            false // shouldRevert
        );

        require(success, "Roles withdraw execution failed");
    }

    function _setupSafeAndRoles() private {
        // Deploy Safe singleton & factory
        GnosisSafe safeSingleton = new GnosisSafe();
        safeFactory = new GnosisSafeProxyFactory();

        // Create a 1/1 Safe with clientAddress as owner
        address[] memory owners = new address[](1);
        owners[0] = clientAddress;

        bytes memory setupData = abi.encodeWithSelector(
            GnosisSafe.setup.selector,
            owners,
            uint256(1),              // threshold
            address(0), bytes(""),   // to,data
            address(0),              // fallback handler (will be set after deployment)
            address(0),              // payment token
            0,                       // payment
            payable(address(0))      // payment receiver
        );

        userSafe = GnosisSafe(payable(
            safeFactory.createProxy(address(safeSingleton), setupData)
        ));

        // Deploy ERC-1271 handler for the Safe
        fallbackHandler = new SimpleERC1271Handler(address(userSafe), clientAddress);

        // Set the ERC-1271 handler as the fallback handler for the Safe
        _safeSetFallbackHandler(address(fallbackHandler));

        // Deploy ModuleProxyFactory and Roles mastercopy
        moduleFactory = new ModuleProxyFactory();
        ZodiacRoles.Roles mastercopy = new ZodiacRoles.Roles(address(this), address(userSafe), address(userSafe));

        // EIP-1167 clone with initializer (owner=this test, avatar=userSafe, target=userSafe)
        bytes memory initParams = abi.encode(address(this), address(userSafe), address(userSafe));
        roles = ZodiacRoles.Roles(
            moduleFactory.deployModule(
                address(mastercopy),
                abi.encodeWithSelector(ZodiacRoles.Roles.setUp.selector, initParams),
                uint256(keccak256("ROLES_CLONE_SALT"))
            )
        );

        // Enable the Roles module on the Safe
        _safeEnableModule(address(roles));
    }

    function _safeEnableModule(address module) private {
        bytes memory enableModuleData = abi.encodeWithSelector(
            ModuleManager.enableModule.selector,
            module
        );

        // Create transaction hash
        bytes32 txHash = userSafe.getTransactionHash(
            address(userSafe), // to
            0,                 // value
            enableModuleData,  // data
            Enum.Operation.Call, // operation
            0,                 // safeTxGas
            0,                 // baseGas
            0,                 // gasPrice
            address(0),       // gasToken
            address(0),       // refundReceiver
            userSafe.nonce()  // nonce
        );

        // Sign the transaction
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(clientPrivateKey, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute the transaction
        userSafe.execTransaction(
            address(userSafe), // to
            0,                 // value
            enableModuleData,  // data
            Enum.Operation.Call, // operation
            0,                 // safeTxGas
            0,                 // baseGas
            0,                 // gasPrice
            address(0),       // gasToken
            payable(address(0)), // refundReceiver
            signature          // signatures
        );
    }

    function _safeSetFallbackHandler(address handler) private {
        bytes memory setFallbackHandlerData = abi.encodeWithSelector(
            FallbackManager.setFallbackHandler.selector,
            handler
        );

        // Create transaction hash
        bytes32 txHash = userSafe.getTransactionHash(
            address(userSafe), // to
            0,                 // value
            setFallbackHandlerData, // data
            Enum.Operation.Call, // operation
            0,                 // safeTxGas
            0,                 // baseGas
            0,                 // gasPrice
            address(0),       // gasToken
            address(0),       // refundReceiver
            userSafe.nonce()  // nonce
        );

        // Sign the transaction
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(clientPrivateKey, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute the transaction
        userSafe.execTransaction(
            address(userSafe), // to
            0,                 // value
            setFallbackHandlerData, // data
            Enum.Operation.Call, // operation
            0,                 // safeTxGas
            0,                 // baseGas
            0,                 // gasPrice
            address(0),       // gasToken
            payable(address(0)), // refundReceiver
            signature          // signatures
        );
    }

}