// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../lib/safe-contracts/contracts/GnosisSafe.sol";
import "../lib/safe-contracts/contracts/proxies/GnosisSafeProxyFactory.sol";
import "../lib/zodiac-modifier-roles/packages/evm/contracts/Roles.sol";
import "../lib/zodiac-modifier-roles/packages/evm/contracts/Types.sol";
import "../lib/zodiac/contracts/factory/ModuleProxyFactory.sol";

// ---- Roles (real implementation) ----
// Adjust path if your tag/commit uses a different folder (sometimes `src/` or `solidity/`).
import "forge-std/Test.sol";

// Minimal interface for the pieces we call from Roles.
interface IRoles {
    // init
    function setUp(bytes memory initParams) external;

    // membership/defaults
    function assignRoles(bytes32 roleKey, address[] calldata members) external;
    function setDefaultRole(bytes32 roleKey) external;

    // scoping - using imported types from Types.sol

    function scopeTarget(address target, Clearance clearance, ExecutionOptions options) external;
    function scopeFunction(address target, bytes4 selector, ConditionFlat[] calldata conditions, ExecutionOptions options) external;
    function allowFunction(address target, bytes4 selector, ExecutionOptions options) external;

    // rolling allowance (daily refill)
    function setAllowance(
        bytes32 allowanceKey,
        bytes32 roleKey,
        uint128 maxAmount,
        uint128 refillAmount,
        uint64  refillInterval,
        uint64  refillTimestamp
    ) external;

    function execTransactionWithRole(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        bytes32 roleKey,
        bool shouldRevert
    ) external returns (bool);
}

// Minimal ERC20 mock
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function mint(address to, uint256 amount) external;
    function balanceOf(address) external view returns (uint256);
}

contract ERC20Mock {
    string public name = "Mock USDC";
    string public symbol = "mUSDC";
    uint8  public decimals = 18;
    mapping(address=>uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract RolesInstallTest is Test {
    // Owner key/address pair (so we can sign Safe txs)
    uint256 internal owner1Key = 0xA11CE;
    address internal owner1    = vm.addr(0xA11CE);

    address internal relayer    = vm.addr(0xBEEF);     // “issuer backend / card relayer”
    address internal settlement = vm.addr(0x515151);   // mock settlement account

    GnosisSafeProxyFactory internal safeFactory;
    GnosisSafe            internal safeSingleton;
    GnosisSafe            internal userSafe;

    ModuleProxyFactory    internal moduleFactory;
    IRoles                internal roles;

    ERC20Mock             internal usdc;

    // Role & allowance keys
    bytes32 constant ROLE_SPENDER = keccak256("ROLE_SPENDER");
    bytes32 constant ALLOW_DAILY  = keccak256("ALLOWANCE_DAILY_USDC");

    function setUp() public {
        // --- Deploy Safe singleton & factory
        safeSingleton = new GnosisSafe();
        safeFactory   = new GnosisSafeProxyFactory();

        // Create a 1/1 Safe
        address[] memory owners = new address[](1);
        owners[0] = owner1;

        bytes memory setupData = abi.encodeWithSelector(
            GnosisSafe.setup.selector,
            owners,
            uint256(1),              // threshold
            address(0), bytes(""),   // to,data
            address(0),              // fallback handler
            address(0),              // payment token
            0,                       // payment
            payable(address(0))      // payment receiver
        );

        userSafe = GnosisSafe(payable(
            safeFactory.createProxy(address(safeSingleton), setupData)
        ));

        // --- Deploy ModuleProxyFactory and Roles mastercopy
        moduleFactory = new ModuleProxyFactory();
        Roles mastercopy = new Roles(address(this), address(userSafe), address(userSafe)); // real implementation

        // EIP-1167 clone with initializer (owner=this test, avatar=userSafe, target=userSafe)
        bytes memory initParams = abi.encode(address(this), address(userSafe), address(userSafe));
        roles = IRoles(
            moduleFactory.deployModule(
                address(mastercopy),
                abi.encodeWithSelector(IRoles.setUp.selector, initParams),
                uint256(keccak256("ROLES_CLONE_SALT"))
            )
        );

        // --- Enable the Roles module on the Safe (Safe tx signed by owner1)
        _safeEnableModule(address(roles));

        // --- Token + funding
        usdc = new ERC20Mock();
        usdc.mint(address(userSafe), 1_000_000e18);
    }

    function test_installRoles_and_scopeUSDC_transfer() public {
        // 1) Role membership
        address[] memory members = new address[](1);
        members[0] = relayer;
        roles.assignRoles(ROLE_SPENDER, members);
        roles.setDefaultRole(bytes32(0)); // ensure no default privileges

        // 2) Scope target to the USDC contract at function granularity; forbid ETH and delegatecall
        roles.scopeTarget(address(usdc), Clearance.Function, ExecutionOptions.None);

        // 3) Conditions for IERC20.transfer(address to, uint256 amount)
        //    (a) to == settlement
        //    (b) amount < PER_TX_CAP + 1
        //    (c) amount WithinAllowance(ALLOW_DAILY)
        uint256 PER_TX_CAP = 2_000e18;
        uint256 DAILY_CAP  = 10_000e18;

        ConditionFlat[] memory conds = new ConditionFlat[](4);

        // Node 0: And(root)
        conds[0] = ConditionFlat({
            parent: 0,
            paramType: ParameterType.Static,
            operator: Operator.And,
            compValue: ""
        });

        // IMPORTANT: Roles.EqualTo compares keccak256(paramBytes) to compValue.
        // For an address param, compValue must be keccak256(abi.encodePacked(expectedAddress)).
        bytes32 toEqHash = keccak256(abi.encodePacked(settlement));

        // Node 1: EqualTo(param0 == settlement)
        conds[1] = ConditionFlat({
            parent: 0,
            paramType: ParameterType.Static,
            operator: Operator.EqualTo,
            compValue: abi.encodePacked(toEqHash)
        });

        // Node 2: LessThan(param1 < PER_TX_CAP + 1)
        conds[2] = ConditionFlat({
            parent: 0,
            paramType: ParameterType.Static,
            operator: Operator.LessThan,
            compValue: abi.encodePacked(PER_TX_CAP + 1)
        });

        // Node 3: WithinAllowance(param1) — consumes from ALLOW_DAILY
        conds[3] = ConditionFlat({
            parent: 0,
            paramType: ParameterType.Static,
            operator: Operator.WithinAllowance,
            compValue: abi.encodePacked(ALLOW_DAILY)
        });

        // 4) Scope the function with the condition tree
        roles.scopeFunction(
            address(usdc),
            IERC20.transfer.selector,
            conds,
            ExecutionOptions.None
        );

        // 5) Configure rolling daily allowance
        roles.setAllowance(
            ALLOW_DAILY,
            ROLE_SPENDER,
            uint128(DAILY_CAP),  // capacity
            uint128(DAILY_CAP),  // refill amount per interval
            uint64(86400),       // 1 day
            uint64(0)            // start now
        );

        // ==== Happy path: settlement within caps ====
        uint256 spend = 1_462e18;
        bytes memory data = abi.encodeWithSelector(IERC20.transfer.selector, settlement, spend);

        // The module call must be sent by the member (relayer)
        vm.prank(relayer);
        bool ok = roles.execTransactionWithRole(
            address(usdc),
            0,
            data,
            Enum.Operation.Call,
            ROLE_SPENDER,
            true
        );
        assertTrue(ok, "roles exec failed");
        assertEq(usdc.balanceOf(settlement), spend, "settlement not paid");

        // ==== Per-tx cap enforced ====
        vm.prank(relayer);
        vm.expectRevert(); // LessThan violation
        roles.execTransactionWithRole(
            address(usdc),
            0,
            abi.encodeWithSelector(IERC20.transfer.selector, settlement, PER_TX_CAP + 1),
            Enum.Operation.Call,
            ROLE_SPENDER,
            true
        );

        // ==== Daily cap enforced ====
        uint256 remaining = DAILY_CAP - spend;
        vm.prank(relayer);
        roles.execTransactionWithRole(
            address(usdc),
            0,
            abi.encodeWithSelector(IERC20.transfer.selector, settlement, remaining),
            Enum.Operation.Call,
            ROLE_SPENDER,
            true
        );

        vm.prank(relayer);
        vm.expectRevert(); // WithinAllowance violation
        roles.execTransactionWithRole(
            address(usdc),
            0,
            abi.encodeWithSelector(IERC20.transfer.selector, settlement, 1),
            Enum.Operation.Call,
            ROLE_SPENDER,
            true
        );

        // Refill after one day
        vm.warp(block.timestamp + 86400 + 1);

        vm.prank(relayer);
        roles.execTransactionWithRole(
            address(usdc),
            0,
            abi.encodeWithSelector(IERC20.transfer.selector, settlement, 1),
            Enum.Operation.Call,
            ROLE_SPENDER,
            true
        );
    }

    // --- helpers ---

    /// Enable `module` on the Safe by executing `enableModule(module)` as the Safe itself.
    function _safeEnableModule(address module) internal {
        bytes memory data = abi.encodeWithSignature("enableModule(address)", module);

        bytes32 txHash = userSafe.getTransactionHash(
            address(userSafe),   // SelfAuthorized.requireSelfCall()
            0,
            data,
            Enum.Operation.Call,
            0, 0, 0,
            address(0),
            payable(address(0)),
            userSafe.nonce()
        );

        // Sign with the *private key* that produced owner1.
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, txHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(owner1);
        bool success = userSafe.execTransaction(
            address(userSafe),
            0,
            data,
            Enum.Operation.Call,
            0, 0, 0,
            address(0),
            payable(address(0)),
            sig
        );
        require(success, "enableModule failed");
    }
}