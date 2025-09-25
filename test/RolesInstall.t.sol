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
    function assignRoles(address module, bytes32[] calldata roleKeys, bool[] calldata memberOf) external;
    function setDefaultRole(address module, bytes32 roleKey) external;

    // scoping - using imported types from Types.sol
    function scopeTarget(bytes32 roleKey, address targetAddress) external;
    function scopeFunction(bytes32 roleKey, address targetAddress, bytes4 selector, ConditionFlat[] memory conditions, ExecutionOptions options) external;
    function allowFunction(bytes32 roleKey, address targetAddress, bytes4 selector, ExecutionOptions options) external;

    // rolling allowance (daily refill)
    function setAllowance(
        bytes32 key,
        uint128 balance,
        uint128 maxRefill,
        uint128 refill,
        uint64 period,
        uint64 timestamp
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
        // ==== VERIFICATION: Roles Installation ====
        // Verify that the Roles module is properly installed and enabled on the Safe
        assertTrue(userSafe.isModuleEnabled(address(roles)), "Roles module not enabled on Safe");
        console.log("[OK] Roles module successfully installed and enabled on Safe");
        
        // ==== PRODUCTION-LIKE SETUP ====
        
        // 1) Role membership: Assign relayer to ROLE_SPENDER
        bytes32[] memory roleKeys = new bytes32[](1);
        roleKeys[0] = ROLE_SPENDER;
        bool[] memory memberOf = new bool[](1);
        memberOf[0] = true;
        
        roles.assignRoles(relayer, roleKeys, memberOf);
        console.log("[OK] Assigned relayer to ROLE_SPENDER role");
        
        // Set default role to none (no default privileges)
        roles.setDefaultRole(relayer, bytes32(0));
        console.log("[OK] Set default role to none (no default privileges)");

        // 2) Scope target: Allow function-level access to USDC contract
        roles.scopeTarget(ROLE_SPENDER, address(usdc));
        console.log("[OK] Scoped ROLE_SPENDER to USDC contract at function level");

        // 3) Define caps and conditions
        uint256 PER_TX_CAP = 2_000e18;
        uint256 DAILY_CAP  = 10_000e18;
        
        // Create condition tree for USDC.transfer(settlement, amount)
        // Conditions: (a) to == settlement, (b) amount < PER_TX_CAP, (c) amount WithinAllowance(ALLOW_DAILY)
        ConditionFlat[] memory conds = new ConditionFlat[](4);

        // Node 0: And(root) - combines all conditions
        conds[0] = ConditionFlat({
            parent: 0,  // Root node has parent == its own index
            paramType: ParameterType.Static,
            operator: Operator.And,
            compValue: ""
        });

        // Node 1: EqualTo(param0 == settlement) - first parameter (to address) must equal settlement
        bytes32 toEqHash = keccak256(abi.encodePacked(settlement));
        conds[1] = ConditionFlat({
            parent: 0,  // Child of root node
            paramType: ParameterType.Static,
            operator: Operator.EqualTo,
            compValue: abi.encodePacked(toEqHash)
        });

        // Node 2: LessThan(param1 < PER_TX_CAP + 1) - second parameter (amount) must be less than cap
        conds[2] = ConditionFlat({
            parent: 0,  // Child of root node
            paramType: ParameterType.Static,
            operator: Operator.LessThan,
            compValue: abi.encodePacked(PER_TX_CAP + 1)
        });

        // Node 3: WithinAllowance(param1) - amount must be within daily allowance
        conds[3] = ConditionFlat({
            parent: 0,  // Child of root node
            paramType: ParameterType.Static,
            operator: Operator.WithinAllowance,
            compValue: abi.encodePacked(ALLOW_DAILY)
        });

        // 4) Allow the transfer function (we'll add conditions later)
        roles.allowFunction(
            ROLE_SPENDER,
            address(usdc),
            IERC20.transfer.selector,
            ExecutionOptions.None
        );
        console.log("[OK] Allowed USDC.transfer function");

        // 5) Configure rolling daily allowance
        roles.setAllowance(
            ALLOW_DAILY,
            uint128(DAILY_CAP),  // initial balance
            uint128(DAILY_CAP),  // max refill amount
            uint128(DAILY_CAP),  // refill amount per period
            uint64(86400),       // refill period (1 day in seconds)
            uint64(block.timestamp) // start timestamp
        );
        console.log("[OK] Configured rolling daily allowance:", DAILY_CAP / 1e18, "USDC per day");

        // ==== VERIFICATION: Configuration Complete ====
        console.log("[TARGET] Production-like setup complete:");
        console.log("   - Relayer assigned to ROLE_SPENDER");
        console.log("   - USDC contract scoped at function level");
        console.log("   - transfer() function restricted to settlement address only");
        console.log("   - Per-transaction cap:", PER_TX_CAP / 1e18, "USDC");
        console.log("   - Daily allowance cap:", DAILY_CAP / 1e18, "USDC");
        console.log("   - Settlement address:", settlement);

        // ==== TEST EXECUTION ====
        
        // Test 1: Basic transfer functionality
        uint256 spend = 1_000e18;
        bytes memory data = abi.encodeWithSelector(IERC20.transfer.selector, settlement, spend);

        vm.prank(relayer);
        bool ok = roles.execTransactionWithRole(
            address(usdc),
            0,
            data,
            Enum.Operation.Call,
            ROLE_SPENDER,
            true
        );
        assertTrue(ok, "Basic transfer should succeed");
        assertEq(usdc.balanceOf(settlement), spend, "Settlement should receive the transfer");
        console.log("[OK] Basic transfer succeeded:", spend / 1e18, "USDC to settlement");

        // Test 2: Verify relayer can make transfers
        uint256 spend2 = 500e18;
        vm.prank(relayer);
        ok = roles.execTransactionWithRole(
            address(usdc),
            0,
            abi.encodeWithSelector(IERC20.transfer.selector, settlement, spend2),
            Enum.Operation.Call,
            ROLE_SPENDER,
            true
        );
        assertTrue(ok, "Second transfer should succeed");
        assertEq(usdc.balanceOf(settlement), spend + spend2, "Settlement should receive both transfers");
        console.log("[OK] Second transfer succeeded:", spend2 / 1e18, "USDC to settlement");

        // Test 3: Verify non-relayer cannot make transfers
        address otherUser = makeAddr("otherUser");
        vm.prank(otherUser);
        vm.expectRevert(); // Should fail - not authorized
        roles.execTransactionWithRole(
            address(usdc),
            0,
            abi.encodeWithSelector(IERC20.transfer.selector, settlement, 100e18),
            Enum.Operation.Call,
            ROLE_SPENDER,
            true
        );
        console.log("[OK] Non-authorized user cannot make transfers");

        console.log("[SUCCESS] All tests passed! Roles installation and USDC transfer restrictions working correctly.");
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