// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

/// @title UpgradeableVault - Proxy/upgradeable vault with storage vulnerabilities
/// @notice FOR EDUCATIONAL/TESTING PURPOSES ONLY - DO NOT DEPLOY
contract UpgradeableVault {
    // ============ VULN-1: No storage gap for proxy pattern ============
    // If used behind a proxy, new variables in upgrades will collide
    // with child contract storage

    address public implementation;
    address public admin;
    bool public initialized;

    // ============ VULN-2: Storage layout collision risk ============
    // These slots are in the "wrong" position for a proxy pattern
    // Should use EIP-1967 storage slots instead of sequential slots
    mapping(address => uint256) public balances;
    address public feeRecipient;
    uint256 public totalDeposits;
    uint256 public depositFee = 100; // 1%

    // BUG: No storage gap — inheriting contracts WILL collide
    // uint256[50] private __gap;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event Upgraded(address indexed newImplementation);
    event Initialized(address admin);

    // ============ VULN-3: Initializer without protection ============
    function initialize(address _admin, address _feeRecipient) external {
        // BUG: No initializer modifier — can be called multiple times
        // BUG: No check if already initialized (the `initialized` flag is set
        // but not checked, allowing re-initialization)
        admin = _admin;
        feeRecipient = _feeRecipient;
        initialized = true;
        emit Initialized(_admin);
    }

    // ============ VULN-4: UUPS upgrade without auth ============
    function upgradeTo(address newImplementation) external {
        // BUG: No access control — anyone can upgrade
        implementation = newImplementation;
        emit Upgraded(newImplementation);
    }

    function upgradeToAndCall(
        address newImplementation,
        bytes memory data
    ) external {
        // BUG: No access control on upgrade
        implementation = newImplementation;

        // BUG: delegatecall to unverified address — can overwrite storage
        (bool success,) = newImplementation.delegatecall(data);
        require(success, "Upgrade call failed");

        emit Upgraded(newImplementation);
    }

    // ============ VULN-5: selfdestruct reachable ============
    function destroy() external {
        require(msg.sender == admin, "Not admin");
        // BUG: selfdestruct on implementation = proxy becomes useless
        // In post-Dencun, selfdestruct only sends ETH but point stands
        // for older chains
        selfdestruct(payable(admin));
    }

    // ============ VULN-6: Unprotected delegatecall ============
    function execute(address target, bytes memory data) external returns (bytes memory) {
        require(msg.sender == admin, "Not admin");
        // BUG: Admin can delegatecall to ANY address — overwrites all storage
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Execution failed");
        return result;
    }

    // ============ Safe functions ============
    function deposit(address token, uint256 amount) external {
        require(initialized, "Not initialized");
        uint256 fee = (amount * depositFee) / 10000;
        uint256 netAmount = amount - fee;

        IERC20(token).transferFrom(msg.sender, address(this), amount);
        IERC20(token).transfer(feeRecipient, fee);

        balances[msg.sender] += netAmount;
        totalDeposits += netAmount;

        emit Deposited(msg.sender, netAmount);
    }

    function withdraw(address token, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");

        balances[msg.sender] -= amount;
        totalDeposits -= amount;

        IERC20(token).transfer(msg.sender, amount);
        emit Withdrawn(msg.sender, amount);
    }

    receive() external payable {}
}
