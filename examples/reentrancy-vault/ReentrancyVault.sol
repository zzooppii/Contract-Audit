// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ReentrancyVault
 * @notice Vulnerable ETH vault with multiple reentrancy issues.
 *         Used for testing the reentrancy detector.
 */
contract ReentrancyVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    uint256 public lastWithdrawTime;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    // BUG 1: CEI violation — state updated after external call
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call BEFORE state update (CEI violation)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update AFTER external call — reentrancy!
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        lastWithdrawTime = block.timestamp;
    }

    // BUG 2: Missing reentrancy guard on public function with ETH transfer
    function withdrawAll() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");

        balances[msg.sender] = 0;
        totalDeposits -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // BUG 3: Cross-function reentrancy — getBalance reads balances
    //         which is updated after external call in withdraw()
    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }

    // BUG 4: Read-only reentrancy — view function reads totalDeposits
    //         which can be stale during reentrancy in withdraw()
    function getSharePrice() external view returns (uint256) {
        if (totalDeposits == 0) return 1e18;
        return address(this).balance * 1e18 / totalDeposits;
    }

    function deposit() external payable {
        require(msg.value > 0, "Must deposit > 0");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    receive() external payable {}
}
