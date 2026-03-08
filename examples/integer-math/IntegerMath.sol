// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IntegerMath
 * @notice DeFi math library with arithmetic vulnerabilities.
 *         Used for testing the integer_detector.
 */
contract IntegerMath {
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public rewards;

    uint256 public constant PRECISION = 1e18;

    // BUG 1: Unsafe downcast — uint256 to uint128 without bounds check
    function compactBalance(uint256 amount) external pure returns (uint128) {
        return uint128(amount);
    }

    // BUG 2: Unchecked block with user-influenced arithmetic
    function batchReward(address[] calldata users, uint256 rewardPerUser) external {
        unchecked {
            uint256 totalReward = users.length * rewardPerUser;
            require(totalReward <= address(this).balance, "Insufficient");
            for (uint256 i = 0; i < users.length; i++) {
                rewards[users[i]] += rewardPerUser;
            }
        }
    }

    // BUG 3: Division before multiplication — precision loss
    function calculateFee(uint256 amount, uint256 feeRate, uint256 boost) external pure returns (uint256) {
        // (amount / PRECISION) * feeRate loses precision
        return (amount / PRECISION) * feeRate * boost / 10000;
    }

    // BUG 4: Division by zero — parameter not validated
    function calculateShare(uint256 amount, uint256 totalShares) external pure returns (uint256) {
        return amount * PRECISION / totalShares;
    }

    // Additional downcast vulnerability
    function packTimestamp(uint256 timestamp) external pure returns (uint64) {
        return uint64(timestamp);
    }

    // Safe function for contrast (uses SafeCast-like check)
    function safeDowncast(uint256 value) external pure returns (uint128) {
        require(value <= type(uint128).max, "Overflow");
        return uint128(value);
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
    }
}
