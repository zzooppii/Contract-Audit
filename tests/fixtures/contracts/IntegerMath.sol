// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IntegerMath {
    uint256 public constant PRECISION = 1e18;

    // Unsafe downcast
    function compactBalance(uint256 amount) external pure returns (uint128) {
        return uint128(amount);
    }

    // Unchecked block with user-influenced arithmetic
    function batchReward(address[] calldata users, uint256 rewardPerUser) external pure returns (uint256) {
        unchecked {
            uint256 totalReward = users.length * rewardPerUser;
            return totalReward;
        }
    }

    // Division before multiplication
    function calculateFee(uint256 amount, uint256 feeRate, uint256 boost) external pure returns (uint256) {
        return (amount / PRECISION) * feeRate * boost / 10000;
    }

    // Division by zero (parameter not validated)
    function calculateShare(uint256 amount, uint256 totalShares) external pure returns (uint256) {
        return amount * PRECISION / totalShares;
    }

    // Safe downcast for contrast
    function safeDowncast(uint256 value) external pure returns (uint128) {
        require(value <= type(uint128).max, "Overflow");
        return uint128(value);
    }
}
