// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title FlashLoanTarget
/// @notice Contract vulnerable to flash loan attacks
/// @dev DO NOT USE IN PRODUCTION
contract FlashLoanTarget {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 public totalAssets;

    // VULN-1: Flash loan callback without caller validation
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        // Missing: require(msg.sender == LENDING_POOL, "Not from pool");
        // Missing: require(initiator == address(this), "Not self-initiated");

        // Manipulate shares with flash-loaned funds
        totalAssets += amount;
        shares[initiator] += amount;
        totalShares += amount;

        return true;
    }

    // VULN-2: Flash loan callback that reaches value sink directly
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32) {
        // Missing caller validation
        // Missing: require(msg.sender == FLASH_LENDER, "Not lender")

        // Directly reaches transfer sink - VULNERABLE
        payable(initiator).transfer(amount);

        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    receive() external payable {}
}
