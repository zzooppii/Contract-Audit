// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title VulnerableVault
/// @notice Test contract with intentional vulnerabilities for testing the audit engine
/// @dev DO NOT USE IN PRODUCTION - For testing purposes only
contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULN-1: Reentrancy vulnerability
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        // State update AFTER external call - classic reentrancy
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    // VULN-2: Missing access control
    function emergencyWithdraw() external {
        // Anyone can call this, not just owner
        payable(msg.sender).transfer(address(this).balance);
    }

    // VULN-3: tx.origin authentication
    function adminAction() external {
        require(tx.origin == owner, "Not owner");
        // Sensitive admin action
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {}
}
