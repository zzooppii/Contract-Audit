// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ReentrancyVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    // CEI violation: state updated after external call
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Failed");
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
    }

    // Missing reentrancy guard
    function withdrawAll() public {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Failed");
    }

    // View function reading stale state (read-only reentrancy)
    function getSharePrice() external view returns (uint256) {
        if (totalDeposits == 0) return 1e18;
        return address(this).balance * 1e18 / totalDeposits;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
}
