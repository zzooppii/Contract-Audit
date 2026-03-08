// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./CrossContractB.sol";

interface ICallback {
    function onReceive(uint256 amount) external;
    function onComplete() external;
}

contract CrossContractA is ICallback {
    CrossContractB public contractB;
    mapping(address => uint256) public balances;

    constructor(address _b) {
        contractB = CrossContractB(_b);
    }

    // Calls B, which calls back into A (reentrancy cycle)
    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
        contractB.process(amount);
    }

    // Callback from B - completes the cycle
    function onReceive(uint256 amount) external {
        balances[msg.sender] += amount;
    }

    // Shadows parent function without override
    function getValue() public view returns (uint256) {
        return 42;
    }
}
