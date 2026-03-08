// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./CrossContractA.sol";

contract CrossContractB {
    CrossContractA public contractA;
    uint256 public total;

    constructor(address _a) {
        contractA = CrossContractA(_a);
    }

    // Called by A, calls back into A (completing the cycle)
    function process(uint256 amount) external {
        total += amount;
        contractA.onReceive(amount);
    }

    function getValue() public pure returns (uint256) {
        return 0;
    }
}
