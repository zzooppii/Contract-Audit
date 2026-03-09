// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IProtocol.sol";

contract PriceOracle is IOracle {
    address public owner;
    mapping(address => uint256) public prices;
    mapping(address => uint256) public lastUpdated;

    // Vulnerability: single oracle, no TWAP, no staleness check
    uint256 public constant STALENESS_THRESHOLD = 0; // effectively disabled

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // Vulnerability: single EOA can set any price — oracle manipulation
    function updatePrice(address token, uint256 price) external override onlyOwner {
        prices[token] = price;
        lastUpdated[token] = block.timestamp;
    }

    function getPrice(address token) external view override returns (uint256) {
        uint256 price = prices[token];
        // Vulnerability: returns 0 if price never set, no revert
        // Vulnerability: no staleness check (STALENESS_THRESHOLD = 0)
        return price;
    }

    // Vulnerability: owner transfer with no two-step pattern
    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}
