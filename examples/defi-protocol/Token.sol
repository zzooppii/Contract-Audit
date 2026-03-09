// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IProtocol.sol";

contract ProtocolToken is IToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    address public owner;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public minters;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // Vulnerability: no access control on constructor alternative
    // Missing initializer pattern for upgradeable deployment
    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
        owner = msg.sender;
    }

    // Vulnerability: minter role can be granted by owner but never revoked
    function addMinter(address minter) external onlyOwner {
        minters[minter] = true;
    }

    function mint(address to, uint256 amount) external override {
        require(minters[msg.sender] || msg.sender == owner, "Not authorized");
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function burn(address from, uint256 amount) external override {
        require(minters[msg.sender] || msg.sender == owner, "Not authorized");
        require(balanceOf[from] >= amount, "Insufficient balance");
        // Vulnerability: no underflow check on totalSupply in edge case
        totalSupply -= amount;
        balanceOf[from] -= amount;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        require(allowance[from][msg.sender] >= amount, "Allowance");
        require(balanceOf[from] >= amount, "Insufficient");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external override returns (bool) {
        // Vulnerability: no zero-check, approve race condition
        allowance[msg.sender][spender] = amount;
        return true;
    }
}
