// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract UninitializedProxy is Initializable, UUPSUpgradeable {
    address public owner;
    uint256 public value;

    // Missing initializer modifier - CRITICAL
    function initialize(address _owner) external {
        owner = _owner;
    }

    // Constructor with logic but no _disableInitializers
    constructor() {
        owner = msg.sender;
        value = 42;
    }

    function setValue(uint256 _value) external {
        require(msg.sender == owner, "Not owner");
        value = _value;
    }

    function _authorizeUpgrade(address) internal override {
        require(msg.sender == owner, "Not owner");
    }
}
