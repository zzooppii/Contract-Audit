// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract UnsafeVault {
    address public owner;
    IERC20 public token;

    constructor(address _token) {
        owner = msg.sender;
        token = IERC20(_token);
    }

    // Unchecked low-level call
    function withdrawETH(address payable to, uint256 amount) external {
        to.call{value: amount}("");
    }

    // Unchecked ERC20 transfer
    function withdrawToken(address to, uint256 amount) external {
        token.transfer(to, amount);
    }

    // Delegatecall to untrusted address
    function execute(address target, bytes calldata data) external {
        target.delegatecall(data);
    }

    // Selfdestruct (combined with delegatecall = critical)
    function destroy() external {
        selfdestruct(payable(owner));
    }
}
