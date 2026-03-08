// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @title UnsafeVault
 * @notice Vault with unchecked call return values and dangerous delegatecall.
 *         Used for testing the unchecked_call detector.
 */
contract UnsafeVault {
    address public owner;
    IERC20 public token;
    mapping(address => uint256) public deposits;

    constructor(address _token) {
        owner = msg.sender;
        token = IERC20(_token);
    }

    // BUG 1: Unchecked low-level call — return value not captured
    function withdrawETH(address payable to, uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        to.call{value: amount}("");
    }

    // BUG 2: Unchecked ERC20 transfer (no SafeERC20)
    function withdrawToken(address to, uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        token.transfer(to, amount);
    }

    // BUG 3: Unchecked transferFrom
    function depositToken(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
    }

    // BUG 4: Delegatecall to untrusted (parameter-supplied) address
    function execute(address target, bytes calldata data) external {
        require(msg.sender == owner, "Not owner");
        target.delegatecall(data);
    }

    // BUG 5: Selfdestruct reachable (combined with delegatecall above)
    function destroy() external {
        require(msg.sender == owner, "Not owner");
        selfdestruct(payable(owner));
    }

    receive() external payable {}
}
