// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract CrossChainBridge {
    IERC20 public bridgeToken;
    uint256 public nonce;

    event TokensLocked(address indexed sender, uint256 amount, uint256 destChainId);

    constructor(address _token) {
        bridgeToken = IERC20(_token);
    }

    function lockTokens(uint256 amount, uint256 destChainId) external {
        bridgeToken.transferFrom(msg.sender, address(this), amount);
        nonce++;
        emit TokensLocked(msg.sender, amount, destChainId);
    }

    // Missing chain ID in message verification
    function verifyMessage(address recipient, uint256 amount, uint256 msgNonce, bytes memory sig)
        public pure returns (bytes32)
    {
        bytes32 messageHash = keccak256(abi.encodePacked(recipient, amount, msgNonce));
        return messageHash;
    }

    // Missing replay protection
    function releaseTokens(address recipient, uint256 amount, bytes memory proof) external {
        bridgeToken.transfer(recipient, amount);
    }

    // Arbitrary delegatecall
    function executeOnBehalf(address target, bytes calldata data) external {
        target.delegatecall(data);
    }

    // Missing relayer validation on processMessage
    function processMessage(address recipient, uint256 amount, uint256 sourceChain, bytes memory sig) external {
        bridgeToken.transfer(recipient, amount);
    }
}
