// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @title CrossChainBridge
 * @notice Cross-chain token bridge with multiple security vulnerabilities.
 *         Used for testing the bridge_detector.
 */
contract CrossChainBridge {
    address public owner;
    IERC20 public bridgeToken;
    uint256 public nonce;

    mapping(bytes32 => bool) public processedMessages;

    event TokensLocked(address indexed sender, uint256 amount, uint256 destChainId, uint256 nonce);
    event TokensReleased(address indexed recipient, uint256 amount);

    constructor(address _token) {
        owner = msg.sender;
        bridgeToken = IERC20(_token);
    }

    function lockTokens(uint256 amount, uint256 destChainId) external {
        bridgeToken.transferFrom(msg.sender, address(this), amount);
        nonce++;
        emit TokensLocked(msg.sender, amount, destChainId, nonce);
    }

    // BUG 1: Missing chain ID in message verification
    function verifyMessage(
        address recipient,
        uint256 amount,
        uint256 msgNonce,
        bytes memory signature
    ) public pure returns (bytes32) {
        // No block.chainid in hash — vulnerable to cross-chain replay
        bytes32 messageHash = keccak256(abi.encodePacked(recipient, amount, msgNonce));
        return messageHash;
    }

    // BUG 2: Missing replay protection — no nonce/ID tracking
    function releaseTokens(
        address recipient,
        uint256 amount,
        bytes memory proof
    ) external {
        // No check for processed messages — can be replayed!
        bridgeToken.transfer(recipient, amount);
        emit TokensReleased(recipient, amount);
    }

    // BUG 3: Arbitrary delegatecall in bridge context
    function executeOnBehalf(address target, bytes calldata data) external {
        target.delegatecall(data);
    }

    // BUG 4: Missing relayer validation — anyone can release tokens
    function processMessage(
        address recipient,
        uint256 amount,
        uint256 sourceChain,
        bytes memory signature
    ) external {
        // No access control — anyone can call and drain bridge
        bridgeToken.transfer(recipient, amount);
    }

    // Admin function (properly protected for contrast)
    function setOwner(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        owner = newOwner;
    }
}
