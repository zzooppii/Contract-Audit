// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
    function mint(address, uint256) external;
    function burn(address, uint256) external;
}

/// @title TokenBridge - Cross-chain bridge with proxy and storage vulnerabilities
/// @notice FOR EDUCATIONAL/TESTING PURPOSES ONLY - DO NOT DEPLOY
contract TokenBridge {
    // ============ VULN-1: Proxy storage layout — no gap ============
    // If this contract is used behind a proxy, these slots will collide
    // with any inheriting contract's storage
    address public implementation;
    address public admin;
    bool public paused;

    mapping(address => bool) public supportedTokens;
    mapping(bytes32 => bool) public processedMessages;
    mapping(address => mapping(address => uint256)) public deposits;

    address public relayer;
    uint256 public nonce;
    uint256 public minConfirmations = 12;
    uint256 public maxTransferAmount = 1000000e18;

    // BUG: No storage gap for upgradeable proxy pattern
    // uint256[50] private __gap;

    event Deposited(address indexed token, address indexed from, uint256 amount, uint256 destChainId);
    event Released(address indexed token, address indexed to, uint256 amount, bytes32 messageId);
    event Upgraded(address indexed newImplementation);

    modifier onlyRelayer() {
        require(msg.sender == relayer, "Not relayer");
        _;
    }

    constructor(address _relayer) {
        admin = msg.sender;
        relayer = _relayer;
    }

    // ============ VULN-2: Replay attack — weak message ID ============
    function releaseTokens(
        address token,
        address recipient,
        uint256 amount,
        uint256 sourceChainId,
        bytes32 messageId
    ) external onlyRelayer {
        // BUG: messageId is not bound to (token, recipient, amount, chainId)
        // Relayer could replay with different parameters using same messageId
        require(!processedMessages[messageId], "Already processed");
        processedMessages[messageId] = true;

        // BUG: No max transfer check
        IERC20(token).transfer(recipient, amount);

        emit Released(token, recipient, amount, messageId);
    }

    // ============ VULN-3: delegatecall to arbitrary address ============
    function upgradeAndCall(address newImpl, bytes calldata data) external {
        require(msg.sender == admin, "Not admin");
        implementation = newImpl;

        // BUG: delegatecall to untrusted address — can overwrite all storage
        (bool success,) = newImpl.delegatecall(data);
        require(success, "Upgrade call failed");

        emit Upgraded(newImpl);
    }

    // ============ VULN-4: Missing access control ============
    function setRelayer(address newRelayer) external {
        // BUG: Anyone can change the relayer — full bridge takeover
        relayer = newRelayer;
    }

    function addSupportedToken(address token) external {
        // BUG: Anyone can add tokens
        supportedTokens[token] = true;
    }

    function setPaused(bool _paused) external {
        // BUG: Anyone can pause/unpause
        paused = _paused;
    }

    // ============ VULN-5: Unchecked arithmetic on amounts ============
    function depositTokens(
        address token,
        uint256 amount,
        uint256 destChainId
    ) external {
        require(!paused, "Bridge paused");
        require(supportedTokens[token], "Token not supported");
        require(amount > 0, "Zero amount");

        // BUG: No max transfer amount check
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender][token] += amount;

        nonce++;
        emit Deposited(token, msg.sender, amount, destChainId);
    }

    // ============ VULN-6: Emergency withdraw without proper auth ============
    function emergencyWithdraw(address token, uint256 amount) external {
        require(tx.origin == admin, "Not admin");
        // BUG: tx.origin instead of msg.sender — phishing attack vector
        IERC20(token).transfer(msg.sender, amount);
    }

    // ============ Safe function ============
    function getDeposit(address user, address token) external view returns (uint256) {
        return deposits[user][token];
    }
}
