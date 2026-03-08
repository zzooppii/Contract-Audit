// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title VulnerableToken - ERC20 token with multiple vulnerabilities
/// @notice FOR EDUCATIONAL/TESTING PURPOSES ONLY - DO NOT DEPLOY
contract VulnerableToken {
    string public name = "VulnerableToken";
    string public symbol = "VULN";
    uint8 public decimals = 18;

    uint256 public totalSupply;
    address public owner;
    address public minter;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public blacklisted;
    mapping(address => bool) public whitelisted;

    bool public paused;
    uint256 public transferFee = 300; // 3%
    address public feeCollector;
    uint256 public maxTransferAmount = 1000000e18;

    // ============ VULN-1: Missing event in critical state change ============
    // No Transfer event definition — breaks ERC20 spec compliance
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor() {
        owner = msg.sender;
        minter = msg.sender;
        feeCollector = msg.sender;
        totalSupply = 1000000e18;
        balanceOf[msg.sender] = totalSupply;
    }

    // ============ VULN-2: Approval race condition ============
    function approve(address spender, uint256 amount) external returns (bool) {
        // BUG: Classic approve race condition — no increaseAllowance/decreaseAllowance
        // Attacker can front-run approve() to spend old + new allowance
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    // ============ VULN-3: Fee-on-transfer with rounding issues ============
    function transfer(address to, uint256 amount) external returns (bool) {
        require(!paused, "Paused");
        require(!blacklisted[msg.sender], "Blacklisted");
        require(amount <= maxTransferAmount, "Exceeds max");
        require(balanceOf[msg.sender] >= amount, "Insufficient");

        // BUG: Fee calculation rounds down — dust accumulates
        uint256 fee = (amount * transferFee) / 10000;
        uint256 netAmount = amount - fee;

        // BUG: No zero-address check — tokens can be burned accidentally
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += netAmount;
        balanceOf[feeCollector] += fee;

        // BUG: Missing Transfer event emission (breaks ERC20 spec)
        return true;
    }

    // ============ VULN-4: transferFrom with double-spend possibility ============
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        require(!paused, "Paused");
        require(!blacklisted[from], "Blacklisted");
        require(amount <= maxTransferAmount, "Exceeds max");
        require(balanceOf[from] >= amount, "Insufficient");

        // BUG: Allowance check after transfer — can be exploited with callbacks
        uint256 fee = (amount * transferFee) / 10000;
        uint256 netAmount = amount - fee;

        balanceOf[from] -= amount;
        balanceOf[to] += netAmount;
        balanceOf[feeCollector] += fee;

        // Allowance update after state change
        require(allowance[from][msg.sender] >= amount, "Allowance exceeded");
        allowance[from][msg.sender] -= amount;

        return true;
    }

    // ============ VULN-5: Unlimited minting without cap ============
    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "Not minter");
        // BUG: No max supply cap — minter can inflate supply infinitely
        // BUG: No zero-address check
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    // ============ VULN-6: Missing access control on critical functions ============
    function setMinter(address newMinter) external {
        // BUG: Anyone can become the minter
        minter = newMinter;
    }

    function setFeeCollector(address newCollector) external {
        // BUG: Anyone can redirect fees
        feeCollector = newCollector;
    }

    function setTransferFee(uint256 newFee) external {
        // BUG: Anyone can set fee to 100%
        // BUG: No upper bound check
        transferFee = newFee;
    }

    function setBlacklist(address account, bool status) external {
        // BUG: Anyone can blacklist any address
        blacklisted[account] = status;
    }

    function setPaused(bool _paused) external {
        // BUG: Anyone can pause/unpause
        paused = _paused;
    }

    // ============ Safe functions ============
    function burn(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "Insufficient");
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
    }
}
