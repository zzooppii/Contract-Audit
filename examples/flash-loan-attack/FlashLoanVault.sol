// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

interface IFlashBorrower {
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32);
}

interface IPriceOracle {
    function getPrice(address token) external view returns (uint256);
}

/// @title FlashLoanVault - Flash loan provider with multiple vulnerabilities
/// @notice FOR EDUCATIONAL/TESTING PURPOSES ONLY - DO NOT DEPLOY
contract FlashLoanVault {
    IERC20 public loanToken;
    IPriceOracle public oracle;
    address public owner;

    uint256 public totalDeposited;
    uint256 public flashLoanFee = 9; // 0.09% (should be in basis points)
    uint256 public constant FEE_DENOMINATOR = 10000;

    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrowed;

    bool public paused;

    event FlashLoan(address indexed borrower, uint256 amount, uint256 fee);
    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    constructor(address _token, address _oracle) {
        loanToken = IERC20(_token);
        oracle = IPriceOracle(_oracle);
        owner = msg.sender;
    }

    // ============ VULN-1: Flash loan callback without sender validation ============
    function flashLoan(
        address borrower,
        uint256 amount,
        bytes calldata data
    ) external {
        require(!paused, "Paused");
        uint256 balanceBefore = loanToken.balanceOf(address(this));
        require(balanceBefore >= amount, "Insufficient liquidity");

        uint256 fee = (amount * flashLoanFee) / FEE_DENOMINATOR;

        // BUG: No check that borrower is msg.sender or authorized
        // Anyone can initiate a flash loan on behalf of another address
        loanToken.transfer(borrower, amount);

        // BUG: Callback to borrower without verifying msg.sender
        // Attacker can call with victim's address as borrower
        IFlashBorrower(borrower).onFlashLoan(
            msg.sender,
            address(loanToken),
            amount,
            fee,
            data
        );

        // BUG: Only checks balance, not that repayment came from borrower
        uint256 balanceAfter = loanToken.balanceOf(address(this));
        require(balanceAfter >= balanceBefore + fee, "Repayment failed");

        emit FlashLoan(borrower, amount, fee);
    }

    // ============ VULN-2: Price oracle manipulation via flash loan ============
    function getCollateralValue(address user) public view returns (uint256) {
        // BUG: Uses spot price from oracle that can be manipulated
        // during a flash loan (e.g., manipulate AMM reserves)
        uint256 price = oracle.getPrice(address(loanToken));
        return deposits[user] * price;
    }

    // ============ VULN-3: Reentrancy in deposit/withdraw ============
    function deposit(uint256 amount) external {
        require(!paused, "Paused");
        loanToken.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
        totalDeposited += amount;
        emit Deposited(msg.sender, amount);
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient deposit");

        // BUG: External call before state update
        loanToken.transfer(msg.sender, amount);

        // State update after external call
        deposits[msg.sender] -= amount;
        totalDeposited -= amount;

        emit Withdrawn(msg.sender, amount);
    }

    // ============ VULN-4: Unchecked return value on transfer ============
    function rescueTokens(address token, uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        // BUG: Return value of transfer not checked
        IERC20(token).transfer(owner, amount);
    }

    // ============ VULN-5: Missing access control ============
    function setFlashLoanFee(uint256 newFee) external {
        // BUG: Anyone can set fee to 0 (free flash loans) or 100%
        flashLoanFee = newFee;
    }

    function setPaused(bool _paused) external {
        // BUG: Anyone can pause/unpause
        paused = _paused;
    }

    function setOracle(address newOracle) external {
        // BUG: Anyone can set a malicious oracle
        oracle = IPriceOracle(newOracle);
    }

    // ============ VULN-6: Flash loan with price-dependent liquidation ============
    function liquidate(address user, uint256 repayAmount) external {
        uint256 collateralValue = getCollateralValue(user);
        uint256 debtValue = borrowed[user];

        // BUG: Liquidation threshold check uses manipulable oracle price
        require(collateralValue < debtValue, "Not liquidatable");

        // BUG: No flash loan guard — attacker can:
        // 1. Flash loan to manipulate oracle price
        // 2. Make collateralValue < debtValue
        // 3. Liquidate at favorable price
        // 4. Repay flash loan
        loanToken.transferFrom(msg.sender, address(this), repayAmount);
        borrowed[user] -= repayAmount;

        // Transfer collateral to liquidator at discount
        uint256 collateralToSeize = deposits[user];
        deposits[user] = 0;
        loanToken.transfer(msg.sender, collateralToSeize);
    }
}
