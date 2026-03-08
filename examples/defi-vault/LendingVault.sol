// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./interfaces/IERC20.sol";

interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80 roundId, int256 answer, uint256 startedAt,
        uint256 updatedAt, uint80 answeredInRound
    );
}

interface IFlashLoanReceiver {
    function executeOperation(
        address asset, uint256 amount, uint256 premium,
        address initiator, bytes calldata params
    ) external returns (bool);
}

/// @title LendingVault - A DeFi lending vault with multiple vulnerabilities
/// @notice FOR EDUCATIONAL/TESTING PURPOSES ONLY - DO NOT DEPLOY
contract LendingVault {
    // ============ State Variables ============
    IERC20 public immutable asset;
    AggregatorV3Interface public priceOracle;
    address public owner;

    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrowings;
    mapping(address => uint256) public collateral;

    uint256 public totalDeposits;
    uint256 public totalBorrows;
    uint256 public liquidationThreshold = 80; // 80%
    uint256 public borrowFee = 50; // 0.5% in basis points
    uint256 public constant PRECISION = 1e18;

    bool private _locked;

    // ============ Events ============
    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    event Borrow(address indexed user, uint256 amount);
    event Repay(address indexed user, uint256 amount);
    event Liquidation(address indexed user, address indexed liquidator, uint256 amount);
    event FlashLoan(address indexed receiver, uint256 amount, uint256 fee);

    constructor(address _asset, address _oracle) {
        asset = IERC20(_asset);
        priceOracle = AggregatorV3Interface(_oracle);
        owner = msg.sender;
    }

    // ============ VULN-1: Reentrancy in withdraw ============
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient balance");

        // BUG: External call before state update
        asset.transfer(msg.sender, amount);

        deposits[msg.sender] -= amount;
        totalDeposits -= amount;

        emit Withdraw(msg.sender, amount);
    }

    // ============ VULN-2: Oracle without staleness check ============
    function getAssetPrice() public view returns (uint256) {
        (, int256 price,,,) = priceOracle.latestRoundData();
        // BUG: No staleness check, no zero/negative check
        return uint256(price);
    }

    // ============ VULN-3: Flash loan without proper validation ============
    function flashLoan(address receiver, uint256 amount, bytes calldata params) external {
        uint256 balanceBefore = asset.balanceOf(address(this));
        require(balanceBefore >= amount, "Not enough liquidity");

        uint256 fee = (amount * borrowFee) / 10000;

        asset.transfer(receiver, amount);

        // BUG: No msg.sender validation in callback
        IFlashLoanReceiver(receiver).executeOperation(
            address(asset), amount, fee, msg.sender, params
        );

        uint256 balanceAfter = asset.balanceOf(address(this));
        require(balanceAfter >= balanceBefore + fee, "Flash loan not repaid");

        emit FlashLoan(receiver, amount, fee);
    }

    // ============ VULN-4: Liquidation with price manipulation ============
    function liquidate(address user, uint256 repayAmount) external {
        uint256 price = getAssetPrice(); // Uses manipulable oracle
        uint256 collateralValue = (collateral[user] * price) / PRECISION;
        uint256 borrowValue = borrowings[user];

        // BUG: Uses spot price that can be manipulated in same tx
        require(
            collateralValue * 100 < borrowValue * liquidationThreshold,
            "Position healthy"
        );

        borrowings[user] -= repayAmount;
        totalBorrows -= repayAmount;

        // BUG: Liquidation bonus calculated incorrectly — can drain collateral
        uint256 liquidationBonus = (repayAmount * 110) / 100; // 10% bonus
        collateral[user] -= liquidationBonus;
        collateral[msg.sender] += liquidationBonus;

        asset.transferFrom(msg.sender, address(this), repayAmount);

        emit Liquidation(user, msg.sender, repayAmount);
    }

    // ============ VULN-5: Missing access control ============
    function setOracle(address newOracle) external {
        // BUG: Anyone can change the oracle
        priceOracle = AggregatorV3Interface(newOracle);
    }

    function setPaused(bool) external {
        // BUG: Anyone can pause/unpause
        _locked = !_locked;
    }

    // ============ Safe functions (for contrast) ============
    function deposit(uint256 amount) external {
        require(amount > 0, "Zero deposit");
        asset.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
        totalDeposits += amount;
        emit Deposit(msg.sender, amount);
    }

    function borrow(uint256 amount) external {
        uint256 price = getAssetPrice();
        uint256 maxBorrow = (collateral[msg.sender] * price * liquidationThreshold) / (PRECISION * 100);
        require(borrowings[msg.sender] + amount <= maxBorrow, "Exceeds borrow limit");

        borrowings[msg.sender] += amount;
        totalBorrows += amount;
        asset.transfer(msg.sender, amount);

        emit Borrow(msg.sender, amount);
    }

    function repay(uint256 amount) external {
        require(borrowings[msg.sender] >= amount, "Overpayment");
        asset.transferFrom(msg.sender, address(this), amount);
        borrowings[msg.sender] -= amount;
        totalBorrows -= amount;
        emit Repay(msg.sender, amount);
    }
}
