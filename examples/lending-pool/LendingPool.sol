// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80 roundId, int256 answer, uint256 startedAt,
        uint256 updatedAt, uint80 answeredInRound
    );
}

/// @title LendingPool - Lending protocol with liquidation and oracle vulnerabilities
/// @notice FOR EDUCATIONAL/TESTING PURPOSES ONLY - DO NOT DEPLOY
contract LendingPool {
    struct Market {
        IERC20 token;
        AggregatorV3Interface oracle;
        uint256 collateralFactor; // e.g., 7500 = 75%
        uint256 totalDeposits;
        uint256 totalBorrowed;
        uint256 interestRate; // per block, in basis points
        uint256 lastAccrualBlock;
        uint256 accumulatedInterest;
    }

    address public admin;
    uint256 public liquidationBonus = 1100; // 110% — 10% bonus
    uint256 public constant BASIS_POINTS = 10000;

    Market[] public markets;

    // user => marketId => deposit amount
    mapping(address => mapping(uint256 => uint256)) public userDeposits;
    // user => marketId => borrow amount
    mapping(address => mapping(uint256 => uint256)) public userBorrows;

    event Deposit(address indexed user, uint256 indexed marketId, uint256 amount);
    event Borrow(address indexed user, uint256 indexed marketId, uint256 amount);
    event Repay(address indexed user, uint256 indexed marketId, uint256 amount);
    event Liquidation(address indexed liquidator, address indexed user, uint256 repaid, uint256 seized);

    constructor() {
        admin = msg.sender;
    }

    function addMarket(
        address token,
        address oracle,
        uint256 collateralFactor,
        uint256 interestRate
    ) external {
        require(msg.sender == admin, "Not admin");
        markets.push(Market({
            token: IERC20(token),
            oracle: AggregatorV3Interface(oracle),
            collateralFactor: collateralFactor,
            totalDeposits: 0,
            totalBorrowed: 0,
            interestRate: interestRate,
            lastAccrualBlock: block.number,
            accumulatedInterest: 0
        }));
    }

    function deposit(uint256 marketId, uint256 amount) external {
        Market storage market = markets[marketId];
        market.token.transferFrom(msg.sender, address(this), amount);
        userDeposits[msg.sender][marketId] += amount;
        market.totalDeposits += amount;
        emit Deposit(msg.sender, marketId, amount);
    }

    // ============ VULN-1: Oracle without staleness check ============
    function getPrice(uint256 marketId) public view returns (uint256) {
        Market storage market = markets[marketId];
        (, int256 price,,,) = market.oracle.latestRoundData();
        // BUG: No staleness check — price could be hours/days old
        // BUG: No check for price <= 0
        // BUG: No check for answeredInRound >= roundId
        return uint256(price);
    }

    // ============ VULN-2: Liquidation uses manipulable oracle ============
    function liquidate(
        address user,
        uint256 collateralMarketId,
        uint256 borrowMarketId,
        uint256 repayAmount
    ) external {
        // BUG: No flash loan guard — attacker can:
        // 1. Flash loan → manipulate oracle price
        // 2. Make user appear undercollateralized
        // 3. Liquidate at discount
        // 4. Repay flash loan with profit

        uint256 collateralValue = _getAccountCollateral(user);
        uint256 borrowValue = _getAccountBorrows(user);

        // BUG: Uses spot oracle price for liquidation check
        require(collateralValue < borrowValue, "Not liquidatable");

        Market storage borrowMarket = markets[borrowMarketId];
        Market storage collateralMarket = markets[collateralMarketId];

        // Repay debt
        borrowMarket.token.transferFrom(msg.sender, address(this), repayAmount);
        userBorrows[user][borrowMarketId] -= repayAmount;
        borrowMarket.totalBorrowed -= repayAmount;

        // Calculate collateral to seize (with bonus)
        uint256 repayValue = repayAmount * getPrice(borrowMarketId);
        uint256 collateralPrice = getPrice(collateralMarketId);

        // BUG: Division before multiplication — precision loss
        uint256 seizeAmount = (repayValue / collateralPrice) * liquidationBonus / BASIS_POINTS;

        userDeposits[user][collateralMarketId] -= seizeAmount;
        collateralMarket.totalDeposits -= seizeAmount;

        // BUG: External call before full state update
        collateralMarket.token.transfer(msg.sender, seizeAmount);

        emit Liquidation(msg.sender, user, repayAmount, seizeAmount);
    }

    // ============ VULN-3: Borrow without proper health check ============
    function borrow(uint256 marketId, uint256 amount) external {
        Market storage market = markets[marketId];

        // BUG: Health check uses manipulable oracle price
        uint256 collateralValue = _getAccountCollateral(msg.sender);
        uint256 currentBorrows = _getAccountBorrows(msg.sender);
        uint256 newBorrowValue = amount * getPrice(marketId);

        require(
            collateralValue >= currentBorrows + newBorrowValue,
            "Insufficient collateral"
        );

        userBorrows[msg.sender][marketId] += amount;
        market.totalBorrowed += amount;

        // BUG: External call after state update but no reentrancy guard
        market.token.transfer(msg.sender, amount);

        emit Borrow(msg.sender, marketId, amount);
    }

    // ============ VULN-4: Interest accrual with timestamp manipulation ============
    function accrueInterest(uint256 marketId) public {
        Market storage market = markets[marketId];

        // BUG: Uses block.number difference which can be gamed
        // Miner can include tx in specific block for favorable interest
        uint256 blockDelta = block.number - market.lastAccrualBlock;
        if (blockDelta == 0) return;

        // BUG: Division before multiplication — precision loss
        uint256 interest = (market.totalBorrowed * market.interestRate * blockDelta) / BASIS_POINTS / 10000;

        market.accumulatedInterest += interest;
        market.totalBorrowed += interest;
        market.lastAccrualBlock = block.number;
    }

    // ============ VULN-5: Missing access control ============
    function setLiquidationBonus(uint256 newBonus) external {
        // BUG: Anyone can set liquidation bonus — could set to 10000 (100x)
        // to drain all collateral in one liquidation
        liquidationBonus = newBonus;
    }

    function setCollateralFactor(uint256 marketId, uint256 newFactor) external {
        // BUG: Anyone can set collateral factor — setting to 0 makes
        // all positions immediately liquidatable
        markets[marketId].collateralFactor = newFactor;
    }

    function setInterestRate(uint256 marketId, uint256 newRate) external {
        // BUG: Anyone can set interest rate — could set extremely high
        // to make borrowers instantly liquidatable
        markets[marketId].interestRate = newRate;
    }

    // ============ VULN-6: Withdrawal without health check ============
    function withdraw(uint256 marketId, uint256 amount) external {
        require(userDeposits[msg.sender][marketId] >= amount, "Insufficient");

        // BUG: No health factor check after withdrawal
        // User can withdraw collateral while having outstanding borrows,
        // creating bad debt (undercollateralized position)
        userDeposits[msg.sender][marketId] -= amount;
        markets[marketId].totalDeposits -= amount;

        markets[marketId].token.transfer(msg.sender, amount);
    }

    // ============ Internal helpers ============
    function _getAccountCollateral(address user) internal view returns (uint256) {
        uint256 totalValue = 0;
        for (uint256 i = 0; i < markets.length; i++) {
            uint256 deposited = userDeposits[user][i];
            if (deposited > 0) {
                uint256 price = getPrice(i);
                uint256 value = deposited * price;
                // Apply collateral factor
                totalValue += (value * markets[i].collateralFactor) / BASIS_POINTS;
            }
        }
        return totalValue;
    }

    function _getAccountBorrows(address user) internal view returns (uint256) {
        uint256 totalValue = 0;
        for (uint256 i = 0; i < markets.length; i++) {
            uint256 borrowed = userBorrows[user][i];
            if (borrowed > 0) {
                totalValue += borrowed * getPrice(i);
            }
        }
        return totalValue;
    }

    function repay(uint256 marketId, uint256 amount) external {
        Market storage market = markets[marketId];
        require(userBorrows[msg.sender][marketId] >= amount, "Overpayment");

        market.token.transferFrom(msg.sender, address(this), amount);
        userBorrows[msg.sender][marketId] -= amount;
        market.totalBorrowed -= amount;

        emit Repay(msg.sender, marketId, amount);
    }
}
