// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IProtocol.sol";
import "./Token.sol";
import "./Oracle.sol";

contract LendingPool is IPool {
    PriceOracle public oracle;
    address public owner;

    // Collateral factor: 75% (represented as 7500 / 10000)
    uint256 public constant COLLATERAL_FACTOR = 7500;
    uint256 public constant LIQUIDATION_BONUS = 500; // 5%
    uint256 public constant BASIS_POINTS = 10000;

    struct UserAccount {
        mapping(address => uint256) deposits;
        mapping(address => uint256) borrows;
    }

    mapping(address => UserAccount) internal accounts;
    mapping(address => uint256) public totalDeposits;
    mapping(address => uint256) public totalBorrows;
    mapping(address => bool) public supportedTokens;

    event Deposit(address indexed user, address indexed token, uint256 amount);
    event Withdraw(address indexed user, address indexed token, uint256 amount);
    event Borrow(address indexed user, address indexed token, uint256 amount);
    event Repay(address indexed user, address indexed token, uint256 amount);
    event Liquidation(address indexed liquidator, address indexed borrower, address indexed token);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(address _oracle) {
        oracle = PriceOracle(_oracle);
        owner = msg.sender;
    }

    function addSupportedToken(address token) external onlyOwner {
        supportedTokens[token] = true;
    }

    function deposit(address token, uint256 amount) external override {
        require(supportedTokens[token], "Token not supported");
        require(amount > 0, "Zero amount");

        IToken(token).transferFrom(msg.sender, address(this), amount);
        accounts[msg.sender].deposits[token] += amount;
        totalDeposits[token] += amount;

        emit Deposit(msg.sender, token, amount);
    }

    // Vulnerability: cross-contract reentrancy
    // withdraw updates state after external call to token.transfer
    function withdraw(address token, uint256 amount) external override {
        require(accounts[msg.sender].deposits[token] >= amount, "Insufficient deposit");

        // Vulnerability: external call before state update
        IToken(token).transfer(msg.sender, amount);

        accounts[msg.sender].deposits[token] -= amount;
        totalDeposits[token] -= amount;

        // Vulnerability: no health check after withdrawal
        emit Withdraw(msg.sender, token, amount);
    }

    function borrow(address token, uint256 amount) external override {
        require(supportedTokens[token], "Token not supported");
        require(totalDeposits[token] - totalBorrows[token] >= amount, "Insufficient liquidity");

        accounts[msg.sender].borrows[token] += amount;
        totalBorrows[token] += amount;

        // Vulnerability: health check uses oracle that can be manipulated
        require(_isHealthy(msg.sender), "Undercollateralized");

        IToken(token).transfer(msg.sender, amount);

        emit Borrow(msg.sender, token, amount);
    }

    function repay(address token, uint256 amount) external override {
        require(accounts[msg.sender].borrows[token] >= amount, "Overpayment");

        IToken(token).transferFrom(msg.sender, address(this), amount);
        accounts[msg.sender].borrows[token] -= amount;
        totalBorrows[token] -= amount;

        emit Repay(msg.sender, token, amount);
    }

    // Vulnerability: liquidation has no partial close, takes everything
    function liquidate(address borrower, address token) external override {
        require(!_isHealthy(borrower), "Account is healthy");

        uint256 debt = accounts[borrower].borrows[token];
        require(debt > 0, "No debt");

        // Liquidator repays full debt
        IToken(token).transferFrom(msg.sender, address(this), debt);
        accounts[borrower].borrows[token] = 0;
        totalBorrows[token] -= debt;

        // Vulnerability: liquidation bonus calculated on debt, not collateral
        uint256 bonus = debt * LIQUIDATION_BONUS / BASIS_POINTS;
        uint256 collateralSeized = debt + bonus;

        // Vulnerability: unchecked — may seize more than borrower's deposit
        accounts[borrower].deposits[token] -= collateralSeized;
        totalDeposits[token] -= collateralSeized;

        IToken(token).transfer(msg.sender, collateralSeized);

        emit Liquidation(msg.sender, borrower, token);
    }

    function getCollateralValue(address user) external view override returns (uint256) {
        return _getCollateralValue(user);
    }

    function _isHealthy(address user) internal view returns (bool) {
        uint256 collateral = _getCollateralValue(user);
        uint256 debt = _getDebtValue(user);

        if (debt == 0) return true;
        return collateral * COLLATERAL_FACTOR / BASIS_POINTS >= debt;
    }

    // Vulnerability: iterates only known tokens — if new token added mid-loop, state inconsistent
    function _getCollateralValue(address user) internal view returns (uint256) {
        // Simplified: would need token registry in production
        return 0; // placeholder
    }

    function _getDebtValue(address user) internal view returns (uint256) {
        return 0; // placeholder
    }
}
