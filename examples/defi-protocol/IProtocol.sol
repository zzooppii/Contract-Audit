// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IToken {
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function totalSupply() external view returns (uint256);
}

interface IOracle {
    function getPrice(address token) external view returns (uint256);
    function updatePrice(address token, uint256 price) external;
}

interface IPool {
    function deposit(address token, uint256 amount) external;
    function withdraw(address token, uint256 amount) external;
    function borrow(address token, uint256 amount) external;
    function repay(address token, uint256 amount) external;
    function liquidate(address borrower, address token) external;
    function getCollateralValue(address user) external view returns (uint256);
}

interface IRouter {
    function swap(address tokenIn, address tokenOut, uint256 amountIn, uint256 minOut) external returns (uint256);
    function addLiquidity(address tokenA, address tokenB, uint256 amountA, uint256 amountB) external;
    function removeLiquidity(address tokenA, address tokenB, uint256 liquidity) external;
}
