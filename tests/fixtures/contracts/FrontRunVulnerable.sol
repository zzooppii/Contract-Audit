// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FrontRunVulnerable {
    mapping(address => uint256) public balances;
    uint256 public reserveA;
    uint256 public reserveB;

    // Missing slippage protection
    function swap(address tokenIn, uint256 amountIn) external {
        uint256 amountOut = (amountIn * reserveB) / reserveA;
        reserveA += amountIn;
        reserveB -= amountOut;
        // transfer tokenOut to msg.sender
    }

    // Missing deadline check
    function addLiquidity(uint256 amountA, uint256 amountB) external {
        reserveA += amountA;
        reserveB += amountB;
    }

    // Missing commit-reveal for auction
    function bid(uint256 amount) external payable {
        require(msg.value >= amount, "Insufficient");
        balances[msg.sender] += amount;
    }

    // Sandwich vulnerable: reserve change + transfer without protection
    function swapExactTokens(uint256 amountIn, address to) external {
        uint256 amountOut = (amountIn * reserveB) / reserveA;
        reserveA += amountIn;
        reserveB -= amountOut;
        payable(to).transfer(amountOut);
    }
}
