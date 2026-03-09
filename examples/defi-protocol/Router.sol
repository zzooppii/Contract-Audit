// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IProtocol.sol";
import "./Token.sol";
import "./Oracle.sol";
import "./Pool.sol";

contract SwapRouter is IRouter {
    PriceOracle public oracle;
    LendingPool public pool;
    address public owner;

    // Vulnerability: fee hardcoded, no governance
    uint256 public constant SWAP_FEE = 30; // 0.3%
    uint256 public constant FEE_BASE = 10000;

    mapping(bytes32 => uint256) public pairLiquidity;
    mapping(bytes32 => mapping(address => uint256)) public liquidityShares;

    event Swap(address indexed user, address tokenIn, address tokenOut, uint256 amountIn, uint256 amountOut);
    event LiquidityAdded(address indexed user, address tokenA, address tokenB, uint256 amountA, uint256 amountB);
    event LiquidityRemoved(address indexed user, address tokenA, address tokenB, uint256 liquidity);

    constructor(address _oracle, address _pool) {
        oracle = PriceOracle(_oracle);
        pool = LendingPool(_pool);
        owner = msg.sender;
    }

    // Vulnerability: swap uses spot oracle price — flash loan manipulable
    // Vulnerability: no deadline parameter — transaction can be delayed
    function swap(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minOut
    ) external override returns (uint256) {
        require(amountIn > 0, "Zero input");

        uint256 priceIn = oracle.getPrice(tokenIn);
        uint256 priceOut = oracle.getPrice(tokenOut);
        // Vulnerability: oracle returns 0 for unknown tokens — division by zero
        require(priceOut > 0, "Invalid price");

        uint256 amountOut = (amountIn * priceIn) / priceOut;
        uint256 fee = amountOut * SWAP_FEE / FEE_BASE;
        amountOut -= fee;

        // Vulnerability: minOut check after fee — user might get less than expected
        require(amountOut >= minOut, "Slippage");

        IToken(tokenIn).transferFrom(msg.sender, address(this), amountIn);

        // Vulnerability: no check if router has enough tokenOut balance
        IToken(tokenOut).transfer(msg.sender, amountOut);

        emit Swap(msg.sender, tokenIn, tokenOut, amountIn, amountOut);
        return amountOut;
    }

    function addLiquidity(
        address tokenA,
        address tokenB,
        uint256 amountA,
        uint256 amountB
    ) external override {
        require(amountA > 0 && amountB > 0, "Zero amounts");

        bytes32 pairKey = _getPairKey(tokenA, tokenB);

        IToken(tokenA).transferFrom(msg.sender, address(this), amountA);
        IToken(tokenB).transferFrom(msg.sender, address(this), amountB);

        // Vulnerability: liquidity share calculation doesn't account for token ratio
        uint256 shares = amountA + amountB;
        liquidityShares[pairKey][msg.sender] += shares;
        pairLiquidity[pairKey] += shares;

        emit LiquidityAdded(msg.sender, tokenA, tokenB, amountA, amountB);
    }

    // Vulnerability: removeLiquidity — proportional withdrawal not enforced
    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint256 liquidity
    ) external override {
        bytes32 pairKey = _getPairKey(tokenA, tokenB);
        require(liquidityShares[pairKey][msg.sender] >= liquidity, "Insufficient shares");

        liquidityShares[pairKey][msg.sender] -= liquidity;
        pairLiquidity[pairKey] -= liquidity;

        // Vulnerability: returns fixed split regardless of actual pool reserves
        uint256 halfLiquidity = liquidity / 2;
        IToken(tokenA).transfer(msg.sender, halfLiquidity);
        IToken(tokenB).transfer(msg.sender, halfLiquidity);

        emit LiquidityRemoved(msg.sender, tokenA, tokenB, liquidity);
    }

    // Vulnerability: flash loan with callback — reentrancy vector across Pool and Router
    function flashSwap(
        address token,
        uint256 amount,
        bytes calldata data
    ) external {
        uint256 balanceBefore = IToken(token).balanceOf(address(this));

        IToken(token).transfer(msg.sender, amount);

        // Vulnerability: callback to arbitrary address — reentrancy
        (bool success,) = msg.sender.call(data);
        require(success, "Callback failed");

        // Vulnerability: fee calculation on amount, not on returned amount
        uint256 fee = amount * SWAP_FEE / FEE_BASE;
        uint256 balanceAfter = IToken(token).balanceOf(address(this));
        require(balanceAfter >= balanceBefore + fee, "Flash swap not repaid");
    }

    function _getPairKey(address tokenA, address tokenB) internal pure returns (bytes32) {
        (address t0, address t1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        return keccak256(abi.encodePacked(t0, t1));
    }
}
