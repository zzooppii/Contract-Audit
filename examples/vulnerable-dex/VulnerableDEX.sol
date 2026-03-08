// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32);
}

interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80, int256, uint256, uint256, uint80
    );
}

/// @title VulnerableDEX - A DEX aggregator with multiple security issues
/// @notice FOR EDUCATIONAL/TESTING PURPOSES ONLY - DO NOT DEPLOY
contract VulnerableDEX {
    address public owner;
    address public feeCollector;

    mapping(address => mapping(address => uint256)) public liquidity;
    mapping(address => bool) public supportedTokens;

    IUniswapV2Pair public pricePair;
    AggregatorV3Interface public chainlinkFeed;

    uint256 public swapFee = 30; // 0.3%

    // ============ Proxy-like storage (collision risk) ============
    address public implementation;
    address public admin;
    // BUG: No storage gap — if inherited, slots will collide
    // uint256[50] private __gap;

    event Swap(address indexed user, address tokenIn, address tokenOut, uint256 amountIn, uint256 amountOut);
    event LiquidityAdded(address indexed user, address token, uint256 amount);

    constructor(address _pricePair, address _chainlinkFeed) {
        owner = msg.sender;
        admin = msg.sender;
        feeCollector = msg.sender;
        pricePair = IUniswapV2Pair(_pricePair);
        chainlinkFeed = AggregatorV3Interface(_chainlinkFeed);
    }

    // ============ VULN-1: Spot price from Uniswap (flash-loan manipulable) ============
    function getSpotPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = pricePair.getReserves();
        // BUG: Spot price can be manipulated via flash loan
        return (uint256(reserve0) * 1e18) / uint256(reserve1);
    }

    // ============ VULN-2: Chainlink without proper validation ============
    function getChainlinkPrice() public view returns (uint256) {
        (, int256 price,,,) = chainlinkFeed.latestRoundData();
        // BUG: No staleness check, no roundId check, no negative check
        return uint256(price);
    }

    // ============ VULN-3: Swap using manipulable price ============
    function swap(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minAmountOut
    ) external returns (uint256 amountOut) {
        require(supportedTokens[tokenIn] && supportedTokens[tokenOut], "Unsupported");

        // BUG: Uses spot price — sandwich attack / flash loan manipulation
        uint256 price = getSpotPrice();
        amountOut = (amountIn * price) / 1e18;

        uint256 fee = (amountOut * swapFee) / 10000;
        amountOut -= fee;

        require(amountOut >= minAmountOut, "Slippage");

        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);

        // BUG: Reentrancy — external call before full state settlement
        IERC20(tokenOut).transfer(msg.sender, amountOut);
        IERC20(tokenOut).transfer(feeCollector, fee);

        emit Swap(msg.sender, tokenIn, tokenOut, amountIn, amountOut);
    }

    // ============ VULN-4: Governance - centralized with no timelock ============
    function setFeeCollector(address newCollector) external {
        require(msg.sender == owner, "Not owner");
        // BUG: No timelock, single admin can redirect all fees instantly
        feeCollector = newCollector;
    }

    function upgradeTo(address newImpl) external {
        require(msg.sender == admin, "Not admin");
        // BUG: No timelock on proxy upgrade
        implementation = newImpl;
    }

    // ============ VULN-5: Missing access control ============
    function addSupportedToken(address token) external {
        // BUG: Anyone can add tokens
        supportedTokens[token] = true;
    }

    function removeSupportedToken(address token) external {
        // BUG: Anyone can remove tokens — griefing
        supportedTokens[token] = false;
    }

    // ============ VULN-6: Gas griefing in batch operations ============
    function batchTransfer(
        address token,
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external {
        // BUG: No length limit — can cause out-of-gas
        // BUG: No length equality check
        for (uint256 i = 0; i < recipients.length; i++) {
            // BUG: Unbounded external calls in loop
            IERC20(token).transfer(recipients[i], amounts[i]);
        }
    }

    // ============ VULN-7: Storage collision in delegatecall ============
    function delegateExecute(address target, bytes calldata data) external returns (bytes memory) {
        require(msg.sender == admin, "Not admin");
        // BUG: delegatecall can overwrite storage slots
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Delegatecall failed");
        return result;
    }

    // ============ Safe function (for contrast) ============
    function addLiquidity(address token, uint256 amount) external {
        require(supportedTokens[token], "Not supported");
        require(amount > 0, "Zero amount");
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        liquidity[msg.sender][token] += amount;
        emit LiquidityAdded(msg.sender, token, amount);
    }
}
