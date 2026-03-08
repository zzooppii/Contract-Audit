// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function totalSupply() external view returns (uint256);
    function mint(address, uint256) external;
    function burn(address, uint256) external;
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

interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80, int256, uint256, uint256, uint80
    );
}

/// @title AMMPool - AMM liquidity pool with flash loans and multiple vulnerabilities
/// @notice FOR EDUCATIONAL/TESTING PURPOSES ONLY - DO NOT DEPLOY
contract AMMPool {
    IERC20 public token0;
    IERC20 public token1;
    IERC20 public lpToken;
    AggregatorV3Interface public oracle;

    uint256 public reserve0;
    uint256 public reserve1;
    uint256 public totalLiquidity;

    address public feeTo;
    uint256 public swapFee = 30; // 0.3%
    uint256 public flashLoanFee = 9; // 0.09%

    uint256 private unlocked = 1;

    bytes32 public constant CALLBACK_SUCCESS = keccak256("ERC3156FlashBorrower.onFlashLoan");

    event Swap(address indexed sender, uint256 amount0In, uint256 amount1Out);
    event Mint(address indexed sender, uint256 liquidity);
    event Burn(address indexed sender, uint256 amount0, uint256 amount1);
    event FlashLoan(address indexed borrower, address token, uint256 amount);

    constructor(address _token0, address _token1, address _lpToken, address _oracle) {
        token0 = IERC20(_token0);
        token1 = IERC20(_token1);
        lpToken = IERC20(_lpToken);
        oracle = AggregatorV3Interface(_oracle);
        feeTo = msg.sender;
    }

    // ============ VULN-1: Flash loan callback without caller validation ============
    function flashLoan(
        address borrower,
        address token,
        uint256 amount,
        bytes calldata data
    ) external {
        require(token == address(token0) || token == address(token1), "Invalid token");
        uint256 balanceBefore = IERC20(token).balanceOf(address(this));
        require(balanceBefore >= amount, "Insufficient liquidity");

        uint256 fee = (amount * flashLoanFee) / 10000;

        IERC20(token).transfer(borrower, amount);

        // BUG: No validation that msg.sender == borrower or that borrower is trusted
        IFlashBorrower(borrower).onFlashLoan(
            msg.sender, token, amount, fee, data
        );

        uint256 balanceAfter = IERC20(token).balanceOf(address(this));
        require(balanceAfter >= balanceBefore + fee, "Not repaid");

        emit FlashLoan(borrower, token, amount);
    }

    // ============ VULN-2: Price calculation uses spot reserves ============
    function getSpotPrice() public view returns (uint256) {
        // BUG: Spot price — manipulable in same transaction via flash loan
        require(reserve1 > 0, "No liquidity");
        return (reserve0 * 1e18) / reserve1;
    }

    // ============ VULN-3: Oracle without staleness check ============
    function getOraclePrice() public view returns (uint256) {
        (, int256 price,,,) = oracle.latestRoundData();
        // BUG: No staleness check, no round completeness check
        return uint256(price);
    }

    // ============ VULN-4: Swap with no slippage protection by default ============
    function swap(
        uint256 amount0In,
        uint256 amount1Out,
        address to
    ) external {
        require(amount0In > 0, "Zero input");
        require(amount1Out < reserve1, "Insufficient liquidity");

        // BUG: No deadline parameter — transaction can be held and executed later
        // BUG: Uses spot reserves which can be manipulated

        uint256 fee = (amount0In * swapFee) / 10000;
        uint256 amountInAfterFee = amount0In - fee;

        // Check constant product (k)
        uint256 newReserve0 = reserve0 + amountInAfterFee;
        uint256 newReserve1 = reserve1 - amount1Out;
        require(newReserve0 * newReserve1 >= reserve0 * reserve1, "K invariant");

        token0.transferFrom(msg.sender, address(this), amount0In);
        token1.transfer(to, amount1Out);

        reserve0 = token0.balanceOf(address(this));
        reserve1 = token1.balanceOf(address(this));

        emit Swap(msg.sender, amount0In, amount1Out);
    }

    // ============ VULN-5: Reentrancy in removeLiquidity ============
    function removeLiquidity(uint256 liquidity) external {
        require(liquidity > 0, "Zero liquidity");
        require(totalLiquidity > 0, "No liquidity");

        uint256 amount0 = (liquidity * reserve0) / totalLiquidity;
        uint256 amount1 = (liquidity * reserve1) / totalLiquidity;

        // BUG: External calls before state update
        token0.transfer(msg.sender, amount0);
        token1.transfer(msg.sender, amount1);

        // State update after transfers
        totalLiquidity -= liquidity;
        reserve0 -= amount0;
        reserve1 -= amount1;

        emit Burn(msg.sender, amount0, amount1);
    }

    // ============ VULN-6: Missing access control ============
    function setFeeTo(address _feeTo) external {
        // BUG: Anyone can redirect fees
        feeTo = _feeTo;
    }

    function setSwapFee(uint256 _fee) external {
        // BUG: Anyone can change swap fee to 100%
        swapFee = _fee;
    }

    // ============ Safe function ============
    function addLiquidity(uint256 amount0, uint256 amount1) external returns (uint256 liquidity) {
        token0.transferFrom(msg.sender, address(this), amount0);
        token1.transferFrom(msg.sender, address(this), amount1);

        if (totalLiquidity == 0) {
            liquidity = sqrt(amount0 * amount1);
        } else {
            liquidity = min(
                (amount0 * totalLiquidity) / reserve0,
                (amount1 * totalLiquidity) / reserve1
            );
        }

        require(liquidity > 0, "Insufficient liquidity minted");

        totalLiquidity += liquidity;
        reserve0 = token0.balanceOf(address(this));
        reserve1 = token1.balanceOf(address(this));

        emit Mint(msg.sender, liquidity);
    }

    function sqrt(uint256 x) internal pure returns (uint256 y) {
        uint256 z = (x + 1) / 2;
        y = x;
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}
