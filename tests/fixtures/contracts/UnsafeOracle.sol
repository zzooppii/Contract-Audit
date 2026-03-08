// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IChainlinkOracle {
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
}

interface IUniswapV2Pair {
    function getReserves()
        external
        view
        returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

/// @title UnsafeOracle
/// @notice Contract with oracle manipulation vulnerabilities
/// @dev DO NOT USE IN PRODUCTION
contract UnsafeOracle {
    IChainlinkOracle public oracle;
    IUniswapV2Pair public uniPair;

    constructor(address _oracle, address _pair) {
        oracle = IChainlinkOracle(_oracle);
        uniPair = IUniswapV2Pair(_pair);
    }

    // VULN-1: No staleness check on Chainlink oracle
    function getChainlinkPrice() external view returns (int256) {
        (, int256 price,,,) = oracle.latestRoundData();
        return price;
    }

    // VULN-2: Spot price from Uniswap V2 (flash loan manipulable)
    function getUniswapPrice() external view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = uniPair.getReserves();
        return uint256(reserve0) * 1e18 / uint256(reserve1);
    }

    // VULN-3: No round completeness check
    function getLatestPrice() external view returns (int256 price) {
        (, price,,,) = oracle.latestRoundData();
        // Missing: require(answeredInRound >= roundId, "Stale price")
        // Missing: require(block.timestamp - updatedAt <= MAX_STALENESS, "Stale")
    }

    // This function is correctly implemented (for contrast)
    function getSafePrice() external view returns (int256) {
        (
            uint80 roundId,
            int256 price,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = oracle.latestRoundData();
        require(answeredInRound >= roundId, "Stale price: incomplete round");
        require(block.timestamp - updatedAt <= 3600, "Stale price: too old");
        require(price > 0, "Invalid price");
        return price;
    }
}
