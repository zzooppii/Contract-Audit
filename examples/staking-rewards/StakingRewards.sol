// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80, int256, uint256, uint256, uint80
    );
}

/// @title StakingRewards - Staking contract with multiple vulnerabilities
/// @notice FOR EDUCATIONAL/TESTING PURPOSES ONLY - DO NOT DEPLOY
contract StakingRewards {
    struct StakeInfo {
        uint256 amount;
        uint256 rewardDebt;
        uint256 lockUntil;
        uint256 lastClaimTime;
    }

    IERC20 public stakingToken;
    IERC20 public rewardToken;
    AggregatorV3Interface public rewardOracle;
    address public owner;

    uint256 public totalStaked;
    uint256 public rewardRate = 100; // rewards per second
    uint256 public accRewardPerShare;
    uint256 public lastUpdateTime;
    uint256 public lockDuration = 7 days;
    uint256 public earlyWithdrawPenalty = 5000; // 50%

    mapping(address => StakeInfo) public stakes;
    mapping(address => bool) public operators;

    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 reward);

    constructor(address _stakingToken, address _rewardToken, address _oracle) {
        stakingToken = IERC20(_stakingToken);
        rewardToken = IERC20(_rewardToken);
        rewardOracle = AggregatorV3Interface(_oracle);
        owner = msg.sender;
        lastUpdateTime = block.timestamp;
    }

    // ============ VULN-1: Reentrancy in claimReward ============
    function claimReward() external {
        _updatePool();
        StakeInfo storage stake = stakes[msg.sender];
        require(stake.amount > 0, "No stake");

        uint256 pending = (stake.amount * accRewardPerShare / 1e12) - stake.rewardDebt;
        require(pending > 0, "No reward");

        // BUG: External call before state update
        rewardToken.transfer(msg.sender, pending);

        // State update after external call
        stake.rewardDebt = stake.amount * accRewardPerShare / 1e12;
        stake.lastClaimTime = block.timestamp;

        emit RewardClaimed(msg.sender, pending);
    }

    // ============ VULN-2: Oracle without staleness check ============
    function getRewardValue(uint256 rewardAmount) public view returns (uint256) {
        (, int256 price,,,) = rewardOracle.latestRoundData();
        // BUG: No staleness check, no negative/zero check
        return rewardAmount * uint256(price) / 1e8;
    }

    // ============ VULN-3: Timestamp manipulation for lock bypass ============
    function withdraw(uint256 amount) external {
        StakeInfo storage stake = stakes[msg.sender];
        require(stake.amount >= amount, "Insufficient stake");

        _updatePool();
        uint256 pending = (stake.amount * accRewardPerShare / 1e12) - stake.rewardDebt;

        uint256 withdrawAmount = amount;

        // BUG: Uses block.timestamp which miners can manipulate slightly
        // BUG: Penalty calculation has rounding issue
        if (block.timestamp < stake.lockUntil) {
            uint256 penalty = (amount * earlyWithdrawPenalty) / 10000;
            withdrawAmount = amount - penalty;
            // BUG: Penalty tokens are locked in contract forever — not redistributed
        }

        // BUG: External calls before state update
        if (pending > 0) {
            rewardToken.transfer(msg.sender, pending);
        }
        stakingToken.transfer(msg.sender, withdrawAmount);

        // State update after transfers
        stake.amount -= amount;
        stake.rewardDebt = stake.amount * accRewardPerShare / 1e12;
        totalStaked -= amount;

        emit Withdrawn(msg.sender, withdrawAmount);
    }

    // ============ VULN-4: Missing access control ============
    function setRewardRate(uint256 newRate) external {
        // BUG: Anyone can set reward rate — drain all rewards instantly
        rewardRate = newRate;
    }

    function setLockDuration(uint256 newDuration) external {
        // BUG: Anyone can set lock duration to 0 or max uint256
        lockDuration = newDuration;
    }

    function setEarlyWithdrawPenalty(uint256 newPenalty) external {
        // BUG: Anyone can set penalty — no upper bound check
        earlyWithdrawPenalty = newPenalty;
    }

    function addOperator(address operator) external {
        // BUG: Anyone can add operators
        operators[operator] = true;
    }

    // ============ VULN-5: Reward calculation with division before multiplication ============
    function _updatePool() internal {
        if (totalStaked == 0) {
            lastUpdateTime = block.timestamp;
            return;
        }

        uint256 elapsed = block.timestamp - lastUpdateTime;
        // BUG: Division before multiplication — precision loss
        uint256 reward = elapsed * rewardRate / totalStaked * 1e12;
        accRewardPerShare += reward;
        lastUpdateTime = block.timestamp;
    }

    // ============ VULN-6: Emergency withdraw bypasses lock ============
    function emergencyWithdraw() external {
        StakeInfo storage stake = stakes[msg.sender];
        uint256 amount = stake.amount;
        require(amount > 0, "No stake");

        // BUG: Bypasses lock entirely — intended as "lose all rewards" but
        // still returns full principal. Should apply penalty.
        stakingToken.transfer(msg.sender, amount);

        // Reset
        stake.amount = 0;
        stake.rewardDebt = 0;
        stake.lockUntil = 0;
        totalStaked -= amount;

        emit Withdrawn(msg.sender, amount);
    }

    // ============ Safe function ============
    function stake(uint256 amount) external {
        require(amount > 0, "Zero amount");
        _updatePool();

        StakeInfo storage userStake = stakes[msg.sender];

        if (userStake.amount > 0) {
            uint256 pending = (userStake.amount * accRewardPerShare / 1e12) - userStake.rewardDebt;
            if (pending > 0) {
                rewardToken.transfer(msg.sender, pending);
            }
        }

        stakingToken.transferFrom(msg.sender, address(this), amount);
        userStake.amount += amount;
        userStake.rewardDebt = userStake.amount * accRewardPerShare / 1e12;
        userStake.lockUntil = block.timestamp + lockDuration;
        userStake.lastClaimTime = block.timestamp;
        totalStaked += amount;

        emit Staked(msg.sender, amount);
    }
}
