// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function totalSupply() external view returns (uint256);
}

interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80, int256, uint256, uint256, uint80
    );
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

/// @title YieldFarm - Staking/yield farm with multiple vulnerabilities
/// @notice FOR EDUCATIONAL/TESTING PURPOSES ONLY - DO NOT DEPLOY
contract YieldFarm {
    struct UserInfo {
        uint256 amount;
        uint256 rewardDebt;
        uint256 lastDepositTime;
    }

    struct PoolInfo {
        IERC20 lpToken;
        uint256 allocPoint;
        uint256 lastRewardBlock;
        uint256 accRewardPerShare;
    }

    IERC20 public rewardToken;
    AggregatorV3Interface public priceOracle;
    IUniswapV2Pair public lpPriceSource;
    address public owner;

    uint256 public rewardPerBlock = 1e18;
    uint256 public totalAllocPoint;

    PoolInfo[] public poolInfo;
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;

    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount);

    constructor(address _rewardToken, address _oracle, address _lpPriceSource) {
        rewardToken = IERC20(_rewardToken);
        priceOracle = AggregatorV3Interface(_oracle);
        lpPriceSource = IUniswapV2Pair(_lpPriceSource);
        owner = msg.sender;
    }

    // ============ VULN-1: Oracle without staleness check ============
    function getRewardTokenPrice() public view returns (uint256) {
        (, int256 price,,,) = priceOracle.latestRoundData();
        // BUG: No staleness check, no negative/zero check
        return uint256(price);
    }

    // ============ VULN-2: Spot price for LP valuation ============
    function getLPTokenPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = lpPriceSource.getReserves();
        // BUG: Spot price — can be manipulated with flash loan
        return (uint256(reserve0) * 1e18) / uint256(reserve1);
    }

    // ============ VULN-3: Reentrancy in withdraw ============
    function withdraw(uint256 pid, uint256 amount) external {
        UserInfo storage user = userInfo[pid][msg.sender];
        require(user.amount >= amount, "Insufficient");

        updatePool(pid);

        uint256 pending = (user.amount * poolInfo[pid].accRewardPerShare / 1e12) - user.rewardDebt;

        // BUG: External call before state update
        if (pending > 0) {
            rewardToken.transfer(msg.sender, pending);
        }

        if (amount > 0) {
            poolInfo[pid].lpToken.transfer(msg.sender, amount);
        }

        // State update after external calls
        user.amount -= amount;
        user.rewardDebt = user.amount * poolInfo[pid].accRewardPerShare / 1e12;

        emit Withdraw(msg.sender, pid, amount);
    }

    // ============ VULN-4: Reward calculation with manipulable price ============
    function harvestWithBonus(uint256 pid) external {
        updatePool(pid);
        UserInfo storage user = userInfo[pid][msg.sender];

        uint256 pending = (user.amount * poolInfo[pid].accRewardPerShare / 1e12) - user.rewardDebt;

        // BUG: Bonus multiplier based on manipulable spot price
        uint256 lpPrice = getLPTokenPrice();
        uint256 bonus = 0;
        if (lpPrice > 1e18) {
            bonus = (pending * (lpPrice - 1e18)) / 1e18;
        }

        user.rewardDebt = user.amount * poolInfo[pid].accRewardPerShare / 1e12;
        rewardToken.transfer(msg.sender, pending + bonus);
    }

    // ============ VULN-5: Missing access control on critical functions ============
    function setRewardPerBlock(uint256 _rewardPerBlock) external {
        // BUG: Anyone can set reward rate
        rewardPerBlock = _rewardPerBlock;
    }

    function addPool(uint256 allocPoint, address lpToken) external {
        // BUG: Anyone can add pools
        totalAllocPoint += allocPoint;
        poolInfo.push(PoolInfo({
            lpToken: IERC20(lpToken),
            allocPoint: allocPoint,
            lastRewardBlock: block.number,
            accRewardPerShare: 0
        }));
    }

    // ============ VULN-6: Unbounded loop in mass update ============
    function massUpdatePools() public {
        uint256 length = poolInfo.length;
        // BUG: If many pools are added (by anyone via addPool), this runs out of gas
        for (uint256 pid = 0; pid < length; ++pid) {
            updatePool(pid);
        }
    }

    // ============ Safe functions ============
    function deposit(uint256 pid, uint256 amount) external {
        UserInfo storage user = userInfo[pid][msg.sender];
        updatePool(pid);

        if (user.amount > 0) {
            uint256 pending = (user.amount * poolInfo[pid].accRewardPerShare / 1e12) - user.rewardDebt;
            if (pending > 0) {
                rewardToken.transfer(msg.sender, pending);
            }
        }

        poolInfo[pid].lpToken.transferFrom(msg.sender, address(this), amount);
        user.amount += amount;
        user.rewardDebt = user.amount * poolInfo[pid].accRewardPerShare / 1e12;
        user.lastDepositTime = block.timestamp;
        emit Deposit(msg.sender, pid, amount);
    }

    function updatePool(uint256 pid) public {
        PoolInfo storage pool = poolInfo[pid];
        if (block.number <= pool.lastRewardBlock) return;

        uint256 lpSupply = pool.lpToken.balanceOf(address(this));
        if (lpSupply == 0) {
            pool.lastRewardBlock = block.number;
            return;
        }

        uint256 blocks = block.number - pool.lastRewardBlock;
        uint256 reward = blocks * rewardPerBlock * pool.allocPoint / totalAllocPoint;
        pool.accRewardPerShare += reward * 1e12 / lpSupply;
        pool.lastRewardBlock = block.number;
    }
}
