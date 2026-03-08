// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80, int256, uint256, uint256, uint80
    );
}

/// @title InflatableVault - ERC4626-style vault with share inflation attack
/// @notice FOR EDUCATIONAL/TESTING PURPOSES ONLY - DO NOT DEPLOY
contract InflatableVault {
    IERC20 public asset;
    AggregatorV3Interface public oracle;
    address public owner;

    string public name = "Inflatable Vault Shares";
    string public symbol = "ivShares";
    uint8 public decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public totalAssets;
    uint256 public withdrawalFee = 50; // 0.5%
    address public feeRecipient;

    bool public paused;

    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, uint256 assets, uint256 shares);
    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(address _asset, address _oracle) {
        asset = IERC20(_asset);
        oracle = AggregatorV3Interface(_oracle);
        owner = msg.sender;
        feeRecipient = msg.sender;
    }

    // ============ VULN-1: Share inflation / first depositor attack ============
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        require(!paused, "Paused");
        require(assets > 0, "Zero assets");

        // BUG: First depositor can manipulate share price
        // 1. Deposit 1 wei → get 1 share
        // 2. Donate large amount directly to vault (not via deposit)
        // 3. Now 1 share = huge amount of assets
        // 4. Next depositor's shares round down to 0
        shares = _convertToShares(assets);
        require(shares > 0, "Zero shares");

        asset.transferFrom(msg.sender, address(this), assets);
        totalAssets += assets;

        // BUG: No minimum share amount enforced
        _mint(receiver, shares);

        emit Deposit(msg.sender, receiver, assets, shares);
    }

    // ============ VULN-2: Withdrawal without slippage protection ============
    function withdraw(
        uint256 assets,
        address receiver,
        address shareOwner
    ) external returns (uint256 shares) {
        require(!paused, "Paused");

        shares = _convertToShares(assets);

        // BUG: No slippage/deadline protection — share price can change
        // between submission and execution
        if (msg.sender != shareOwner) {
            uint256 allowed = allowance[shareOwner][msg.sender];
            require(allowed >= shares, "Allowance exceeded");
            allowance[shareOwner][msg.sender] -= shares;
        }

        uint256 fee = (assets * withdrawalFee) / 10000;
        uint256 netAssets = assets - fee;

        _burn(shareOwner, shares);
        totalAssets -= assets;

        // BUG: External calls before full state update
        asset.transfer(receiver, netAssets);
        asset.transfer(feeRecipient, fee);

        emit Withdraw(msg.sender, receiver, netAssets, shares);
    }

    // ============ VULN-3: Oracle without staleness check ============
    function getSharePrice() public view returns (uint256) {
        (, int256 price,,,) = oracle.latestRoundData();
        // BUG: No staleness check, no zero/negative check
        return uint256(price);
    }

    // ============ VULN-4: Share calculation uses spot balance ============
    function _convertToShares(uint256 assets) internal view returns (uint256) {
        if (totalSupply == 0) {
            return assets; // BUG: 1:1 ratio for first deposit enables inflation attack
        }
        // BUG: Uses totalAssets which can be manipulated by direct transfer
        return (assets * totalSupply) / totalAssets;
    }

    function _convertToAssets(uint256 shares) internal view returns (uint256) {
        if (totalSupply == 0) return 0;
        return (shares * totalAssets) / totalSupply;
    }

    // ============ VULN-5: Missing access control ============
    function setWithdrawalFee(uint256 newFee) external {
        // BUG: Anyone can set fee — no upper bound
        withdrawalFee = newFee;
    }

    function setFeeRecipient(address newRecipient) external {
        // BUG: Anyone can redirect fees
        feeRecipient = newRecipient;
    }

    function setPaused(bool _paused) external {
        // BUG: Anyone can pause/unpause
        paused = _paused;
    }

    // ============ VULN-6: Reentrancy in redeem ============
    function redeem(
        uint256 shares,
        address receiver,
        address shareOwner
    ) external returns (uint256 assets) {
        require(!paused, "Paused");

        assets = _convertToAssets(shares);
        require(assets > 0, "Zero assets");

        if (msg.sender != shareOwner) {
            uint256 allowed = allowance[shareOwner][msg.sender];
            require(allowed >= shares, "Allowance exceeded");
            allowance[shareOwner][msg.sender] -= shares;
        }

        // BUG: External call before state update
        asset.transfer(receiver, assets);

        // State update after external call
        _burn(shareOwner, shares);
        totalAssets -= assets;

        emit Withdraw(msg.sender, receiver, assets, shares);
    }

    // ============ Safe functions ============
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function previewDeposit(uint256 assets) external view returns (uint256) {
        return _convertToShares(assets);
    }

    function previewRedeem(uint256 shares) external view returns (uint256) {
        return _convertToAssets(shares);
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function _burn(address from, uint256 amount) internal {
        require(balanceOf[from] >= amount, "Burn exceeds balance");
        balanceOf[from] -= amount;
        totalSupply -= amount;
        emit Transfer(from, address(0), amount);
    }
}
