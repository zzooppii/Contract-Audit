// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract VulnerableVault4626 is ERC20 {
    IERC20 public asset;
    uint256 public totalShares;

    constructor(address _asset) ERC20("Vault", "vTKN") {
        asset = IERC20(_asset);
    }

    // No inflation attack protection (no virtual offset, no dead shares)
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = convertToShares(assets);
        asset.transferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);
    }

    function withdraw(uint256 assets, address receiver, address owner_) external returns (uint256 shares) {
        shares = convertToShares(assets);
        _burn(owner_, shares);
        asset.transfer(receiver, assets);
    }

    function redeem(uint256 shares, address receiver, address owner_) external returns (uint256 assets) {
        assets = convertToAssets(shares);
        _burn(owner_, shares);
        asset.transfer(receiver, assets);
    }

    function mint(uint256 shares, address receiver) external returns (uint256 assets) {
        assets = convertToAssets(shares);
        asset.transferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);
    }

    // Uses balanceOf(address(this)) - direct balance manipulation
    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    // Division without explicit rounding direction
    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply();
        return supply == 0 ? assets : assets * supply / totalAssets();
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 supply = totalSupply();
        return supply == 0 ? shares : shares * totalAssets() / supply;
    }

    function previewDeposit(uint256 assets) public view returns (uint256) {
        return assets * totalSupply() / totalAssets();
    }

    function previewRedeem(uint256 shares) public view returns (uint256) {
        return shares * totalAssets() / totalSupply();
    }
}
