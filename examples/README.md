# Example Contracts for Testing

These contracts contain **intentional vulnerabilities** for testing the audit engine.
**DO NOT deploy these contracts.**

## Quick Test

```bash
# Audit a single example
contract-audit audit ./examples/defi-vault --no-llm -v

# Audit all examples at once
contract-audit audit ./examples --no-llm --formats sarif,json,markdown

# With LLM enrichment (requires API keys)
contract-audit audit ./examples/defi-vault --formats markdown,html
```

### Via MCP (Claude Code)

With the MCP server configured, ask Claude Code directly:

```
> Audit the contracts in ./examples/defi-vault
> Check this Solidity code for issues: <paste from any example>
> List available security detectors
```

## Example Contracts (24 total)

### Multi-Contract Examples

| # | Directory | Contracts | Target Detectors | Key Vulnerabilities |
|---|-----------|-----------|-----------------|---------------------|
| 24 | `defi-protocol` | IProtocol.sol, Token.sol, Oracle.sol, Pool.sol, Router.sol, Governance.sol | Cross-Contract, Oracle, Reentrancy, Flash Loan, Governance, Front-run, Access Control, Unchecked Call | Cross-contract reentrancy (Pool↔Token), oracle manipulation via single EOA, flash loan governance attack, no timelock, approve race condition, flash swap callback reentrancy, liquidation overflow |

### Single-Contract Examples

| # | Directory | Contract | Target Detectors | Key Vulnerabilities |
|---|-----------|----------|-----------------|---------------------|
| 1 | `amm-pool` | AMMPool.sol | Oracle, Reentrancy | Spot price manipulation, CEI violation |
| 2 | `cross-chain-bridge` | CrossChainBridge.sol | Bridge | Missing message validation, replay attacks |
| 3 | `dao-treasury` | DAOTreasury.sol | Governance | Centralized control, missing timelock |
| 4 | `defi-vault` | LendingVault.sol | Oracle | Stale price feed, manipulable liquidation |
| 5 | `erc4626-vault` | InflatableVault.sol | ERC-4626 | Inflation attack, rounding direction |
| 6 | `flash-loan-attack` | FlashLoanVault.sol | Flash Loan | Unvalidated callback, price manipulation |
| 7 | `gas-auction` | GasAuction.sol | Gas Griefing | Unbounded loops, DoS via gas |
| 8 | `integer-math` | IntegerMath.sol | Integer | Overflow/underflow, division by zero |
| 9 | `lending-pool` | LendingPool.sol | Oracle | Stale oracle, manipulable collateral |
| 10 | `lottery-rng` | Lottery.sol | Randomness | Block-based RNG, predictable outcomes |
| 11 | `merkle-airdrop` | MerkleAirdrop.sol | Merkle | Leaf preimage attack, missing checks |
| 12 | `multisig-wallet` | MultisigWallet.sol | Reentrancy | Re-entrancy in execution |
| 13 | `nft-auction` | NFTAuction.sol | NFT | Bid manipulation, pull-over-push |
| 14 | `nft-marketplace` | NFTMarketplace.sol | Reentrancy | CEI violation in purchase flow |
| 15 | `reentrancy-vault` | ReentrancyVault.sol | Reentrancy | Classic reentrancy, state after call |
| 16 | `staking-rewards` | StakingRewards.sol | Oracle | Reward calculation manipulation |
| 17 | `timelock-vault` | TimelockVault.sol | Timelock | Bypass, insufficient delay |
| 18 | `token-bridge` | TokenBridge.sol | Bridge | Missing validation, replay |
| 19 | `unsafe-vault` | UnsafeVault.sol | Unchecked Call | Unchecked low-level calls |
| 20 | `upgradeable-proxy` | UpgradeableVault.sol | Proxy | Storage collision, unprotected upgrade |
| 21 | `vulnerable-dex` | VulnerableDEX.sol | Oracle, Front-run | Spot price oracle, sandwich attack |
| 22 | `vulnerable-token` | VulnerableToken.sol | ERC-20 | Approval race, missing return |
| 23 | `yield-farm` | YieldFarm.sol | Oracle | Reward manipulation via price feed |

## Detector Coverage

All 22 detectors are exercised by at least one example contract:

- **Reentrancy**: amm-pool, multisig-wallet, nft-marketplace, reentrancy-vault
- **Access Control**: dao-treasury, defi-vault
- **Oracle Manipulation**: amm-pool, defi-vault, lending-pool, staking-rewards, vulnerable-dex, yield-farm
- **Flash Loan**: flash-loan-attack
- **ERC-20**: vulnerable-token
- **ERC-4626**: erc4626-vault
- **Proxy/Storage Collision**: upgradeable-proxy
- **Gas Griefing**: gas-auction
- **Governance**: dao-treasury
- **Front-running**: vulnerable-dex
- **Initialization**: (tested via edge cases)
- **Integer Overflow**: integer-math
- **Signature Replay**: (tested via edge cases)
- **Randomness**: lottery-rng
- **Merkle Tree**: merkle-airdrop
- **Timelock**: timelock-vault
- **Bridge**: cross-chain-bridge, token-bridge
- **NFT**: nft-auction
- **Unchecked Call**: unsafe-vault
- **Cross-Contract**: defi-protocol
- **Pragma**: (tested via edge cases)
