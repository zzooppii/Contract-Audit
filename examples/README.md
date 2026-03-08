# Example Contracts for Testing

These contracts contain **intentional vulnerabilities** for testing the audit engine.
**DO NOT deploy these contracts.**

## Quick Test

```bash
# Audit the DeFi vault example
contract-audit audit ./examples/defi-vault --no-llm -v

# Audit the DEX example
contract-audit audit ./examples/vulnerable-dex --no-llm -v

# Audit all examples at once
contract-audit audit ./examples --no-llm --formats sarif,json,markdown

# With LLM enrichment (requires API keys)
contract-audit audit ./examples/defi-vault --formats markdown,html
```

## What Each Example Contains

### `defi-vault/LendingVault.sol`
| # | Vulnerability | Severity |
|---|--------------|----------|
| 1 | Reentrancy in withdraw (state update after transfer) | Critical |
| 2 | Oracle without staleness check | High |
| 3 | Flash loan callback without caller validation | High |
| 4 | Liquidation using manipulable price | High |
| 5 | Missing access control (setOracle, setPaused) | Critical |

### `vulnerable-dex/VulnerableDEX.sol`
| # | Vulnerability | Severity |
|---|--------------|----------|
| 1 | Uniswap spot price manipulation | High |
| 2 | Chainlink without staleness/round checks | High |
| 3 | Swap using manipulable price (sandwich attack) | High |
| 4 | Centralized governance without timelock | Medium |
| 5 | Missing access control on token management | High |
| 6 | Gas griefing in unbounded batch loop | Medium |
| 7 | Storage collision via delegatecall | High |
