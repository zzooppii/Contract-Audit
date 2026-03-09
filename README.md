# contract-audit

AI-assisted Smart Contract Audit Engine combining static analysis, dynamic analysis, and LLM enrichment to produce comprehensive security audit reports.

[![CI](https://github.com/zzooppii/Contract-Audit/actions/workflows/self-test.yml/badge.svg)](https://github.com/zzooppii/Contract-Audit/actions/workflows/self-test.yml)

## Features

- **22 Specialized Detectors**: Reentrancy, access control, oracle manipulation, flash loan, ERC-20/ERC-4626, proxy, storage collision, gas griefing, governance, front-running, initialization, integer overflow, signature replay, randomness, merkle tree, timelock, bridge, NFT, cross-contract, pragma, unchecked calls
- **Static Analysis**: Slither (90+ detectors) + Aderyn (Rust, sub-second) + Custom AST parser
- **Cross-Contract Analysis**: Import resolution, inheritance graph, call graph with cycle detection
- **Dynamic Analysis**: Foundry fuzz testing (category-targeted harness generation) + invariant generation + symbolic execution (Mythril/hevm)
- **LLM Enrichment**: Claude for PoC generation, Gemini for explanations and remediations, LLM-based audit for business logic vulnerabilities
- **False Positive Reduction**: Configurable scoring engine + LLM triage
- **Multi-format Reports**: SARIF, JSON, Markdown, HTML, PDF + audit comparison (diff between runs)
- **GitHub CI Integration**: Automatic SARIF upload, PR comments, diff-only filtering
- **CLI + API**: Typer CLI with `audit`, `init`, `login`, `logout`, `version` commands + FastAPI REST API

## Quick Start

```bash
pip install contract-audit

# Run audit
contract-audit audit ./src --config audit.toml

# Run without LLM (static analysis only)
contract-audit audit ./src --no-llm -v

# Compare with previous audit
contract-audit audit ./src --compare-to previous-report.json

# Initialize config
contract-audit init

# Login to LLM providers (optional)
contract-audit login --anthropic
contract-audit login --google
```

## Architecture

```
Pipeline Phases:
  1. Source Loading     → Load .sol files
  2. Static Analysis    → Slither + Aderyn + AST parser + Cross-contract analysis
  3. Detection          → 22 specialized detectors
  3.5 LLM Audit        → Business logic vulnerability detection via LLM
  4. Dynamic Analysis   → Foundry fuzz + invariant tests + symbolic execution
  5. Scoring            → Risk scoring with configurable weights
  5.5 FP Reduction      → Heuristic + LLM triage false positive filtering
  6. LLM Enrichment     → Explanations, remediations, PoC generation
  7. Reporting          → SARIF, JSON, Markdown, HTML, PDF
```

## Configuration

```toml
# audit.toml
[project]
name = "My Protocol"

[llm]
enabled = true
max_budget_usd = 10.0

[llm.providers.anthropic]
api_key_env = "ANTHROPIC_API_KEY"

[llm.providers.google]
api_key_env = "GOOGLE_AI_API_KEY"

[analysis]
slither_enabled = true
aderyn_enabled = true
foundry_fuzz_enabled = true
symbolic_enabled = false
```

## CI Integration

```yaml
# .github/workflows/audit.yml
- name: Run Audit
  run: |
    contract-audit audit ./src --ci-mode --output-sarif audit.sarif
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: audit.sarif
```

## Development

```bash
# Install in dev mode
python3.11 -m pip install -e ".[dev]"

# Run tests (428 tests)
python3.11 -m pytest tests/ -v

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

## Test Suite

| Category | Tests | Description |
|----------|-------|-------------|
| Unit | ~300 | Detector logic, utils, scoring, config |
| Edge Cases | 264 | 22 detectors x 12 edge case inputs |
| Integration | ~20 | LLM pipeline with mock router, detector integration |
| E2E | ~25 | Full pipeline against 23 example contracts |

## License

MIT
