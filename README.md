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

# Run audit with config file
contract-audit audit ./src --config audit.toml

# Run without LLM (static analysis only), verbose output
contract-audit audit ./src --no-llm -v

# Generate reports in multiple formats (sarif, json, markdown, html, pdf)
contract-audit audit ./src --no-llm --formats sarif,json,markdown

# Compare with previous audit
contract-audit audit ./src --compare-to previous-report.json

# Initialize config
contract-audit init

# Login to LLM providers (optional)
contract-audit login --anthropic
contract-audit login --google
```

### CLI Options

| Option | Description |
|--------|-------------|
| `--config`, `-c` | Path to audit config file (TOML) |
| `--no-llm` | Skip LLM analysis (static analysis only) |
| `--verbose`, `-v` | Enable verbose logging (DEBUG level) |
| `--formats`, `-f` | Comma-separated report formats: `sarif`, `json`, `markdown`, `html`, `pdf` |
| `--output-dir` | Output directory for generated reports |
| `--output-sarif` | Output path for SARIF report |
| `--output-json` | Output path for JSON report |
| `--output-markdown` | Output path for Markdown report |
| `--compare-to` | Path to previous report for diff comparison |
| `--severity-filter` | Comma-separated severity filter (e.g. `high,critical`) |
| `--ci-mode` | CI mode: exit non-zero on findings |

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
auth_method = "oauth"                    # "oauth" (recommended) or "api_key"
api_key_env = "ANTHROPIC_API_KEY"        # Fallback for CI environments

[llm.providers.google]
auth_method = "oauth"                    # "oauth" (recommended) or "api_key"
api_key_env = "GOOGLE_AI_API_KEY"        # Fallback for CI environments

[analysis]
slither_enabled = true
aderyn_enabled = true
foundry_fuzz_enabled = true
symbolic_enabled = false
```

### Authentication

```bash
# OAuth login (recommended) - tokens stored securely via keyring
contract-audit login --anthropic
contract-audit login --google

# Or use API keys via environment variables (for CI)
export ANTHROPIC_API_KEY="sk-ant-..."
export GOOGLE_AI_API_KEY="AI..."
```

## MCP Integration

Use contract-audit as an MCP tool server in Claude Code or any MCP-compatible client.

### Setup

Add to your Claude Code MCP config (`~/.claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "contract-audit": {
      "command": "python3.11",
      "args": ["-m", "contract_audit.mcp"]
    }
  }
}
```

### Available Tools

| Tool | Parameters | Description |
|------|-----------|-------------|
| `audit_contract` | `project_path` | Full project audit (22 detectors + AST parser + Slither + Aderyn) |
| `audit_source` | `source_code`, `filename?` | Inline source code audit (Slither/Aderyn disabled) |
| `list_detectors` | — | List all 22 detectors with descriptions |

### Usage

Once configured, Claude Code can directly use these tools:

```
> Audit the contracts in /path/to/my-project
  → calls audit_contract with project_path="/path/to/my-project"

> Check this Solidity code for vulnerabilities: <paste code>
  → calls audit_source with the pasted source code
```

### Authentication (for LLM features)

The MCP server runs with LLM disabled by default. For the CLI with LLM enrichment:

```bash
# Anthropic — use API key
export ANTHROPIC_API_KEY="sk-ant-..."

# Google — use API key or OAuth
export GOOGLE_AI_API_KEY="AI..."
contract-audit login --google
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

# 1. Create audit.toml in the audit target folder
cd ~/my-defi-project
contract-audit init          # audit.toml created
contract-audit audit ./src   # Automatically use audit.toml in the same folder

# 2. Or specify absolute path
contract-audit audit ~/my-defi-project/src --config ~/configs/audit.toml
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
