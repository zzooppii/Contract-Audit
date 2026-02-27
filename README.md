# contract-audit

AI-assisted Smart Contract Audit Engine combining static analysis (Slither, Aderyn), dynamic analysis (Foundry fuzzing, hevm symbolic execution), and LLM enrichment (Claude, Gemini) to produce comprehensive security audit reports.

## Features

- **Static Analysis**: Slither (90+ detectors) + Aderyn (Rust, sub-second)
- **Specialized Detectors**: Oracle manipulation, flash loan, proxy, storage collision, gas griefing, governance
- **Dynamic Analysis**: Foundry fuzzing + hevm/Mythril symbolic execution
- **LLM Enrichment**: Claude Opus for PoC generation, Gemini Pro for explanations and remediations
- **Multi-format Reports**: SARIF, JSON, Markdown, HTML
- **GitHub CI Integration**: Automatic SARIF upload + PR comments

## Quick Start

```bash
pip install contract-audit

# Run audit
contract-audit audit ./src --config audit.toml

# Initialize config
contract-audit init

# Login to LLM providers (optional)
contract-audit login --anthropic
contract-audit login --google
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
