"""Configuration loader with TOML + Pydantic validation."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .models import AuditConfig

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore[no-reuse-import]


class TaskRoute(BaseModel):
    """LLM task routing configuration."""

    provider: str = "google"
    model: str = "gemini-3.1-pro"


class ProviderConfig(BaseModel):
    """Configuration for a single LLM provider."""

    auth_method: str = "api_key"  # "oauth" | "api_key"
    api_key_env: str = ""


class LLMConfig(BaseModel):
    """LLM configuration block."""

    enabled: bool = True
    max_budget_usd: float = 10.0
    providers: dict[str, ProviderConfig] = Field(
        default_factory=lambda: {
            "anthropic": ProviderConfig(
                auth_method="api_key", api_key_env="ANTHROPIC_API_KEY"
            ),
            "google": ProviderConfig(
                auth_method="api_key", api_key_env="GOOGLE_AI_API_KEY"
            ),
        }
    )
    task_routing: dict[str, TaskRoute] = Field(
        default_factory=lambda: {
            "triage": TaskRoute(provider="google", model="gemini-3-flash"),
            "explain": TaskRoute(provider="google", model="gemini-3.1-pro"),
            "remediate": TaskRoute(provider="google", model="gemini-3.1-pro"),
            "poc_generate": TaskRoute(provider="anthropic", model="claude-opus-4"),
            "summarize": TaskRoute(provider="google", model="gemini-3.1-pro"),
        }
    )


class FullConfig(BaseModel):
    """Full configuration including all sections."""

    audit: AuditConfig = Field(default_factory=AuditConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)


def _flatten_toml(data: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flatten nested TOML dict to dot-notation keys."""
    result: dict[str, Any] = {}
    for key, value in data.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            result.update(_flatten_toml(value, full_key))
        else:
            result[full_key] = value
    return result


def load_config(config_path: Path | None = None) -> FullConfig:
    """Load and validate configuration from TOML file."""
    default_path = Path(__file__).parent.parent.parent.parent / "config" / "default.toml"

    raw: dict[str, Any] = {}

    # Load defaults first
    if default_path.exists():
        with open(default_path, "rb") as f:
            raw = tomllib.load(f)

    # Override with user config
    if config_path and config_path.exists():
        with open(config_path, "rb") as f:
            user_config = tomllib.load(f)
        # Deep merge
        raw = _deep_merge(raw, user_config)

    return _parse_config(raw)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _parse_config(raw: dict[str, Any]) -> FullConfig:
    """Parse raw TOML dict into typed config."""
    project_section = raw.get("project", {})
    analyzers_section = raw.get("analyzers", {})
    detectors_section = raw.get("detectors", {})
    scoring_section = raw.get("scoring", {})
    llm_section = raw.get("llm", {})
    reporting_section = raw.get("reporting", {})
    ci_section = raw.get("ci", {})

    oracle_cfg = detectors_section.get("oracle", {})
    governance_cfg = detectors_section.get("governance", {})
    severity_scores = scoring_section.get("severity_scores", {})

    audit_cfg = AuditConfig(
        project_name=project_section.get("name", "Unknown Project"),
        solidity_version=project_section.get("solidity_version", "auto"),
        contracts_dir=Path(project_section.get("contracts_dir", "./src")),
        exclude_patterns=project_section.get(
            "exclude_patterns", ["**/test/**", "**/mock/**", "**/script/**"]
        ),
        ast_parser_enabled=analyzers_section.get("ast_parser", True),
        slither_enabled=analyzers_section.get("slither", True),
        aderyn_enabled=analyzers_section.get("aderyn", True),
        foundry_fuzz_enabled=analyzers_section.get("foundry_fuzz", False),
        symbolic_enabled=analyzers_section.get("symbolic", False),
        proxy_detector_enabled=detectors_section.get("proxy", True),
        flash_loan_detector_enabled=detectors_section.get("flash_loan", True),
        oracle_detector_enabled=oracle_cfg.get("enabled", True)
        if oracle_cfg
        else detectors_section.get("oracle", True),
        storage_collision_enabled=detectors_section.get("storage_collision", True),
        gas_griefing_enabled=detectors_section.get("gas_griefing", True),
        governance_detector_enabled=governance_cfg.get("enabled", True)
        if governance_cfg
        else detectors_section.get("governance", True),
        oracle_max_staleness_seconds=oracle_cfg.get("max_staleness_seconds", 3600),
        oracle_interfaces=oracle_cfg.get(
            "oracle_interfaces", ["AggregatorV3Interface", "IUniswapV3Pool"]
        ),
        governance_min_quorum_threshold=governance_cfg.get("min_quorum_threshold", 0.04),
        governance_min_timelock_seconds=governance_cfg.get("min_timelock_seconds", 86400),
        severity_scores=severity_scores
        or {
            "critical": 10.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "informational": 1.0,
            "gas": 0.5,
        },
        llm_enabled=llm_section.get("enabled", True),
        llm_max_budget_usd=llm_section.get("max_budget_usd", 10.0),
        report_formats=reporting_section.get("formats", ["sarif", "json", "markdown"]),
        output_dir=Path(reporting_section.get("output_dir", "./audit-results")),
        ci_fail_on_critical=ci_section.get("fail_on_critical", True),
        ci_fail_on_high=ci_section.get("fail_on_high", False),
        ci_sarif_upload=ci_section.get("sarif_upload", True),
        ci_pr_comment=ci_section.get("pr_comment", True),
    )

    # Parse LLM config
    providers_raw = llm_section.get("providers", {})
    providers = {}
    for name, pcfg in providers_raw.items():
        if isinstance(pcfg, dict):
            providers[name] = ProviderConfig(
                auth_method=pcfg.get("auth_method", "api_key"),
                api_key_env=pcfg.get("api_key_env", ""),
            )

    routing_raw = llm_section.get("task_routing", {})
    task_routing = {}
    for task, rcfg in routing_raw.items():
        if isinstance(rcfg, dict):
            task_routing[task] = TaskRoute(
                provider=rcfg.get("provider", "google"),
                model=rcfg.get("model", "gemini-3.1-pro"),
            )

    llm_cfg = LLMConfig(
        enabled=llm_section.get("enabled", True),
        max_budget_usd=llm_section.get("max_budget_usd", 10.0),
        providers=providers or LLMConfig().providers,
        task_routing=task_routing or LLMConfig().task_routing,
    )

    return FullConfig(audit=audit_cfg, llm=llm_cfg)


def config_hash(config: FullConfig) -> str:
    """Generate a hash of the configuration for audit metadata."""
    content = config.model_dump_json()
    return hashlib.sha256(content.encode()).hexdigest()[:8]
