"""Unit tests for configuration loading."""

import pytest
import tempfile
from pathlib import Path

from contract_audit.core.config import load_config, FullConfig


class TestLoadConfig:
    def test_load_default_config(self):
        """Should load without error even without a config file."""
        config = load_config(config_path=None)
        assert isinstance(config, FullConfig)
        assert config.audit is not None
        assert config.llm is not None

    def test_load_custom_config(self, tmp_path):
        """Should merge custom config over defaults."""
        config_file = tmp_path / "test.toml"
        config_file.write_text("""
[project]
name = "Test Protocol"

[llm]
max_budget_usd = 5.0
""")
        config = load_config(config_path=config_file)
        assert config.audit.project_name == "Test Protocol"
        assert config.llm.max_budget_usd == 5.0

    def test_defaults_applied_when_missing(self, tmp_path):
        """Missing config values should use defaults."""
        config_file = tmp_path / "minimal.toml"
        config_file.write_text("[project]\nname = 'Minimal'\n")
        config = load_config(config_path=config_file)
        assert config.audit.slither_enabled is True  # Default
        assert config.audit.oracle_detector_enabled is True  # Default

    def test_llm_task_routing_defaults(self):
        config = load_config()
        routing = config.llm.task_routing
        assert "triage" in routing
        assert "explain" in routing
        assert "poc_generate" in routing
        assert routing["poc_generate"].provider == "anthropic"
