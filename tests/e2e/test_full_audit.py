"""End-to-end tests: full pipeline against fixture contracts."""

import pytest
from pathlib import Path

from contract_audit.core.config import load_config
from contract_audit.core.models import AuditContext, AuditConfig, FindingCategory, Severity
from contract_audit.core.pipeline import PipelineOrchestrator
from contract_audit.analyzers.ast_parser.analyzer import ASTAnalyzer
from contract_audit.detectors.oracle_detector import OracleDetector
from contract_audit.detectors.flash_loan_detector import FlashLoanDetector
from contract_audit.detectors.governance_detector import GovernanceDetector
from contract_audit.detectors.gas_griefing import GasGriefingDetector
from contract_audit.scoring.engine import RiskScoringEngine
from contract_audit.scoring.false_positive import FalsePositiveReducer

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "contracts"


@pytest.fixture
def audit_config():
    """Minimal audit config for e2e tests (no LLM, no external tools)."""
    config = AuditConfig()
    config.llm_enabled = False
    config.slither_enabled = False  # Skip Slither in e2e (requires installation)
    config.aderyn_enabled = False   # Skip Aderyn in e2e
    config.foundry_fuzz_enabled = False
    config.symbolic_enabled = False
    return config


@pytest.fixture
def pipeline(audit_config):
    """Build a minimal pipeline for testing."""
    analyzers = [ASTAnalyzer()]
    detectors = [
        OracleDetector(),
        FlashLoanDetector(),
        GovernanceDetector(),
        GasGriefingDetector(),
    ]
    scoring_engine = RiskScoringEngine()
    fp_reducer = FalsePositiveReducer()

    return PipelineOrchestrator(
        analyzers=analyzers,
        detectors=detectors,
        scoring_engine=scoring_engine,
        fp_reducer=fp_reducer,
    )


@pytest.mark.asyncio
async def test_full_audit_finds_vulnerabilities(pipeline, audit_config, tmp_path):
    """Full pipeline should find known vulnerabilities in fixture contracts."""
    # Copy fixtures to temp dir
    import shutil
    for sol_file in FIXTURES_DIR.glob("*.sol"):
        shutil.copy(sol_file, tmp_path / sol_file.name)

    context = AuditContext(
        project_path=tmp_path,
        config=audit_config,
    )

    result = await pipeline.run(context)

    # Should find findings
    assert result.summary.total_findings > 0
    assert result.summary.overall_risk_score > 0

    # Should find oracle issues
    oracle_findings = [
        f for f in result.active_findings
        if f.category == FindingCategory.ORACLE_MANIPULATION
    ]
    assert len(oracle_findings) > 0, "Expected oracle findings in UnsafeOracle.sol"

    # Should find flash loan issues
    flash_findings = [
        f for f in result.active_findings
        if f.category == FindingCategory.FLASH_LOAN
    ]
    assert len(flash_findings) > 0, "Expected flash loan findings in FlashLoanTarget.sol"


@pytest.mark.asyncio
async def test_report_generation(pipeline, audit_config, tmp_path):
    """Reports should be generated successfully."""
    import shutil
    for sol_file in FIXTURES_DIR.glob("*.sol"):
        shutil.copy(sol_file, tmp_path / sol_file.name)

    audit_config.output_dir = tmp_path / "reports"
    audit_config.report_formats = ["json", "markdown"]

    context = AuditContext(project_path=tmp_path, config=audit_config)
    result = await pipeline.run(context)

    from contract_audit.reporting.generator import ReportGenerator
    generator = ReportGenerator(audit_config)
    output_paths = generator.generate_all(result)

    assert "json" in output_paths
    assert output_paths["json"].exists()
    assert output_paths["json"].stat().st_size > 0

    assert "markdown" in output_paths
    assert output_paths["markdown"].exists()
    assert "# Smart Contract Security Audit Report" in output_paths["markdown"].read_text()


@pytest.mark.asyncio
async def test_sarif_format_valid(pipeline, audit_config, tmp_path):
    """SARIF output should be valid JSON with correct schema."""
    import shutil, json
    shutil.copy(FIXTURES_DIR / "UnsafeOracle.sol", tmp_path / "UnsafeOracle.sol")

    context = AuditContext(project_path=tmp_path, config=audit_config)
    result = await pipeline.run(context)

    from contract_audit.reporting.formats.sarif import generate_sarif
    sarif = generate_sarif(result)

    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert "tool" in run
    assert "results" in run


@pytest.mark.asyncio
async def test_deduplication_works(pipeline, audit_config, tmp_path):
    """Same finding from multiple tools should be deduplicated."""
    import shutil
    shutil.copy(FIXTURES_DIR / "UnsafeOracle.sol", tmp_path / "UnsafeOracle.sol")

    context = AuditContext(project_path=tmp_path, config=audit_config)
    result = await pipeline.run(context)

    # Check no exact duplicates by fingerprint
    fingerprints = [f.fingerprint for f in result.findings]
    assert len(fingerprints) == len(set(fingerprints)), "Duplicate fingerprints found"


@pytest.mark.asyncio
async def test_empty_project_no_crash(pipeline, audit_config, tmp_path):
    """Empty project directory should not crash the pipeline."""
    context = AuditContext(project_path=tmp_path, config=audit_config)
    result = await pipeline.run(context)

    assert result is not None
    assert result.summary.total_findings == 0
