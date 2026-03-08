"""End-to-end tests: full pipeline against fixture contracts."""

import pytest
from pathlib import Path

from contract_audit.core.config import load_config
from contract_audit.core.models import AuditContext, AuditConfig, FindingCategory, Severity
from contract_audit.core.pipeline import PipelineOrchestrator
from contract_audit.analyzers.ast_parser.analyzer import ASTAnalyzer
from contract_audit.detectors.access_control_detector import AccessControlDetector
from contract_audit.detectors.bridge_detector import BridgeDetector
from contract_audit.detectors.cross_contract_detector import CrossContractDetector
from contract_audit.detectors.erc20_detector import ERC20Detector
from contract_audit.detectors.erc4626_detector import ERC4626Detector
from contract_audit.detectors.flash_loan_detector import FlashLoanDetector
from contract_audit.detectors.frontrun_detector import FrontrunDetector
from contract_audit.detectors.gas_griefing import GasGriefingDetector
from contract_audit.detectors.governance_detector import GovernanceDetector
from contract_audit.detectors.initialization_detector import InitializationDetector
from contract_audit.detectors.integer_detector import IntegerDetector
from contract_audit.detectors.merkle_detector import MerkleDetector
from contract_audit.detectors.nft_detector import NFTDetector
from contract_audit.detectors.oracle_detector import OracleDetector
from contract_audit.detectors.pragma_detector import PragmaDetector
from contract_audit.detectors.proxy_detector import ProxyDetector
from contract_audit.detectors.randomness_detector import RandomnessDetector
from contract_audit.detectors.reentrancy_detector import ReentrancyDetector
from contract_audit.detectors.signature_detector import SignatureDetector
from contract_audit.detectors.storage_collision import StorageCollisionDetector
from contract_audit.detectors.timelock_detector import TimelockDetector
from contract_audit.detectors.unchecked_call_detector import UncheckedCallDetector
from contract_audit.scoring.engine import RiskScoringEngine
from contract_audit.scoring.false_positive import FalsePositiveReducer

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "contracts"
EXAMPLES_DIR = Path(__file__).parent.parent.parent / "examples"


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


# ---------------------------------------------------------------------------
# E2E: Example contract tests with all 22 detectors
# ---------------------------------------------------------------------------

ALL_DETECTORS = [
    AccessControlDetector(),
    BridgeDetector(),
    CrossContractDetector(),
    ERC20Detector(),
    ERC4626Detector(),
    FlashLoanDetector(),
    FrontrunDetector(),
    GasGriefingDetector(),
    GovernanceDetector(),
    InitializationDetector(),
    IntegerDetector(),
    MerkleDetector(),
    NFTDetector(),
    OracleDetector(),
    PragmaDetector(),
    ProxyDetector(),
    RandomnessDetector(),
    ReentrancyDetector(),
    SignatureDetector(),
    StorageCollisionDetector(),
    TimelockDetector(),
    UncheckedCallDetector(),
]


@pytest.fixture
def full_pipeline(audit_config):
    """Pipeline with all 22 detectors."""
    return PipelineOrchestrator(
        analyzers=[ASTAnalyzer()],
        detectors=ALL_DETECTORS,
        scoring_engine=RiskScoringEngine(),
        fp_reducer=FalsePositiveReducer(),
    )


# Expected detectors per example contract.
# Each entry maps a subdirectory to expected detector name substrings
# and a minimum number of findings.
EXAMPLE_EXPECTATIONS = {
    "amm-pool": {"detectors": ["oracle", "reentrancy"], "min_findings": 2},
    "cross-chain-bridge": {"detectors": ["bridge"], "min_findings": 1},
    "dao-treasury": {"detectors": ["governance"], "min_findings": 1},
    "defi-vault": {"detectors": ["oracle"], "min_findings": 1},
    "erc4626-vault": {"detectors": ["erc4626"], "min_findings": 1},
    "flash-loan-attack": {"detectors": ["flash_loan"], "min_findings": 1},
    "gas-auction": {"detectors": ["gas_griefing"], "min_findings": 1},
    "integer-math": {"detectors": ["integer"], "min_findings": 1},
    "lending-pool": {"detectors": ["oracle"], "min_findings": 1},
    "lottery-rng": {"detectors": ["randomness"], "min_findings": 1},
    "merkle-airdrop": {"detectors": ["merkle"], "min_findings": 1},
    "multisig-wallet": {"detectors": ["reentrancy"], "min_findings": 1},
    "nft-auction": {"detectors": ["nft"], "min_findings": 1},
    "nft-marketplace": {"detectors": ["reentrancy"], "min_findings": 1},
    "reentrancy-vault": {"detectors": ["reentrancy"], "min_findings": 1},
    "staking-rewards": {"detectors": ["oracle"], "min_findings": 1},
    "timelock-vault": {"detectors": ["timelock"], "min_findings": 1},
    "token-bridge": {"detectors": ["bridge"], "min_findings": 1},
    "unsafe-vault": {"detectors": ["unchecked_call"], "min_findings": 1},
    "upgradeable-proxy": {"detectors": ["proxy"], "min_findings": 1},
    "vulnerable-dex": {"detectors": ["oracle", "frontrun"], "min_findings": 1},
    "vulnerable-token": {"detectors": ["erc20"], "min_findings": 1},
    "yield-farm": {"detectors": ["oracle"], "min_findings": 1},
}


def _load_example_sources(example_dir: str) -> dict[str, str]:
    """Load all .sol files from an example directory."""
    d = EXAMPLES_DIR / example_dir
    sources = {}
    for sol in d.glob("**/*.sol"):
        sources[sol.name] = sol.read_text()
    return sources


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "example_dir,expectations",
    EXAMPLE_EXPECTATIONS.items(),
    ids=EXAMPLE_EXPECTATIONS.keys(),
)
async def test_example_contract(
    full_pipeline, audit_config, tmp_path, example_dir, expectations
):
    """Each example contract should trigger its expected detectors."""
    sources = _load_example_sources(example_dir)
    if not sources:
        pytest.skip(f"No .sol files found in examples/{example_dir}")

    context = AuditContext(
        project_path=tmp_path,
        contract_sources=sources,
        config=audit_config,
    )

    result = await full_pipeline.run(context)
    findings = result.findings

    # Check minimum findings count
    assert len(findings) >= expectations["min_findings"], (
        f"Expected >= {expectations['min_findings']} findings for {example_dir}, "
        f"got {len(findings)}: {[f.title for f in findings]}"
    )

    # Check expected detector coverage
    finding_sources = {f.source for f in findings}
    finding_detector_names = {f.detector_name for f in findings}
    all_identifiers = finding_sources | finding_detector_names

    for expected_detector in expectations["detectors"]:
        matched = any(expected_detector in ident for ident in all_identifiers)
        if not matched:
            # Also check category
            categories = {f.category.value for f in findings}
            matched = any(expected_detector in cat for cat in categories)
        assert matched, (
            f"Expected detector '{expected_detector}' to fire on {example_dir}, "
            f"but sources={finding_sources}, detectors={finding_detector_names}, "
            f"categories={categories if not matched else 'N/A'}"
        )
