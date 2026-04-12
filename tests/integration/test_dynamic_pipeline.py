"""Integration tests for the dynamic analysis phase of the pipeline.

Verifies:
- Targeted harnesses are generated BEFORE forge runs (ordering fix)
- Symbolic verify_finding runs AFTER asyncio.gather (ordering fix)
- Graceful fallback when forge/hevm is not installed
- Generated harnesses include improvements from Phase 2 (reentrancy attacker, etc.)
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from contract_audit.core.models import (
    AuditConfig,
    AuditContext,
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)
from contract_audit.core.pipeline import PipelineOrchestrator


def _make_pipeline() -> PipelineOrchestrator:
    return PipelineOrchestrator(analyzers=[], detectors=[])


def _make_context(tmp_path: Path, foundry: bool = True, symbolic: bool = False) -> AuditContext:
    config = AuditConfig(
        foundry_fuzz_enabled=foundry,
        symbolic_enabled=symbolic,
        llm_enabled=False,
    )
    return AuditContext(project_path=tmp_path, config=config)


def _make_critical_finding(func_name: str = "withdraw", contract: str = "Vault") -> Finding:
    return Finding(
        title=f"Reentrancy in {func_name}",
        description="CEI violation",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category=FindingCategory.REENTRANCY,
        source="test",
        detector_name="test-detector",
        locations=[
            SourceLocation(
                file=f"{contract}.sol",
                start_line=10,
                end_line=20,
                function=func_name,
                contract=contract,
            )
        ],
    )


class TestDynamicPhaseOrdering:
    """Harnesses must be written to disk before forge subprocess starts."""

    @pytest.mark.asyncio
    async def test_harnesses_generated_before_forge_runs(self, tmp_path):
        """Verify that targeted test files exist when forge is called."""
        (tmp_path / "foundry.toml").write_text("[profile.default]\n")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "Vault.sol").write_text("contract Vault {}")

        pipeline = _make_pipeline()
        context = _make_context(tmp_path, foundry=True)
        finding = _make_critical_finding()
        finding.locations[0].contract = "Vault"

        harness_files_at_forge_time: list[list[Path]] = []

        async def mock_forge_analyze(ctx):
            # Capture what files exist in test/ at the time forge "runs"
            test_dir = ctx.project_path / "test"
            harness_files_at_forge_time.append(
                list(test_dir.glob("**/*.t.sol")) if test_dir.exists() else []
            )
            return []

        with patch(
            "contract_audit.analyzers.foundry.analyzer.FoundryAnalyzer.is_available",
            return_value=True,
        ), patch(
            "contract_audit.analyzers.foundry.analyzer.FoundryAnalyzer.analyze",
            side_effect=mock_forge_analyze,
        ):
            await pipeline._phase_dynamic(context, existing_findings=[finding])

        # Harnesses MUST be on disk when forge runs
        assert len(harness_files_at_forge_time) == 1, "forge.analyze should have been called"
        assert len(harness_files_at_forge_time[0]) > 0, (
            "Targeted harness files should exist when forge runs — "
            "ordering bug: harnesses generated after forge"
        )

    @pytest.mark.asyncio
    async def test_symbolic_verify_runs_after_forge(self, tmp_path):
        """Symbolic verify_finding must be called after asyncio.gather."""
        (tmp_path / "foundry.toml").write_text("[profile.default]\n")

        pipeline = _make_pipeline()
        context = _make_context(tmp_path, foundry=True, symbolic=True)
        finding = _make_critical_finding()

        call_order: list[str] = []

        async def mock_forge_analyze(ctx):
            call_order.append("forge")
            return []

        async def mock_symbolic_analyze(ctx):
            call_order.append("symbolic_analyze")
            return []

        async def mock_verify(finding_, ctx):
            call_order.append("verify_finding")
            return False

        with patch(
            "contract_audit.analyzers.foundry.analyzer.FoundryAnalyzer.is_available",
            return_value=True,
        ), patch(
            "contract_audit.analyzers.foundry.analyzer.FoundryAnalyzer.analyze",
            side_effect=mock_forge_analyze,
        ), patch(
            "contract_audit.analyzers.symbolic.analyzer.SymbolicAnalyzer.is_available",
            return_value=True,
        ), patch(
            "contract_audit.analyzers.symbolic.analyzer.SymbolicAnalyzer.analyze",
            side_effect=mock_symbolic_analyze,
        ), patch(
            "contract_audit.analyzers.symbolic.analyzer.SymbolicAnalyzer.verify_finding",
            side_effect=mock_verify,
        ):
            await pipeline._phase_dynamic(context, existing_findings=[finding])

        assert "forge" in call_order
        assert "verify_finding" in call_order
        # verify_finding must come after both forge and symbolic analyze
        forge_idx = call_order.index("forge")
        verify_idx = call_order.index("verify_finding")
        assert verify_idx > forge_idx, (
            f"verify_finding (pos {verify_idx}) must run after forge (pos {forge_idx})"
        )


class TestDynamicPhaseGracefulFallback:
    @pytest.mark.asyncio
    async def test_foundry_not_installed_returns_empty(self, tmp_path):
        pipeline = _make_pipeline()
        context = _make_context(tmp_path, foundry=True)

        with patch(
            "contract_audit.analyzers.foundry.analyzer.FoundryAnalyzer.is_available",
            return_value=False,
        ):
            findings = await pipeline._phase_dynamic(context)

        assert findings == []

    @pytest.mark.asyncio
    async def test_symbolic_not_installed_returns_empty(self, tmp_path):
        pipeline = _make_pipeline()
        context = _make_context(tmp_path, foundry=False, symbolic=True)

        with patch(
            "contract_audit.analyzers.symbolic.analyzer.SymbolicAnalyzer.is_available",
            return_value=False,
        ):
            findings = await pipeline._phase_dynamic(context)

        assert findings == []

    @pytest.mark.asyncio
    async def test_both_disabled_returns_empty(self, tmp_path):
        pipeline = _make_pipeline()
        context = _make_context(tmp_path, foundry=False, symbolic=False)
        findings = await pipeline._phase_dynamic(context)
        assert findings == []

    @pytest.mark.asyncio
    async def test_no_existing_findings_skips_harness_generation(self, tmp_path):
        """With no existing findings, no harness files should be created."""
        (tmp_path / "foundry.toml").write_text("[profile.default]\n")
        pipeline = _make_pipeline()
        context = _make_context(tmp_path, foundry=True)

        with patch(
            "contract_audit.analyzers.foundry.analyzer.FoundryAnalyzer.is_available",
            return_value=True,
        ), patch(
            "contract_audit.analyzers.foundry.analyzer.FoundryAnalyzer.analyze",
            new=AsyncMock(return_value=[]),
        ):
            await pipeline._phase_dynamic(context, existing_findings=None)

        targeted_dir = tmp_path / "test" / "audit_targeted"
        assert not targeted_dir.exists() or not list(targeted_dir.glob("*.t.sol"))

    @pytest.mark.asyncio
    async def test_only_low_severity_findings_skip_harness(self, tmp_path):
        """LOW/MEDIUM findings should not trigger targeted harness generation."""
        (tmp_path / "foundry.toml").write_text("[profile.default]\n")
        pipeline = _make_pipeline()
        context = _make_context(tmp_path, foundry=True)

        low_finding = Finding(
            title="Minor issue",
            description="Low severity",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            category=FindingCategory.OTHER,
            source="test",
            detector_name="test",
            locations=[
                SourceLocation(file="Foo.sol", start_line=1, end_line=1, contract="Foo")
            ],
        )

        with patch(
            "contract_audit.analyzers.foundry.analyzer.FoundryAnalyzer.is_available",
            return_value=True,
        ), patch(
            "contract_audit.analyzers.foundry.analyzer.FoundryAnalyzer.analyze",
            new=AsyncMock(return_value=[]),
        ):
            await pipeline._phase_dynamic(context, existing_findings=[low_finding])

        targeted_dir = tmp_path / "test" / "audit_targeted"
        assert not targeted_dir.exists() or not list(targeted_dir.glob("*.t.sol"))


class TestFuzzAndInvariantHarnessGeneration:
    """Verify Step 1b/1c generate fuzz + invariant harnesses for all contracts."""

    @pytest.mark.asyncio
    async def test_fuzz_harnesses_generated_for_all_contracts(self, tmp_path):
        """audit_fuzz/ should contain .t.sol files when forge executes (before cleanup)."""
        (tmp_path / "foundry.toml").write_text("[profile.default]\n")

        pipeline = _make_pipeline()
        config = AuditConfig(foundry_fuzz_enabled=True, llm_enabled=False)
        context = AuditContext(project_path=tmp_path, config=config)

        context.compilation_artifacts = {
            "contracts": {
                "src/Token.sol": {
                    "Token": {
                        "abi": [
                            {"type": "function", "name": "transfer",
                             "inputs": [{"type": "address", "name": "to"},
                                        {"type": "uint256", "name": "amount"}],
                             "stateMutability": "nonpayable"},
                        ]
                    }
                }
            }
        }

        files_at_forge_time: list[list[Path]] = []

        async def capture_and_return(ctx):
            fuzz_dir = ctx.project_path / "test" / "audit_fuzz"
            files_at_forge_time.append(
                list(fuzz_dir.glob("*.t.sol")) if fuzz_dir.exists() else []
            )
            return []

        with patch(
            "contract_audit.analyzers.foundry.analyzer.FoundryAnalyzer.is_available",
            return_value=True,
        ), patch(
            "contract_audit.analyzers.foundry.analyzer.FoundryAnalyzer.analyze",
            side_effect=capture_and_return,
        ):
            await pipeline._phase_dynamic(context)

        # Files must exist during forge execution (before cleanup)
        assert len(files_at_forge_time) == 1
        assert len(files_at_forge_time[0]) >= 1
        assert any("Token" in f.name for f in files_at_forge_time[0])
        # Directories are cleaned up after forge runs
        assert not (tmp_path / "test" / "audit_fuzz").exists()

    @pytest.mark.asyncio
    async def test_invariant_tests_generated_for_all_contracts(self, tmp_path):
        """audit_invariants/ should contain .t.sol files when forge executes (before cleanup)."""
        (tmp_path / "foundry.toml").write_text("[profile.default]\n")

        pipeline = _make_pipeline()
        config = AuditConfig(foundry_fuzz_enabled=True, llm_enabled=False)
        context = AuditContext(project_path=tmp_path, config=config)

        context.contract_sources = {
            "src/Vault.sol": (
                "contract Vault { uint256 public totalAssets; "
                "function totalSupply() public view returns (uint256) {} }"
            )
        }

        files_at_forge_time: list[list[Path]] = []

        async def capture_and_return(ctx):
            inv_dir = ctx.project_path / "test" / "audit_invariants"
            files_at_forge_time.append(
                list(inv_dir.glob("*.t.sol")) if inv_dir.exists() else []
            )
            return []

        with patch(
            "contract_audit.analyzers.foundry.analyzer.FoundryAnalyzer.is_available",
            return_value=True,
        ), patch(
            "contract_audit.analyzers.foundry.analyzer.FoundryAnalyzer.analyze",
            side_effect=capture_and_return,
        ):
            await pipeline._phase_dynamic(context)

        assert len(files_at_forge_time) == 1
        assert len(files_at_forge_time[0]) >= 1
        assert any("Vault" in f.name for f in files_at_forge_time[0])
        # Directories are cleaned up after forge runs
        assert not (tmp_path / "test" / "audit_invariants").exists()

    @pytest.mark.asyncio
    async def test_harness_dirs_cleaned_up_after_phase(self, tmp_path):
        """All audit_* test directories must be removed after _phase_dynamic completes."""
        (tmp_path / "foundry.toml").write_text("[profile.default]\n")

        pipeline = _make_pipeline()
        config = AuditConfig(foundry_fuzz_enabled=True, llm_enabled=False)
        context = AuditContext(project_path=tmp_path, config=config)
        context.contract_sources = {"src/Token.sol": "contract Token {}"}

        with patch(
            "contract_audit.analyzers.foundry.analyzer.FoundryAnalyzer.is_available",
            return_value=True,
        ), patch(
            "contract_audit.analyzers.foundry.analyzer.FoundryAnalyzer.analyze",
            new=AsyncMock(return_value=[]),
        ):
            await pipeline._phase_dynamic(context)

        for dirname in ("audit_targeted", "audit_fuzz", "audit_invariants"):
            assert not (tmp_path / "test" / dirname).exists(), \
                f"test/{dirname} should be cleaned up after dynamic phase"


class TestGeneratedHarnessContent:
    """Verify quality improvements from Phase 2."""

    def test_reentrancy_harness_has_attacker_contract(self, tmp_path):
        from contract_audit.analyzers.foundry.harness_generator import generate_targeted_harness

        finding = _make_critical_finding("withdraw", "Vault")
        source = "contract Vault { function withdraw(uint256 amount) external payable {} }"

        result = generate_targeted_harness("Vault", finding, source, tmp_path)
        content = result.read_text()

        assert "receive()" in content, "Reentrancy harness must have receive() callback"
        assert "fallback()" in content, "Reentrancy harness must have fallback() callback"
        assert "attackCount" in content, "Attacker must track re-entry count"
        assert "assertLe" in content, "Must assert attackCount <= 1"

    def test_reentrancy_harness_no_noop_catch(self, tmp_path):
        from contract_audit.analyzers.foundry.harness_generator import generate_targeted_harness

        finding = _make_critical_finding("withdraw", "Vault")
        result = generate_targeted_harness("Vault", finding, "contract Vault {}", tmp_path)
        content = result.read_text()

        # The attacker contract should NOT silently swallow all errors
        # (bare catch {} with no action is the no-op pattern we removed)
        lines = [l.strip() for l in content.splitlines()]
        bare_catch_lines = [l for l in lines if l in ("} catch {}", "} catch {}")]
        assert not bare_catch_lines, "Reentrancy harness should not have bare no-op catch blocks"

    def test_arithmetic_harness_has_boundary_values(self, tmp_path):
        from contract_audit.analyzers.foundry.harness_generator import generate_targeted_harness
        from contract_audit.core.models import FindingCategory

        finding = Finding(
            title="Overflow",
            description="",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.ARITHMETIC,
            source="test",
            detector_name="test",
            locations=[SourceLocation(file="Math.sol", start_line=1, end_line=1, function="add")],
        )
        source = "contract Math { function add(uint256 a, uint256 b) external {} }"
        result = generate_targeted_harness("Math", finding, source, tmp_path)
        content = result.read_text()

        assert "type(uint256).max" in content
        assert "testFuzz_" in content

    def test_arithmetic_harness_has_boundary_values_even_without_source(self, tmp_path):
        """Even with unparseable source, arithmetic harness should include max value."""
        from contract_audit.analyzers.foundry.harness_generator import generate_targeted_harness
        from contract_audit.core.models import FindingCategory

        finding = Finding(
            title="Overflow",
            description="",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.ARITHMETIC,
            source="test",
            detector_name="test",
            locations=[SourceLocation(file="Math.sol", start_line=1, end_line=1, function="add")],
        )
        result = generate_targeted_harness("Math", finding, "contract Math {}", tmp_path)
        content = result.read_text()

        assert "type(uint256).max" in content

    def test_fuzz_harness_no_noop_catch(self, tmp_path):
        """Generic fuzz harness should not use try/catch that swallows all errors."""
        from contract_audit.analyzers.foundry.harness_generator import generate_fuzz_harness

        functions = [{"name": "deposit", "inputs": [{"type": "uint256", "name": "amount"}], "stateMutability": "nonpayable"}]
        result = generate_fuzz_harness("Vault", functions, tmp_path)
        content = result.read_text()

        assert "} catch {}" not in content, "Fuzz tests must not silently swallow all errors"
        assert "} catch{}" not in content
