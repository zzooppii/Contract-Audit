"""Unit tests for Phase 8: DeFi Simulation and Symbolic Execution Integration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from contract_audit.analyzers.symbolic.analyzer import SymbolicAnalyzer
from contract_audit.core.models import (
    AuditConfig,
    AuditContext,
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)


@pytest.mark.asyncio
async def test_symbolic_analyzer_verify_finding_mythril():
    """hevm이 없고 Mythril만 사용 가능할 때 targeted verification 검증."""
    analyzer = SymbolicAnalyzer()

    # hevm은 사용 불가, mythril은 사용 가능하도록 모킹
    analyzer.hevm.is_available = MagicMock(return_value=False)
    analyzer.mythril.is_available = MagicMock(return_value=True)

    # Mythril 분석 Mock
    mock_issues = [
        {
            "title": "Exception state",
            "description": "Assertion failed in withdraw(uint256)",
            "severity": "High",
            "location": {
                "file": "Vault.sol",
                "line": 42,
                "function": "withdraw(uint256)",
            },
        }
    ]
    analyzer.mythril.analyze_source = AsyncMock(return_value=mock_issues)

    finding = Finding(
        title="Missing zero check",
        description="Missing check for address zero",
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        category=FindingCategory.ACCESS_CONTROL,
        detector_name="test-detector",
        source="test-source",
        locations=[
            SourceLocation(
                file="Vault.sol",
                start_line=42,
                end_line=42,
                contract="Vault",
                function="withdraw",
            )
        ],
    )

    context = AuditContext(
        project_path=Path("."),
        target_path="Vault.sol",
        config=AuditConfig(),
        contract_sources={"Vault.sol": "contract Vault { ... }"},
        compilation_artifacts={
            "contracts": {
                "Vault.sol": {
                    "Vault": {
                        "evm": {"bytecode": {"object": "6080604052..."}},
                        "abi": [],
                    }
                }
            }
        },
    )

    # 검증 실행
    verified = await analyzer.verify_finding(finding, context)

    # 검증 성공 및 신뢰도 향상 대조
    assert verified is True
    assert finding.confidence == Confidence.HIGH
    assert finding.metadata.get("symbolic_verified") is True

    # Mythril 호출 시 함수명이 타겟팅되었는지 검증
    analyzer.mythril.analyze_source.assert_called_once_with(
        "Vault.sol", "contract Vault { ... }", timeout=60, function_name="withdraw"
    )


@pytest.mark.asyncio
async def test_symbolic_analyzer_analyze_invariant_contract():
    """테스트 계약 분석 시 어서션 위반을 DeFi Invariant Violation Finding으로 변환하는지 검증."""
    analyzer = SymbolicAnalyzer()

    # hevm 모킹
    analyzer.hevm.is_available = MagicMock(return_value=True)
    analyzer.mythril.is_available = MagicMock(return_value=False)

    mock_violations = [
        {
            "type": "assertion_violation",
            "details": "Assertion violation: totalAssets <= maxCap failed",
            "trace": ["deposit()", "invariant_custom_1() -> revert"],
        }
    ]
    analyzer.hevm.run_symbolic = AsyncMock(return_value=mock_violations)

    context = AuditContext(
        project_path=Path("."),
        target_path="InvariantVaultTest.sol",
        config=AuditConfig(),
        contract_sources={"InvariantVaultTest.sol": "contract InvariantVaultTest { ... }"},
        compilation_artifacts={
            "contracts": {
                "InvariantVaultTest.sol": {
                    "InvariantVaultTest": {
                        "evm": {"bytecode": {"object": "6080604052..."}},
                        "abi": [],
                    }
                }
            }
        },
    )

    # 분석 수행
    findings = await analyzer.analyze(context)

    # DeFi Invariant Violation 형태로 Finding이 변환되었는지 검증
    assert len(findings) == 1
    finding = findings[0]

    assert "DeFi Invariant Violation" in finding.title
    assert finding.category == FindingCategory.GOVERNANCE_ATTACK
    assert finding.metadata.get("is_invariant") is True
    assert "InvariantVaultTest" in finding.description
