"""Integration tests for LLM pipeline phases using mock router."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from contract_audit.core.models import (
    AuditConfig,
    AuditContext,
    Confidence,
    Finding,
    FindingCategory,
    LLMResponse,
    Severity,
    SourceLocation,
)
from contract_audit.core.pipeline import PipelineOrchestrator
from contract_audit.scoring.engine import RiskScoringEngine
from contract_audit.scoring.false_positive import FalsePositiveReducer


SAMPLE_SOURCE = """\
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"""


def _make_llm_response(content: str, cost: float = 0.001) -> LLMResponse:
    return LLMResponse(
        content=content,
        model="mock-model",
        provider="mock",
        input_tokens=100,
        output_tokens=50,
        cost_usd=cost,
    )


def _make_llm_response_with_structured(
    content: str, structured: dict, cost: float = 0.001
) -> LLMResponse:
    return LLMResponse(
        content=content,
        model="mock-model",
        provider="mock",
        input_tokens=100,
        output_tokens=50,
        cost_usd=cost,
        structured_data=structured,
    )


class MockLLMRouter:
    """Mock LLM router returning predefined responses."""

    is_available = True

    def __init__(self, *, audit_findings=None, triage_fp=False):
        self._audit_findings = audit_findings or []
        self._triage_fp = triage_fp
        self._call_count = 0
        self.budget_tracker = MagicMock()
        self.budget_tracker.is_exhausted = False
        self.budget_tracker.spent_usd = 0.0
        self.budget_tracker.remaining_usd = 10.0

    async def execute_task(self, task_type, messages, **kwargs):
        self._call_count += 1

        if task_type == "audit":
            findings_data = [
                {
                    "title": f["title"],
                    "description": f.get("description", "Mock finding"),
                    "severity": f.get("severity", "High"),
                    "category": f.get("category", "other"),
                    "start_line": f.get("start_line", 1),
                    "end_line": f.get("end_line", 1),
                    "function_name": f.get("function_name"),
                }
                for f in self._audit_findings
            ]
            return _make_llm_response(json.dumps({"findings": findings_data}))

        if task_type == "triage":
            structured = {
                "is_false_positive": self._triage_fp,
                "reason": "Mock triage decision",
            }
            return _make_llm_response_with_structured(
                json.dumps(structured), structured
            )

        if task_type == "explain":
            return _make_llm_response("## Mock Explanation\nThis is a mock explanation.")

        if task_type == "remediate":
            return _make_llm_response("## Mock Remediation\nFix the code.")

        if task_type == "poc_generate":
            return _make_llm_response("```solidity\n// Mock PoC\n```")

        if task_type == "summarize":
            return _make_llm_response("## Executive Summary\nMock summary.")

        return _make_llm_response("OK")

    def get_budget_summary(self):
        return {
            "spent_usd": self._call_count * 0.001,
            "max_usd": 10.0,
            "remaining_usd": 10.0 - self._call_count * 0.001,
        }


def _make_config(llm_enabled=True):
    return AuditConfig(
        llm_enabled=llm_enabled,
        slither_enabled=False,
        aderyn_enabled=False,
        foundry_fuzz_enabled=False,
        symbolic_enabled=False,
    )


def _make_context(tmp_path, llm_enabled=True, sources=None):
    return AuditContext(
        project_path=tmp_path,
        contract_sources=sources or {"Vault.sol": SAMPLE_SOURCE},
        config=_make_config(llm_enabled),
    )


@pytest.fixture
def mock_router():
    return MockLLMRouter(
        audit_findings=[
            {
                "title": "CEI Violation in withdraw()",
                "description": "State updated after external call",
                "severity": "Critical",
                "category": "reentrancy",
                "start_line": 12,
                "end_line": 16,
                "function_name": "withdraw",
            }
        ]
    )


# --- Test 1: LLM audit phase produces findings ---

@pytest.mark.asyncio
async def test_llm_audit_phase_produces_findings(mock_router, tmp_path):
    """Phase 3.5 should produce findings from LLM audit."""
    pipeline = PipelineOrchestrator(
        analyzers=[],
        detectors=[],
        scoring_engine=RiskScoringEngine(),
        fp_reducer=FalsePositiveReducer(),
        llm_router=mock_router,
    )
    context = _make_context(tmp_path, llm_enabled=True)

    findings = await pipeline._phase_llm_audit(context)

    assert len(findings) == 1
    assert "CEI Violation" in findings[0].title
    assert findings[0].source == "llm_audit"


# --- Test 2: LLM audit skipped when disabled ---

@pytest.mark.asyncio
async def test_llm_audit_phase_skipped_when_disabled(mock_router, tmp_path):
    """LLM audit should not run when llm_enabled=False."""
    pipeline = PipelineOrchestrator(
        analyzers=[],
        detectors=[],
        llm_router=mock_router,
    )
    context = _make_context(tmp_path, llm_enabled=False)

    # _phase_llm_audit should return empty when router is present but disabled
    # The pipeline.run() checks config.llm_enabled before calling this
    # So we test the run() method directly
    result = await pipeline.run(context)
    assert mock_router._call_count == 0


# --- Test 3: LLM enrichment adds explanation ---

@pytest.mark.asyncio
async def test_llm_enrichment_adds_explanation(mock_router, tmp_path):
    """Phase 6 should add LLM explanation to findings."""
    pipeline = PipelineOrchestrator(
        analyzers=[],
        detectors=[],
        llm_router=mock_router,
    )
    context = _make_context(tmp_path)

    finding = Finding(
        title="Test Finding",
        description="A test",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category=FindingCategory.REENTRANCY,
        source="test",
        detector_name="test",
        locations=[SourceLocation(file="Vault.sol", start_line=12, end_line=16)],
    )

    enriched = await pipeline._phase_llm_enrich([finding], context)

    assert len(enriched) == 1
    assert enriched[0].llm_explanation is not None
    assert "Mock Explanation" in enriched[0].llm_explanation


# --- Test 4: LLM enrichment adds PoC for critical ---

@pytest.mark.asyncio
async def test_llm_enrichment_adds_poc(mock_router, tmp_path):
    """Phase 6 should generate PoC for Critical findings."""
    pipeline = PipelineOrchestrator(
        analyzers=[],
        detectors=[],
        llm_router=mock_router,
    )
    context = _make_context(tmp_path)

    finding = Finding(
        title="Critical Vuln",
        description="A critical vulnerability",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category=FindingCategory.REENTRANCY,
        source="test",
        detector_name="test",
        locations=[SourceLocation(file="Vault.sol", start_line=12, end_line=16)],
    )

    enriched = await pipeline._phase_llm_enrich([finding], context)

    assert enriched[0].llm_poc is not None
    assert "Mock PoC" in enriched[0].llm_poc


# --- Test 5: LLM triage filters false positives ---

@pytest.mark.asyncio
async def test_llm_triage_filters_fp(tmp_path):
    """FP reducer with LLM triage should suppress false positives."""
    router = MockLLMRouter(triage_fp=True)
    reducer = FalsePositiveReducer(llm_router=router, triage_threshold=1.0)

    context = _make_context(tmp_path)

    finding = Finding(
        title="Borderline Finding",
        description="Maybe FP",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category=FindingCategory.OTHER,
        source="test",
        detector_name="test",
        locations=[SourceLocation(file="Vault.sol", start_line=5, end_line=5)],
        risk_score=5.0,
    )

    result = await reducer.reduce_with_llm([finding], context)

    assert len(result) == 1
    assert result[0].suppressed is True
    assert "false positive" in result[0].suppression_reason.lower()


# --- Test 6: LLM triage keeps true positives ---

@pytest.mark.asyncio
async def test_llm_triage_keeps_tp(tmp_path):
    """FP reducer with LLM triage should keep true positives."""
    router = MockLLMRouter(triage_fp=False)
    reducer = FalsePositiveReducer(llm_router=router, triage_threshold=1.0)

    context = _make_context(tmp_path)

    finding = Finding(
        title="Real Bug",
        description="Definitely a bug",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category=FindingCategory.REENTRANCY,
        source="test",
        detector_name="test",
        locations=[SourceLocation(file="Vault.sol", start_line=12, end_line=16)],
        risk_score=5.0,
    )

    result = await reducer.reduce_with_llm([finding], context)

    assert len(result) == 1
    assert result[0].suppressed is False


# --- Test 7: Full pipeline with mock LLM end-to-end ---

@pytest.mark.asyncio
async def test_pipeline_with_mock_llm_end_to_end(tmp_path):
    """Full pipeline run with mock LLM should complete without errors."""
    router = MockLLMRouter(
        audit_findings=[
            {
                "title": "Business Logic Flaw",
                "severity": "High",
                "category": "other",
            }
        ]
    )
    pipeline = PipelineOrchestrator(
        analyzers=[],
        detectors=[],
        scoring_engine=RiskScoringEngine(),
        fp_reducer=FalsePositiveReducer(),
        llm_router=router,
    )

    context = _make_context(tmp_path, llm_enabled=True)
    result = await pipeline.run(context)

    assert result is not None
    assert result.summary is not None
    # LLM audit should have been called
    assert router._call_count > 0


# --- Test 8: LLM budget tracking ---

@pytest.mark.asyncio
async def test_llm_budget_tracking(mock_router, tmp_path):
    """Budget tracking should record costs across calls."""
    pipeline = PipelineOrchestrator(
        analyzers=[],
        detectors=[],
        llm_router=mock_router,
    )
    context = _make_context(tmp_path)

    # Run LLM audit to trigger calls
    await pipeline._phase_llm_audit(context)

    summary = mock_router.get_budget_summary()
    assert summary["spent_usd"] > 0
    assert summary["remaining_usd"] < summary["max_usd"]
