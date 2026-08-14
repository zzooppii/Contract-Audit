import pytest
from unittest.mock import AsyncMock, MagicMock
from contract_audit.core.models import Finding, Severity, FindingCategory, Confidence
from contract_audit.llm.tasks.triage import TriageTask, TriageResult


class MockLLMResponse:
    def __init__(self, content, structured_data=None):
        self.content = content
        self.structured_data = structured_data


@pytest.mark.asyncio
async def test_multi_agent_triage_flow_for_critical_finding():
    """Verify that multi-agent triage runs the attacker, defender, and referee debating flow for Critical/High findings."""
    mock_router = MagicMock()
    
    # Set up simulated LLM responses for the 3 steps
    attacker_res = MockLLMResponse(content="Attacker argument: This is valid reentrancy.")
    defender_res = MockLLMResponse(content="Defender argument: This is false positive because it is locked by modifier.")
    referee_res = MockLLMResponse(
        content='{"is_false_positive": true, "reason": "Locked by custom logic"}',
        structured_data={"is_false_positive": True, "reason": "Locked by custom logic"}
    )
    
    mock_router.execute_task = AsyncMock(side_effect=[attacker_res, defender_res, referee_res])
    
    task = TriageTask(router=mock_router)
    finding = Finding(
        title="Critical Vulnerability",
        description="Vulnerable code allows state mutation after call",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        detector_name="reentrancy",
        category=FindingCategory.REENTRANCY,
        source="reentrancy_detector",
        locations=[]
    )
    
    is_fp = await task.classify(finding, source_snippet="msg.sender.call(''); balances[msg.sender] = 0;")
    
    # Verify it classified as False Positive based on the Referee structured response
    assert is_fp is True
    assert mock_router.execute_task.call_count == 3
    
    # Check that custom system instructions were set correctly for each role
    calls = mock_router.execute_task.call_args_list
    assert "offensive" in calls[0][1]["messages"][0]["content"].lower()
    assert "defensive" in calls[1][1]["messages"][0]["content"].lower()
    assert "referee" in calls[2][1]["messages"][0]["content"].lower()


@pytest.mark.asyncio
async def test_single_agent_triage_fallback_for_medium_finding():
    """Verify that triage falls back to single-agent execution for Medium/Low findings to conserve budget."""
    mock_router = MagicMock()
    single_res = MockLLMResponse(
        content='{"is_false_positive": false, "reason": "Valid logic check"}',
        structured_data={"is_false_positive": False, "reason": "Valid logic check"}
    )
    mock_router.execute_task = AsyncMock(return_value=single_res)
    
    task = TriageTask(router=mock_router)
    finding = Finding(
        title="Medium Vulnerability",
        description="Unchecked return value",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        detector_name="unchecked-call",
        category=FindingCategory.REENTRANCY,
        source="unchecked_call_detector",
        locations=[]
    )
    
    is_fp = await task.classify(finding, source_snippet="target.call('');")
    
    # Verify it only called LLM once
    assert is_fp is False
    assert mock_router.execute_task.call_count == 1
