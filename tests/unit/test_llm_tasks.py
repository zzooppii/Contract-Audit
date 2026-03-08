"""Unit tests for LLM task modules."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from contract_audit.core.models import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
)


class TestAuditTask:
    def test_parse_response_valid_json(self):
        from contract_audit.llm.tasks.audit_task import AuditTask

        router = MagicMock()
        task = AuditTask(router)

        response_json = json.dumps({
            "findings": [
                {
                    "title": "Missing access control",
                    "description": "Function lacks modifier",
                    "severity": "High",
                    "category": "access-control",
                    "start_line": 10,
                    "end_line": 15,
                    "function_name": "withdraw",
                }
            ]
        })

        findings = task._parse_response(response_json, "Test.sol")
        assert len(findings) == 1
        assert findings[0].title == "Missing access control"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == FindingCategory.ACCESS_CONTROL
        assert findings[0].source == "llm_audit"

    def test_parse_response_markdown_wrapped(self):
        from contract_audit.llm.tasks.audit_task import AuditTask

        router = MagicMock()
        task = AuditTask(router)

        response = '```json\n{"findings": []}\n```'
        findings = task._parse_response(response, "Test.sol")
        assert findings == []

    def test_parse_response_invalid_json(self):
        from contract_audit.llm.tasks.audit_task import AuditTask

        router = MagicMock()
        task = AuditTask(router)

        findings = task._parse_response("not valid json", "Test.sol")
        assert findings == []

    def test_parse_response_empty_findings(self):
        from contract_audit.llm.tasks.audit_task import AuditTask

        router = MagicMock()
        task = AuditTask(router)

        findings = task._parse_response('{"findings": []}', "Test.sol")
        assert findings == []


class TestPoCVerifyTask:
    def test_extract_solidity_from_markdown(self):
        from contract_audit.llm.tasks.poc_verify import PoCVerifyTask

        task = PoCVerifyTask()

        poc_text = """Here's the PoC:

```solidity
pragma solidity ^0.8.0;
contract PoCTest {
    function test_exploit() public {}
}
```
"""
        result = task._extract_solidity(poc_text)
        assert "pragma solidity" in result
        assert "PoCTest" in result

    def test_extract_solidity_raw(self):
        from contract_audit.llm.tasks.poc_verify import PoCVerifyTask

        task = PoCVerifyTask()

        poc_text = "pragma solidity ^0.8.0;\ncontract Test {}"
        result = task._extract_solidity(poc_text)
        assert "pragma solidity" in result

    def test_extract_solidity_empty(self):
        from contract_audit.llm.tasks.poc_verify import PoCVerifyTask

        task = PoCVerifyTask()

        result = task._extract_solidity("no code here")
        assert result == ""

    @pytest.mark.asyncio
    async def test_run_without_poc(self):
        from contract_audit.llm.tasks.poc_verify import PoCVerifyTask

        task = PoCVerifyTask()
        finding = Finding(
            title="Test",
            description="Test finding",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category=FindingCategory.REENTRANCY,
            source="test",
            detector_name="test",
            llm_poc=None,
        )

        result = await task.run(finding, Path("/tmp"))
        assert result is False


class TestFalsePositiveReducerEnhanced:
    def test_triage_threshold_parameter(self):
        from contract_audit.scoring.false_positive import FalsePositiveReducer

        reducer = FalsePositiveReducer(triage_threshold=0.5, context_window=15)
        assert reducer.triage_threshold == 0.5
        assert reducer.context_window == 15

    def test_default_triage_threshold(self):
        from contract_audit.scoring.false_positive import FalsePositiveReducer

        reducer = FalsePositiveReducer()
        assert reducer.triage_threshold == 0.7
        assert reducer.context_window == 10
