"""Unit tests for AST-based Missing Zero Address Validation detector."""

from __future__ import annotations

from pathlib import Path
import pytest

from contract_audit.analyzers.ast_parser.analyzer import ASTAnalyzer
from contract_audit.core.models import Severity, FindingCategory
from contract_audit.utils.solc import compile_contracts, extract_ast_trees


@pytest.mark.asyncio
async def test_missing_zero_address_validation_detection(tmp_path: Path):
    from contract_audit.utils.solc import solc_available
    if not solc_available():
        pytest.skip("solc not installed")

    # Contract with a missing check and one with a proper check
    source_code = """
pragma solidity ^0.8.20;

contract Wallet {
    address public owner;
    address public backup;

    // Bad: missing zero address check
    function setOwner(address _owner) external {
        owner = _owner;
    }

    // Good: has zero address check
    function setBackup(address _backup) external {
        require(_backup != address(0), "zero address");
        backup = _backup;
    }
}
"""
    filename = "Wallet.sol"
    sources = {filename: source_code}

    # Compile to get real AST
    output = await compile_contracts(tmp_path, sources, "auto")
    ast_trees = extract_ast_trees(output)

    assert filename in ast_trees

    analyzer = ASTAnalyzer()
    findings = analyzer._check_missing_zero_check(filename, ast_trees[filename], source_code)

    # Wallet.sol has one function (setOwner) missing check, and one (setBackup) having check
    assert len(findings) == 1
    finding = findings[0]
    assert finding.title == "Missing Zero Address Validation"
    assert "owner" in finding.description
    assert finding.severity == Severity.LOW
    assert finding.category == FindingCategory.ACCESS_CONTROL
    assert finding.locations[0].function == "setOwner"
