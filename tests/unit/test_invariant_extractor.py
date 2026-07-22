"""Unit tests for NatSpec comment-based Invariant Extractor and Invariant Generator integration."""

from __future__ import annotations

from pathlib import Path

from contract_audit.analyzers.foundry.invariant_extractor import InvariantExtractor
from contract_audit.analyzers.foundry.invariant_generator import generate_invariant_tests


def test_invariant_extractor_translation():
    """주석에서 불변량을 추출하여 target. 접두사 조건식으로 번역하는지 검증."""
    source_code = """
pragma solidity ^0.8.20;

contract Vault {
    uint256 public totalAssets;
    address public owner;
    bool public paused;

    /// @dev invariant: totalAssets == address(this).balance
    /// @notice invariant: owner != address(0)
    /// @dev invariant: paused == false
    function deposit() external payable {}
}
"""
    extractor = InvariantExtractor()
    custom_invariants = extractor.extract_custom_invariants(source_code, "Vault")

    assert len(custom_invariants) == 3

    # 각 불변량이 알맞게 번역되었는지 테스트
    inv1 = custom_invariants[0]
    assert "target.totalAssets == address(this).balance" in inv1["test"]

    inv2 = custom_invariants[1]
    assert "target.owner != address(0)" in inv2["test"]

    inv3 = custom_invariants[2]
    assert "target.paused == false" in inv3["test"]


def test_invariant_generator_with_custom_invariants(tmp_path: Path):
    """실제 하네스 생성기 실행 시 커스텀 불변량이 테스트 파일 내부에 함수 형태로 포함되는지 검증."""
    source_code = """
pragma solidity ^0.8.20;

contract Vault {
    uint256 public maxCap;
    uint256 public totalAssets;

    /// @dev invariant: totalAssets <= maxCap
    function deposit() external {}
}
"""
    result_path = generate_invariant_tests(
        "Vault",
        source_code,
        tmp_path,
        source_path="src/Vault.sol"
    )

    assert result_path != Path("")
    assert result_path.exists()

    content = result_path.read_text()

    # 커스텀 불변량이 테스트 메소드로 포함되어 있어야 함
    assert "function invariant_custom_invariant_1()" in content
    # target. 접두사와 단언문(assertTrue)이 존재해야 함
    assert "assertTrue(" in content
    assert "target.totalAssets <= target.maxCap" in content
