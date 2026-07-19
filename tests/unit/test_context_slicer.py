"""Unit tests for the ContextSlicer component (Phase 6)."""

from __future__ import annotations

from pathlib import Path

from contract_audit.core.models import (
    AuditContext,
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)
from contract_audit.llm.context_slicer import ContextSlicer


def test_context_slicer_skeleton_generation():
    """스켈레톤 생성기가 함수 바디를 성공적으로 지우고 인터페이스 구조만 남기는지 테스트."""
    source_code = """
pragma solidity ^0.8.20;

contract Token {
    string public name = "Token";
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(uint256 initialSupply) {
        balanceOf[msg.sender] = initialSupply;
        totalSupply = initialSupply;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function nameLength() public view returns (uint256) {
        return bytes(name).length;
    }
}
"""
    slicer = ContextSlicer()
    skeleton = slicer._generate_contract_skeleton(source_code, "Token.sol")

    # 뼈대에 상태 변수와 선언부는 남아 있어야 함
    assert "string public name" in skeleton
    assert "event Transfer" in skeleton

    # 함수 바디 내부의 비즈니스 로직(대입문, require 등)은 지워지고 생략 주석이 있어야 함
    assert "balanceOf[msg.sender] -= amount;" not in skeleton
    assert "balanceOf[msg.sender] = initialSupply;" not in skeleton
    assert "returns (bool)" in skeleton
    assert "[함수 본문 구현부 생략 (토큰 절약)]" in skeleton


def test_context_slicer_get_sliced_context():
    """타겟 파일 윈도우 코드와 의존 계약 스켈레톤의 결합 기능 테스트."""
    vault_code = """
pragma solidity ^0.8.20;

import "./Token.sol";

contract Vault {
    Token public token;
    address public owner;

    constructor(address _token) {
        token = Token(_token);
        owner = msg.sender;
    }

    function deposit(uint256 amount) external {
        // Vulnerability: Unchecked return value
        token.transfer(address(this), amount);
    }
}
"""
    token_code = """
pragma solidity ^0.8.20;

contract Token {
    function transfer(address to, uint256 amount) public returns (bool) {
        return true;
    }
}
"""

    from contract_audit.core.models import AuditConfig
    context = AuditContext(
        project_path=Path("/tmp"),
        config=AuditConfig(),
    )
    context.contract_sources = {
        "src/Vault.sol": vault_code,
        "src/Token.sol": token_code,
    }
    context.import_graph = {
        "src/Vault.sol": ["src/Token.sol"]
    }

    finding = Finding(
        title="Unchecked Return Value",
        description="Unchecked return value in deposit",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        category=FindingCategory.UNCHECKED_RETURN,
        source="detector",
        detector_name="unchecked-return",
        locations=[
            SourceLocation(
                file="src/Vault.sol",
                start_line=15,
                end_line=15,
                function="deposit",
                contract="Vault"
            )
        ]
    )

    slicer = ContextSlicer(context_window=3)
    sliced_context = slicer.get_sliced_context(finding, context)

    # 타겟 파일명이 표시되어야 함
    assert "src/Vault.sol" in sliced_context
    # 슬라이스된 타겟 코드가 들어있어야 함 (윈도우 3줄이므로 12~18라인)
    assert "deposit" in sliced_context
    assert "token.transfer" in sliced_context

    # 의존 계약 스켈레톤도 결합되어야 함
    assert "src/Token.sol" in sliced_context
    assert "contract Token" in sliced_context
