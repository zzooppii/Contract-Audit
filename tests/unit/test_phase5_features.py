"""Unit tests for Phase 5 features: Smart Fuzzing Harness Healing & AST-based Call Graph Analysis."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from contract_audit.analyzers.foundry.harness_generator import generate_fuzz_harness
from contract_audit.analyzers.cross_contract.call_graph import CallGraph
from contract_audit.utils.solc import compile_contracts, extract_ast_trees


def test_struct_constructor_harness_generation(tmp_path: Path):
    """구조체 및 튜플 타입 생성자 파라미터가 있을 때, 하네스를 스킵 없이 치유하여 정상 생성하는지 테스트."""
    # Vault.sol의 구조체 정의가 포함된 ABI 형식 재현
    ctor_abi = [
        {
            "name": "_config",
            "type": "tuple",
            "internalType": "struct Vault.Config",
            "components": [
                {"name": "owner", "type": "address"},
                {"name": "delay", "type": "uint256"},
                {"name": "isActive", "type": "bool"}
            ]
        }
    ]
    
    result_path = generate_fuzz_harness(
        "Vault",
        [],
        tmp_path,
        constructor_abi=ctor_abi
    )
    
    assert result_path != Path("")
    assert result_path.exists()
    
    content = result_path.read_text()
    # 생성된 코드 내부에 구조체 캐스팅 디폴트 값이 명시되어 있는지 확인
    assert "Vault.Config(" in content
    # address(1), 3600, true 형태로 파라미터가 매핑되었는지 검증
    assert "address(1)" in content
    assert "3600" in content
    assert "true" in content


@pytest.mark.asyncio
async def test_ast_based_cross_contract_call_graph(tmp_path: Path):
    """AST 정보를 활용해 인터페이스 캐스팅 및 로컬 변수 타입 외부 호출을 정확하게 추적하는지 테스트."""
    from contract_audit.utils.solc import solc_available
    if not solc_available():
        pytest.skip("solc not installed")

    # 두 계약 간의 순환 관계가 생성되도록 코드를 작성
    # Pool은 IToken 인터페이스 캐스팅을 통해 transfer를 호출하고, Token은 Pool을 호출하는 시나리오
    token_code = """
pragma solidity ^0.8.20;

interface IToken {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract Pool {
    address public tokenAddr;

    constructor(address _token) {
        tokenAddr = _token;
    }

    // A->B 호출 1: 직접 인터페이스 캐스팅 호출
    function executeDirect(address to, uint256 amount) external {
        IToken(tokenAddr).transfer(to, amount);
    }

    // A->B 호출 2: 로컬 변수 바인딩 호출
    function executeLocal(address to, uint256 amount) external {
        IToken t = IToken(tokenAddr);
        t.transfer(to, amount);
    }
}
"""
    sources = {"Pool.sol": token_code}
    output = await compile_contracts(tmp_path, sources, "auto")
    ast_trees = extract_ast_trees(output)
    
    assert "Pool.sol" in ast_trees
    
    # 상속 정보 (가장 단순화된 맵)
    inheritance_map = {"Pool": [], "IToken": []}
    
    builder = CallGraph()
    call_graph = builder.build(sources, inheritance_map, ast_trees)
    
    # Pool에서 IToken으로의 호출이 정상적으로 잡혔는지 확인
    assert "Pool" in call_graph
    calls = call_graph["Pool"]
    
    # IToken.transfer 호출이 정상 추출되었는지 검증
    assert ("IToken", "transfer") in calls
