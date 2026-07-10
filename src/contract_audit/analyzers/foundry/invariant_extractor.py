"""Extractor utility for custom business invariants inside Solidity comments.

Parses custom Natspec comment tags like `/// @dev invariant: <expression>` and
converts them into executable Solidity assertions.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)


class InvariantExtractor:
    """Solidity 소스 코드 주석에서 커스텀 비즈니스 불변량(Invariant)을 추출 및 번역하는 클래스."""

    def __init__(self) -> None:
        # Natspec 주석 내에서 invariant 패턴 식별: /// @dev invariant: <expr> 또는 /// @notice invariant: <expr>
        self.invariant_comment_pattern = re.compile(
            r'///\s*@(dev|notice)\s+invariant:\s*(.+)',
            re.IGNORECASE
        )

    def extract_custom_invariants(self, source: str, contract_name: str) -> list[dict[str, str]]:
        """소스코드에서 커스텀 불변량 주석을 찾아내어 Foundry invariant test 데이터 구조로 변환합니다.

        Returns:
            list of dict containing {"name": ..., "description": ..., "test": ...}
        """
        invariants: list[dict[str, str]] = []
        lines = source.splitlines()

        count = 0
        for line in lines:
            match = self.invariant_comment_pattern.search(line)
            if match:
                raw_expression = match.group(2).strip()
                if not raw_expression:
                    continue

                count += 1
                description = f"Custom invariant: {raw_expression}"
                name = f"custom_invariant_{count}"

                # 표현식을 유효한 솔리디티 조건식으로 변환
                solidity_assertion = self._translate_to_solidity(raw_expression, contract_name)
                escaped_expression = raw_expression.replace('"', '\\"')

                test_body = f"""
    /// @notice {description}
    function invariant_{name}() public {{
        assertTrue(
            {solidity_assertion},
            "Invariant violation: {escaped_expression}"
        );
    }}"""
                invariants.append({
                    "name": name,
                    "description": description,
                    "test": test_body
                })

        logger.info(f"Extracted {len(invariants)} custom invariants from {contract_name}")
        return invariants

    def _translate_to_solidity(self, expr: str, contract_name: str) -> str:
        """자연어/간이 조건식 표현식을 솔리디티 단언문 조건으로 가공합니다.

        예: 'totalAssets() == address(this).balance' -> 'target.totalAssets() == address(this).balance'
        """
        # 세미콜론이 끝에 있다면 제거
        expr = expr.rstrip(";")

        # 계약 상태 변수 및 함수 호출 앞에 'target.'을 붙이기 위한 치환 로직
        # 1. 단어 토큰들을 찾아냄
        words = re.findall(r'\b[a-zA-Z_]\w*\b', expr)

        # 2. 앞에 'target.'을 붙여선 안 되는 솔리디티 빌트인 키워드/상수/타입 리스트
        builtins = {
            "address", "uint", "uint256", "int", "int256", "bool", "bytes", "string",
            "bytes32", "this", "msg", "sender", "value", "tx", "origin", "block",
            "timestamp", "number", "difficulty", "gaslimit", "coinbase", "type",
            "max", "min", "true", "false", "keccak256", "abi", "encode", "decode",
            "require", "assert", "revert"
        }

        # 3. 각 단어가 빌트인이 아니고 숫자가 아니며, 이미 'target.'이 붙어있지 않다면 'target.'을 앞에 결합
        replaced_expr = expr
        # 문자열을 정확히 토큰 단위로 치환하기 위해 정규식 패턴을 동적으로 조합하여 교체
        # 중복 치환 방지를 위해 세트화
        for word in sorted(set(words), key=len, reverse=True):
            if word in builtins:
                continue
            if word.isdigit():
                continue

            # 단어 앞뒤 경계를 확실히 하고, 바로 앞에 'target.'이나 '.'이 붙어있지 않은 경우에만 치환
            # 예: '(?<!target\.)(?<!\.)\btotalAssets\b'
            pattern = rf'(?<!target\.)(?<!\.)\b{word}\b'
            replaced_expr = re.sub(pattern, f"target.{word}", replaced_expr)

        return replaced_expr
