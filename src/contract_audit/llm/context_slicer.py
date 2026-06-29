"""Solidity source code context slicer for LLM analysis.

Filters and compresses contract sources to fit LLM context limits,
reducing token costs while preserving dependent structure and interface definitions.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from ..core.models import AuditContext, Finding

logger = logging.getLogger(__name__)


class ContextSlicer:
    """Solidity 소스 코드의 의존성 트리를 기반으로 컨텍스트를 슬라이싱/압축하는 유틸리티."""

    def __init__(self, context_window: int = 50) -> None:
        self.context_window = context_window

    def get_sliced_context(
        self,
        finding: Finding,
        context: AuditContext,
        max_total_lines: int = 600,
    ) -> str:
        """Finding과 연관성이 높은 최소한의 소스 코드 슬라이스를 마크다운 형태로 반환합니다.

        - Finding이 발생한 파일: 취약점 행(line) 기준 앞뒤로 50줄의 상세 본문을 유지.
        - 직접 임포트된 파일들: 함수 바디를 제거하고 상태 변수 및 함수 선언부(인터페이스 뼈대)만 남김.
        """
        if not finding.locations:
            return ""

        target_file = finding.locations[0].file
        # 경로 차이가 있을 수 있으므로 표준 매칭 시도
        matched_target = self._resolve_file_key(target_file, context.contract_sources)
        if not matched_target:
            return ""

        # 1. 의존 파일 수집 (import_graph 활용)
        dependent_files = set()
        if context.import_graph and matched_target in context.import_graph:
            for dep in context.import_graph[matched_target]:
                resolved_dep = self._resolve_file_key(dep, context.contract_sources)
                if resolved_dep:
                    dependent_files.add(resolved_dep)

        # 2. 타겟 파일 코드 조각 추출
        target_src = context.contract_sources[matched_target]
        start_line = finding.locations[0].start_line
        end_line = finding.locations[0].end_line
        
        target_slice = self._slice_target_file(
            target_src, start_line, end_line, matched_target
        )

        # 3. 의존 파일들의 스켈레톤(뼈대) 생성 및 누적
        slices = [target_slice]
        for dep in dependent_files:
            dep_src = context.contract_sources[dep]
            skeleton = self._generate_contract_skeleton(dep_src, dep)
            slices.append(skeleton)

        # 4. 하나의 컨텍스트 문자열로 병합
        merged_context = "\n\n".join(slices)
        
        # 병합된 코드가 여전히 너무 길 경우, 세부적인 라인 압축 수행
        merged_lines = merged_context.splitlines()
        if len(merged_lines) > max_total_lines:
            logger.info(
                f"Merged context size ({len(merged_lines)} lines) exceeds threshold. Slicing further."
            )
            # 타겟 영역만 더 극적으로 한정
            target_slice_strict = self._slice_target_file(
                target_src, start_line, end_line, matched_target, strict=True
            )
            slices = [target_slice_strict]
            for dep in dependent_files:
                dep_src = context.contract_sources[dep]
                skeleton = self._generate_contract_skeleton(dep_src, dep)
                slices.append(skeleton)
            merged_context = "\n\n".join(slices)

        return merged_context

    def _resolve_file_key(self, path: str, sources: dict[str, str]) -> str | None:
        """상대/절대 경로 불일치를 극복하고 sources의 키를 해석합니다."""
        if path in sources:
            return path
        basename = path.rsplit("/", 1)[-1]
        for key in sources:
            if key.rsplit("/", 1)[-1] == basename or key.endswith(path) or path.endswith(key):
                return key
        return None

    def _slice_target_file(
        self, source: str, start: int, end: int, filename: str, strict: bool = False
    ) -> str:
        """취약점 주변 줄번호 영역을 중심으로 코드를 슬라이싱합니다."""
        lines = source.splitlines()
        window = 20 if strict else self.context_window
        
        # 1-based index 보정
        start_idx = max(0, start - 1 - window)
        end_idx = min(len(lines), end + window)

        sliced_lines = []
        if start_idx > 0:
            sliced_lines.append(f"// ... (이전 소스 코드 생략 - {filename}) ...")
            
        for i in range(start_idx, end_idx):
            line_num = i + 1
            marker = ">>>" if start <= line_num <= end else "   "
            sliced_lines.append(f"{marker} {line_num:4d} | {lines[i]}")
            
        if end_idx < len(lines):
            sliced_lines.append(f"// ... (이후 소스 코드 생략 - {filename}) ...")

        code_block = "\n".join(sliced_lines)
        return f"### Vulnerable Target File: {filename}\n```solidity\n{code_block}\n```"

    def _generate_contract_skeleton(self, source: str, filename: str) -> str:
        """함수 바디를 비우고 상태 변수, 이벤트, 함수 시그니처만 남기는 스켈레톤 추출."""
        lines = source.splitlines()
        skeleton_lines = []
        
        # 함수 바디 매칭 및 생성을 위한 괄호 깊이 추적 상태 기계
        in_function = False
        bracket_depth = 0
        
        for line in lines:
            stripped = line.strip()
            
            # 주석 및 빈줄 유지
            if not stripped or stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                # 단, 너무 많은 빈줄은 생략
                if skeleton_lines and not skeleton_lines[-1]:
                    continue
                skeleton_lines.append(line)
                continue

            # 함수 정의의 시작 부분 탐색
            if not in_function:
                if re.match(r'\b(function|constructor|fallback|receive)\b', stripped):
                    # 만약 한 줄짜리 함수 선언이고 끝이 세미콜론(인터페이스/추상메소드)이면 그대로 포함
                    if stripped.endswith(";"):
                        skeleton_lines.append(line)
                        continue
                    
                    # 중괄호가 열렸는지 확인
                    skeleton_lines.append(line)
                    if "{" in stripped:
                        in_function = True
                        bracket_depth = stripped.count("{") - stripped.count("}")
                        if bracket_depth <= 0:
                            # 한 줄에 완성된 경우 (예: function f() {} )
                            in_function = False
                            bracket_depth = 0
                    else:
                        # 다음 줄에서 괄호가 열릴 가능성이 있음
                        in_function = True
                        bracket_depth = 0
                else:
                    # 함수 외부의 선언(상수, 상태 변수, 이벤트, 에러, 구조체 등)은 그대로 유지
                    skeleton_lines.append(line)
            else:
                # 함수 본문 스킵 중인 경우
                bracket_depth += line.count("{") - line.count("}")
                if bracket_depth <= 0:
                    # 함수의 끝을 발견
                    # 함수 본문 축약 표시 삽입
                    indent = " " * (len(line) - len(stripped))
                    skeleton_lines.append(f"{indent}    // [함수 본문 구현부 생략 (토큰 절약)]")
                    skeleton_lines.append(f"{indent}}}")
                    in_function = False
                    bracket_depth = 0
                    
        code_block = "\n".join(skeleton_lines)
        # 빈 줄 정돈
        code_block = re.sub(r'\n{3,}', '\n\n', code_block)
        return f"### Dependent Contract Interface Skeleton: {filename}\n```solidity\n{code_block}\n```"
