"""AST-based analysis using solc output."""

from __future__ import annotations

import logging
import re
from typing import Any

from ...core.models import (
    AuditContext,
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)
from ...utils.solc import compile_contracts, extract_ast_trees, extract_storage_layouts
from .visitors import (
    walk_ast,
)

logger = logging.getLogger(__name__)


class ASTAnalyzer:
    """Analyzes Solidity contracts via the solc AST.

    Extracts AST trees and performs pattern-based analysis for
    common vulnerability patterns.
    """

    name = "ast_parser"

    def is_available(self) -> bool:
        from ...utils.solc import solc_available
        return solc_available()

    async def analyze(self, context: AuditContext) -> list[Finding]:
        """Run AST analysis on all source files."""
        findings: list[Finding] = []

        if not context.contract_sources:
            logger.warning("No source files to analyze")
            return findings

        # Compile if not already done
        if not context.ast_trees:
            try:
                output = await compile_contracts(
                    context.project_path,
                    context.contract_sources,
                    context.config.solidity_version,
                )
                if output:
                    context.ast_trees = extract_ast_trees(output)
                    context.storage_layouts = extract_storage_layouts(output)
                    context.compilation_artifacts = output
                    logger.info(f"Compiled {len(context.ast_trees)} files")
            except Exception as e:
                logger.warning(f"Compilation failed: {e}. Proceeding with regex-based analysis.")

        # Run AST-based checks
        for filename, ast in context.ast_trees.items():
            try:
                source = context.contract_sources.get(filename, "")
                findings.extend(self._check_unchecked_returns(filename, ast, source))
                findings.extend(self._check_missing_zero_check(filename, ast, source))
                findings.extend(self._check_tx_origin(filename, ast, source))
                findings.extend(self._check_block_timestamp(filename, ast))
            except Exception as e:
                logger.warning(f"AST analysis failed for {filename}: {e}")

        # Fallback: regex-based analysis on source
        for filename, source in context.contract_sources.items():
            findings.extend(self._regex_checks(filename, source))

        logger.info(f"AST analyzer found {len(findings)} findings")
        return findings

    def _get_line_number(self, source: str, byte_offset: int) -> int:
        """Convert byte offset to a 1-based line number."""
        if not source:
            return 1
        # Encode to utf-8 bytes to correctly map byte offsets from AST
        encoded = source.encode('utf-8')
        target_slice = encoded[:byte_offset]
        return target_slice.decode('utf-8', errors='ignore').count('\n') + 1

    def _check_unchecked_returns(self, filename: str, ast: dict[str, Any], source: str) -> list[Finding]:
        """Check for unchecked low-level call return values."""
        findings: list[Finding] = []
        calls_found: list[dict[str, Any]] = []

        def collect_calls(node: dict[str, Any]) -> None:
            if node.get("nodeType") == "ExpressionStatement":
                expr = node.get("expression", {})
                if expr.get("nodeType") == "FunctionCall":
                    inner = expr.get("expression", {})
                    member = inner.get("memberName", "")
                    if member in ("call", "delegatecall", "staticcall", "send"):
                        calls_found.append(node)

        walk_ast(ast, collect_calls)

        for call in calls_found:
            src = call.get("src", "").split(":")
            offset = int(src[0]) if src else 0
            line = self._get_line_number(source, offset)
            findings.append(
                Finding(
                    title="Unchecked Low-Level Call Return Value",
                    description=(
                        "Low-level call return value is not checked. "
                        "Failed calls will silently continue execution."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category=FindingCategory.UNCHECKED_RETURN,
                    source=self.name,
                    detector_name="unchecked-return",
                    locations=[
                        SourceLocation(
                            file=filename,
                            start_line=max(1, line),
                            end_line=max(1, line),
                        )
                    ],
                )
            )
        return findings

    def _check_missing_zero_check(self, filename: str, ast: dict[str, Any], source: str) -> list[Finding]:
        """Check for missing zero-address checks on address parameters."""
        findings: list[Finding] = []

        # Collect all functions
        functions: list[dict[str, Any]] = []
        def collect_functions(node: dict[str, Any]) -> None:
            if node.get("nodeType") == "FunctionDefinition":
                functions.append(node)
        walk_ast(ast, collect_functions)

        for func in functions:
            if func.get("stateMutability") in ("view", "pure") or not func.get("body"):
                continue

            # Get address params
            params = func.get("parameters", {}).get("parameters", [])
            addr_params = []
            for p in params:
                type_desc = p.get("typeDescriptions", {}).get("typeString", "")
                p_name = p.get("name", "")
                if "address" in type_desc and p_name:
                    addr_params.append(p_name)

            if not addr_params:
                continue

            body = func.get("body", {})
            checked_params: set[str] = set()

            # Helper to identify if a node is address(0) or 0
            # 노드가 address(0) 또는 0인지 판별하는 헬퍼 함수
            def is_zero_node(n: dict[str, Any]) -> bool:
                if n.get("nodeType") == "FunctionCall":
                    expr = n.get("expression", {})
                    # address(0)의 경우 nodeType이 ElementaryTypeNameExpression이고 typeName.name이 address이거나,
                    # name이 address인 경우
                    is_addr_conversion = (
                        expr.get("name") == "address" or
                        expr.get("typeName", {}).get("name") == "address" or
                        (expr.get("nodeType") == "ElementaryTypeNameExpression" and expr.get("typeName", {}).get("name") == "address")
                    )
                    arguments = n.get("arguments", [])
                    if is_addr_conversion and arguments:
                        first_arg = arguments[0]
                        if first_arg.get("nodeType") == "Literal" and str(first_arg.get("value")) in ("0", "0x0", "0x0000000000000000000000000000000000000000"):
                            return True
                if n.get("nodeType") == "Literal" and str(n.get("value")) in ("0", "0x0", "0x0000000000000000000000000000000000000000"):
                    return True
                return False

            # Step 1: Collect all checked parameters in binary conditions
            # 1단계: 바이너리 조건문에서 검증된 파라미터 수집
            def find_zero_guards(node: dict[str, Any]) -> None:
                if node.get("nodeType") == "BinaryOperation":
                    operator = node.get("operator", "")
                    if operator in ("==", "!="):
                        left = node.get("leftExpression", {})
                        right = node.get("rightExpression", {})

                        l_name = left.get("name", "")
                        r_name = right.get("name", "")

                        if l_name in addr_params and is_zero_node(right):
                            checked_params.add(l_name)
                        elif r_name in addr_params and is_zero_node(left):
                            checked_params.add(r_name)
            walk_ast(body, find_zero_guards)

            # Step 2: Detect assignments of unchecked parameters to state vars
            # 2단계: 검증되지 않은 파라미터가 상태 변수에 할당되는지 감지
            def find_unprotected_assignments(node: dict[str, Any]) -> None:
                if node.get("nodeType") == "Assignment":
                    left = node.get("leftHandSide", {})
                    right = node.get("rightHandSide", {})

                    r_name = right.get("name", "")
                    if r_name in addr_params and r_name not in checked_params:
                        l_name = left.get("name", "")
                        if l_name:
                            src = node.get("src", "0:0:0").split(":")
                            offset = int(src[0]) if src else 0
                            line = self._get_line_number(source, offset)
                            findings.append(
                                Finding(
                                    title="Missing Zero Address Validation",
                                    description=(
                                        f"Address parameter `{r_name}` is assigned to state variable `{l_name}` "
                                        f"without a zero-address validation check. This can result in locking the "
                                        f"contract state or blocking transactions if set to `address(0)`."
                                    ),
                                    severity=Severity.LOW,
                                    confidence=Confidence.HIGH,
                                    category=FindingCategory.ACCESS_CONTROL,
                                    source=self.name,
                                    detector_name="missing-zero-check",
                                    locations=[
                                        SourceLocation(
                                            file=filename,
                                            start_line=max(1, line),
                                            end_line=max(1, line),
                                            function=func.get("name", ""),
                                        )
                                    ],
                                )
                            )
            walk_ast(body, find_unprotected_assignments)

        return findings

    def _check_tx_origin(self, filename: str, ast: dict[str, Any], source: str) -> list[Finding]:
        """Detect tx.origin usage for authentication."""
        findings = []
        tx_origin_nodes: list[dict[str, Any]] = []

        def find_tx_origin(node: dict[str, Any]) -> None:
            if (
                node.get("nodeType") == "MemberAccess"
                and node.get("memberName") == "origin"
                and node.get("expression", {}).get("name") == "tx"
            ):
                tx_origin_nodes.append(node)

        walk_ast(ast, find_tx_origin)

        for node in tx_origin_nodes:
            src = node.get("src", "0:0:0").split(":")
            char_pos = int(src[0]) if src else 0
            line = self._get_line_number(source, char_pos)
            findings.append(
                Finding(
                    title="Use of tx.origin for Authentication",
                    description=(
                        "tx.origin is used for authentication. This is dangerous because "
                        "a malicious contract can trick a legitimate user into calling it, "
                        "and the tx.origin check will pass."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.ACCESS_CONTROL,
                    source=self.name,
                    detector_name="tx-origin",
                    locations=[
                        SourceLocation(
                            file=filename,
                            start_line=max(1, line),
                            end_line=max(1, line),
                        )
                    ],
                )
            )
        return findings

    def _check_block_timestamp(self, filename: str, ast: dict[str, Any]) -> list[Finding]:
        """Detect dangerous use of block.timestamp."""
        findings = []
        timestamp_in_condition: list[dict[str, Any]] = []

        def find_timestamp(node: dict[str, Any]) -> None:
            if (
                node.get("nodeType") == "MemberAccess"
                and node.get("memberName") == "timestamp"
                and node.get("expression", {}).get("name") == "block"
            ):
                timestamp_in_condition.append(node)

        walk_ast(ast, find_timestamp)

        if len(timestamp_in_condition) > 2:
            findings.append(
                Finding(
                    title="Timestamp Dependence",
                    description=(
                        "Multiple uses of block.timestamp detected. Miners can manipulate "
                        "timestamps by ~900 seconds, which can affect time-sensitive logic."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    category=FindingCategory.OTHER,
                    source=self.name,
                    detector_name="timestamp-dependence",
                    locations=[
                        SourceLocation(file=filename, start_line=1, end_line=1)
                    ],
                )
            )
        return findings

    def _regex_checks(self, filename: str, source: str) -> list[Finding]:
        """Fallback regex-based checks when AST is unavailable."""
        findings = []
        lines = source.splitlines()

        patterns = [
            (
                r"\bassembly\s*\{",
                "Inline Assembly Usage",
                "Inline assembly detected. Review carefully for security implications.",
                Severity.INFORMATIONAL,
                Confidence.HIGH,
                FindingCategory.OTHER,
                "inline-assembly",
            ),
            (
                r"\bselfdestruct\s*\(",
                "Use of selfdestruct",
                "selfdestruct() can permanently destroy the contract.",
                Severity.HIGH,
                Confidence.HIGH,
                FindingCategory.ACCESS_CONTROL,
                "selfdestruct",
            ),
            (
                r"\bdelegatecall\s*\(",
                "Use of delegatecall",
                "delegatecall executes code in the context of the calling contract. "
                "Ensure the target is trusted.",
                Severity.MEDIUM,
                Confidence.MEDIUM,
                FindingCategory.PROXY_VULNERABILITY,
                "delegatecall",
            ),
        ]

        for pattern, title, description, severity, confidence, category, detector in patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    findings.append(
                        Finding(
                            title=title,
                            description=description,
                            severity=severity,
                            confidence=confidence,
                            category=category,
                            source=self.name,
                            detector_name=detector,
                            locations=[
                                SourceLocation(
                                    file=filename,
                                    start_line=i,
                                    end_line=i,
                                )
                            ],
                        )
                    )

        return findings
