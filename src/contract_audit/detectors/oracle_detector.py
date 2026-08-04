"""Oracle manipulation pattern detector."""

from __future__ import annotations

import logging
import re

from ..core.models import (
    AuditContext,
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)

logger = logging.getLogger(__name__)

CHAINLINK_FUNCTIONS = {
    "latestRoundData",
    "latestAnswer",
    "getRoundData",
}

UNISWAP_PRICE_FUNCTIONS = {
    "getReserves",
    "slot0",
    "observe",
    "consult",
}

STALENESS_INDICATORS = {
    "updatedAt",
    "answeredInRound",
    "MAX_STALENESS",
    "STALE_PRICE_DELAY",
    "heartbeat",
}

TWAP_INDICATORS = {
    "observe",
    "consult",
    "TWAP",
    "twap",
    "timeWeighted",
    "period",
    "windowSize",
}


def _get_line_number(source: str, byte_offset: int) -> int:
    """Convert byte offset to a 1-based line number."""
    if not source:
        return 1
    encoded = source.encode('utf-8')
    target_slice = encoded[:byte_offset]
    return target_slice.decode('utf-8', errors='ignore').count('\n') + 1


class OracleDetector:
    """Detects oracle manipulation vulnerabilities."""

    name = "oracle_detector"
    category = "oracle-manipulation"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        """Detect oracle-related vulnerabilities."""
        findings: list[Finding] = []

        max_staleness = context.config.oracle_max_staleness_seconds
        has_ast = context.ast_trees and len(context.ast_trees) > 0

        for filename, source in context.contract_sources.items():
            if has_ast and filename in context.ast_trees:
                ast = context.ast_trees[filename]
                findings.extend(self._check_chainlink_staleness_ast(filename, ast, source, max_staleness))
            else:
                findings.extend(self._check_chainlink_staleness(filename, source, max_staleness))

            findings.extend(self._check_uniswap_spot_price(filename, source))
            findings.extend(self._check_round_completeness(filename, source))
            findings.extend(self._check_oracle_decimals(filename, source))

        logger.info(f"Oracle detector found {len(findings)} findings")
        return findings

    def _check_chainlink_staleness_ast(
        self, filename: str, ast: dict[str, Any], source: str, max_staleness: int
    ) -> list[Finding]:
        """Check for Chainlink price reads without staleness validation using AST."""
        findings = []
        from ..analyzers.ast_parser.visitors import walk_ast

        functions = []
        def collect_functions(node: dict[str, Any]) -> None:
            if node.get("nodeType") == "FunctionDefinition":
                functions.append(node)
        walk_ast(ast, collect_functions)

        for func in functions:
            body = func.get("body")
            if not body:
                continue

            func_name = func.get("name", "")
            chainlink_calls = []

            def find_chainlink_calls(n: dict[str, Any]) -> None:
                if n.get("nodeType") == "FunctionCall":
                    expr = n.get("expression", {})
                    if expr.get("nodeType") == "MemberAccess":
                        member = expr.get("memberName", "")
                        if member in CHAINLINK_FUNCTIONS:
                            chainlink_calls.append((n, member))
            walk_ast(body, find_chainlink_calls)

            for call_node, fn_name in chainlink_calls:
                src_parts = call_node.get("src", "").split(":")
                offset = int(src_parts[0]) if src_parts else 0
                line = _get_line_number(source, offset)

                bound_var_names = []

                def find_binding_statement(parent_node: dict[str, Any]) -> None:
                    if parent_node.get("nodeType") == "VariableDeclarationStatement":
                        # Checks if the initialization node matches the target function call node
                        init_val = parent_node.get("initialValue", {})
                        is_match = False
                        if init_val:
                            if init_val.get("id") == call_node.get("id"):
                                is_match = True
                            elif init_val.get("nodeType") == "TupleExpression":
                                # Handle calls nested inside a tuple conversion or assignment
                                components = init_val.get("components", [])
                                for comp in components:
                                    if comp and comp.get("id") == call_node.get("id"):
                                        is_match = True

                        if is_match:
                            decls = parent_node.get("declarations", [])
                            # For latestRoundData, 4th element (index 3) is updatedAt
                            if len(decls) > 3 and fn_name == "latestRoundData":
                                target_decl = decls[3]
                                if target_decl and target_decl.get("name"):
                                    bound_var_names.append(target_decl.get("name"))
                            else:
                                for decl in decls:
                                    if decl and decl.get("name"):
                                        bound_var_names.append(decl.get("name"))
                
                walk_ast(body, find_binding_statement)

                has_staleness = False
                if bound_var_names:
                    def verify_staleness_usage(n: dict[str, Any]) -> None:
                        nonlocal has_staleness
                        if n.get("nodeType") == "BinaryOperation":
                            left = n.get("leftExpression", {})
                            right = n.get("rightExpression", {})
                            l_name = left.get("name", "")
                            r_name = right.get("name", "")
                            
                            if l_name in bound_var_names or r_name in bound_var_names:
                                has_staleness = True
                            
                            def check_nested_member(expr: dict[str, Any]) -> bool:
                                if expr.get("nodeType") == "MemberAccess":
                                    return expr.get("memberName") in bound_var_names or check_nested_member(expr.get("expression", {}))
                                return False
                            if check_nested_member(left) or check_nested_member(right):
                                has_staleness = True

                    walk_ast(body, verify_staleness_usage)

                if not has_staleness:
                    findings.append(
                        Finding(
                            title=f"Chainlink Oracle: Missing Staleness Check ({fn_name}) [AST]",
                            description=(
                                f"`{fn_name}()` is called in `{func_name}()` at line {line} without validating "
                                "`updatedAt` for staleness. "
                                "If the oracle stops updating, stale prices could be used, "
                                f"enabling price manipulation attacks.\n\n"
                                "**Fix:**\n"
                                "```solidity\n"
                                "(, int256 price, , uint256 updatedAt,) = oracle.latestRoundData();\n"
                                f"require(block.timestamp - updatedAt <= {max_staleness}, 'Stale price');\n"
                                "```"
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.ORACLE_MANIPULATION,
                            source=self.name,
                            detector_name="chainlink-staleness",
                            locations=[
                                SourceLocation(
                                    file=filename,
                                    start_line=line,
                                    end_line=line,
                                    function=func_name,
                                )
                            ],
                            metadata={"oracle_function": fn_name, "max_staleness": max_staleness},
                        )
                    )

        return findings

    def _check_chainlink_staleness(
        self, filename: str, source: str, max_staleness: int
    ) -> list[Finding]:
        """Check for Chainlink price reads without staleness validation."""
        findings = []
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            for fn in CHAINLINK_FUNCTIONS:
                if re.search(rf'\b{re.escape(fn)}\s*\(', line):
                    # Skip function declarations (not calls)
                    if re.search(r'\bfunction\s+\w', line):
                        continue
                    # Look at enclosing function body (strip comments first)
                    func_body = self._extract_function_body(lines, i - 1)
                    func_code = re.sub(r'//.*$', '', func_body, flags=re.MULTILINE)
                    func_code = re.sub(r'/\*.*?\*/', '', func_code, flags=re.DOTALL)

                    has_staleness = any(
                        indicator in func_code for indicator in STALENESS_INDICATORS
                    )

                    if not has_staleness:
                        findings.append(
                            Finding(
                                title=f"Chainlink Oracle: Missing Staleness Check ({fn})",
                                description=(
                                    f"`{fn}()` is called without checking "
                                    "`updatedAt` for staleness. "
                                    "If the oracle stops updating, stale prices "
                                    f"older than {max_staleness}s could be used, "
                                    "enabling price manipulation attacks.\n\n"
                                    "**Fix:**\n"
                                    "```solidity\n"
                                    "(, int256 price, , uint256 updatedAt,) = "
                                    "oracle.latestRoundData();\n"
                                    "require(block.timestamp - updatedAt <= "
                                    f"{max_staleness}, 'Stale price');\n"
                                    "```"
                                ),
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                category=FindingCategory.ORACLE_MANIPULATION,
                                source=self.name,
                                detector_name="chainlink-staleness",
                                locations=[
                                    SourceLocation(
                                        file=filename,
                                        start_line=i,
                                        end_line=i,
                                    )
                                ],
                                metadata={"oracle_function": fn},
                            )
                        )
        return findings

    @staticmethod
    def _extract_function_body(lines: list[str], call_line_idx: int) -> str:
        """Extract the enclosing function body for a given line index."""
        # Walk backwards to find the function start
        func_start = call_line_idx
        for i in range(call_line_idx, max(0, call_line_idx - 50), -1):
            if re.search(r'\bfunction\s+\w', lines[i]):
                func_start = i
                break

        # Extract up to the closing brace of the function
        depth = 0
        started = False
        body_lines = []
        for i in range(func_start, min(len(lines), func_start + 100)):
            body_lines.append(lines[i])
            for char in lines[i]:
                if char == "{":
                    depth += 1
                    started = True
                elif char == "}" and started:
                    depth -= 1
                    if depth == 0:
                        return "\n".join(body_lines)
        return "\n".join(body_lines)

    def _check_uniswap_spot_price(self, filename: str, source: str) -> list[Finding]:
        """Check for Uniswap spot price reads vulnerable to flash loan manipulation."""
        findings = []
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            if re.search(r'\bgetReserves\s*\(', line):
                # Check if TWAP is used in the same function
                context_block = "\n".join(lines[max(0, i - 10):min(len(lines), i + 30)])
                has_twap = any(t in context_block for t in TWAP_INDICATORS)

                if not has_twap:
                    findings.append(
                        Finding(
                            title="Uniswap V2 Spot Price: Flash Loan Manipulation Risk",
                            description=(
                                "`getReserves()` returns the current spot price, which can be "
                                "manipulated within a single transaction via flash loans. "
                                "Attackers can temporarily skew reserves to obtain favorable "
                                "pricing, then repay the flash loan in the same block.\n\n"
                                "**Fix:** Use Uniswap V3's TWAP via `observe()` or a dedicated "
                                "TWAP oracle with a 30-minute minimum period."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.ORACLE_MANIPULATION,
                            source=self.name,
                            detector_name="uniswap-spot-price",
                            locations=[
                                SourceLocation(
                                    file=filename,
                                    start_line=i,
                                    end_line=i,
                                )
                            ],
                        )
                    )

            if re.search(r'\.slot0\s*\(', line):
                context_block = "\n".join(lines[max(0, i - 5):min(len(lines), i + 20)])
                has_twap = any(t in context_block for t in TWAP_INDICATORS)

                if not has_twap:
                    findings.append(
                        Finding(
                            title="Uniswap V3 slot0: Spot Price Manipulation Risk",
                            description=(
                                "`slot0()` returns the current spot price from Uniswap V3, "
                                "which can be manipulated within a single transaction. "
                                "Use `observe()` with a TWAP period instead."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.ORACLE_MANIPULATION,
                            source=self.name,
                            detector_name="uniswap-v3-slot0",
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

    def _check_round_completeness(self, filename: str, source: str) -> list[Finding]:
        """Check for missing answeredInRound validation in Chainlink reads."""
        findings = []
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            if "latestRoundData" in line and not re.search(r'\bfunction\s+\w', line):
                func_body = self._extract_function_body(lines, i - 1)
                func_code = re.sub(r'//.*$', '', func_body, flags=re.MULTILINE)
                func_code = re.sub(r'/\*.*?\*/', '', func_code, flags=re.DOTALL)
                has_round_check = "answeredInRound" in func_code

                if not has_round_check:
                    findings.append(
                        Finding(
                            title="Chainlink: Missing Round Completeness Check",
                            description=(
                                "`latestRoundData()` is used without checking "
                                "`answeredInRound >= roundId`. "
                                "During Chainlink aggregator downtime, it can "
                                "return data from a previous incomplete round, "
                                "providing stale/incorrect prices."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            category=FindingCategory.ORACLE_MANIPULATION,
                            source=self.name,
                            detector_name="chainlink-round-completeness",
                            locations=[
                                SourceLocation(
                                    file=filename,
                                    start_line=i,
                                    end_line=i,
                                )
                            ],
                        )
                    )
                    break  # Only report once per file

        return findings

    def _check_oracle_decimals(self, filename: str, source: str) -> list[Finding]:
        """Check for hardcoded oracle decimals instead of querying decimals()."""
        findings = []
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            # Check for hardcoded 1e8 or 10**8 near oracle reads
            if re.search(r'1e8|10\*\*8|100000000', line):
                context_block = "\n".join(lines[max(0, i - 5):min(len(lines), i + 5)])
                if any(fn in context_block for fn in CHAINLINK_FUNCTIONS):
                    has_decimals_call = "decimals()" in context_block
                    if not has_decimals_call:
                        findings.append(
                            Finding(
                                title="Hardcoded Oracle Decimals",
                                description=(
                                    "Oracle price scaling uses hardcoded decimals (1e8) instead of "
                                    "calling `oracle.decimals()`. Different Chainlink feeds have "
                                    "different decimal places (e.g., ETH/USD is 8, some are 18)."
                                ),
                                severity=Severity.LOW,
                                confidence=Confidence.LOW,
                                category=FindingCategory.ORACLE_MANIPULATION,
                                source=self.name,
                                detector_name="hardcoded-oracle-decimals",
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
