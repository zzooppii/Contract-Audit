"""Reentrancy vulnerability detector.

Detects CEI violations, cross-function reentrancy, missing reentrancy guards,
and read-only reentrancy patterns.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from ..core.models import (
    AuditContext,
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)
from .utils import extract_functions, strip_comments, strip_interfaces

logger = logging.getLogger(__name__)

# Patterns indicating external calls that can trigger reentrancy
EXTERNAL_CALL_PATTERNS = [
    r'\.call\s*\{?\s*value\s*:',       # .call{value: ...}
    r'\.call\s*\(',                      # .call(...)
    r'\.transfer\s*\(',                  # .transfer(...)
    r'\.send\s*\(',                      # .send(...)
    r'\.safeTransfer\s*\(',             # safeTransfer
    r'\.safeTransferFrom\s*\(',         # safeTransferFrom
]

ETH_TRANSFER_PATTERNS = [
    r'\.call\s*\{?\s*value\s*:',
    r'\.transfer\s*\(',
    r'\.send\s*\(',
]

# State variable assignment patterns (after stripping comments)
STATE_UPDATE_PATTERN = re.compile(
    r'\b(\w+)\s*(?:\[.*?\])?\s*(?:=|\+=|-=|\*=|/=)\s*'
)

# Reentrancy guard modifiers
REENTRANCY_GUARD_PATTERNS = [
    r'\bnonReentrant\b',
    r'\bnoReentrant\b',
    r'\breentrancyGuard\b',
    r'\block\b',
    r'\b_locked\b',
    r'\b_notEntered\b',
]


def _get_line_number(source: str, byte_offset: int) -> int:
    """Convert byte offset to a 1-based line number."""
    if not source:
        return 1
    encoded = source.encode('utf-8')
    target_slice = encoded[:byte_offset]
    return target_slice.decode('utf-8', errors='ignore').count('\n') + 1


class ReentrancyDetector:
    """Detects reentrancy vulnerabilities in Solidity contracts."""

    name = "reentrancy_detector"
    category = "reentrancy"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        """Run all reentrancy checks on contract sources."""
        findings: list[Finding] = []

        has_ast = context.ast_trees and len(context.ast_trees) > 0

        for filename, source in context.contract_sources.items():
            clean = strip_comments(source)
            clean = strip_interfaces(clean)
            functions = extract_functions(clean)

            if has_ast and filename in context.ast_trees:
                ast = context.ast_trees[filename]
                findings.extend(self._check_cei_violation_ast(filename, ast, source))
            else:
                findings.extend(self._check_cei_violation(filename, functions))

            findings.extend(self._check_cross_function_reentrancy(filename, functions))
            findings.extend(self._check_missing_reentrancy_guard(filename, functions))
            findings.extend(self._check_read_only_reentrancy(filename, clean, functions))

        logger.info(f"Reentrancy detector found {len(findings)} findings")
        return findings

    def _check_cei_violation(
        self, filename: str, functions: list[dict[str, Any]]
    ) -> list[Finding]:
        """Detect Check-Effects-Interactions pattern violations.

        A CEI violation occurs when state variables are updated AFTER an external call.
        """
        findings: list[Finding] = []

        for func in functions:
            if func['is_view_pure']:
                continue

            body_lines = func['body'].splitlines()
            external_call_line = -1

            for idx, line in enumerate(body_lines):
                # Look for external calls
                if any(re.search(pat, line) for pat in EXTERNAL_CALL_PATTERNS):
                    external_call_line = idx

                # After an external call, check for state updates
                if external_call_line >= 0 and idx > external_call_line:
                    match = STATE_UPDATE_PATTERN.search(line)
                    if match:
                        var_name = match.group(1)
                        # Skip local variable declarations and common local names
                        esc = re.escape(var_name)
                        if re.search(
                            rf'\b(uint|int|bool|address|bytes|string|mapping)\b.*\b{esc}\b',
                            line,
                        ):
                            continue
                        local_names = (
                            'success', 'result', 'ret', 'data',
                            'amount', 'i', 'j', 'k',
                        )
                        if var_name in local_names:
                            # Check if declared locally in function
                            if re.search(
                                rf'\b(uint|int|bool|address)\d*\s+{esc}\b',
                                func['body'],
                            ):
                                continue

                        findings.append(
                            Finding(
                                title=f"CEI Violation in {func['name']}()",
                                description=(
                                    f"State variable `{var_name}` is updated "
                                    "after an external call "
                                    f"in `{func['name']}()`. This violates the "
                                    "Check-Effects-Interactions "
                                    "pattern and may allow reentrancy attacks.\n\n"
                                    "**Fix:** Move all state changes before external calls."
                                ),
                                severity=Severity.CRITICAL,
                                confidence=Confidence.HIGH,
                                category=FindingCategory.REENTRANCY,
                                source=self.name,
                                detector_name="cei-violation",
                                locations=[
                                    SourceLocation(
                                        file=filename,
                                        start_line=func['start'] + idx,
                                        end_line=func['start'] + idx,
                                        function=func['name'],
                                    )
                                ],
                                metadata={"variable": var_name},
                            )
                        )
                        break  # One finding per function

        return findings

    def _check_cei_violation_ast(
        self, filename: str, ast: dict[str, Any], source: str
    ) -> list[Finding]:
        """Detect CEI violations using exact AST node sequencing."""
        findings: list[Finding] = []
        from ..analyzers.ast_parser.visitors import walk_ast

        contracts = []
        def collect_contracts(node: dict[str, Any]) -> None:
            if node.get("nodeType") == "ContractDefinition":
                contracts.append(node)
        walk_ast(ast, collect_contracts)

        for contract in contracts:
            state_vars = set()
            for subnode in contract.get("nodes", []):
                if subnode.get("nodeType") == "VariableDeclaration" and subnode.get("stateVariable"):
                    name = subnode.get("name", "")
                    if name:
                        state_vars.add(name)

            for subnode in contract.get("nodes", []):
                if subnode.get("nodeType") == "FunctionDefinition" and subnode.get("body"):
                    func_name = subnode.get("name", "")
                    body = subnode["body"]

                    external_calls = []
                    state_writes = []

                    def find_calls_and_writes(n: dict[str, Any]) -> None:
                        # Find external calls (e.g. call, transfer, send, safeTransfer, safeTransferFrom)
                        if n.get("nodeType") == "FunctionCall":
                            expr = n.get("expression", {})
                            is_ext = False
                            if expr.get("nodeType") == "MemberAccess":
                                member = expr.get("memberName", "")
                                if member in ("call", "transfer", "send", "safeTransfer", "safeTransferFrom"):
                                    is_ext = True
                            
                            if n.get("kind") == "typeConversion":
                                is_ext = False

                            if is_ext:
                                src_parts = n.get("src", "").split(":")
                                if src_parts:
                                    offset = int(src_parts[0])
                                    external_calls.append((offset, _get_line_number(source, offset)))

                        # Find assignments to state variables
                        if n.get("nodeType") == "Assignment":
                            left = n.get("leftHandSide", {})
                            var_name = left.get("name", "")
                            if not var_name:
                                def get_id_name(inner_n: dict[str, Any]) -> str:
                                    if inner_n.get("nodeType") == "Identifier":
                                        return inner_n.get("name", "")
                                    elif inner_n.get("nodeType") == "MemberAccess":
                                        return get_id_name(inner_n.get("expression", {}))
                                    elif inner_n.get("nodeType") == "IndexAccess":
                                        return get_id_name(inner_n.get("baseExpression", {}))
                                    return ""
                                var_name = get_id_name(left)
                            
                            if var_name in state_vars:
                                src_parts = n.get("src", "").split(":")
                                if src_parts:
                                    offset = int(src_parts[0])
                                    state_writes.append((offset, _get_line_number(source, offset), var_name))

                        # Find unary operations changing state variables (e.g., ++, --)
                        elif n.get("nodeType") == "UnaryOperation":
                            op = n.get("operator", "")
                            if op in ("++", "--"):
                                sub_expr = n.get("subExpression", {})
                                var_name = sub_expr.get("name", "")
                                if not var_name and sub_expr.get("nodeType") == "IndexAccess":
                                    def get_id_name(inner_n: dict[str, Any]) -> str:
                                        if inner_n.get("nodeType") == "Identifier":
                                            return inner_n.get("name", "")
                                        elif inner_n.get("nodeType") == "IndexAccess":
                                            return get_id_name(inner_n.get("baseExpression", {}))
                                        return ""
                                    var_name = get_id_name(sub_expr)
                                
                                if var_name in state_vars:
                                    src_parts = n.get("src", "").split(":")
                                    if src_parts:
                                        offset = int(src_parts[0])
                                        state_writes.append((offset, _get_line_number(source, offset), var_name))

                    walk_ast(body, find_calls_and_writes)

                    # Trigger finding if a state write offset exceeds an external call offset
                    for call_offset, call_line in external_calls:
                        for write_offset, write_line, var_name in state_writes:
                            if write_offset > call_offset:
                                findings.append(
                                    Finding(
                                        title=f"CEI Violation in {func_name}() [AST]",
                                        description=(
                                            f"State variable `{var_name}` is updated at line {write_line} "
                                            f"after an external call at line {call_line} in `{func_name}()`. This violates the "
                                            "Check-Effects-Interactions pattern and may allow reentrancy attacks.\n\n"
                                            "**Fix:** Move all state changes before external calls."
                                        ),
                                        severity=Severity.CRITICAL,
                                        confidence=Confidence.HIGH,
                                        category=FindingCategory.REENTRANCY,
                                        source=self.name,
                                        detector_name="cei-violation",
                                        locations=[
                                            SourceLocation(
                                                file=filename,
                                                start_line=write_line,
                                                end_line=write_line,
                                                function=func_name,
                                            )
                                        ],
                                        metadata={"variable": var_name, "call_line": call_line},
                                    )
                                )
                                break
                        else:
                            continue
                        break

        return findings

    def _check_cross_function_reentrancy(
        self, filename: str, functions: list[dict[str, Any]]
    ) -> list[Finding]:
        """Detect cross-function reentrancy.

        Occurs when a function makes an external call, then another function
        reads a state variable that's modified after that call.
        """
        findings: list[Finding] = []

        # First, find functions with external calls and their post-call state writes
        post_call_writes: dict[str, set[str]] = {}
        for func in functions:
            if func['is_view_pure']:
                continue
            body_lines = func['body'].splitlines()
            after_call = False
            written_vars: set[str] = set()

            for line in body_lines:
                if any(re.search(pat, line) for pat in EXTERNAL_CALL_PATTERNS):
                    after_call = True
                if after_call:
                    match = STATE_UPDATE_PATTERN.search(line)
                    if match:
                        written_vars.add(match.group(1))

            if written_vars:
                post_call_writes[func['name']] = written_vars

        if not post_call_writes:
            return findings

        # Then find other functions that read those variables
        all_written = set()
        for vars_ in post_call_writes.values():
            all_written.update(vars_)

        for func in functions:
            if func['name'] in post_call_writes:
                continue
            for var in all_written:
                if re.search(rf'\b{re.escape(var)}\b', func['body']):
                    writer_funcs = [
                        fn for fn, vs in post_call_writes.items() if var in vs
                    ]
                    findings.append(
                        Finding(
                            title=f"Cross-function Reentrancy: {var}",
                            description=(
                                f"`{func['name']}()` reads `{var}` which is written after "
                                f"an external call in `{', '.join(writer_funcs)}()`. "
                                "An attacker could re-enter through this function during "
                                "the external call to exploit stale state.\n\n"
                                "**Fix:** Apply `nonReentrant` modifier to both functions "
                                "or update state before external calls."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            category=FindingCategory.REENTRANCY,
                            source=self.name,
                            detector_name="cross-function-reentrancy",
                            locations=[
                                SourceLocation(
                                    file=filename,
                                    start_line=func['start'],
                                    end_line=func['start'],
                                    function=func['name'],
                                )
                            ],
                            metadata={"variable": var, "writer_functions": writer_funcs},
                        )
                    )
                    break  # One finding per reader function

        return findings

    def _check_missing_reentrancy_guard(
        self, filename: str, functions: list[dict[str, Any]]
    ) -> list[Finding]:
        """Detect functions with ETH transfers or external calls missing reentrancy guards."""
        findings: list[Finding] = []

        for func in functions:
            if func['is_view_pure']:
                continue
            if func['visibility'] not in ('external', 'public'):
                continue

            has_eth_transfer = any(
                re.search(pat, func['body']) for pat in ETH_TRANSFER_PATTERNS
            )
            has_external_call = any(
                re.search(pat, func['body']) for pat in EXTERNAL_CALL_PATTERNS
            )

            if not (has_eth_transfer or has_external_call):
                continue

            has_guard = any(
                re.search(pat, func['signature'] + func['body'])
                for pat in REENTRANCY_GUARD_PATTERNS
            )

            if not has_guard:
                findings.append(
                    Finding(
                        title=f"Missing Reentrancy Guard: {func['name']}()",
                        description=(
                            f"`{func['name']}()` performs external calls or ETH transfers "
                            "but lacks a reentrancy guard (e.g., `nonReentrant` modifier).\n\n"
                            "**Fix:** Add OpenZeppelin's `ReentrancyGuard` and apply "
                            "`nonReentrant` modifier."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.REENTRANCY,
                        source=self.name,
                        detector_name="missing-reentrancy-guard",
                        locations=[
                            SourceLocation(
                                file=filename,
                                start_line=func['start'],
                                end_line=func['start'],
                                function=func['name'],
                            )
                        ],
                    )
                )

        return findings

    def _check_read_only_reentrancy(
        self, filename: str, source: str, functions: list[dict[str, Any]]
    ) -> list[Finding]:
        """Detect read-only reentrancy.

        View functions reading state that can be stale during an external call
        in another function (e.g., price oracles based on pool balances).
        """
        findings: list[Finding] = []

        # Find state vars written after external calls
        post_call_state_vars: set[str] = set()
        for func in functions:
            if func['is_view_pure']:
                continue
            body_lines = func['body'].splitlines()
            after_call = False
            for line in body_lines:
                if any(re.search(pat, line) for pat in EXTERNAL_CALL_PATTERNS):
                    after_call = True
                if after_call:
                    match = STATE_UPDATE_PATTERN.search(line)
                    if match:
                        post_call_state_vars.add(match.group(1))

        if not post_call_state_vars:
            return findings

        # Find view functions that read those state vars
        for func in functions:
            if not func['is_view_pure']:
                continue
            for var in post_call_state_vars:
                if re.search(rf'\b{re.escape(var)}\b', func['body']):
                    findings.append(
                        Finding(
                            title=f"Read-only Reentrancy Risk: {func['name']}()",
                            description=(
                                f"View function `{func['name']}()` reads `{var}` which "
                                "is updated after an external call in another function. "
                                "During reentrancy, this view function may return stale "
                                "values, affecting contracts that depend on it.\n\n"
                                "**Fix:** Ensure state is updated before external calls "
                                "or document this known limitation."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            category=FindingCategory.REENTRANCY,
                            source=self.name,
                            detector_name="read-only-reentrancy",
                            locations=[
                                SourceLocation(
                                    file=filename,
                                    start_line=func['start'],
                                    end_line=func['start'],
                                    function=func['name'],
                                )
                            ],
                            metadata={"variable": var},
                        )
                    )
                    break

        return findings
