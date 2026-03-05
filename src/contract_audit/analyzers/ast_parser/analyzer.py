"""AST-based analysis using solc output."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from ...core.exceptions import AnalyzerError
from ...core.models import (
    AuditContext,
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)
from ...utils.solc import compile_contracts, extract_ast_trees, extract_storage_layouts
from ..base import AnalyzerProtocol
from .visitors import (
    FunctionCallCollector,
    InheritanceCollector,
    ModifierCollector,
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
                findings.extend(self._check_unchecked_returns(filename, ast))
                findings.extend(self._check_missing_zero_check(filename, ast))
                findings.extend(self._check_tx_origin(filename, ast))
                findings.extend(self._check_block_timestamp(filename, ast))
            except Exception as e:
                logger.warning(f"AST analysis failed for {filename}: {e}")

        # Fallback: regex-based analysis on source
        for filename, source in context.contract_sources.items():
            findings.extend(self._regex_checks(filename, source))

        logger.info(f"AST analyzer found {len(findings)} findings")
        return findings

    def _check_unchecked_returns(self, filename: str, ast: dict) -> list[Finding]:
        """Check for unchecked low-level call return values."""
        findings = []
        calls_found: list[dict] = []

        def collect_calls(node: dict) -> None:
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
            line = int(src[0]) // 100 if src else 0  # Rough estimate
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

    def _check_missing_zero_check(self, filename: str, ast: dict) -> list[Finding]:
        """Check for missing zero-address checks on address parameters."""
        findings = []
        # Look for functions setting address state variables without zero check
        addr_assignments: list[dict] = []

        def find_address_assigns(node: dict) -> None:
            if node.get("nodeType") == "Assignment":
                right = node.get("rightHandSide", {})
                if right.get("nodeType") == "Identifier":
                    type_name = node.get("typeDescriptions", {}).get("typeString", "")
                    if "address" in type_name:
                        addr_assignments.append(node)

        walk_ast(ast, find_address_assigns)
        # Would need full function context to check for zero-address require
        # Simplified check: just report if assignments exist without require nearby
        return findings  # Complex analysis deferred to Slither

    def _check_tx_origin(self, filename: str, ast: dict) -> list[Finding]:
        """Detect tx.origin usage for authentication."""
        findings = []
        tx_origin_nodes: list[dict] = []

        def find_tx_origin(node: dict) -> None:
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
                            start_line=max(1, char_pos // 50),  # rough line estimate
                            end_line=max(1, char_pos // 50),
                        )
                    ],
                )
            )
        return findings

    def _check_block_timestamp(self, filename: str, ast: dict) -> list[Finding]:
        """Detect dangerous use of block.timestamp."""
        findings = []
        timestamp_in_condition: list[dict] = []

        def find_timestamp(node: dict) -> None:
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
