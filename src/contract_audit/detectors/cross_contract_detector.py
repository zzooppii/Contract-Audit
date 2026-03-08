"""Cross-contract vulnerability detector.

Detects cross-contract reentrancy cycles, function shadowing in
inheritance, and interface implementation mismatches.
"""

from __future__ import annotations

import logging
import re

from .utils import strip_comments
from ..core.models import (
    AuditContext,
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)

logger = logging.getLogger(__name__)


class CrossContractDetector:
    """Detects cross-contract vulnerabilities using graph analysis."""

    name = "cross_contract_detector"
    category = "reentrancy"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        findings: list[Finding] = []

        if len(context.contract_sources) < 2:
            return findings

        # Build graphs
        from ..analyzers.cross_contract.import_resolver import ImportResolver
        from ..analyzers.cross_contract.inheritance_graph import InheritanceGraph
        from ..analyzers.cross_contract.call_graph import CallGraph

        import_graph = ImportResolver().resolve(context.contract_sources)
        inheritance_map = InheritanceGraph().build(context.contract_sources)
        call_graph_builder = CallGraph()
        call_graph = call_graph_builder.build(context.contract_sources, inheritance_map)

        # Store in context for other detectors
        context.import_graph = import_graph
        context.inheritance_map = inheritance_map
        context.call_graph = call_graph

        findings.extend(self._check_cross_contract_reentrancy(
            call_graph_builder, call_graph, context
        ))
        findings.extend(self._check_function_shadowing(
            inheritance_map, context
        ))
        findings.extend(self._check_interface_mismatch(
            inheritance_map, context
        ))

        logger.info(f"Cross-contract detector found {len(findings)} findings")
        return findings

    def _check_cross_contract_reentrancy(
        self,
        builder: "CallGraph",
        call_graph: dict[str, list[tuple[str, str]]],
        context: AuditContext,
    ) -> list[Finding]:
        """Detect A->B->A callback cycles."""
        findings: list[Finding] = []
        cycles = builder.find_cycles(call_graph)

        for cycle in cycles:
            if len(cycle) < 3:
                continue

            cycle_str = " -> ".join(cycle)
            # Find the file containing the first contract in cycle
            filename = self._find_contract_file(cycle[0], context)

            findings.append(
                Finding(
                    title=f"Cross-Contract Reentrancy Cycle: {cycle_str}",
                    description=(
                        f"Detected a potential cross-contract reentrancy cycle: "
                        f"`{cycle_str}`. Contract `{cycle[0]}` calls into "
                        f"`{cycle[1]}`, which calls back into `{cycle[0]}`, "
                        "potentially re-entering before state updates complete.\n\n"
                        "**Fix:** Apply the checks-effects-interactions pattern across "
                        "contract boundaries. Consider using reentrancy guards on both "
                        "contracts."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.MEDIUM,
                    category=FindingCategory.REENTRANCY,
                    source=self.name,
                    detector_name="cross-contract-reentrancy",
                    locations=[
                        SourceLocation(
                            file=filename or cycle[0],
                            start_line=1,
                            end_line=1,
                            contract=cycle[0],
                        )
                    ],
                )
            )

        return findings

    def _check_function_shadowing(
        self,
        inheritance_map: dict[str, list[str]],
        context: AuditContext,
    ) -> list[Finding]:
        """Detect child contracts redefining parent functions without override."""
        findings: list[Finding] = []

        # Extract functions per contract
        contract_functions: dict[str, dict[str, int]] = {}

        for filename, source in context.contract_sources.items():
            clean = strip_comments(source)
            contracts = self._extract_contracts_with_functions(clean)
            for name, funcs in contracts:
                contract_functions[name] = funcs

        for contract_name, parents in inheritance_map.items():
            if not parents:
                continue

            child_funcs = contract_functions.get(contract_name, {})

            for parent in parents:
                parent_funcs = contract_functions.get(parent, {})

                for func_name, line_num in child_funcs.items():
                    if func_name in parent_funcs:
                        # Check if override keyword is used
                        filename = self._find_contract_file(contract_name, context)
                        if filename:
                            source = context.contract_sources[filename]
                            # Find the function and check for override
                            pattern = re.compile(
                                rf'\bfunction\s+{re.escape(func_name)}\s*\([^)]*\)[^{{]*',
                                re.DOTALL
                            )
                            match = pattern.search(source)
                            if match and 'override' not in match.group():
                                findings.append(
                                    Finding(
                                        title=f"Function Shadowing: {contract_name}.{func_name}()",
                                        description=(
                                            f"`{contract_name}.{func_name}()` redefines "
                                            f"`{parent}.{func_name}()` without the `override` "
                                            "keyword. This may silently change behavior.\n\n"
                                            "**Fix:** Add the `override` keyword to explicitly "
                                            "acknowledge the override, or rename the function."
                                        ),
                                        severity=Severity.MEDIUM,
                                        confidence=Confidence.MEDIUM,
                                        category=FindingCategory.OTHER,
                                        source=self.name,
                                        detector_name="function-shadowing",
                                        locations=[
                                            SourceLocation(
                                                file=filename,
                                                start_line=line_num,
                                                end_line=line_num,
                                                function=func_name,
                                                contract=contract_name,
                                            )
                                        ],
                                    )
                                )

        return findings

    def _check_interface_mismatch(
        self,
        inheritance_map: dict[str, list[str]],
        context: AuditContext,
    ) -> list[Finding]:
        """Detect contracts declaring interface implementation but missing functions."""
        findings: list[Finding] = []

        # Extract interface functions
        interface_funcs: dict[str, set[str]] = {}
        contract_funcs: dict[str, set[str]] = {}

        for filename, source in context.contract_sources.items():
            clean = strip_comments(source)

            # Extract interfaces
            for match in re.finditer(r'\binterface\s+(\w+)\s*\{', clean):
                iface_name = match.group(1)
                start = match.end()
                depth = 1
                pos = start
                while pos < len(clean) and depth > 0:
                    if clean[pos] == '{':
                        depth += 1
                    elif clean[pos] == '}':
                        depth -= 1
                    pos += 1
                body = clean[start:pos - 1]

                funcs = set(re.findall(
                    r'\bfunction\s+(\w+)\s*\(', body
                ))
                interface_funcs[iface_name] = funcs

            # Extract contract functions
            for match in re.finditer(r'\bcontract\s+(\w+)[^{]*\{', clean):
                cname = match.group(1)
                start = match.end()
                depth = 1
                pos = start
                while pos < len(clean) and depth > 0:
                    if clean[pos] == '{':
                        depth += 1
                    elif clean[pos] == '}':
                        depth -= 1
                    pos += 1
                body = clean[start:pos - 1]

                funcs = set(re.findall(
                    r'\bfunction\s+(\w+)\s*\(', body
                ))
                contract_funcs[cname] = funcs

        # Check for interface implementation gaps
        for contract_name, parents in inheritance_map.items():
            for parent in parents:
                if parent in interface_funcs:
                    required = interface_funcs[parent]
                    implemented = contract_funcs.get(contract_name, set())

                    missing = required - implemented
                    if missing:
                        filename = self._find_contract_file(contract_name, context)
                        findings.append(
                            Finding(
                                title=f"Interface Mismatch: {contract_name} missing {parent} functions",
                                description=(
                                    f"`{contract_name}` declares `is {parent}` but does not "
                                    f"implement: {', '.join(sorted(missing))}. This will "
                                    "cause a compilation error or unexpected behavior.\n\n"
                                    "**Fix:** Implement all required interface functions."
                                ),
                                severity=Severity.LOW,
                                confidence=Confidence.HIGH,
                                category=FindingCategory.OTHER,
                                source=self.name,
                                detector_name="interface-mismatch",
                                locations=[
                                    SourceLocation(
                                        file=filename or contract_name,
                                        start_line=1,
                                        end_line=1,
                                        contract=contract_name,
                                    )
                                ],
                            )
                        )

        return findings

    def _extract_contracts_with_functions(
        self, source: str
    ) -> list[tuple[str, dict[str, int]]]:
        """Extract contracts and their function names with line numbers."""
        results = []

        lines = source.splitlines()
        i = 0
        while i < len(lines):
            contract_match = re.search(r'\bcontract\s+(\w+)', lines[i])
            if contract_match:
                contract_name = contract_match.group(1)
                depth = 0
                found_open = False
                funcs: dict[str, int] = {}

                for k in range(i, len(lines)):
                    depth += lines[k].count('{') - lines[k].count('}')
                    if lines[k].count('{') > 0:
                        found_open = True

                    func_match = re.search(r'\bfunction\s+(\w+)\s*\(', lines[k])
                    if func_match:
                        funcs[func_match.group(1)] = k + 1

                    if found_open and depth <= 0:
                        break

                results.append((contract_name, funcs))

            i += 1

        return results

    def _find_contract_file(
        self, contract_name: str, context: AuditContext
    ) -> str | None:
        """Find which file contains a given contract."""
        for filename, source in context.contract_sources.items():
            if re.search(rf'\bcontract\s+{re.escape(contract_name)}\b', source):
                return filename
        return None
