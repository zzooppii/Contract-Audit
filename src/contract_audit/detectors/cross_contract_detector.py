"""Cross-contract vulnerability detector.

Detects cross-contract reentrancy cycles, function shadowing in
inheritance, and interface implementation mismatches.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from ..core.models import (
    AuditContext,
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)
from .utils import strip_comments

if TYPE_CHECKING:
    from ..analyzers.cross_contract.call_graph import CallGraph

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
        from ..analyzers.cross_contract.call_graph import CallGraph
        from ..analyzers.cross_contract.import_resolver import ImportResolver
        from ..analyzers.cross_contract.inheritance_graph import InheritanceGraph

        import_graph = ImportResolver().resolve(context.contract_sources)
        inheritance_map = InheritanceGraph().build(context.contract_sources)
        call_graph_builder = CallGraph()
        call_graph = call_graph_builder.build(
            context.contract_sources,
            inheritance_map,
            context.ast_trees
        )

        # Store in context for other detectors
        context.import_graph = import_graph
        context.inheritance_map = inheritance_map
        context.call_graph = call_graph

        findings.extend(self._check_cross_contract_reentrancy(
            call_graph_builder, call_graph, context
        ))
        findings.extend(self._check_cross_contract_read_only_reentrancy(
            call_graph, context
        ))
        findings.extend(self._check_function_shadowing(
            inheritance_map, context
        ))
        findings.extend(self._check_interface_mismatch(
            inheritance_map, context
        ))

        logger.info(f"Cross-contract detector found {len(findings)} findings")
        return findings

    def _check_cross_contract_read_only_reentrancy(
        self,
        call_graph: dict[str, list[tuple[str, str]]],
        context: AuditContext,
    ) -> list[Finding]:
        """Detect cross-contract read-only reentrancy vulnerabilities."""
        findings: list[Finding] = []

        for caller_contract, calls in call_graph.items():
            caller_file = self._find_contract_file(caller_contract, context)
            if not caller_file:
                continue

            for callee_contract, callee_function in calls:
                callee_file = self._find_contract_file(callee_contract, context)
                if not callee_file or caller_contract == callee_contract:
                    continue

                callee_src = context.contract_sources[callee_file]
                
                # Check if view or pure function
                fn_pattern = rf'\bfunction\s+{re.escape(callee_function)}\s*\([^)]*\)[^{{]*\b(view|pure)\b'
                if not re.search(fn_pattern, callee_src):
                    continue

                # Parse function body
                body_match = re.search(rf'\bfunction\s+{re.escape(callee_function)}\s*\([^)]*\)[^{{]*\{{', callee_src)
                if not body_match:
                    continue
                
                start_pos = body_match.end()
                depth = 1
                pos = start_pos
                while pos < len(callee_src) and depth > 0:
                    if callee_src[pos] == '{':
                        depth += 1
                    elif callee_src[pos] == '}':
                        depth -= 1
                    pos += 1
                fn_body = callee_src[start_pos:pos - 1]

                # Identify referenced state variables
                referenced_vars = set(re.findall(r'\b([a-zA-Z_]\w*)\b', fn_body))
                ignored_keywords = {
                    "return", "view", "pure", "public", "external", "internal", "private",
                    "constant", "override", "returns", "memory", "calldata", "storage",
                    "msg", "sender", "value", "tx", "origin", "block", "timestamp", "number",
                    "true", "false", "uint", "uint256", "int", "int256", "address", "bool",
                    "bytes", "string", "mapping"
                }
                referenced_vars = referenced_vars - ignored_keywords
                if not referenced_vars:
                    continue

                has_read_only_reentrancy_risk = False
                trigger_var = ""
                trigger_func = ""

                # Try AST analysis first
                callee_ast = context.ast_trees.get(callee_file) if context.ast_trees else None
                if callee_ast:
                    from ..analyzers.ast_parser.visitors import walk_ast
                    functions_nodes = []
                    def collect_funcs(node):
                        if node.get("nodeType") == "FunctionDefinition":
                            functions_nodes.append(node)
                    walk_ast(callee_ast, collect_funcs)

                    for func_node in functions_nodes:
                        stateMutability = func_node.get("stateMutability", "")
                        if stateMutability in ("view", "pure"):
                            continue

                        external_calls = []
                        assignments = []

                        def collect_elements(node):
                            if node.get("nodeType") == "FunctionCall":
                                expr = node.get("expression", {})
                                if expr.get("nodeType") == "MemberAccess" and expr.get("memberName") in ("call", "transfer", "send"):
                                    external_calls.append(node)
                            elif node.get("nodeType") in ("Assignment", "UnaryOperation"):
                                if node.get("nodeType") == "Assignment":
                                    lhs = node.get("leftHandSide", {})
                                else:
                                    lhs = node.get("subExpression", {})
                                
                                def collect_identifiers(n, target_list):
                                    if n.get("nodeType") == "Identifier":
                                        target_list.append(n)
                                collect_identifiers(lhs, assignments)
                                if lhs.get("nodeType") in ("IndexAccess", "MemberAccess"):
                                    def collect_inner(inner_node):
                                        if inner_node.get("nodeType") == "Identifier":
                                            assignments.append(inner_node)
                                    walk_ast(lhs, collect_inner)

                        walk_ast(func_node, collect_elements)

                        for call in external_calls:
                            call_offset = int(call.get("src", "0:0").split(":")[0])
                            for assign in assignments:
                                assign_offset = int(assign.get("src", "0:0").split(":")[0])
                                assign_name = assign.get("name", "")
                                if assign_offset > call_offset and assign_name in referenced_vars:
                                    has_read_only_reentrancy_risk = True
                                    trigger_var = assign_name
                                    trigger_func = func_node.get("name", "unknown")
                                    break
                            if has_read_only_reentrancy_risk:
                                break
                        if has_read_only_reentrancy_risk:
                            break

                else:
                    # Regex Fallback
                    for match in re.finditer(r'\bfunction\s+(\w+)\s*\(', callee_src):
                        f_name = match.group(1)
                        if f_name == callee_function:
                            continue
                        
                        body_m = re.search(rf'\bfunction\s+{re.escape(f_name)}\s*\([^)]*\)[^{{]*\{{', callee_src)
                        if not body_m:
                            continue
                        s_pos = body_m.end()
                        dep = 1
                        p = s_pos
                        while p < len(callee_src) and dep > 0:
                            if callee_src[p] == '{':
                                dep += 1
                            elif callee_src[p] == '}':
                                dep -= 1
                            p += 1
                        w_body = callee_src[s_pos:p - 1]
                        
                        if "view" in callee_src[body_m.start():s_pos] or "pure" in callee_src[body_m.start():s_pos]:
                            continue
                        
                        call_match = re.search(r'\.(call|transfer|send)\s*\(', w_body)
                        if call_match:
                            post_call_body = w_body[call_match.end():]
                            for var in referenced_vars:
                                update_pattern = rf'\b{re.escape(var)}\b.*(=|\+=|-=)'
                                if re.search(update_pattern, post_call_body):
                                    has_read_only_reentrancy_risk = True
                                    trigger_var = var
                                    trigger_func = f_name
                                    break
                        if has_read_only_reentrancy_risk:
                            break

                if has_read_only_reentrancy_risk:
                    findings.append(
                        Finding(
                            title=f"Cross-Contract Read-Only Reentrancy Risk on {callee_contract}.{callee_function}",
                            description=(
                                f"Contract `{caller_contract}` queries `{callee_contract}.{callee_function}()` "
                                f"which reads state variable `{trigger_var}`. However, `{callee_contract}` "
                                f"updates `{trigger_var}` after an external call within its `{trigger_func}()` "
                                f"function (CEI violation).\n\n"
                                f"During the external call in `{callee_contract}.{trigger_func}()`, an attacker "
                                f"can re-enter `{caller_contract}` and execute actions while `{callee_contract}.{callee_function}()` "
                                f"returns a stale/manipulated value of `{trigger_var}`.\n\n"
                                f"**Fix:** Apply `nonReentrant` guards on both the state-changing `{trigger_func}()` "
                                f"and the view function `{callee_function}()` (if using custom lock checks), or ensure "
                                f"checks-effects-interactions is strictly followed."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            category=FindingCategory.REENTRANCY,
                            source=self.name,
                            detector_name="cross-contract-read-only-reentrancy",
                            locations=[
                                SourceLocation(
                                    file=caller_file,
                                    start_line=1,
                                    end_line=1,
                                    contract=caller_contract,
                                )
                            ],
                            metadata={
                                "vulnerable_contract": callee_contract,
                                "view_function": callee_function,
                                "state_changing_function": trigger_func,
                                "variable": trigger_var
                            }
                        )
                    )

        return findings

    def _check_cross_contract_reentrancy(
        self,
        builder: CallGraph,
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
                        contract_file = self._find_contract_file(contract_name, context)
                        if contract_file:
                            source = context.contract_sources[contract_file]
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
                                                file=contract_file,
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
                        iface_file = self._find_contract_file(contract_name, context)
                        findings.append(
                            Finding(
                                title=(
                                    f"Interface Mismatch: {contract_name} "
                                    f"missing {parent} functions"
                                ),
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
                                        file=iface_file or contract_name,
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
