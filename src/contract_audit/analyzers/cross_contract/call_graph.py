"""Call graph builder for cross-contract analysis.

Tracks external call patterns between contracts to detect
cross-contract reentrancy and other interaction vulnerabilities.
"""

from __future__ import annotations

import re


def _strip_comments(source: str) -> str:
    source = re.sub(r'//.*?$', '', source, flags=re.MULTILINE)
    source = re.sub(r'/\*.*?\*/', '', source, flags=re.DOTALL)
    return source


class CallGraph:
    """Builds cross-contract call graph."""

    def build(
        self,
        sources: dict[str, str],
        inheritance: dict[str, list[str]],
    ) -> dict[str, list[tuple[str, str]]]:
        """Build call graph from sources and inheritance map.

        Returns:
            dict mapping contract_name -> list of (target_contract, function_name)
        """
        call_graph: dict[str, list[tuple[str, str]]] = {}

        # Collect all known contract names and their state variables
        contract_types: dict[str, dict[str, str]] = {}  # contract -> {var: type}
        all_contracts = set(inheritance.keys())

        for filename, source in sources.items():
            clean = _strip_comments(source)
            contracts = self._extract_contract_blocks(clean)

            for contract_name, body in contracts:
                # Find state variable types that reference other contracts
                var_types = self._extract_typed_variables(body, inheritance)
                contract_types[contract_name] = var_types

                # Find external calls
                calls = self._extract_external_calls(body, var_types, all_contracts)
                call_graph[contract_name] = calls

        return call_graph

    def _extract_contract_blocks(self, source: str) -> list[tuple[str, str]]:
        """Extract contract names and their bodies."""
        contracts = []

        pattern = re.compile(r'\bcontract\s+(\w+)[^{]*\{')
        for match in pattern.finditer(source):
            name = match.group(1)
            start = match.end()

            # Find matching closing brace
            depth = 1
            pos = start
            while pos < len(source) and depth > 0:
                if source[pos] == '{':
                    depth += 1
                elif source[pos] == '}':
                    depth -= 1
                pos += 1

            body = source[start:pos - 1]
            contracts.append((name, body))

        return contracts

    def _extract_typed_variables(
        self, body: str, inheritance: dict[str, list[str]]
    ) -> dict[str, str]:
        """Extract state variables that are typed as known contracts."""
        var_types: dict[str, str] = {}
        all_contracts = set(inheritance.keys())

        # Match: ContractType varName; or ContractType public varName;
        pattern = re.compile(
            r'\b(\w+)\s+(?:public\s+|private\s+|internal\s+)?(\w+)\s*;'
        )

        for match in pattern.finditer(body):
            type_name = match.group(1)
            var_name = match.group(2)

            # Check if type is a known contract or interface
            if type_name in all_contracts or type_name.startswith('I'):
                var_types[var_name] = type_name

        return var_types

    def _extract_external_calls(
        self, body: str, var_types: dict[str, str], all_contracts: set[str]
    ) -> list[tuple[str, str]]:
        """Extract external calls to other contracts."""
        calls: list[tuple[str, str]] = []
        local_var_types = var_types.copy()

        # 1. Track local variable typed assignments: e.g. "IToken t = IToken(addr);" or "IToken t;"
        local_decl_pattern = re.compile(
            r'\b(\w+)\s+(?:memory\s+|storage\s+|calldata\s+)?(\w+)\s*(?:=|;)'
        )
        for match in local_decl_pattern.finditer(body):
            type_name = match.group(1)
            var_name = match.group(2)
            if type_name in all_contracts or type_name.startswith('I'):
                local_var_types[var_name] = type_name

        # 2. Match direct interface casting: e.g. "IToken(addr).transfer("
        cast_pattern = re.compile(r'\b(\w+)\s*\([^)]*\)\s*\.\s*(\w+)\s*\(')
        for match in cast_pattern.finditer(body):
            type_name = match.group(1)
            func_name = match.group(2)

            if type_name in ('msg', 'block', 'tx', 'abi', 'type', 'super', 'this', 'uint', 'int', 'bool', 'address', 'bytes', 'string', 'keccak256', 'require', 'assert'):
                continue
            if func_name in ('push', 'pop', 'length', 'encode', 'decode'):
                continue

            if type_name in all_contracts or type_name.startswith('I'):
                calls.append((type_name, func_name))

        # 3. Match variable call: e.g. "variable.functionName("
        pattern = re.compile(r'\b(\w+)\s*\.\s*(\w+)\s*\(')

        for match in pattern.finditer(body):
            var_name = match.group(1)
            func_name = match.group(2)

            # Skip common non-contract calls
            if var_name in ('msg', 'block', 'tx', 'abi', 'type', 'super', 'this'):
                continue
            if func_name in ('push', 'pop', 'length', 'encode', 'decode'):
                continue

            if var_name in local_var_types:
                target_type = local_var_types[var_name]
                calls.append((target_type, func_name))

        # Deduplicate calls
        unique_calls = list(dict.fromkeys(calls))
        return unique_calls

    def find_cycles(
        self, call_graph: dict[str, list[tuple[str, str]]]
    ) -> list[list[str]]:
        """Find cyclic call paths (potential reentrancy)."""
        cycles: list[list[str]] = []
        visited: set[str] = set()
        path: list[str] = []

        # Build adjacency list from call graph
        adjacency: dict[str, set[str]] = {}
        for caller, calls in call_graph.items():
            adjacency.setdefault(caller, set())
            for target, _ in calls:
                adjacency[caller].add(target)
                adjacency.setdefault(target, set())

        def dfs(node: str) -> None:
            if node in path:
                cycle_start = path.index(node)
                cycles.append(path[cycle_start:] + [node])
                return

            if node in visited:
                return

            path.append(node)
            for neighbor in adjacency.get(node, set()):
                dfs(neighbor)
            path.pop()
            visited.add(node)

        for node in adjacency:
            visited.clear()
            path.clear()
            dfs(node)

        return cycles
