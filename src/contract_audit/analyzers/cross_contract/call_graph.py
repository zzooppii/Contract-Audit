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
        ast_trees: dict[str, Any] | None = None,
    ) -> dict[str, list[tuple[str, str]]]:
        """Build call graph from sources and inheritance map.

        Returns:
            dict mapping contract_name -> list of (target_contract, function_name)
        """
        call_graph: dict[str, list[tuple[str, str]]] = {}
        all_contracts = set(inheritance.keys())

        # AST 분석 시도
        if ast_trees:
            for filename, ast in ast_trees.items():
                try:
                    ast_calls = self._extract_external_calls_from_ast(ast, inheritance)
                    for cname, calls in ast_calls.items():
                        call_graph[cname] = calls
                except Exception as e:
                    import logging as _logging
                    _logging.getLogger(__name__).warning(f"AST-based call graph failed for {filename}: {e}. Falling back to regex.")

        # AST에 존재하지 않는 계약들은 기존 정규식 기반 분석으로 보완 (Fallback)
        contract_types: dict[str, dict[str, str]] = {}  # contract -> {var: type}
        for filename, source in sources.items():
            clean = _strip_comments(source)
            contracts = self._extract_contract_blocks(clean)

            for contract_name, body in contracts:
                if contract_name in call_graph:
                    continue  # 이미 AST 분석으로 처리됨

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

    def _extract_external_calls_from_ast(
        self,
        ast: dict[str, Any],
        inheritance: dict[str, list[str]]
    ) -> dict[str, list[tuple[str, str]]]:
        """AST 기반으로 각 계약별 외부 호출을 정밀 분석합니다."""
        from ...analyzers.ast_parser.visitors import walk_ast
        
        all_contracts = set(inheritance.keys())
        contract_calls: dict[str, list[tuple[str, str]]] = {}
        
        # 1. 먼저 계약 노드를 모두 찾습니다.
        contracts: list[dict[str, Any]] = []
        def find_contracts(node: dict[str, Any]) -> None:
            if node.get("nodeType") == "ContractDefinition":
                contracts.append(node)
        walk_ast(ast, find_contracts)
        
        for contract in contracts:
            cname = contract.get("name", "")
            if not cname:
                continue
                
            calls: list[tuple[str, str]] = []
            state_var_types: dict[str, str] = {}
            
            # 해당 계약의 상태 변수 수집
            for subnode in contract.get("nodes", []):
                if subnode.get("nodeType") == "VariableDeclaration" and subnode.get("stateVariable"):
                    var_name = subnode.get("name", "")
                    # typeDescriptions에서 타입 이름 추출
                    type_str = subnode.get("typeDescriptions", {}).get("typeString", "")
                    # 예: "contract IToken" 또는 "interface IToken" 또는 "IToken"
                    type_name = type_str.replace("contract ", "").replace("interface ", "").strip() if type_str else ""
                    if type_name in all_contracts or type_name.startswith("I"):
                        state_var_types[var_name] = type_name
            
            # 함수 정의들을 순회하면서 로컬 변수 및 외부 호출 분석
            for subnode in contract.get("nodes", []):
                if subnode.get("nodeType") == "FunctionDefinition" and subnode.get("body"):
                    body = subnode["body"]
                    local_var_types = state_var_types.copy()
                    
                    # 1) 로컬 변수 선언 수집
                    def collect_local_decls(n: dict[str, Any]) -> None:
                        if n.get("nodeType") == "VariableDeclarationStatement":
                            decls = n.get("declarations", [])
                            for d in decls:
                                if d and d.get("nodeType") == "VariableDeclaration":
                                    vname = d.get("name", "")
                                    t_str = d.get("typeDescriptions", {}).get("typeString", "")
                                    t_name = t_str.replace("contract ", "").replace("interface ", "").strip() if t_str else ""
                                    if t_name in all_contracts or t_name.startswith("I"):
                                        local_var_types[vname] = t_name
                    walk_ast(body, collect_local_decls)
                    
                    # 2) 외부 호출 분석
                    def find_calls(n: dict[str, Any]) -> None:
                        if n.get("nodeType") == "FunctionCall":
                            expr = n.get("expression", {})
                            if expr.get("nodeType") == "MemberAccess":
                                member_name = expr.get("memberName", "")
                                inner_expr = expr.get("expression", {})
                                
                                # Case A: 인터페이스 캐스팅 직접 호출 - IToken(addr).transfer(...)
                                if inner_expr.get("nodeType") == "FunctionCall" and inner_expr.get("kind") == "typeConversion":
                                    cast_expr = inner_expr.get("expression", {})
                                    t_name = cast_expr.get("name") or cast_expr.get("typeName", {}).get("name")
                                    if not t_name and cast_expr.get("nodeType") == "UserDefinedTypeNameExpression":
                                        t_name = cast_expr.get("pathNode", {}).get("name")
                                    if t_name:
                                        t_name = t_name.replace("contract ", "").replace("interface ", "").strip()
                                        if t_name in all_contracts or t_name.startswith("I"):
                                            # msg, block, tx 등 솔리디티 내장 객체는 건너뜀
                                            if t_name not in ('msg', 'block', 'tx', 'abi', 'type', 'super', 'this'):
                                                calls.append((t_name, member_name))
                                
                                # Case B: 변수를 통한 호출 - t.transfer(...)
                                elif inner_expr.get("nodeType") == "Identifier":
                                    vname = inner_expr.get("name", "")
                                    if vname in local_var_types:
                                        t_name = local_var_types[vname]
                                        calls.append((t_name, member_name))
                                        
                    walk_ast(body, find_calls)
            
            # 중복 제거
            unique_calls = []
            seen = set()
            for t, f in calls:
                # 솔리디티 내장 함수/예외 필터링
                if t in ('msg', 'block', 'tx', 'abi', 'type', 'super', 'this'):
                    continue
                if f in ('push', 'pop', 'length', 'encode', 'decode'):
                    continue
                if (t, f) not in seen:
                    seen.add((t, f))
                    unique_calls.append((t, f))
                    
            contract_calls[cname] = unique_calls
            
        return contract_calls

