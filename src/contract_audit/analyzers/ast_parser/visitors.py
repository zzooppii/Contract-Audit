"""AST node visitors for pattern detection."""

from __future__ import annotations

from typing import Any, Callable


class ASTVisitor:
    """Base visitor for traversing solc AST nodes."""

    def visit(self, node: dict[str, Any]) -> None:
        """Visit a node and all its children."""
        node_type = node.get("nodeType", "")
        method_name = f"visit_{node_type}"
        method = getattr(self, method_name, self.generic_visit)
        method(node)

        # Traverse children
        for key, value in node.items():
            if isinstance(value, dict) and "nodeType" in value:
                self.visit(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict) and "nodeType" in item:
                        self.visit(item)

    def generic_visit(self, node: dict[str, Any]) -> None:
        """Default visit - does nothing."""
        pass


class FunctionCallCollector(ASTVisitor):
    """Collects all function calls matching specified names."""

    def __init__(self, target_names: set[str]) -> None:
        self.target_names = target_names
        self.calls: list[dict[str, Any]] = []

    def visit_FunctionCall(self, node: dict[str, Any]) -> None:
        expression = node.get("expression", {})
        name = (
            expression.get("memberName")
            or expression.get("name")
            or ""
        )
        if name in self.target_names:
            self.calls.append(node)


class StateVariableCollector(ASTVisitor):
    """Collects all state variable declarations."""

    def __init__(self) -> None:
        self.variables: list[dict[str, Any]] = []

    def visit_StateVariableDeclaration(self, node: dict[str, Any]) -> None:
        self.variables.append(node)

    def visit_VariableDeclaration(self, node: dict[str, Any]) -> None:
        if node.get("stateVariable"):
            self.variables.append(node)


class ModifierCollector(ASTVisitor):
    """Collects all function modifiers used."""

    def __init__(self) -> None:
        self.modifiers: list[str] = []

    def visit_ModifierInvocation(self, node: dict[str, Any]) -> None:
        modifier_name = node.get("modifierName", {}).get("name", "")
        if modifier_name:
            self.modifiers.append(modifier_name)


class InheritanceCollector(ASTVisitor):
    """Collects contract inheritance relationships."""

    def __init__(self) -> None:
        self.contracts: list[dict[str, Any]] = []

    def visit_ContractDefinition(self, node: dict[str, Any]) -> None:
        self.contracts.append({
            "name": node.get("name", ""),
            "base_contracts": [
                bc.get("baseName", {}).get("name", "")
                for bc in node.get("baseContracts", [])
            ],
            "kind": node.get("contractKind", "contract"),
        })


def walk_ast(node: dict[str, Any], callback: Callable[[dict[str, Any]], None]) -> None:
    """Walk all AST nodes, calling callback on each."""
    callback(node)
    for key, value in node.items():
        if isinstance(value, dict) and "nodeType" in value:
            walk_ast(value, callback)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and "nodeType" in item:
                    walk_ast(item, callback)
