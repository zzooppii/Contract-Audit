"""Unit tests for cross-contract analysis modules."""

import pytest
from contract_audit.analyzers.cross_contract.import_resolver import ImportResolver
from contract_audit.analyzers.cross_contract.inheritance_graph import InheritanceGraph
from contract_audit.analyzers.cross_contract.call_graph import CallGraph


class TestImportResolver:
    def test_resolves_direct_imports(self):
        sources = {
            "A.sol": 'import "B.sol";\ncontract A {}',
            "B.sol": "contract B {}",
        }
        resolver = ImportResolver()
        graph = resolver.resolve(sources)

        assert "B.sol" in graph["A.sol"]
        assert graph["B.sol"] == []

    def test_resolves_named_imports(self):
        sources = {
            "A.sol": 'import {Foo} from "B.sol";\ncontract A {}',
            "B.sol": "contract B {}",
        }
        resolver = ImportResolver()
        graph = resolver.resolve(sources)

        assert "B.sol" in graph["A.sol"]

    def test_resolves_by_filename(self):
        sources = {
            "A.sol": 'import "./lib/B.sol";\ncontract A {}',
            "B.sol": "contract B {}",
        }
        resolver = ImportResolver()
        graph = resolver.resolve(sources)

        assert "B.sol" in graph["A.sol"]

    def test_handles_no_imports(self):
        sources = {
            "A.sol": "contract A {}",
        }
        resolver = ImportResolver()
        graph = resolver.resolve(sources)

        assert graph["A.sol"] == []


class TestInheritanceGraph:
    def test_builds_single_inheritance(self):
        sources = {
            "A.sol": "contract A is B { }",
            "B.sol": "contract B { }",
        }
        ig = InheritanceGraph()
        result = ig.build(sources)

        assert "B" in result["A"]
        assert result["B"] == []

    def test_builds_multiple_inheritance(self):
        sources = {
            "A.sol": "contract A is B, C { }",
        }
        ig = InheritanceGraph()
        result = ig.build(sources)

        assert set(result["A"]) == {"B", "C"}

    def test_no_inheritance(self):
        sources = {
            "A.sol": "contract A { }",
        }
        ig = InheritanceGraph()
        result = ig.build(sources)

        assert result["A"] == []

    def test_get_all_ancestors(self):
        inheritance = {
            "C": ["B"],
            "B": ["A"],
            "A": [],
        }
        ig = InheritanceGraph()
        ancestors = ig.get_all_ancestors("C", inheritance)

        assert ancestors == {"A", "B"}


class TestCallGraph:
    def test_builds_call_graph(self):
        sources = {
            "A.sol": """
contract A {
    B public contractB;
    function foo() external {
        contractB.bar();
    }
}
""",
            "B.sol": """
contract B {
    function bar() external {
    }
}
""",
        }
        inheritance = {"A": [], "B": []}
        cg = CallGraph()
        result = cg.build(sources, inheritance)

        assert ("B", "bar") in result.get("A", [])

    def test_finds_cycles(self):
        call_graph = {
            "A": [("B", "process")],
            "B": [("A", "callback")],
        }
        cg = CallGraph()
        cycles = cg.find_cycles(call_graph)

        assert len(cycles) > 0
        # Cycle should contain both A and B
        cycle_contracts = set()
        for cycle in cycles:
            cycle_contracts.update(cycle)
        assert "A" in cycle_contracts
        assert "B" in cycle_contracts

    def test_no_cycles(self):
        call_graph = {
            "A": [("B", "foo")],
            "B": [],
        }
        cg = CallGraph()
        cycles = cg.find_cycles(call_graph)

        assert len(cycles) == 0

    def test_skips_builtin_calls(self):
        sources = {
            "A.sol": """
contract A {
    function foo() external {
        msg.sender.call("");
        block.timestamp;
    }
}
""",
        }
        inheritance = {"A": []}
        cg = CallGraph()
        result = cg.build(sources, inheritance)

        # Should not include msg.sender or block.timestamp as external calls
        assert result.get("A", []) == []
