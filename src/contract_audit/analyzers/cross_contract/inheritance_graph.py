"""Inheritance graph builder for cross-contract analysis.

Parses 'contract A is B, C' declarations and builds an inheritance map.
"""

from __future__ import annotations

import re


def _strip_comments(source: str) -> str:
    source = re.sub(r'//.*?$', '', source, flags=re.MULTILINE)
    source = re.sub(r'/\*.*?\*/', '', source, flags=re.DOTALL)
    return source


class InheritanceGraph:
    """Builds contract inheritance relationships."""

    def build(self, contract_sources: dict[str, str]) -> dict[str, list[str]]:
        """Parse contract declarations and return inheritance map.

        Returns:
            dict mapping contract_name -> list of parent contract names
        """
        inheritance: dict[str, list[str]] = {}

        for filename, source in contract_sources.items():
            clean = _strip_comments(source)
            contracts = self._extract_contracts(clean)
            for name, parents in contracts:
                inheritance[name] = parents

        return inheritance

    def _extract_contracts(self, source: str) -> list[tuple[str, list[str]]]:
        """Extract contract declarations with their parents."""
        results = []

        # Match: contract Name is Parent1, Parent2 {
        pattern = re.compile(
            r'\bcontract\s+(\w+)\s+is\s+([^{]+)\{',
            re.DOTALL
        )

        for match in pattern.finditer(source):
            name = match.group(1)
            parents_str = match.group(2).strip()
            # Split parents, handling generic args like Initializable
            parents = [p.strip().split('(')[0].strip()
                       for p in parents_str.split(',')]
            parents = [p for p in parents if p]
            results.append((name, parents))

        # Contracts without inheritance
        pattern_no_is = re.compile(
            r'\bcontract\s+(\w+)\s*\{',
        )
        for match in pattern_no_is.finditer(source):
            name = match.group(1)
            if name not in [r[0] for r in results]:
                results.append((name, []))

        return results

    def get_all_ancestors(
        self, contract_name: str, inheritance: dict[str, list[str]]
    ) -> set[str]:
        """Get all transitive ancestors of a contract."""
        ancestors: set[str] = set()
        stack = list(inheritance.get(contract_name, []))

        while stack:
            parent = stack.pop()
            if parent not in ancestors:
                ancestors.add(parent)
                stack.extend(inheritance.get(parent, []))

        return ancestors
