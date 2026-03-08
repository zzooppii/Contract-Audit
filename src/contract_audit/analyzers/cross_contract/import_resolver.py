"""Import resolver for cross-contract analysis.

Parses import statements from Solidity source files and builds
a file dependency graph.
"""

from __future__ import annotations

import re


class ImportResolver:
    """Resolves import dependencies between Solidity files."""

    def resolve(self, contract_sources: dict[str, str]) -> dict[str, list[str]]:
        """Parse import statements and return file dependency graph.

        Returns:
            dict mapping filename -> list of imported filenames
        """
        graph: dict[str, list[str]] = {}

        for filename, source in contract_sources.items():
            imports = self._extract_imports(source)
            resolved = self._resolve_imports(imports, contract_sources)
            graph[filename] = resolved

        return graph

    def _extract_imports(self, source: str) -> list[str]:
        """Extract import paths from Solidity source."""
        imports = []

        # import "path.sol";
        imports.extend(re.findall(
            r'import\s+"([^"]+)"', source
        ))

        # import {Symbol} from "path.sol";
        imports.extend(re.findall(
            r'import\s+\{[^}]*\}\s+from\s+"([^"]+)"', source
        ))

        # import * as Alias from "path.sol";
        imports.extend(re.findall(
            r'import\s+\*\s+as\s+\w+\s+from\s+"([^"]+)"', source
        ))

        # import 'path.sol'; (single quotes)
        imports.extend(re.findall(
            r"import\s+'([^']+)'", source
        ))
        imports.extend(re.findall(
            r"import\s+\{[^}]*\}\s+from\s+'([^']+)'", source
        ))

        return imports

    def _resolve_imports(
        self, imports: list[str], contract_sources: dict[str, str]
    ) -> list[str]:
        """Resolve import paths to actual filenames in contract_sources."""
        resolved = []

        for imp in imports:
            # Direct match
            if imp in contract_sources:
                resolved.append(imp)
                continue

            # Match by filename (strip path prefix)
            imp_filename = imp.rsplit("/", 1)[-1]
            for key in contract_sources:
                key_filename = key.rsplit("/", 1)[-1]
                if key_filename == imp_filename:
                    resolved.append(key)
                    break

        return resolved
