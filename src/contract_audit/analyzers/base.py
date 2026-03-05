"""Base protocol for all analyzers."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..core.models import AuditContext, Finding


@runtime_checkable
class AnalyzerProtocol(Protocol):
    """Protocol that all analyzers must implement."""

    @property
    def name(self) -> str:
        """Unique name of this analyzer."""
        ...

    async def analyze(self, context: AuditContext) -> list[Finding]:
        """Run analysis and return findings.

        Args:
            context: Shared audit context with source files, ASTs, etc.

        Returns:
            List of findings discovered by this analyzer.
        """
        ...

    def is_available(self) -> bool:
        """Check if this analyzer's external tool is installed and available."""
        ...
