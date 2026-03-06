"""Base protocol for all specialized detectors."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..core.models import AuditContext, Finding


@runtime_checkable
class DetectorProtocol(Protocol):
    """Protocol that all detectors must implement."""

    @property
    def name(self) -> str:
        """Unique name of this detector."""
        ...

    @property
    def category(self) -> str:
        """Category of vulnerabilities this detector finds."""
        ...

    @property
    def required_context(self) -> list[str]:
        """List of AuditContext fields required by this detector.

        Example: ["slither_instance", "ast_trees"]
        """
        ...

    async def detect(self, context: AuditContext) -> list[Finding]:
        """Run detection and return findings.

        Args:
            context: Shared audit context.

        Returns:
            List of findings discovered by this detector.
        """
        ...
