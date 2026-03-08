"""Patch generation (remediation) task."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ...core.models import Finding
from ..prompts import render_prompt

if TYPE_CHECKING:
    from ..router import LLMRouter

logger = logging.getLogger(__name__)


class RemediateTask:
    """Generates code patches for findings using LLM."""

    def __init__(self, router: "LLMRouter") -> None:
        self.router = router

    async def run(self, finding: Finding, source_snippet: str = "") -> str:
        """Generate a remediation/patch for a finding.

        Returns:
            Markdown-formatted remediation with code examples
        """
        prompt = render_prompt(
            "remediate.j2",
            finding=finding,
            source_snippet=source_snippet,
        )

        response = await self.router.execute_task(
            task_type="remediate",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert smart contract security engineer. "
                        "Provide concrete, production-ready Solidity code fixes. "
                        "Show before/after diffs and explain why each change addresses the root cause."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=2048,
        )

        return response.content
