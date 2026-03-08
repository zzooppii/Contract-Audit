"""Exploit PoC generation task using Claude Opus."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ...core.models import Finding
from ..prompts import render_prompt

if TYPE_CHECKING:
    from ..router import LLMRouter

logger = logging.getLogger(__name__)


class PoCGenerateTask:
    """Generates Foundry exploit PoC tests using Claude Opus."""

    def __init__(self, router: "LLMRouter") -> None:
        self.router = router

    async def run(self, finding: Finding, source_snippet: str = "") -> str:
        """Generate a Foundry PoC exploit test.

        Returns:
            Complete Solidity test file content
        """
        prompt = render_prompt(
            "poc_generate.j2",
            finding=finding,
            source_snippet=source_snippet,
        )

        response = await self.router.execute_task(
            task_type="poc_generate",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert smart contract security researcher specializing in "
                        "exploit development. Generate Foundry test files that demonstrate "
                        "vulnerabilities. Use forge-std Test, vm.prank, deal, etc. "
                        "Make tests realistic and runnable."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=4096,
        )

        return response.content
