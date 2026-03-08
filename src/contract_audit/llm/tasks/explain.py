"""Vulnerability explanation task."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ...core.models import Finding
from ..prompts import render_prompt

if TYPE_CHECKING:
    from ..router import LLMRouter

logger = logging.getLogger(__name__)


class ExplainTask:
    """Generates detailed vulnerability explanations using LLM."""

    def __init__(self, router: "LLMRouter") -> None:
        self.router = router

    async def run(self, finding: Finding, source_snippet: str = "") -> str:
        """Generate an explanation for a finding.

        Returns:
            Markdown-formatted explanation string
        """
        prompt = render_prompt(
            "explain.j2",
            finding=finding,
            source_snippet=source_snippet,
        )

        response = await self.router.execute_task(
            task_type="explain",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert smart contract security auditor with deep knowledge "
                        "of Solidity, EVM, DeFi protocols, and common vulnerability patterns. "
                        "Provide clear, actionable security analysis."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=2048,
        )

        return response.content
