"""Executive summary generation task."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ...core.models import Finding
from ..prompts import render_prompt

if TYPE_CHECKING:
    from ..router import LLMRouter

logger = logging.getLogger(__name__)


class SummarizeTask:
    """Generates executive summary using Gemini Pro."""

    def __init__(self, router: LLMRouter) -> None:
        self.router = router

    async def run(self, findings: list[Finding]) -> str:
        """Generate an executive summary for the audit results.

        Returns:
            Markdown-formatted executive summary
        """
        prompt = render_prompt(
            "summarize.j2",
            findings=findings,
        )

        response = await self.router.execute_task(
            task_type="summarize",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior smart contract security auditor writing professional "
                        "audit reports. Write clear, business-focused executive summaries that "
                        "convey risk to non-technical stakeholders while providing actionable "
                        "guidance for developers."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=1024,
        )

        return response.content
