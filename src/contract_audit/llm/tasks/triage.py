"""False-positive triage task using Gemini Flash."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pydantic import BaseModel

from ...core.models import Finding
from ..prompts import render_prompt

if TYPE_CHECKING:
    from ..router import LLMRouter

logger = logging.getLogger(__name__)


class TriageResult(BaseModel):
    """Structured result from LLM triage."""
    is_false_positive: bool
    reason: str


class TriageTask:
    """Binary false-positive classification using Gemini Flash."""

    def __init__(self, router: LLMRouter) -> None:
        self.router = router

    async def classify(self, finding: Finding, source_snippet: str = "") -> bool:
        """Classify whether a finding is a false positive.

        Returns:
            True if the finding is a false positive, False if true positive
        """
        prompt = render_prompt(
            "triage.j2",
            finding=finding,
            source_snippet=source_snippet,
        )

        try:
            response = await self.router.execute_task(
                task_type="triage",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a precise smart contract security analyst. "
                            "Classify security findings as true or false positives. "
                            "Be conservative: only classify as false positive if you are confident."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                response_schema=TriageResult,
                max_tokens=512,
                temperature=0.0,
            )

            if response.structured_data:
                result = TriageResult.model_validate(response.structured_data)
                logger.debug(
                    f"Triage: '{finding.title}' -> "
                    f"{'FP' if result.is_false_positive else 'TP'}: {result.reason}"
                )
                return result.is_false_positive

            # Parse from content if structured output failed
            content = response.content
            if '"is_false_positive": true' in content or '"is_false_positive":true' in content:
                return True
            return False

        except Exception as e:
            logger.warning(f"Triage failed: {e}")
            return False  # Conservative: don't suppress on error
