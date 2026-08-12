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
        from ...core.models import Severity

        # Critical / High 등급은 Multi-Agent Debate 합의 프로세스 구동
        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            logger.info(f"Running Multi-Agent Triage Debate for Critical/High finding: {finding.title}")
            try:
                # 1단계: Attacker Agent
                attacker_prompt = render_prompt(
                    "triage_attacker.j2",
                    finding=finding,
                    source_snippet=source_snippet,
                )
                attacker_res = await self.router.execute_task(
                    task_type="triage",
                    messages=[
                        {"role": "system", "content": "You are an offensive smart contract security researcher."},
                        {"role": "user", "content": attacker_prompt},
                    ],
                    max_tokens=256,
                    temperature=0.2,
                )
                attacker_arg = attacker_res.content

                # 2단계: Defender Agent
                defender_prompt = render_prompt(
                    "triage_defender.j2",
                    finding=finding,
                    source_snippet=source_snippet,
                )
                defender_res = await self.router.execute_task(
                    task_type="triage",
                    messages=[
                        {"role": "system", "content": "You are a defensive smart contract auditor."},
                        {"role": "user", "content": defender_prompt},
                    ],
                    max_tokens=256,
                    temperature=0.2,
                )
                defender_arg = defender_res.content

                # 3단계: Referee Agent
                referee_prompt = render_prompt(
                    "triage_referee.j2",
                    finding=finding,
                    source_snippet=source_snippet,
                    attacker_argument=attacker_arg,
                    defender_argument=defender_arg,
                )
                response = await self.router.execute_task(
                    task_type="triage",
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "You are a precise smart contract security referee. "
                                "Classify security findings as true or false positives based on debates. "
                                "Be conservative: only classify as false positive if you are confident."
                            ),
                        },
                        {"role": "user", "content": referee_prompt},
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

                content = response.content
                if '"is_false_positive": true' in content or '"is_false_positive":true' in content:
                    return True
                return False

            except Exception as e:
                logger.warning(f"Multi-Agent Triage Debate failed: {e}. Falling back to single triage.")

        # Medium/Low 등 기존 단일 Triage 방식 실행
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
