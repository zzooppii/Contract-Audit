"""Token cost estimation and budget tracking."""

from __future__ import annotations

import logging

from ..core.exceptions import BudgetExhaustedError

logger = logging.getLogger(__name__)


class BudgetTracker:
    """Tracks LLM spending across all providers."""

    def __init__(self, max_usd: float = 10.0) -> None:
        self.max_usd = max_usd
        self._spent_usd: float = 0.0
        self._call_count: int = 0

    @property
    def spent_usd(self) -> float:
        return self._spent_usd

    @property
    def remaining_usd(self) -> float:
        return max(0.0, self.max_usd - self._spent_usd)

    @property
    def is_exhausted(self) -> bool:
        return self._spent_usd >= self.max_usd

    def record(self, cost_usd: float) -> None:
        """Record a completed LLM call cost."""
        self._spent_usd += cost_usd
        self._call_count += 1
        logger.debug(
            f"LLM cost recorded: ${cost_usd:.4f} "
            f"(total: ${self._spent_usd:.4f}/{self.max_usd})"
        )

    def check_budget(self, estimated_cost: float = 0.0) -> None:
        """Raise BudgetExhaustedError if budget would be exceeded."""
        if self._spent_usd + estimated_cost >= self.max_usd:
            raise BudgetExhaustedError(self._spent_usd)

    def summary(self) -> dict[str, float | int]:
        return {
            "spent_usd": round(self._spent_usd, 4),
            "remaining_usd": round(self.remaining_usd, 4),
            "call_count": self._call_count,
            "max_usd": self.max_usd,
        }
