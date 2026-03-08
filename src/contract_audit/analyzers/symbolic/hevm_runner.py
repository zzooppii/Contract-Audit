"""hevm symbolic execution wrapper."""

from __future__ import annotations

import asyncio
import logging
import shutil
from typing import Any

logger = logging.getLogger(__name__)

HEVM_CMD = "hevm"


class HevmRunner:
    """Runs hevm symbolic execution on compiled contracts."""

    def is_available(self) -> bool:
        return shutil.which(HEVM_CMD) is not None

    async def run_symbolic(
        self,
        bytecode: str,
        sig: str | None = None,
        timeout: int = 120,
    ) -> list[dict[str, Any]]:
        """Run hevm symbolic execution on a bytecode string.

        Returns list of counterexamples/violations found.
        """
        if not self.is_available():
            return []

        cmd = [HEVM_CMD, "symbolic", "--code", bytecode]

        if sig:
            cmd.extend(["--sig", sig])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )

            output = stdout.decode()
            violations = self._parse_output(output)
            logger.info(f"hevm found {len(violations)} violations")
            return violations

        except TimeoutError:
            logger.warning(f"hevm timed out after {timeout}s")
            return []
        except Exception as e:
            logger.error(f"hevm failed: {e}")
            return []

    def _parse_output(self, output: str) -> list[dict[str, Any]]:
        """Parse hevm output for assertion violations."""
        violations = []
        lines = output.splitlines()

        current_violation: dict[str, Any] | None = None
        for line in lines:
            if "Assertion violation" in line or "counterexample" in line.lower():
                current_violation = {"type": "assertion_violation", "details": line.strip()}
                violations.append(current_violation)
            elif current_violation and line.strip():
                current_violation.setdefault("trace", []).append(line.strip())

        return violations
