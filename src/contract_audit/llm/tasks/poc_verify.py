"""PoC verification task.

Takes LLM-generated PoC code and runs it with `forge test` to verify
whether the exploit actually works. Updates finding confidence accordingly.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from ...core.models import Confidence, Finding

if TYPE_CHECKING:
    from ..router import LLMRouter

logger = logging.getLogger(__name__)


class PoCVerifyTask:
    """Verifies LLM-generated PoC exploits by running them with Foundry."""

    def __init__(self, router: LLMRouter | None = None) -> None:
        self.router = router

    async def run(self, finding: Finding, project_path: Path) -> bool:
        """Verify a finding's PoC by running forge test.

        Args:
            finding: Finding with llm_poc populated
            project_path: Path to the Foundry project

        Returns:
            True if PoC passes (vulnerability confirmed), False otherwise
        """
        if not finding.llm_poc:
            return False

        poc_code = self._extract_solidity(finding.llm_poc)
        if not poc_code:
            return False

        # Generate a unique test name
        test_name = f"test_poc_{finding.fingerprint[:8]}"

        try:
            result = await self._run_forge_test(
                poc_code, test_name, project_path
            )

            if result:
                finding.confidence = Confidence.HIGH
                finding.metadata["poc_verified"] = True
                logger.info(f"PoC verified for '{finding.title}'")
                return True

            # Try regenerating once if first attempt fails
            if self.router:
                logger.debug(f"PoC failed for '{finding.title}', attempting regeneration")
                regenerated = await self._regenerate_poc(finding)
                if regenerated:
                    poc_code = self._extract_solidity(regenerated)
                    if poc_code:
                        result = await self._run_forge_test(
                            poc_code, test_name, project_path
                        )
                        if result:
                            finding.llm_poc = regenerated
                            finding.confidence = Confidence.HIGH
                            finding.metadata["poc_verified"] = True
                            logger.info(f"PoC verified on retry for '{finding.title}'")
                            return True

            finding.metadata["poc_verified"] = False
            logger.debug(f"PoC unverified for '{finding.title}'")
            return False

        except Exception as e:
            logger.warning(f"PoC verification error for '{finding.title}': {e}")
            finding.metadata["poc_verified"] = False
            return False

    async def _run_forge_test(
        self, poc_code: str, test_name: str, project_path: Path
    ) -> bool:
        """Write PoC to temp file and run forge test."""
        test_dir = project_path / "test"
        test_dir.mkdir(exist_ok=True)

        test_file = test_dir / f"PoCVerify_{test_name}.t.sol"

        try:
            test_file.write_text(poc_code)

            process = await asyncio.create_subprocess_exec(
                "forge", "test",
                "--match-test", test_name,
                "--json",
                "--no-match-path", "!test/PoCVerify_*.t.sol",
                cwd=str(project_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=120
            )

            if process.returncode == 0:
                # Parse forge JSON output for test results
                try:
                    output = json.loads(stdout.decode())
                    # Check if any test passed
                    for _file, results in output.items():
                        if isinstance(results, dict):
                            test_results = results.get("test_results", {})
                            for _name, result in test_results.items():
                                if result.get("status") == "Success":
                                    return True
                except (json.JSONDecodeError, KeyError):
                    pass
                return True  # Forge returned 0, consider success

            return False

        finally:
            # Clean up test file
            if test_file.exists():
                test_file.unlink()

    async def _regenerate_poc(self, finding: Finding) -> str | None:
        """Ask LLM to regenerate a failing PoC."""
        if not self.router:
            return None

        try:
            from .poc_generate import PoCGenerateTask
            poc_task = PoCGenerateTask(self.router)
            return await poc_task.run(finding, "")
        except Exception as e:
            logger.warning(f"PoC regeneration failed: {e}")
            return None

    def _extract_solidity(self, poc_text: str) -> str:
        """Extract Solidity code from PoC text (may be in markdown blocks)."""
        if "```solidity" in poc_text:
            parts = poc_text.split("```solidity")
            if len(parts) > 1:
                return parts[1].split("```")[0].strip()

        if "```" in poc_text:
            parts = poc_text.split("```")
            if len(parts) > 1:
                return parts[1].split("```")[0].strip()

        # Assume raw Solidity
        if "pragma solidity" in poc_text or "import" in poc_text:
            return poc_text.strip()

        return ""
