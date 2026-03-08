"""Filter findings to changed lines (for PR reviews)."""

from __future__ import annotations

import logging
import subprocess

from ..core.models import Finding

logger = logging.getLogger(__name__)


def get_changed_lines(base_ref: str = "HEAD~1") -> dict[str, set[int]]:
    """Get changed lines from git diff.

    Returns:
        Dict mapping file path to set of changed line numbers
    """
    changed: dict[str, set[int]] = {}

    try:
        result = subprocess.run(
            ["git", "diff", "--unified=0", base_ref],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            logger.warning(f"git diff failed: {result.stderr}")
            return changed

        current_file = None
        for line in result.stdout.splitlines():
            if line.startswith("--- ") or line.startswith("+++ "):
                if line.startswith("+++ b/"):
                    current_file = line[6:]
                continue

            if line.startswith("@@"):
                # Parse hunk header: @@ -old_start,old_count +new_start,new_count @@
                import re
                match = re.search(r'\+(\d+)(?:,(\d+))?', line)
                if match and current_file:
                    new_start = int(match.group(1))
                    new_count = int(match.group(2) or "1")
                    if current_file not in changed:
                        changed[current_file] = set()
                    changed[current_file].update(
                        range(new_start, new_start + new_count)
                    )

    except subprocess.TimeoutExpired:
        logger.warning("git diff timed out")
    except Exception as e:
        logger.warning(f"Failed to get changed lines: {e}")

    return changed


def filter_to_changed_lines(
    findings: list[Finding],
    changed_lines: dict[str, set[int]],
) -> list[Finding]:
    """Filter findings to only those in changed lines."""
    if not changed_lines:
        return findings  # If no diff info, return all findings

    filtered = []
    for finding in findings:
        for loc in finding.locations:
            file_changed = changed_lines.get(loc.file, set())
            if any(
                line in file_changed
                for line in range(loc.start_line, loc.end_line + 1)
            ):
                filtered.append(finding)
                break

    logger.info(
        f"Diff filter: {len(findings)} -> {len(filtered)} findings in changed lines"
    )
    return filtered
