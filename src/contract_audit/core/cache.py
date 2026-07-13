"""Audit cache manager: handles incremental audit file hashing and finding storage."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from .models import Finding

logger = logging.getLogger(__name__)

CACHE_FILE_NAME = ".contract-audit-cache.json"


def calculate_hash(content: str) -> str:
    """Calculate SHA-256 hash of file content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class AuditCache:
    """Manages file hashes and cached findings for incremental audits."""

    def __init__(self, project_path: Path) -> None:
        self.project_path = project_path
        self.cache_file = project_path / CACHE_FILE_NAME
        # Maps relative_file_path -> { "hash": "sha256", "findings": [...] }
        self.data: dict[str, dict[str, Any]] = {}

    def load(self) -> None:
        """Load cache from disk if it exists."""
        if not self.cache_file.exists():
            self.data = {}
            return

        try:
            with open(self.cache_file, encoding="utf-8") as f:
                self.data = json.load(f)
            logger.info(f"Loaded incremental audit cache from {self.cache_file}")
        except Exception as e:
            logger.warning(f"Failed to load cache file {self.cache_file}: {e}. Starting fresh.")
            self.data = {}

    def save(self) -> None:
        """Save cache to disk."""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
            logger.debug(f"Saved incremental audit cache to {self.cache_file}")
        except Exception as e:
            logger.warning(f"Failed to save cache file {self.cache_file}: {e}")

    def get_cached_findings(self, file_path: str, current_hash: str) -> list[Finding] | None:
        """Return cached findings if file hash matches, else None."""
        entry = self.data.get(file_path)
        if not entry:
            return None

        if entry.get("hash") != current_hash:
            return None

        findings = []
        for f_data in entry.get("findings", []):
            try:
                findings.append(Finding.model_validate(f_data))
            except Exception as e:
                logger.debug(f"Failed to deserialize cached finding: {e}")
                return None  # Invalidate cache entry on deserialization failure
        return findings

    def update_file_cache(self, file_path: str, current_hash: str, findings: list[Finding]) -> None:
        """Update cache entry for a file."""
        file_findings = []
        for f in findings:
            loc = f.primary_location()
            if loc and (loc.file == file_path or Path(loc.file).name == Path(file_path).name):
                file_findings.append(f.model_dump(mode="json"))

        self.data[file_path] = {
            "hash": current_hash,
            "findings": file_findings,
        }
