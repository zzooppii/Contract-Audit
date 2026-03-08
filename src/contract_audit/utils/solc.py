"""Solidity compiler utilities: version management, compilation, storage layout."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SOLC_SELECT_CMD = "solc-select"
SOLC_CMD = "solc"


def solc_available() -> bool:
    """Check if solc is installed."""
    return shutil.which(SOLC_CMD) is not None


def get_solc_version() -> str | None:
    """Get the current solc version."""
    if not solc_available():
        return None
    try:
        result = subprocess.run(
            [SOLC_CMD, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        match = re.search(r"Version: (\d+\.\d+\.\d+)", result.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass
    return None


def detect_pragma_version(source: str) -> str | None:
    """Extract the Solidity version pragma from source."""
    match = re.search(r'pragma solidity\s+([^;]+);', source)
    if match:
        return match.group(1).strip()
    return None


async def compile_contracts(
    project_path: Path,
    sources: dict[str, str],
    solc_version: str = "auto",
) -> dict[str, Any]:
    """Compile Solidity contracts and return compilation artifacts."""
    if not solc_available():
        logger.warning("solc not found, skipping direct compilation")
        return {}

    # Build input JSON for solc standard JSON interface
    input_data = {
        "language": "Solidity",
        "sources": {name: {"content": src} for name, src in sources.items()},
        "settings": {
            "outputSelection": {
                "*": {
                    "*": ["abi", "evm.bytecode", "storageLayout"],
                    "": ["ast"],
                }
            },
            "optimizer": {"enabled": False},
        },
    }

    try:
        proc = await asyncio.create_subprocess_exec(
            SOLC_CMD, "--standard-json",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=json.dumps(input_data).encode()),
            timeout=120,
        )

        if proc.returncode != 0:
            logger.warning(f"solc exited with {proc.returncode}: {stderr.decode()[:500]}")

        output = json.loads(stdout.decode())
        errors = output.get("errors", [])
        for err in errors:
            if err.get("severity") == "error":
                logger.warning(f"Compilation error: {err.get('message', '')}")

        return output
    except asyncio.TimeoutError:
        logger.error("solc compilation timed out")
        return {}
    except Exception as e:
        logger.error(f"Compilation failed: {e}")
        return {}


def extract_storage_layouts(
    compilation_output: dict[str, Any],
) -> dict[str, dict]:
    """Extract storage layout from solc output."""
    layouts: dict[str, dict] = {}
    contracts = compilation_output.get("contracts", {})
    for filename, file_contracts in contracts.items():
        for contract_name, contract_data in file_contracts.items():
            storage_layout = contract_data.get("storageLayout", {})
            if storage_layout:
                layouts[contract_name] = storage_layout
    return layouts


def extract_ast_trees(
    compilation_output: dict[str, Any],
) -> dict[str, dict]:
    """Extract AST trees from solc output."""
    trees: dict[str, dict] = {}
    sources = compilation_output.get("sources", {})
    for filename, source_data in sources.items():
        ast = source_data.get("ast", {})
        if ast:
            trees[filename] = ast
    return trees


async def load_source_files(
    contracts_dir: Path,
    exclude_patterns: list[str] | None = None,
) -> dict[str, str]:
    """Load all Solidity source files from a directory."""
    import fnmatch

    sources: dict[str, str] = {}
    exclude_patterns = exclude_patterns or []

    for sol_file in contracts_dir.rglob("*.sol"):
        rel_path = sol_file.relative_to(contracts_dir.parent)
        rel_str = str(rel_path)

        # Check exclusions
        excluded = False
        for pattern in exclude_patterns:
            if fnmatch.fnmatch(rel_str, pattern) or fnmatch.fnmatch(str(sol_file), pattern):
                excluded = True
                break

        if not excluded:
            try:
                sources[rel_str] = sol_file.read_text(encoding="utf-8")
            except Exception as e:
                logger.warning(f"Could not read {sol_file}: {e}")

    logger.info(f"Loaded {len(sources)} Solidity source files")
    return sources
