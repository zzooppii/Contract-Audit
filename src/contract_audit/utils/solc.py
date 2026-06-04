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


def _clean_version_string(pragma: str) -> str | None:
    """Extract semantic version (x.y.z) from pragma string."""
    match = re.search(r"(\d+\.\d+\.\d+)", pragma)
    if match:
        return match.group(1)
    return None


async def _setup_solc_version(version: str) -> bool:
    """Ensure specific solc version is installed and selected via solc-select."""
    if shutil.which(SOLC_SELECT_CMD) is None:
        logger.debug("solc-select not found on system")
        return False
    try:
        # Check if already installed
        proc = await asyncio.create_subprocess_exec(
            SOLC_SELECT_CMD, "versions",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        installed_versions = stdout.decode()

        # If the target version is not in installed list, install it
        if version not in installed_versions:
            logger.info(f"Installing solc version {version} via solc-select...")
            install_proc = await asyncio.create_subprocess_exec(
                SOLC_SELECT_CMD, "install", version,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await install_proc.communicate()

        # Select version
        logger.info(f"Switching to solc version {version}...")
        use_proc = await asyncio.create_subprocess_exec(
            SOLC_SELECT_CMD, "use", version,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await use_proc.communicate()
        return True
    except Exception as e:
        logger.warning(f"Failed to setup solc version {version} via solc-select: {e}")
        return False


async def compile_contracts(
    project_path: Path,
    sources: dict[str, str],
    solc_version: str = "auto",
) -> dict[str, Any]:
    """Compile Solidity contracts and return compilation artifacts."""
    # Try dynamic version swithing if auto or specified
    target_version = None
    if solc_version == "auto":
        for src in sources.values():
            pragma = detect_pragma_version(src)
            if pragma:
                target_version = _clean_version_string(pragma)
                if target_version:
                    break
    elif solc_version:
        target_version = _clean_version_string(solc_version)

    if target_version:
        await _setup_solc_version(target_version)

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

        result: dict[str, Any] = output
        return result
    except TimeoutError:
        logger.error("solc compilation timed out")
        return {}
    except Exception as e:
        logger.error(f"Compilation failed: {e}")
        return {}


def extract_storage_layouts(
    compilation_output: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Extract storage layout from solc output."""
    layouts: dict[str, dict[str, Any]] = {}
    contracts = compilation_output.get("contracts", {})
    for filename, file_contracts in contracts.items():
        for contract_name, contract_data in file_contracts.items():
            storage_layout = contract_data.get("storageLayout", {})
            if storage_layout:
                layouts[contract_name] = storage_layout
    return layouts


def extract_ast_trees(
    compilation_output: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Extract AST trees from solc output."""
    trees: dict[str, dict[str, Any]] = {}
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
