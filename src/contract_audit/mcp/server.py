"""MCP server exposing contract-audit as Claude Code tools."""

from __future__ import annotations

import asyncio
import logging
import tempfile
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

logger = logging.getLogger(__name__)

DETECTOR_DESCRIPTIONS: list[tuple[str, str]] = [
    ("proxy_detector", "Detects proxy upgrade vulnerabilities (unprotected upgrades, storage collisions)"),
    ("flash_loan_detector", "Detects flash loan attack vectors (unvalidated callbacks, price manipulation)"),
    ("oracle_detector", "Detects oracle manipulation risks (stale prices, spot price usage)"),
    ("storage_collision", "Detects storage layout collisions in upgradeable contracts"),
    ("gas_griefing", "Detects gas griefing / DoS vectors (unbounded loops, external calls in loops)"),
    ("governance_detector", "Detects governance attack vectors (low quorum, missing timelock)"),
    ("access_control_detector", "Detects access control issues (missing modifiers, centralization risks)"),
    ("erc20_detector", "Detects ERC-20 compliance issues (approval race, missing return values)"),
    ("signature_detector", "Detects signature replay and malleability vulnerabilities"),
    ("randomness_detector", "Detects weak randomness sources (block.timestamp, blockhash)"),
    ("merkle_detector", "Detects merkle tree vulnerabilities (leaf preimage, missing checks)"),
    ("timelock_detector", "Detects timelock bypass and insufficient delay issues"),
    ("reentrancy_detector", "Detects reentrancy vulnerabilities (CEI violations, cross-function)"),
    ("unchecked_call_detector", "Detects unchecked low-level call return values"),
    ("nft_detector", "Detects NFT-specific vulnerabilities (bid manipulation, unsafe transfers)"),
    ("bridge_detector", "Detects cross-chain bridge vulnerabilities (replay, missing validation)"),
    ("integer_detector", "Detects integer overflow/underflow and division-by-zero risks"),
    ("frontrun_detector", "Detects front-running vectors (missing slippage, deadline, sandwich)"),
    ("initialization_detector", "Detects initializer issues (missing modifier, reinitializable)"),
    ("erc4626_detector", "Detects ERC-4626 vault issues (inflation attack, rounding direction)"),
    ("pragma_detector", "Detects pragma issues (floating version, outdated compiler, missing SPDX)"),
    ("cross_contract_detector", "Detects cross-contract reentrancy cycles and interface mismatches"),
]


def _build_pipeline(
    *,
    slither_enabled: bool = True,
    aderyn_enabled: bool = True,
) -> Any:
    """Build an audit pipeline with LLM always disabled."""
    from ..core.models import AuditConfig

    config = AuditConfig(
        llm_enabled=False,
        slither_enabled=slither_enabled,
        aderyn_enabled=aderyn_enabled,
    )

    from ..cli.main import _build_pipeline as cli_build_pipeline
    from ..core.config import LLMConfig

    return cli_build_pipeline(config, LLMConfig(enabled=False)), config


def _format_result(result: Any) -> str:
    """Format an AuditResult into readable text."""
    lines: list[str] = []
    summary = result.summary

    lines.append("=" * 60)
    lines.append("CONTRACT AUDIT RESULTS")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Total findings: {summary.total_findings}")
    lines.append(f"Risk score: {summary.overall_risk_score}/10")
    lines.append("")

    severity_counts = [
        ("Critical", summary.critical_count),
        ("High", summary.high_count),
        ("Medium", summary.medium_count),
        ("Low", summary.low_count),
        ("Informational", summary.informational_count),
        ("Gas", summary.gas_count),
    ]
    for sev, count in severity_counts:
        if count > 0:
            lines.append(f"  {sev}: {count}")

    if summary.suppressed_count > 0:
        lines.append(f"  Suppressed (FP): {summary.suppressed_count}")

    lines.append("")

    active = [f for f in result.findings if not f.suppressed]
    if not active:
        lines.append("No findings detected.")
        return "\n".join(lines)

    sev_order = ["Critical", "High", "Medium", "Low", "Informational", "Gas"]
    by_sev: dict[str, list[Any]] = {s: [] for s in sev_order}
    for f in active:
        by_sev.setdefault(f.severity.value, []).append(f)

    counter = 0
    for sev in sev_order:
        group = by_sev.get(sev, [])
        if not group:
            continue

        lines.append(f"--- {sev} ({len(group)}) ---")
        lines.append("")

        for finding in group:
            counter += 1
            loc = finding.primary_location()
            loc_str = f"{loc.file}:{loc.start_line}" if loc else "unknown"

            lines.append(f"[{counter}] {finding.title}")
            lines.append(f"    Severity: {finding.severity.value} | "
                         f"Confidence: {finding.confidence.value} | "
                         f"Score: {finding.risk_score}")
            lines.append(f"    Category: {finding.category.value}")
            lines.append(f"    Location: {loc_str}")
            lines.append(f"    Detector: {finding.detector_name}")

            if finding.description:
                desc = finding.description
                if len(desc) > 300:
                    desc = desc[:300] + "..."
                lines.append(f"    Description: {desc}")

            lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


def create_server() -> Server:
    """Create and configure the MCP server."""
    server = Server("contract-audit")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="audit_contract",
                description=(
                    "Run a comprehensive smart contract security audit on a project directory. "
                    "Uses 22 specialized detectors + AST parser. "
                    "Requires Solidity source files in the project path."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "project_path": {
                            "type": "string",
                            "description": "Absolute path to the Solidity project directory",
                        },
                    },
                    "required": ["project_path"],
                },
            ),
            Tool(
                name="audit_source",
                description=(
                    "Audit inline Solidity source code. "
                    "Runs AST parser + 22 detectors on the provided source. "
                    "Slither and Aderyn are disabled (no project context)."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "source_code": {
                            "type": "string",
                            "description": "Solidity source code to audit",
                        },
                        "filename": {
                            "type": "string",
                            "description": "Optional filename (default: Contract.sol)",
                            "default": "Contract.sol",
                        },
                    },
                    "required": ["source_code"],
                },
            ),
            Tool(
                name="list_detectors",
                description="List all 22 available security detectors with descriptions.",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        if name == "audit_contract":
            return await _handle_audit_contract(arguments)
        elif name == "audit_source":
            return await _handle_audit_source(arguments)
        elif name == "list_detectors":
            return _handle_list_detectors()
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

    return server


async def _handle_audit_contract(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle audit_contract tool call."""
    project_path = Path(arguments["project_path"])
    if not project_path.exists():
        return [TextContent(type="text", text=f"Error: Path not found: {project_path}")]

    try:
        pipeline, config = _build_pipeline(slither_enabled=True, aderyn_enabled=True)

        from ..core.models import AuditContext

        context = AuditContext(project_path=project_path, config=config)
        result = await pipeline.run(context)
        return [TextContent(type="text", text=_format_result(result))]
    except Exception as e:
        logger.exception("audit_contract failed")
        return [TextContent(type="text", text=f"Audit failed: {e}")]


async def _handle_audit_source(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle audit_source tool call."""
    source_code = arguments["source_code"]
    filename = arguments.get("filename", "Contract.sol")

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            sol_file = tmp_path / filename
            sol_file.write_text(source_code)

            pipeline, config = _build_pipeline(
                slither_enabled=False, aderyn_enabled=False,
            )

            from ..core.models import AuditContext

            context = AuditContext(
                project_path=tmp_path,
                config=config,
                contract_sources={filename: source_code},
            )
            result = await pipeline.run(context)
            return [TextContent(type="text", text=_format_result(result))]
    except Exception as e:
        logger.exception("audit_source failed")
        return [TextContent(type="text", text=f"Audit failed: {e}")]


def _handle_list_detectors() -> list[TextContent]:
    """Handle list_detectors tool call."""
    lines = ["Available Detectors (22):", ""]
    for i, (name, desc) in enumerate(DETECTOR_DESCRIPTIONS, 1):
        lines.append(f"  {i:2d}. {name}: {desc}")
    return [TextContent(type="text", text="\n".join(lines))]


def main() -> None:
    """Run the MCP server via stdio."""
    async def _run() -> None:
        server = create_server()
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(_run())
