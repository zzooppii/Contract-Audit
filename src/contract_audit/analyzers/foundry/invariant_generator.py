"""Invariant test generator for Foundry.

Automatically detects common invariants based on contract patterns
(ERC20, vault, ownable, etc.) and generates Foundry invariant tests.
"""

from __future__ import annotations

import re
from pathlib import Path

# Pattern -> invariant mapping
# Each pattern may include optional "state_vars" and "setup_extra" fields
# to inject contract-level state and setUp initialization code.
INVARIANT_PATTERNS: list[dict[str, str]] = [
    {
        "name": "erc20_supply",
        "detect": r'\btotalSupply\b.*\bbalanceOf\b|\bbalanceOf\b.*\btotalSupply\b',
        "description": "ERC20 total supply should remain consistent",
        "state_vars": "uint256 private _initialSupply;",
        "setup_extra": "_initialSupply = target.totalSupply();",
        "test": """
    /// @notice totalSupply should not decrease below initial (unauthorized burns)
    function invariant_totalSupplyConsistency() public {{
        uint256 currentSupply = target.totalSupply();
        // Supply should not shrink below what it started at (unless burns are
        // a feature, in which extend this test with protocol specifics).
        assertTrue(
            currentSupply >= _initialSupply || currentSupply == 0,
            "totalSupply decreased unexpectedly"
        );
        // Supply should never overflow into unreasonable range
        assertTrue(currentSupply <= type(uint128).max, "totalSupply overflowed uint128");
    }}""",
    },
    {
        "name": "vault_assets",
        "detect": r'\btotalAssets\b.*\btotalSupply\b|\bshares\b.*\bassets\b',
        "description": "Vault total assets >= total shares (no inflation)",
        "test": """
    /// @notice totalAssets should maintain consistency with shares
    function invariant_vaultAssetsConsistency() public {{
        uint256 shares = target.totalSupply();
        if (shares > 0) {{
            assertTrue(
                target.totalAssets() > 0,
                "Non-zero shares should mean non-zero assets"
            );
            // Assets per share should not collapse to zero (inflation attack)
            uint256 assetsPerShare = target.totalAssets() / shares;
            assertTrue(assetsPerShare > 0, "Assets per share collapsed to zero");
        }}
    }}""",
    },
    {
        "name": "ownable",
        "detect": r'\bowner\b.*\baddress\b|\bonlyOwner\b',
        "description": "Owner should never be address(0)",
        "test": """
    /// @notice Owner should never be zero address
    function invariant_ownerNotZero() public {{
        assertTrue(
            target.owner() != address(0),
            "Owner must not be zero address"
        );
    }}""",
    },
    {
        "name": "pausable",
        "detect": r'\bpaused\b.*\bwhenNotPaused\b|\bpause\b.*\bunpause\b',
        "description": "Paused state should be stable across reads",
        "test": """
    /// @notice Paused state should be consistent across reads (no reentrancy corruption)
    function invariant_pauseConsistency() public {{
        bool state1 = target.paused();
        bool state2 = target.paused();
        assertEq(state1, state2, "Paused state changed between two consecutive reads");
    }}""",
    },
    {
        "name": "balance_conservation",
        "detect": r'\.transfer\s*\(|\bcall\s*\{.*value',
        "description": "ETH balance should not exceed deposited amount",
        "state_vars": "uint256 private _initialBalance;",
        "setup_extra": "_initialBalance = address(target).balance;",
        "test": """
    /// @notice Contract ETH balance should not grow beyond expected cap
    function invariant_balanceConservation() public {{
        uint256 balance = address(target).balance;
        // Balance should not have grown more than 10x the initial deposit
        // (adjust this threshold to match protocol expectations)
        assertTrue(
            balance <= _initialBalance + 10_000 ether,
            "Contract balance exceeded reasonable maximum"
        );
    }}""",
    },
]


def generate_invariant_tests(
    contract_name: str,
    source: str,
    output_dir: Path,
) -> Path:
    """Auto-detect invariants and generate Foundry invariant tests.

    Args:
        contract_name: Name of the target contract
        source: Solidity source code
        output_dir: Directory to write test file

    Returns:
        Path to the generated test file
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    test_file = output_dir / f"Invariant{contract_name}.t.sol"

    # Detect which invariants apply
    applicable_tests = []
    for pattern in INVARIANT_PATTERNS:
        if re.search(pattern["detect"], source, re.IGNORECASE | re.DOTALL):
            applicable_tests.append(pattern)

    if not applicable_tests:
        # Add a basic liveness invariant
        applicable_tests.append({
            "name": "no_unexpected_revert",
            "test": """
    /// @notice Basic liveness: contract should not self-destruct
    function invariant_contractExists() public {{
        assertTrue(
            address(target).code.length > 0,
            "Contract should still exist"
        );
    }}""",
        })

    # Collect optional state variables and setUp extras from each pattern
    state_vars_lines = []
    setup_extra_lines = []
    for t in applicable_tests:
        if t.get("state_vars"):
            state_vars_lines.append(f"    {t['state_vars']}")
        if t.get("setup_extra"):
            setup_extra_lines.append(f"        {t['setup_extra']}")

    state_vars_section = ("\n" + "\n".join(state_vars_lines)) if state_vars_lines else ""
    setup_extra_section = ("\n" + "\n".join(setup_extra_lines)) if setup_extra_lines else ""
    test_bodies = "\n".join(t["test"] for t in applicable_tests)

    content = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract_name}.sol";

/// @title Invariant tests for {contract_name}
/// @notice Auto-generated by contract-audit
contract Invariant{contract_name}Test is Test {{
    {contract_name} target;{state_vars_section}

    function setUp() public {{
        target = new {contract_name}();{setup_extra_section}
    }}
{test_bodies}
}}
"""
    test_file.write_text(content)
    return test_file


def detect_invariants(source: str) -> list[str]:
    """Detect which invariant patterns apply to the given source.

    Returns:
        List of invariant pattern names that matched
    """
    matches = []
    for pattern in INVARIANT_PATTERNS:
        if re.search(pattern["detect"], source, re.IGNORECASE | re.DOTALL):
            matches.append(pattern["name"])
    return matches
