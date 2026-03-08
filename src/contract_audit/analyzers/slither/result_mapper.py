"""Maps Slither findings to the unified Finding model."""

from __future__ import annotations

import logging
from typing import Any

from ...core.models import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)

logger = logging.getLogger(__name__)

# Slither impact -> Severity mapping
IMPACT_MAP: dict[str, Severity] = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFORMATIONAL,
    "Optimization": Severity.GAS,
}

# Slither confidence -> Confidence mapping
CONFIDENCE_MAP: dict[str, Confidence] = {
    "High": Confidence.HIGH,
    "Medium": Confidence.MEDIUM,
    "Low": Confidence.LOW,
}

# Slither check name -> FindingCategory mapping
CATEGORY_MAP: dict[str, FindingCategory] = {
    "reentrancy-eth": FindingCategory.REENTRANCY,
    "reentrancy-no-eth": FindingCategory.REENTRANCY,
    "reentrancy-benign": FindingCategory.REENTRANCY,
    "reentrancy-events": FindingCategory.REENTRANCY,
    "reentrancy-balance": FindingCategory.REENTRANCY,
    "reentrancy-unlimited-gas": FindingCategory.REENTRANCY,
    "unprotected-upgrade": FindingCategory.PROXY_VULNERABILITY,
    "backdoor": FindingCategory.ACCESS_CONTROL,
    "suicidal": FindingCategory.ACCESS_CONTROL,
    "controlled-delegatecall": FindingCategory.PROXY_VULNERABILITY,
    "msg-value-loop": FindingCategory.ARITHMETIC,
    "shadowing-state": FindingCategory.OTHER,
    "shadowing-local": FindingCategory.OTHER,
    "tx-origin": FindingCategory.ACCESS_CONTROL,
    "arbitrary-send-eth": FindingCategory.ACCESS_CONTROL,
    "arbitrary-send-erc20": FindingCategory.ACCESS_CONTROL,
    "arbitrary-send": FindingCategory.ACCESS_CONTROL,
    "unchecked-transfer": FindingCategory.UNCHECKED_RETURN,
    "unchecked-send": FindingCategory.UNCHECKED_RETURN,
    "unchecked-lowlevel": FindingCategory.UNCHECKED_RETURN,
    "oracle-manipulation": FindingCategory.ORACLE_MANIPULATION,
    "flash-loan-taint": FindingCategory.FLASH_LOAN,
    "integer-overflow": FindingCategory.ARITHMETIC,
    "divide-before-multiply": FindingCategory.ARITHMETIC,
    "tautology": FindingCategory.ARITHMETIC,
    "boolean-cst": FindingCategory.ARITHMETIC,
    "missing-zero-check": FindingCategory.ACCESS_CONTROL,
    "locked-ether": FindingCategory.OTHER,
    "events-access": FindingCategory.ACCESS_CONTROL,
    "events-maths": FindingCategory.ARITHMETIC,
    "low-level-calls": FindingCategory.OTHER,
    "calls-loop": FindingCategory.GAS_GRIEFING,
    "costly-loop": FindingCategory.GAS_GRIEFING,
    "constable-states": FindingCategory.OTHER,
    "immutable-states": FindingCategory.OTHER,
    "unused-return": FindingCategory.UNCHECKED_RETURN,
    "solc-version": FindingCategory.OTHER,
}

# Human-readable titles for common checks
TITLE_MAP: dict[str, str] = {
    "reentrancy-eth": "Reentrancy (ETH transfer)",
    "reentrancy-no-eth": "Reentrancy (state modification)",
    "reentrancy-benign": "Reentrancy (benign)",
    "reentrancy-events": "Reentrancy (event ordering)",
    "reentrancy-balance": "Reentrancy (balance dependency)",
    "unprotected-upgrade": "Unprotected Proxy Upgrade",
    "controlled-delegatecall": "Controlled Delegatecall",
    "tx-origin": "tx.origin Authentication",
    "arbitrary-send-eth": "Arbitrary ETH Transfer",
    "arbitrary-send-erc20": "Arbitrary ERC20 Transfer",
    "arbitrary-send": "Arbitrary ETH Transfer",
    "unchecked-transfer": "Unchecked ERC20 Transfer",
    "unchecked-send": "Unchecked send()",
    "unchecked-lowlevel": "Unchecked Low-Level Call",
    "oracle-manipulation": "Oracle Price Manipulation",
    "flash-loan-taint": "Flash Loan Taint",
    "calls-loop": "External Calls Inside Loop",
    "costly-loop": "Costly Loop Operation",
    "divide-before-multiply": "Divide Before Multiply (Precision Loss)",
    "unused-return": "Unused Return Value",
    "missing-zero-check": "Missing Zero Address Check",
    "locked-ether": "Locked Ether",
    "constable-states": "State Variable Could Be Constant",
    "immutable-states": "State Variable Could Be Immutable",
    "solc-version": "Solidity Version Issue",
}


def _get_val(result: Any, key: str, default: Any = None) -> Any:
    """Get a value from a result that may be a dict or an object."""
    if isinstance(result, dict):
        return result.get(key, default)
    return getattr(result, key, default)


def map_slither_result(result: Any, source_name: str = "slither") -> Finding | None:
    """Convert a Slither detector result (dict or object) to a unified Finding."""
    try:
        check = _get_val(result, "check", "unknown")
        impact_raw = _get_val(result, "impact", "Informational")
        confidence_raw = _get_val(result, "confidence", "Medium")

        # Normalize to strings
        if hasattr(impact_raw, "name"):
            impact_str = impact_raw.name.title()
        else:
            impact_str = str(impact_raw) if impact_raw else "Informational"

        if hasattr(confidence_raw, "name"):
            confidence_str = confidence_raw.name.title()
        else:
            confidence_str = str(confidence_raw) if confidence_raw else "Medium"

        severity = IMPACT_MAP.get(impact_str, Severity.INFORMATIONAL)
        conf = CONFIDENCE_MAP.get(confidence_str, Confidence.MEDIUM)
        category = CATEGORY_MAP.get(check, FindingCategory.OTHER)

        elements = _get_val(result, "elements", []) or []
        description = _build_description(result, elements)
        title = _build_title(check, elements)
        locations = _extract_locations(elements)

        return Finding(
            title=title,
            description=description,
            severity=severity,
            confidence=conf,
            category=category,
            source=source_name,
            detector_name=check,
            locations=locations,
            metadata={"slither_check": check, "elements": len(elements)},
        )
    except Exception as e:
        logger.warning(f"Failed to map Slither result: {e}")
        return None


def _build_title(check: str, elements: list[Any]) -> str:
    """Build a human-readable title from check name and elements."""
    base = TITLE_MAP.get(check, check.replace("-", " ").title())

    # Append affected function name for context
    for elem in elements:
        elem_type = elem.get("type", "") if isinstance(elem, dict) else getattr(elem, "type", "")
        elem_name = elem.get("name", "") if isinstance(elem, dict) else getattr(elem, "name", "")
        if elem_type == "function" and elem_name:
            return f"{base}: {elem_name}"

    return base


def _build_description(result: Any, elements: list[Any]) -> str:
    """Build description from Slither result."""
    desc = _get_val(result, "description", None)
    if desc:
        return str(desc).strip()

    # Fallback: describe elements
    contract_names = []
    function_names = []
    for elem in elements:
        elem_type = elem.get("type", "") if isinstance(elem, dict) else getattr(elem, "type", "")
        elem_name = elem.get("name", "") if isinstance(elem, dict) else getattr(elem, "name", "")
        if elem_type == "contract" and elem_name:
            contract_names.append(elem_name)
        elif elem_type == "function" and elem_name:
            function_names.append(elem_name)

    parts = []
    if contract_names:
        parts.append(f"Contracts: {', '.join(contract_names)}")
    if function_names:
        parts.append(f"Functions: {', '.join(function_names)}")
    return "; ".join(parts) or "Security issue detected by Slither"


def _extract_locations(elements: list[Any]) -> list[SourceLocation]:
    """Extract source locations from Slither elements (dicts or objects)."""
    locations = []
    seen: set[tuple[str, int]] = set()

    for elem in elements:
        if isinstance(elem, dict):
            source_mapping = elem.get("source_mapping")
        else:
            source_mapping = getattr(elem, "source_mapping", None)

        if not source_mapping:
            continue

        try:
            if isinstance(source_mapping, dict):
                filename = source_mapping.get("filename_short", "")
                lines = source_mapping.get("lines", [])
            else:
                filename = getattr(source_mapping, "filename_short", "")
                lines = getattr(source_mapping, "lines", [])

            if filename and lines:
                key = (filename, lines[0])
                if key not in seen:
                    seen.add(key)
                    locations.append(
                        SourceLocation(
                            file=filename,
                            start_line=lines[0],
                            end_line=lines[-1],
                        )
                    )
        except Exception:
            continue

    return locations
