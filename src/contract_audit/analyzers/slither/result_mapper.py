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
    "unprotected-upgrade": FindingCategory.PROXY_VULNERABILITY,
    "backdoor": FindingCategory.ACCESS_CONTROL,
    "suicidal": FindingCategory.ACCESS_CONTROL,
    "controlled-delegatecall": FindingCategory.PROXY_VULNERABILITY,
    "msg-value-loop": FindingCategory.ARITHMETIC,
    "shadowing-state": FindingCategory.OTHER,
    "shadowing-local": FindingCategory.OTHER,
    "tx-origin": FindingCategory.ACCESS_CONTROL,
    "arbitrary-send": FindingCategory.ACCESS_CONTROL,
    "unchecked-transfer": FindingCategory.UNCHECKED_RETURN,
    "unchecked-send": FindingCategory.UNCHECKED_RETURN,
    "unchecked-lowlevel": FindingCategory.UNCHECKED_RETURN,
    "oracle-manipulation": FindingCategory.ORACLE_MANIPULATION,
    "flash-loan-taint": FindingCategory.FLASH_LOAN,
    "integer-overflow": FindingCategory.ARITHMETIC,
    "tautology": FindingCategory.ARITHMETIC,
    "boolean-cst": FindingCategory.ARITHMETIC,
    "missing-zero-check": FindingCategory.ACCESS_CONTROL,
    "locked-ether": FindingCategory.OTHER,
    "events-access": FindingCategory.ACCESS_CONTROL,
    "events-maths": FindingCategory.ARITHMETIC,
    "low-level-calls": FindingCategory.OTHER,
    "calls-loop": FindingCategory.GAS_GRIEFING,
    "costly-loop": FindingCategory.GAS_GRIEFING,
}


def map_slither_result(result: Any, source_name: str = "slither") -> Finding | None:
    """Convert a Slither DetectorResult to a unified Finding."""
    try:
        check = getattr(result, "check", "unknown")
        impact = getattr(result, "impact", None)
        confidence = getattr(result, "confidence", None)

        # Get impact/confidence as strings
        if hasattr(impact, "name"):
            impact_str = impact.name.title()
        else:
            impact_str = str(impact) if impact else "Informational"

        if hasattr(confidence, "name"):
            confidence_str = confidence.name.title()
        else:
            confidence_str = str(confidence) if confidence else "Medium"

        severity = IMPACT_MAP.get(impact_str, Severity.INFORMATIONAL)
        conf = CONFIDENCE_MAP.get(confidence_str, Confidence.MEDIUM)
        category = CATEGORY_MAP.get(check, FindingCategory.OTHER)

        # Build description from elements
        elements = getattr(result, "elements", [])
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
    """Build a human-readable title from check name."""
    title_map = {
        "reentrancy-eth": "Reentrancy (ETH)",
        "reentrancy-no-eth": "Reentrancy (no ETH)",
        "unprotected-upgrade": "Unprotected Proxy Upgrade",
        "controlled-delegatecall": "Controlled Delegatecall",
        "tx-origin": "tx.origin Authentication",
        "arbitrary-send": "Arbitrary ETH Transfer",
        "unchecked-transfer": "Unchecked ERC20 Transfer",
        "oracle-manipulation": "Oracle Price Manipulation",
        "flash-loan-taint": "Flash Loan Taint",
        "calls-loop": "Calls Inside Loop",
    }
    return title_map.get(check, check.replace("-", " ").title())


def _build_description(result: Any, elements: list[Any]) -> str:
    """Build description from Slither result."""
    # Try to get the formatted description
    try:
        info = getattr(result, "description", None)
        if info:
            return str(info)
    except Exception:
        pass

    # Fallback: describe elements
    contract_names = []
    function_names = []
    for elem in elements:
        if hasattr(elem, "type"):
            if elem.type == "contract":
                contract_names.append(getattr(elem, "name", ""))
            elif elem.type == "function":
                function_names.append(getattr(elem, "name", ""))

    parts = []
    if contract_names:
        parts.append(f"Contracts: {', '.join(contract_names)}")
    if function_names:
        parts.append(f"Functions: {', '.join(function_names)}")
    return "; ".join(parts) or "Security issue detected by Slither"


def _extract_locations(elements: list[Any]) -> list[SourceLocation]:
    """Extract source locations from Slither elements."""
    locations = []
    seen = set()

    for elem in elements:
        source_mapping = getattr(elem, "source_mapping", None)
        if not source_mapping:
            # Try nested access
            try:
                source_mapping = elem.get("source_mapping", {}) if isinstance(elem, dict) else None
            except Exception:
                continue

        if source_mapping:
            try:
                filename = getattr(source_mapping, "filename_short", None) or (
                    source_mapping.get("filename_short", "") if isinstance(source_mapping, dict) else ""
                )
                lines = getattr(source_mapping, "lines", []) or (
                    source_mapping.get("lines", []) if isinstance(source_mapping, dict) else []
                )

                if filename and lines:
                    key = (filename, lines[0] if lines else 0)
                    if key not in seen:
                        seen.add(key)
                        locations.append(
                            SourceLocation(
                                file=filename,
                                start_line=lines[0] if lines else 1,
                                end_line=lines[-1] if lines else 1,
                            )
                        )
            except Exception:
                continue

    return locations
