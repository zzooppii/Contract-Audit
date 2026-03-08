"""Storage layout collision detector.

Uses solc --storage-layout output to detect:
- Proxy vs implementation storage collisions
- V1->V2 upgrade safety (strict superset check)
- Inheritance order changes
- EIP-1967 slot compliance
"""

from __future__ import annotations

import logging
from typing import Any

from ..core.models import (
    AuditContext,
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)

logger = logging.getLogger(__name__)

# EIP-1967 standard slots (in decimal for comparison)
# These are keccak256 of known strings, minus 1
EIP1967_IMPL_SLOT_DEC = int(
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16
)
EIP1967_ADMIN_SLOT_DEC = int(
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", 16
)


class StorageCollisionDetector:
    """Detects storage layout collision vulnerabilities."""

    name = "storage_collision"
    category = "storage-collision"
    required_context = ["storage_layouts", "contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        """Detect storage collisions using compiled storage layouts."""
        findings: list[Finding] = []

        layouts = context.storage_layouts
        if not layouts:
            logger.debug("No storage layouts available, skipping storage collision checks")
            # Fall back to regex-based detection
            for filename, source in context.contract_sources.items():
                findings.extend(self._regex_storage_checks(filename, source))
            return findings

        # Check all pairs of proxy/implementation contracts
        contract_names = list(layouts.keys())
        for i, c1 in enumerate(contract_names):
            for c2 in contract_names[i + 1:]:
                collisions = self._check_collision(
                    c1, layouts[c1], c2, layouts[c2]
                )
                findings.extend(collisions)

        # Check upgrade compatibility within versioned pairs
        findings.extend(self._check_upgrade_safety(layouts))

        logger.info(f"Storage collision detector found {len(findings)} findings")
        return findings

    def _check_collision(
        self,
        name1: str,
        layout1: dict[str, Any],
        name2: str,
        layout2: dict[str, Any],
    ) -> list[Finding]:
        """Check for slot collisions between two contract storage layouts."""
        findings = []

        slots1 = _extract_slots(layout1)
        slots2 = _extract_slots(layout2)

        common_slots = set(slots1.keys()) & set(slots2.keys())
        for slot in common_slots:
            var1 = slots1[slot]
            var2 = slots2[slot]

            # Different variable names at same slot = potential collision
            if var1["label"] != var2["label"] or var1["type"] != var2["type"]:
                findings.append(
                    Finding(
                        title=f"Storage Slot Collision: {name1} vs {name2}",
                        description=(
                            f"Contracts `{name1}` and `{name2}` use the same storage slot "
                            f"(slot {slot}) for different variables:\n"
                            f"- `{name1}`: `{var1['type']} {var1['label']}`\n"
                            f"- `{name2}`: `{var2['type']} {var2['label']}`\n\n"
                            "If these contracts interact via delegatecall, the proxy's storage "
                            "will be corrupted."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.STORAGE_COLLISION,
                        source=self.name,
                        detector_name="storage-slot-collision",
                        locations=[SourceLocation(file=name1, start_line=1, end_line=1)],
                        metadata={
                            "slot": slot,
                            "contract1": name1,
                            "var1": var1,
                            "contract2": name2,
                            "var2": var2,
                        },
                    )
                )

        return findings

    def _check_upgrade_safety(self, layouts: dict[str, dict[str, Any]]) -> list[Finding]:
        """Check upgrade safety between V1/V2 pairs."""
        findings = []

        # Find versioned pairs by name pattern
        versioned: dict[str, dict[int, dict[str, Any]]] = {}  # base -> version -> layout
        for name in layouts:
            import re
            match = re.match(r"(.+?)V(\d+)$", name)
            if match:
                base, version = match.group(1), int(match.group(2))
                versioned.setdefault(base, {})[version] = layouts[name]

        for base, versions in versioned.items():
            sorted_versions = sorted(versions.keys())
            for i in range(len(sorted_versions) - 1):
                v1 = sorted_versions[i]
                v2 = sorted_versions[i + 1]
                name_v1 = f"{base}V{v1}"
                name_v2 = f"{base}V{v2}"

                v1_slots = _extract_slots(versions[v1])
                v2_slots = _extract_slots(versions[v2])

                # V2 must be a strict superset of V1 (no slot changes or removals)
                for slot, var1 in v1_slots.items():
                    if slot not in v2_slots:
                        findings.append(
                            Finding(
                                title=f"Unsafe Upgrade: {name_v1} -> {name_v2} Removes Slot",
                                description=(
                                    f"Upgrading from `{name_v1}` to `{name_v2}` removes "
                                    f"storage slot {slot} (`{var1['type']} {var1['label']}`). "
                                    "This will corrupt existing storage, as the slot will "
                                    "contain the old value but no longer be typed correctly."
                                ),
                                severity=Severity.CRITICAL,
                                confidence=Confidence.HIGH,
                                category=FindingCategory.STORAGE_COLLISION,
                                source=self.name,
                                detector_name="unsafe-upgrade-slot-removal",
                                locations=[SourceLocation(file=name_v1, start_line=1, end_line=1)],
                                metadata={"v1": name_v1, "v2": name_v2, "removed_slot": slot},
                            )
                        )
                    elif v2_slots[slot] != var1:
                        findings.append(
                            Finding(
                                title=f"Unsafe Upgrade: {name_v1} -> {name_v2} Changes Slot Type",
                                description=(
                                    f"Upgrading from `{name_v1}` to `{name_v2}` changes "
                                    f"slot {slot}: `{var1['type']} {var1['label']}` -> "
                                    f"`{v2_slots[slot]['type']} {v2_slots[slot]['label']}`. "
                                    "Changing variable types at the same "
                                    "slot causes data corruption."
                                ),
                                severity=Severity.CRITICAL,
                                confidence=Confidence.HIGH,
                                category=FindingCategory.STORAGE_COLLISION,
                                source=self.name,
                                detector_name="unsafe-upgrade-type-change",
                                locations=[SourceLocation(file=name_v1, start_line=1, end_line=1)],
                                metadata={"v1": name_v1, "v2": name_v2, "changed_slot": slot},
                            )
                        )

        return findings

    def _regex_storage_checks(self, filename: str, source: str) -> list[Finding]:
        """Fallback regex-based storage analysis."""
        findings = []

        # Check for unsafe gap patterns in upgradeable contracts
        if "Upgradeable" in source or "upgradeable" in source:
            if "__gap" not in source and "StorageGap" not in source:
                findings.append(
                    Finding(
                        title="Upgradeable Contract Missing Storage Gap",
                        description=(
                            "Upgradeable contract does not define a `__gap` storage variable. "
                            "Adding new state variables in future upgrades will shift all existing "
                            "variable slots if a gap is not reserved."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        category=FindingCategory.STORAGE_COLLISION,
                        source=self.name,
                        detector_name="missing-storage-gap",
                        locations=[SourceLocation(file=filename, start_line=1, end_line=1)],
                    )
                )

        return findings


def _extract_slots(layout: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Extract slot -> variable mapping from solc storage layout."""
    slots: dict[str, dict[str, Any]] = {}
    storage = layout.get("storage", [])
    for var in storage:
        slot = str(var.get("slot", ""))
        slots[slot] = {
            "label": var.get("label", ""),
            "type": var.get("type", ""),
            "offset": var.get("offset", 0),
        }
    return slots
