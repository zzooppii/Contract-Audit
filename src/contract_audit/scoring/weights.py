"""Severity and category weight tables for risk scoring."""

from ..core.models import Confidence, FindingCategory, Severity

# Base severity scores
SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFORMATIONAL: 1.0,
    Severity.GAS: 0.5,
}

# Confidence multipliers
CONFIDENCE_MULTIPLIERS: dict[Confidence, float] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.7,
    Confidence.LOW: 0.4,
}

# Category risk multipliers (relative to base severity)
CATEGORY_MULTIPLIERS: dict[FindingCategory, float] = {
    FindingCategory.ORACLE_MANIPULATION: 1.5,
    FindingCategory.STORAGE_COLLISION: 1.5,
    FindingCategory.FLASH_LOAN: 1.4,
    FindingCategory.GOVERNANCE_ATTACK: 1.3,
    FindingCategory.REENTRANCY: 1.3,
    FindingCategory.PROXY_VULNERABILITY: 1.2,
    FindingCategory.ACCESS_CONTROL: 1.2,
    FindingCategory.CENTRALIZATION_RISK: 1.1,
    FindingCategory.ARITHMETIC: 1.0,
    FindingCategory.UNCHECKED_RETURN: 0.9,
    FindingCategory.GAS_GRIEFING: 0.8,
    FindingCategory.DENIAL_OF_SERVICE: 0.9,
    FindingCategory.FRONT_RUNNING: 0.9,
    FindingCategory.WEAK_RANDOMNESS: 1.3,
    FindingCategory.MERKLE_AIRDROP: 1.2,
    FindingCategory.TIMELOCK_BYPASS: 1.4,
    FindingCategory.NFT_VULNERABILITY: 1.1,
    FindingCategory.BRIDGE_VULNERABILITY: 1.5,
    FindingCategory.ERC4626_VULNERABILITY: 1.4,
    FindingCategory.INITIALIZATION: 1.1,
    FindingCategory.INFORMATIONAL: 0.5,
    FindingCategory.OTHER: 0.8,
    FindingCategory.TYPO: 0.3,
}

# Context modifiers
MULTI_TOOL_BONUS = 0.5       # Finding confirmed by 2+ tools
SINGLE_LOW_CONFIDENCE_PENALTY = -0.3  # Single low-confidence tool
