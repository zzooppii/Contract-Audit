"""Core data models for the audit engine."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"
    GAS = "Gas"


class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class FindingCategory(str, Enum):
    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access-control"
    ORACLE_MANIPULATION = "oracle-manipulation"
    FLASH_LOAN = "flash-loan"
    PROXY_VULNERABILITY = "proxy-vulnerability"
    STORAGE_COLLISION = "storage-collision"
    GAS_GRIEFING = "gas-griefing"
    GOVERNANCE_ATTACK = "governance-attack"
    CENTRALIZATION_RISK = "centralization-risk"
    ARITHMETIC = "arithmetic"
    UNCHECKED_RETURN = "unchecked-return"
    INITIALIZATION = "initialization"
    DENIAL_OF_SERVICE = "denial-of-service"
    FRONT_RUNNING = "front-running"
    TYPO = "typo"
    INFORMATIONAL = "informational"
    OTHER = "other"


class SourceLocation(BaseModel):
    """A source code location."""

    file: str
    start_line: int
    end_line: int
    function: str | None = None
    contract: str | None = None

    def __str__(self) -> str:
        loc = f"{self.file}:{self.start_line}"
        if self.end_line != self.start_line:
            loc += f"-{self.end_line}"
        if self.function:
            loc += f" ({self.function})"
        return loc


def _compute_fingerprint(category: str, title: str, locations: list[SourceLocation]) -> str:
    """Generate a stable SHA-256 fingerprint for deduplication."""
    loc_strs = sorted(str(loc) for loc in locations)
    content = f"{category}:{title}:{':'.join(loc_strs)}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


class Finding(BaseModel):
    """A single security finding from any analysis tool."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    fingerprint: str = Field(default="")
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    category: FindingCategory
    source: str  # "slither", "aderyn", "oracle_detector", etc.
    detector_name: str  # Specific detector ID
    locations: list[SourceLocation] = Field(default_factory=list)
    risk_score: float = 0.0
    suppressed: bool = False
    suppression_reason: str | None = None
    llm_explanation: str | None = None
    llm_remediation: str | None = None
    llm_poc: str | None = None
    related_findings: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def compute_fingerprint(self) -> Finding:
        if not self.fingerprint:
            self.fingerprint = _compute_fingerprint(
                self.category.value, self.title, self.locations
            )
        return self

    def primary_location(self) -> SourceLocation | None:
        return self.locations[0] if self.locations else None


class AuditSummary(BaseModel):
    """High-level summary of audit results."""

    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    informational_count: int = 0
    gas_count: int = 0
    suppressed_count: int = 0
    overall_risk_score: float = 0.0
    executive_summary: str | None = None

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> AuditSummary:
        active = [f for f in findings if not f.suppressed]
        counts = {s: 0 for s in Severity}
        for f in active:
            counts[f.severity] += 1

        scores = [f.risk_score for f in active if f.risk_score > 0]
        overall = max(scores) if scores else 0.0

        return cls(
            total_findings=len(active),
            critical_count=counts[Severity.CRITICAL],
            high_count=counts[Severity.HIGH],
            medium_count=counts[Severity.MEDIUM],
            low_count=counts[Severity.LOW],
            informational_count=counts[Severity.INFORMATIONAL],
            gas_count=counts[Severity.GAS],
            suppressed_count=len(findings) - len(active),
            overall_risk_score=round(overall, 2),
        )


class AuditMetadata(BaseModel):
    """Metadata about the audit run."""

    start_time: datetime = Field(default_factory=datetime.utcnow)
    end_time: datetime | None = None
    duration_seconds: float | None = None
    tool_versions: dict[str, str] = Field(default_factory=dict)
    contract_count: int = 0
    line_count: int = 0
    config_hash: str = ""
    engine_version: str = "1.0.0"

    def finalize(self) -> None:
        self.end_time = datetime.utcnow()
        if self.start_time:
            self.duration_seconds = (self.end_time - self.start_time).total_seconds()


class AuditConfig(BaseModel):
    """Runtime audit configuration (loaded from TOML)."""

    project_name: str = "Unknown Project"
    solidity_version: str = "auto"
    contracts_dir: Path = Path("./src")
    exclude_patterns: list[str] = Field(
        default_factory=lambda: ["**/test/**", "**/mock/**", "**/script/**"]
    )

    # Analyzer flags
    ast_parser_enabled: bool = True
    slither_enabled: bool = True
    aderyn_enabled: bool = True
    foundry_fuzz_enabled: bool = False
    symbolic_enabled: bool = False

    # Detector flags
    proxy_detector_enabled: bool = True
    flash_loan_detector_enabled: bool = True
    oracle_detector_enabled: bool = True
    storage_collision_enabled: bool = True
    gas_griefing_enabled: bool = True
    governance_detector_enabled: bool = True

    # Detector config
    oracle_max_staleness_seconds: int = 3600
    oracle_interfaces: list[str] = Field(
        default_factory=lambda: ["AggregatorV3Interface", "IUniswapV3Pool"]
    )
    governance_min_quorum_threshold: float = 0.04
    governance_min_timelock_seconds: int = 86400

    # Scoring
    severity_scores: dict[str, float] = Field(
        default_factory=lambda: {
            "critical": 10.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "informational": 1.0,
            "gas": 0.5,
        }
    )

    # LLM
    llm_enabled: bool = True
    llm_max_budget_usd: float = 10.0

    # Reporting
    report_formats: list[str] = Field(default_factory=lambda: ["sarif", "json", "markdown"])
    output_dir: Path = Path("./audit-results")

    # CI
    ci_fail_on_critical: bool = True
    ci_fail_on_high: bool = False
    ci_sarif_upload: bool = True
    ci_pr_comment: bool = True


class AuditContext(BaseModel):
    """Shared context passed through the pipeline phases."""

    model_config = {"arbitrary_types_allowed": True}

    project_path: Path
    contract_sources: dict[str, str] = Field(default_factory=dict)
    ast_trees: dict[str, dict] = Field(default_factory=dict)
    storage_layouts: dict[str, dict] = Field(default_factory=dict)
    slither_instance: Any = None  # Slither object (not serialized)
    compilation_artifacts: dict[str, Any] = Field(default_factory=dict)
    config: AuditConfig = Field(default_factory=AuditConfig)

    @field_validator("project_path", mode="before")
    @classmethod
    def resolve_path(cls, v: Any) -> Path:
        return Path(v).resolve()


class AuditResult(BaseModel):
    """Final output of the pipeline."""

    findings: list[Finding] = Field(default_factory=list)
    summary: AuditSummary = Field(default_factory=AuditSummary)
    metadata: AuditMetadata = Field(default_factory=AuditMetadata)

    @property
    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed]

    @property
    def critical_findings(self) -> list[Finding]:
        return [f for f in self.active_findings if f.severity == Severity.CRITICAL]

    @property
    def high_findings(self) -> list[Finding]:
        return [f for f in self.active_findings if f.severity == Severity.HIGH]

    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for finding in self.active_findings:
            result[finding.severity].append(finding)
        return result


class OAuthToken(BaseModel):
    """OAuth token data."""

    access_token: str
    refresh_token: str | None = None
    expires_at: float | None = None
    token_type: str = "Bearer"
    scopes: list[str] = Field(default_factory=list)

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        import time
        return time.time() >= self.expires_at - 60  # 60s buffer


class LLMResponse(BaseModel):
    """Response from an LLM provider."""

    content: str
    model: str
    provider: str
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    structured_data: dict[str, Any] | None = None
