"""Custom exceptions for the audit engine."""


class AuditEngineError(Exception):
    """Base exception for all audit engine errors."""


class CompilationError(AuditEngineError):
    """Raised when smart contract compilation fails."""


class AnalyzerError(AuditEngineError):
    """Raised when an analyzer fails."""

    def __init__(self, analyzer_name: str, message: str) -> None:
        self.analyzer_name = analyzer_name
        super().__init__(f"[{analyzer_name}] {message}")


class DetectorError(AuditEngineError):
    """Raised when a detector fails."""

    def __init__(self, detector_name: str, message: str) -> None:
        self.detector_name = detector_name
        super().__init__(f"[{detector_name}] {message}")


class ConfigError(AuditEngineError):
    """Raised when configuration is invalid."""


class AuthError(AuditEngineError):
    """Raised when authentication fails."""


class BudgetExhaustedError(AuditEngineError):
    """Raised when LLM budget is exhausted."""

    def __init__(self, spent_usd: float) -> None:
        self.spent_usd = spent_usd
        super().__init__(f"LLM budget exhausted (spent ${spent_usd:.4f})")


class ToolNotAvailableError(AuditEngineError):
    """Raised when a required external tool is not installed."""

    def __init__(self, tool_name: str) -> None:
        self.tool_name = tool_name
        super().__init__(f"Tool '{tool_name}' is not available. Please install it first.")


class ReportGenerationError(AuditEngineError):
    """Raised when report generation fails."""


class PluginError(AuditEngineError):
    """Raised when a plugin fails to load."""
