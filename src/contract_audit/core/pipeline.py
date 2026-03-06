"""Pipeline orchestrator: async phased execution of all analysis stages."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .models import AuditContext, AuditMetadata, AuditResult, AuditSummary, Finding
from .exceptions import AuditEngineError

if TYPE_CHECKING:
    from ..analyzers.base import AnalyzerProtocol
    from ..detectors.base import DetectorProtocol
    from ..llm.router import LLMRouter
    from ..scoring.engine import RiskScoringEngine
    from ..scoring.false_positive import FalsePositiveReducer

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """Orchestrates the full audit pipeline across all phases."""

    def __init__(
        self,
        analyzers: list[Any],
        detectors: list[Any],
        scoring_engine: "RiskScoringEngine | None" = None,
        fp_reducer: "FalsePositiveReducer | None" = None,
        llm_router: "LLMRouter | None" = None,
    ) -> None:
        self.analyzers = analyzers
        self.detectors = detectors
        self.scoring_engine = scoring_engine
        self.fp_reducer = fp_reducer
        self.llm_router = llm_router

    async def run(self, context: AuditContext) -> AuditResult:
        """Execute the full audit pipeline."""
        metadata = AuditMetadata()
        all_findings: list[Finding] = []

        logger.info(f"Starting audit of {context.project_path}")

        # Phase 1: Compile (sequential - needed by everything)
        await self._phase_compile(context, metadata)

        # Phase 2+3: Analyzers and Detectors (parallel within each group)
        logger.info("Phase 2: Running static analyzers...")
        analyzer_results = await asyncio.gather(
            *[self._run_analyzer(a, context) for a in self.analyzers],
            return_exceptions=True,
        )
        for result in analyzer_results:
            if isinstance(result, Exception):
                logger.error(f"Analyzer error: {result}")
            elif isinstance(result, list):
                all_findings.extend(result)

        logger.info("Phase 3: Running specialized detectors...")
        detector_results = await asyncio.gather(
            *[self._run_detector(d, context) for d in self.detectors],
            return_exceptions=True,
        )
        for result in detector_results:
            if isinstance(result, Exception):
                logger.error(f"Detector error: {result}")
            elif isinstance(result, list):
                all_findings.extend(result)

        # Phase 4: Dynamic analysis (optional)
        if context.config.foundry_fuzz_enabled or context.config.symbolic_enabled:
            logger.info("Phase 4: Running dynamic analysis...")
            all_findings.extend(
                await self._phase_dynamic(context)
            )

        # Deduplicate and correlate
        logger.info(f"Deduplicating {len(all_findings)} total findings...")
        from ..utils.hashing import correlate_findings, deduplicate_findings
        all_findings = deduplicate_findings(all_findings)
        all_findings = correlate_findings(all_findings)

        # Phase 5: Score and reduce false positives
        logger.info("Phase 5: Scoring and false-positive reduction...")
        if self.scoring_engine:
            all_findings = self.scoring_engine.score_findings(all_findings)

        if self.fp_reducer:
            if self.llm_router and context.config.llm_enabled:
                all_findings = await self.fp_reducer.reduce_with_llm(all_findings, context)
            else:
                all_findings = self.fp_reducer.reduce(all_findings, context)

        # Phase 6: LLM enrichment (budget-aware, critical first)
        if self.llm_router and context.config.llm_enabled:
            logger.info("Phase 6: LLM enrichment...")
            all_findings = await self._phase_llm_enrich(all_findings, context)

        # Finalize
        metadata.finalize()
        metadata.contract_count = len(context.contract_sources)
        metadata.line_count = sum(
            len(src.splitlines()) for src in context.contract_sources.values()
        )
        metadata.tool_versions = await self._collect_tool_versions()

        summary = AuditSummary.from_findings(all_findings)
        if self.scoring_engine:
            summary.overall_risk_score = self.scoring_engine.aggregate_score(all_findings)

        logger.info(
            f"Audit complete: {summary.total_findings} findings "
            f"(critical={summary.critical_count}, high={summary.high_count})"
        )

        return AuditResult(
            findings=all_findings,
            summary=summary,
            metadata=metadata,
        )

    async def _phase_compile(self, context: AuditContext, metadata: AuditMetadata) -> None:
        """Phase 1: Load sources and compile contracts."""
        from ..utils.solc import compile_contracts, extract_ast_trees, extract_storage_layouts, load_source_files

        logger.info("Phase 1: Loading source files...")

        # Load source files if not already loaded
        if not context.contract_sources:
            contracts_dir = context.project_path / context.config.contracts_dir
            if not contracts_dir.exists():
                contracts_dir = context.project_path
            context.contract_sources = await load_source_files(
                contracts_dir,
                context.config.exclude_patterns,
            )

        if not context.contract_sources:
            logger.warning("No Solidity source files found")
            return

        # Compile for AST and storage layout
        if not context.ast_trees:
            logger.info(f"Compiling {len(context.contract_sources)} files...")
            try:
                output = await compile_contracts(
                    context.project_path,
                    context.contract_sources,
                    context.config.solidity_version,
                )
                if output:
                    context.ast_trees = extract_ast_trees(output)
                    context.storage_layouts = extract_storage_layouts(output)
                    context.compilation_artifacts = output
                    logger.info(
                        f"Compiled: {len(context.ast_trees)} AST trees, "
                        f"{len(context.storage_layouts)} storage layouts"
                    )
            except Exception as e:
                logger.warning(f"Compilation failed: {e}")

    async def _run_analyzer(self, analyzer: Any, context: AuditContext) -> list[Finding]:
        """Run a single analyzer with error handling."""
        try:
            if hasattr(analyzer, "is_available") and not analyzer.is_available():
                logger.info(f"Skipping {analyzer.name}: not installed")
                return []
            logger.debug(f"Running analyzer: {analyzer.name}")
            findings = await analyzer.analyze(context)
            logger.info(f"{analyzer.name}: {len(findings)} findings")
            return findings
        except Exception as e:
            logger.error(f"Analyzer {getattr(analyzer, 'name', '?')} failed: {e}")
            return []

    async def _run_detector(self, detector: Any, context: AuditContext) -> list[Finding]:
        """Run a single detector with error handling."""
        try:
            # Check required context
            if hasattr(detector, "required_context"):
                for req in detector.required_context:
                    if not getattr(context, req, None):
                        logger.debug(
                            f"Skipping {detector.name}: missing required context '{req}'"
                        )
                        # Don't skip, detectors handle missing context gracefully
            logger.debug(f"Running detector: {detector.name}")
            findings = await detector.detect(context)
            logger.info(f"{detector.name}: {len(findings)} findings")
            return findings
        except Exception as e:
            logger.error(f"Detector {getattr(detector, 'name', '?')} failed: {e}")
            return []

    async def _phase_dynamic(self, context: AuditContext) -> list[Finding]:
        """Phase 4: Optional dynamic analysis."""
        findings = []
        tasks = []

        if context.config.foundry_fuzz_enabled:
            try:
                from ..analyzers.foundry.analyzer import FoundryAnalyzer
                tasks.append(FoundryAnalyzer().analyze(context))
            except ImportError:
                logger.debug("Foundry analyzer not available")

        if context.config.symbolic_enabled:
            try:
                from ..analyzers.symbolic.analyzer import SymbolicAnalyzer
                tasks.append(SymbolicAnalyzer().analyze(context))
            except ImportError:
                logger.debug("Symbolic analyzer not available")

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    findings.extend(r)
                elif isinstance(r, Exception):
                    logger.warning(f"Dynamic analysis error: {r}")

        return findings

    async def _phase_llm_enrich(
        self, findings: list[Finding], context: AuditContext
    ) -> list[Finding]:
        """Phase 6: Enrich findings with LLM explanations, remediations, PoCs."""
        if not self.llm_router:
            return findings

        from ..llm.tasks.explain import ExplainTask
        from ..llm.tasks.remediate import RemediateTask
        from ..llm.tasks.poc_generate import PoCGenerateTask
        from ..llm.tasks.summarize import SummarizeTask

        explain = ExplainTask(self.llm_router)
        remediate = RemediateTask(self.llm_router)
        poc = PoCGenerateTask(self.llm_router)

        # Process critical and high findings first (budget-aware)
        priority_order = ["Critical", "High", "Medium"]
        processed_count = 0

        for severity_str in priority_order:
            for finding in findings:
                if finding.suppressed or finding.severity.value != severity_str:
                    continue

                # Get source context
                source_snippet = self._get_source_snippet(finding, context)

                try:
                    # Explain
                    if not finding.llm_explanation:
                        finding.llm_explanation = await explain.run(finding, source_snippet)

                    # Remediate
                    if not finding.llm_remediation:
                        finding.llm_remediation = await remediate.run(finding, source_snippet)

                    # PoC for critical findings only
                    if severity_str == "Critical" and not finding.llm_poc:
                        finding.llm_poc = await poc.run(finding, source_snippet)

                    processed_count += 1

                except Exception as e:
                    error_str = str(e)
                    if "budget" in error_str.lower() or "exhausted" in error_str.lower():
                        logger.warning("LLM budget exhausted, stopping enrichment")
                        return findings
                    logger.warning(f"LLM enrichment failed for '{finding.title}': {e}")

        # Generate executive summary
        try:
            from ..llm.tasks.summarize import SummarizeTask
            summarize = SummarizeTask(self.llm_router)
            active = [f for f in findings if not f.suppressed]
            summary_text = await summarize.run(active)
            # Store in metadata for report generator
            for f in findings:
                f.metadata.setdefault("executive_summary", summary_text)
                break  # Just tag first finding; report generator retrieves it
        except Exception as e:
            logger.warning(f"Executive summary generation failed: {e}")

        logger.info(f"LLM enriched {processed_count} findings")
        return findings

    def _get_source_snippet(self, finding: Finding, context: AuditContext) -> str:
        """Extract relevant source code snippet for a finding."""
        for loc in finding.locations[:1]:
            src = context.contract_sources.get(loc.file, "")
            if src:
                lines = src.splitlines()
                start = max(0, loc.start_line - 5)
                end = min(len(lines), loc.end_line + 15)
                return "\n".join(lines[start:end])
        return ""

    async def _collect_tool_versions(self) -> dict[str, str]:
        """Collect version information from available tools."""
        versions: dict[str, str] = {}

        from ..utils.solc import get_solc_version
        solc_v = get_solc_version()
        if solc_v:
            versions["solc"] = solc_v

        # Slither version
        try:
            import slither
            versions["slither"] = getattr(slither, "__version__", "unknown")
        except ImportError:
            pass

        return versions
