"""Pipeline orchestrator: async phased execution of all analysis stages."""

from __future__ import annotations

import asyncio
import logging
import shutil
from typing import TYPE_CHECKING, Any

from .models import AuditContext, AuditMetadata, AuditResult, AuditSummary, Finding, Severity

if TYPE_CHECKING:
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
        scoring_engine: RiskScoringEngine | None = None,
        fp_reducer: FalsePositiveReducer | None = None,
        llm_router: LLMRouter | None = None,
    ) -> None:
        self.analyzers = analyzers
        self.detectors = detectors
        self.scoring_engine = scoring_engine
        self.fp_reducer = fp_reducer
        self.llm_router = llm_router

    async def run(self, context: AuditContext) -> AuditResult:
        """Execute the full audit pipeline."""
        metadata = AuditMetadata()
        new_findings: list[Finding] = []

        logger.info(f"Starting audit of {context.project_path}")

        # Phase 1: Compile (sequential - needed by everything)
        await self._phase_compile(context, metadata)

        # Cache & Incremental analysis setup
        from .cache import AuditCache, calculate_hash
        cache = AuditCache(context.project_path)
        cache.load()

        file_hashes: dict[str, str] = {}
        cached_findings: list[Finding] = []
        active_sources: dict[str, str] = {}

        if context.contract_sources:
            for filepath, source in context.contract_sources.items():
                h = calculate_hash(source)
                file_hashes[filepath] = h
                cached = cache.get_cached_findings(filepath, h)
                if cached is not None:
                    cached_findings.extend(cached)
                    logger.info(f"Incremental Audit: {filepath} is unchanged. Using {len(cached)} cached findings.")
                else:
                    active_sources[filepath] = source
                    logger.info(f"Incremental Audit: {filepath} is modified. Running analysis.")

        # Save original full contract sources
        original_sources = context.contract_sources.copy()

        # Temporarily restrict contract sources to only modified files for analysis phases
        if active_sources:
            context.contract_sources = active_sources

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
                    new_findings.extend(result)

            logger.info("Phase 3: Running specialized detectors...")
            detector_results = await asyncio.gather(
                *[self._run_detector(d, context) for d in self.detectors],
                return_exceptions=True,
            )
            for result in detector_results:
                if isinstance(result, Exception):
                    logger.error(f"Detector error: {result}")
                elif isinstance(result, list):
                    new_findings.extend(result)

            # Phase 3.5: LLM-based direct audit (optional)
            if self.llm_router and context.config.llm_enabled:
                logger.info("Phase 3.5: LLM direct audit...")
                new_findings.extend(
                    await self._phase_llm_audit(context)
                )

            # Phase 4: Dynamic analysis (optional)
            if context.config.foundry_fuzz_enabled or context.config.symbolic_enabled:
                logger.info("Phase 4: Running dynamic analysis...")
                new_findings.extend(
                    await self._phase_dynamic(context, existing_findings=new_findings)
                )

            # Restore original full contract sources for scoring and reporting phases
            context.contract_sources = original_sources

            # Update cache for analyzed active files
            for filepath in active_sources.keys():
                h = file_hashes[filepath]
                cache.update_file_cache(filepath, h, new_findings)
            cache.save()
        else:
            logger.info("Incremental Audit: No files modified. Skipping all analysis phases.")
            context.contract_sources = original_sources

        # Combine new and cached findings
        all_findings = new_findings + cached_findings

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

        # Attach source code snippets to findings for reports
        self._attach_source_snippets(all_findings, context)

        # Phase 6: LLM enrichment (budget-aware, critical first)
        executive_summary: str | None = None
        if self.llm_router and context.config.llm_enabled:
            logger.info("Phase 6: LLM enrichment...")
            all_findings, executive_summary = await self._phase_llm_enrich(all_findings, context)

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
        if executive_summary:
            summary.executive_summary = executive_summary

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
        from ..utils.solc import (
            compile_contracts,
            extract_ast_trees,
            extract_storage_layouts,
            load_source_files,
        )

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
            findings: list[Finding] = await analyzer.analyze(context)
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
            findings: list[Finding] = await detector.detect(context)
            logger.info(f"{detector.name}: {len(findings)} findings")
            return findings
        except Exception as e:
            logger.error(f"Detector {getattr(detector, 'name', '?')} failed: {e}")
            return []

    async def _phase_dynamic(
        self, context: AuditContext, existing_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Phase 4: Optional dynamic analysis with targeted harness generation."""
        findings = []
        symbolic = None

        # Step 1: Generate targeted harnesses BEFORE running forge so they are included
        if context.config.foundry_fuzz_enabled and existing_findings:
            try:
                from ..analyzers.foundry.harness_generator import generate_targeted_harness

                test_dir = context.project_path / "test" / "audit_targeted"
                for finding in existing_findings:
                    if finding.severity in (Severity.CRITICAL, Severity.HIGH):
                        if finding.locations and finding.locations[0].contract:
                            try:
                                ctor_inputs, src_path = self._resolve_contract_info(
                                    finding.locations[0].contract, context
                                )
                                generate_targeted_harness(
                                    finding.locations[0].contract,
                                    finding,
                                    context.contract_sources.get(
                                        finding.locations[0].file, ""
                                    ),
                                    test_dir,
                                    source_path=src_path,
                                    constructor_abi=ctor_inputs,
                                )
                            except Exception as e:
                                logger.debug(f"Targeted harness failed: {e}")
            except ImportError:
                logger.debug("Harness generator not available")

        # Step 1b: Generate generic fuzz harnesses for every compiled contract
        if context.config.foundry_fuzz_enabled and context.compilation_artifacts:
            try:
                from ..analyzers.foundry.harness_generator import generate_fuzz_harness

                fuzz_dir = context.project_path / "test" / "audit_fuzz"
                for _fname, file_contracts in context.compilation_artifacts.get(
                    "contracts", {}
                ).items():
                    for cname, cdata in file_contracts.items():
                        abi = cdata.get("abi", [])
                        functions = [e for e in abi if e.get("type") == "function"]
                        if not functions:
                            continue
                        try:
                            ctor_inputs, src_path = self._resolve_contract_info(cname, context)
                            generate_fuzz_harness(
                                cname, functions, fuzz_dir,
                                source_path=src_path,
                                constructor_abi=ctor_inputs,
                            )
                        except Exception as e:
                            logger.debug(f"Fuzz harness generation failed for {cname}: {e}")
            except ImportError:
                logger.debug("Harness generator not available")

        # Step 1c: Generate invariant tests for every contract source file
        if context.config.foundry_fuzz_enabled:
            try:
                from ..analyzers.foundry.invariant_generator import generate_invariant_tests

                inv_dir = context.project_path / "test" / "audit_invariants"
                for fname, source in context.contract_sources.items():
                    basename = fname.rsplit("/", 1)[-1]
                    if not basename.endswith(".sol"):
                        continue
                    cname = basename[:-4]
                    try:
                        ctor_inputs, src_path = self._resolve_contract_info(cname, context)
                        generate_invariant_tests(
                            cname, source, inv_dir,
                            source_path=src_path,
                            constructor_abi=ctor_inputs,
                        )
                    except Exception as e:
                        logger.debug(f"Invariant test generation failed for {cname}: {e}")
            except ImportError:
                logger.debug("Invariant generator not available")

        # Step 2: Run forge and symbolic analysis in parallel
        tasks = []
        forge_analyzer = None
        if context.config.foundry_fuzz_enabled:
            try:
                from ..analyzers.foundry.analyzer import FoundryAnalyzer
                forge_analyzer = FoundryAnalyzer()
                tasks.append(forge_analyzer.analyze(context))
            except ImportError:
                logger.debug("Foundry analyzer not available")

        if context.config.symbolic_enabled:
            try:
                from ..analyzers.symbolic.analyzer import SymbolicAnalyzer
                symbolic = SymbolicAnalyzer()
                tasks.append(symbolic.analyze(context))
            except ImportError:
                logger.debug("Symbolic analyzer not available")

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    findings.extend(r)
                elif isinstance(r, Exception):
                    logger.warning(f"Dynamic analysis error: {r}")

        # Step 3: Verify existing HIGH/CRITICAL findings AFTER forge has run
        if symbolic and existing_findings:
            for finding in existing_findings:
                if finding.severity in (Severity.CRITICAL, Severity.HIGH):
                    try:
                        await symbolic.verify_finding(finding, context)
                    except Exception as e:
                        logger.debug(f"Symbolic verify failed for '{finding.title}': {e}")

        # Step 4: Clean up generated harness directories and scaffold files
        for dirname in ("audit_targeted", "audit_fuzz", "audit_invariants"):
            audit_dir = context.project_path / "test" / dirname
            if audit_dir.exists():
                try:
                    shutil.rmtree(audit_dir)
                    logger.debug(f"Cleaned up {audit_dir}")
                except Exception as e:
                    logger.debug(f"Cleanup failed for {audit_dir}: {e}")

        # Clean up any scaffold files created by _ensure_foundry_project
        if forge_analyzer is not None:
            forge_analyzer.cleanup_scaffold()

        return findings

    async def _phase_llm_audit(self, context: AuditContext) -> list[Finding]:
        """Phase 3.5: Use LLM to directly audit contracts for business logic flaws."""
        if not self.llm_router:
            return []

        findings: list[Finding] = []

        try:
            from ..llm.tasks.audit_task import AuditTask
            audit_task = AuditTask(self.llm_router)

            for filename, source in context.contract_sources.items():
                try:
                    llm_findings = await audit_task.run(source, filename)
                    findings.extend(llm_findings)
                    logger.info(f"LLM audit of {filename}: {len(llm_findings)} findings")
                except Exception as e:
                    error_str = str(e)
                    if "budget" in error_str.lower():
                        logger.warning("LLM budget exhausted during audit phase")
                        break
                    logger.warning(f"LLM audit failed for {filename}: {e}")
        except ImportError:
            logger.debug("LLM audit task not available")

        return findings

    async def _phase_llm_enrich(
        self, findings: list[Finding], context: AuditContext
    ) -> tuple[list[Finding], str | None]:
        """Phase 6: Enrich findings with LLM explanations, remediations, PoCs.

        Returns:
            Tuple of (enriched findings, executive summary text or None)
        """
        if not self.llm_router:
            return findings, None

        from ..llm.tasks.explain import ExplainTask
        from ..llm.tasks.poc_generate import PoCGenerateTask
        from ..llm.tasks.remediate import RemediateTask
        from ..llm.tasks.summarize import SummarizeTask

        explain = ExplainTask(self.llm_router)
        remediate = RemediateTask(self.llm_router)
        poc = PoCGenerateTask(self.llm_router)

        # Process critical and high findings first (budget-aware)
        priority_order = ["Critical", "High", "Medium"]
        processed_count = 0

        from ..llm.context_slicer import ContextSlicer
        slicer = ContextSlicer()

        for severity_str in priority_order:
            for finding in findings:
                if finding.suppressed or finding.severity.value != severity_str:
                    continue

                # Get source context (slicing with dependent contract skeletons)
                try:
                    source_snippet = slicer.get_sliced_context(finding, context)
                except Exception as se:
                    logger.debug(f"Context Slicing failed: {se}. Falling back to default snippet.")
                    source_snippet = ""

                if not source_snippet:
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

                    # Verify PoC with forge if available
                    if finding.llm_poc and context.config.foundry_fuzz_enabled:
                        try:
                            from ..llm.tasks.poc_verify import PoCVerifyTask
                            verifier = PoCVerifyTask(self.llm_router)
                            await verifier.run(finding, context.project_path)
                        except Exception as ve:
                            logger.debug(f"PoC verification skipped: {ve}")

                    processed_count += 1

                except Exception as e:
                    error_str = str(e)
                    if "budget" in error_str.lower() or "exhausted" in error_str.lower():
                        logger.warning("LLM budget exhausted, stopping enrichment")
                        return findings, None
                    logger.warning(f"LLM enrichment failed for '{finding.title}': {e}")

        # Generate executive summary
        executive_summary: str | None = None
        try:
            from ..llm.tasks.summarize import SummarizeTask
            summarize = SummarizeTask(self.llm_router)
            active = [f for f in findings if not f.suppressed]
            executive_summary = await summarize.run(active)
        except Exception as e:
            logger.warning(f"Executive summary generation failed: {e}")

        logger.info(f"LLM enriched {processed_count} findings")
        return findings, executive_summary

    def _attach_source_snippets(
        self, findings: list[Finding], context: AuditContext
    ) -> None:
        """Attach source code snippets to each finding's metadata for reports."""
        for finding in findings:
            if finding.metadata.get("source_snippet"):
                continue
            snippet = self._get_source_snippet(finding, context)
            if snippet:
                finding.metadata["source_snippet"] = snippet

    def _get_source_snippet(self, finding: Finding, context: AuditContext) -> str:
        """Extract relevant source code snippet for a finding."""
        for loc in finding.locations[:1]:
            src = self._resolve_source(loc.file, context)
            if src:
                lines = src.splitlines()
                # Show a window around the finding with line numbers
                ctx_before = 2
                ctx_after = 8
                start = max(0, loc.start_line - 1 - ctx_before)
                end = min(len(lines), loc.end_line + ctx_after)
                numbered = []
                for i in range(start, end):
                    line_num = i + 1
                    marker = ">>>" if loc.start_line <= line_num <= loc.end_line else "   "
                    numbered.append(f"{marker} {line_num:4d} | {lines[i]}")
                return "\n".join(numbered)
        return ""

    @staticmethod
    def _resolve_source(file_path: str, context: AuditContext) -> str:
        """Resolve a file path against context.contract_sources, handling
        relative path mismatches between tools."""
        # Direct match
        if file_path in context.contract_sources:
            return context.contract_sources[file_path]
        # Try matching by filename
        filename = file_path.rsplit("/", 1)[-1]
        for key, src in context.contract_sources.items():
            if key.rsplit("/", 1)[-1] == filename:
                return src
        # Try matching by suffix
        for key, src in context.contract_sources.items():
            if key.endswith(file_path) or file_path.endswith(key):
                return src
        return ""

    def _resolve_contract_info(
        self, contract_name: str, context: AuditContext
    ) -> tuple[list[dict[str, Any]] | None, str | None]:
        """Resolve constructor ABI inputs and source path for a contract.

        Args:
            contract_name: Solidity contract name (without ``.sol``)
            context: Current audit context

        Returns:
            ``(constructor_inputs, source_path)`` where *constructor_inputs* is
            the ABI ``inputs`` list (or ``None``), and *source_path* is the
            relative path within the project (or ``None``).
        """
        ctor_inputs: list[dict[str, Any]] | None = None
        source_path: str | None = None

        # Resolve source path from contract_sources keys
        for key in context.contract_sources:
            basename = key.rsplit("/", 1)[-1]  # e.g. "Vault.sol"
            if basename == f"{contract_name}.sol":
                source_path = key
                break

        # Extract constructor ABI from compilation artifacts
        if context.compilation_artifacts:
            contracts = context.compilation_artifacts.get("contracts", {})
            for _fname, file_contracts in contracts.items():
                if contract_name in file_contracts:
                    abi: list[dict[str, Any]] = file_contracts[contract_name].get("abi", [])
                    ctor = next((e for e in abi if e.get("type") == "constructor"), None)
                    if ctor:
                        ctor_inputs = ctor.get("inputs", [])
                    break

        return ctor_inputs, source_path

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
