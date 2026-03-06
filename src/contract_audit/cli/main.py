"""CLI entry point using Typer.

Commands:
  contract-audit audit <path>   - Run a full audit
  contract-audit init           - Initialize config in current directory
  contract-audit login          - Authenticate with Anthropic or Google
  contract-audit logout         - Remove stored credentials
  contract-audit report         - Re-generate report from existing results
  contract-audit version        - Show version info
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .. import __version__

app = typer.Typer(
    name="contract-audit",
    help="AI-assisted Smart Contract Audit Engine",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()
err_console = Console(stderr=True)


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@app.command()
def audit(
    path: Path = typer.Argument(
        ..., help="Path to the Solidity project or contracts directory"
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to audit config TOML file"
    ),
    output_dir: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output directory for reports"
    ),
    output_sarif: Optional[Path] = typer.Option(
        None, "--output-sarif", help="Output SARIF file path"
    ),
    output_markdown: Optional[Path] = typer.Option(
        None, "--output-markdown", help="Output Markdown report path"
    ),
    output_json: Optional[Path] = typer.Option(
        None, "--output-json", help="Output JSON report path"
    ),
    formats: Optional[str] = typer.Option(
        None, "--formats", "-f", help="Comma-separated report formats: sarif,json,markdown,html"
    ),
    severity_filter: Optional[str] = typer.Option(
        None, "--severity", "-s",
        help="Minimum severity to include: Critical,High,Medium,Low,Informational"
    ),
    no_llm: bool = typer.Option(False, "--no-llm", help="Disable LLM enrichment"),
    ci_mode: bool = typer.Option(False, "--ci-mode", help="CI mode: exit non-zero on findings"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
) -> None:
    """Run a comprehensive smart contract security audit."""
    _setup_logging(verbose)

    if not path.exists():
        err_console.print(f"[red]Error:[/red] Path not found: {path}")
        raise typer.Exit(1)

    console.print(Panel.fit(
        f"[bold cyan]contract-audit v{__version__}[/bold cyan]\n"
        f"Auditing: [yellow]{path.resolve()}[/yellow]",
        border_style="cyan",
    ))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Initializing audit engine...", total=None)

        # Load config
        from ..core.config import load_config
        full_config = load_config(config)
        audit_config = full_config.audit
        llm_config = full_config.llm

        if no_llm:
            audit_config.llm_enabled = False

        if output_dir:
            audit_config.output_dir = output_dir

        if formats:
            audit_config.report_formats = [f.strip() for f in formats.split(",")]

        progress.update(task, description="Setting up analyzers and detectors...")

        # Build pipeline
        pipeline = _build_pipeline(audit_config, llm_config)

        # Create context
        from ..core.models import AuditContext
        context = AuditContext(
            project_path=path,
            config=audit_config,
        )

        progress.update(task, description="Running analysis pipeline...")

        # Run pipeline
        try:
            result = asyncio.run(pipeline.run(context))
        except KeyboardInterrupt:
            err_console.print("\n[yellow]Audit interrupted by user[/yellow]")
            raise typer.Exit(130)
        except Exception as e:
            err_console.print(f"[red]Audit failed:[/red] {e}")
            if verbose:
                import traceback
                traceback.print_exc()
            raise typer.Exit(1)

        progress.update(task, description="Generating reports...")

        # Generate reports
        _generate_reports(
            result,
            audit_config,
            output_sarif=output_sarif,
            output_markdown=output_markdown,
            output_json=output_json,
        )

    # Print summary table
    _print_summary(result)

    # CI exit codes
    if ci_mode:
        if audit_config.ci_fail_on_critical and result.summary.critical_count > 0:
            err_console.print(
                f"[red]FAIL:[/red] {result.summary.critical_count} critical findings"
            )
            raise typer.Exit(1)
        if audit_config.ci_fail_on_high and result.summary.high_count > 0:
            err_console.print(
                f"[red]FAIL:[/red] {result.summary.high_count} high findings"
            )
            raise typer.Exit(1)

    console.print(f"\n[green]Audit complete.[/green] Risk score: [bold]{result.summary.overall_risk_score}/10[/bold]")


@app.command()
def init(
    path: Path = typer.Argument(Path("."), help="Directory to initialize"),
) -> None:
    """Initialize a contract-audit config file in the current directory."""
    config_path = path / "audit.toml"

    if config_path.exists():
        console.print(f"[yellow]Config already exists:[/yellow] {config_path}")
        raise typer.Exit(0)

    # Copy default config
    default_config = Path(__file__).parent.parent.parent.parent / "config" / "default.toml"
    if default_config.exists():
        import shutil
        shutil.copy(default_config, config_path)
        console.print(f"[green]Created:[/green] {config_path}")
    else:
        # Write minimal config
        config_path.write_text(
            '[project]\nname = "My Protocol"\n\n'
            '[llm]\nenabled = true\nmax_budget_usd = 10.0\n'
        )
        console.print(f"[green]Created minimal config:[/green] {config_path}")


@app.command()
def login(
    anthropic: bool = typer.Option(False, "--anthropic", help="Login to Anthropic"),
    google: bool = typer.Option(False, "--google", help="Login to Google"),
) -> None:
    """Authenticate with LLM providers."""
    from ..auth.token_store import TokenStore

    token_store = TokenStore()

    if not anthropic and not google:
        console.print("Specify [cyan]--anthropic[/cyan] or [cyan]--google[/cyan]")
        raise typer.Exit(1)

    if anthropic:
        from ..auth.anthropic_oauth import AnthropicOAuth
        oauth = AnthropicOAuth(token_store)
        try:
            console.print("Opening browser for Anthropic login...")
            token = oauth.login_browser()
            console.print("[green]Successfully logged in to Anthropic[/green]")
        except Exception as e:
            err_console.print(f"[red]Anthropic login failed:[/red] {e}")
            console.print(
                "\n[dim]Tip: Set ANTHROPIC_API_KEY environment variable as an alternative[/dim]"
            )
            raise typer.Exit(1)

    if google:
        from ..auth.google_oauth import GoogleOAuth
        oauth = GoogleOAuth(token_store)
        try:
            console.print("Opening browser for Google login...")
            token = oauth.login_browser()
            user_info = oauth.get_user_info()
            name = user_info.get("name", "unknown") if user_info else "unknown"
            console.print(f"[green]Successfully logged in as {name}[/green]")
        except Exception as e:
            err_console.print(f"[red]Google login failed:[/red] {e}")
            raise typer.Exit(1)


@app.command()
def logout(
    all_providers: bool = typer.Option(True, "--all", help="Logout from all providers"),
    anthropic: bool = typer.Option(False, "--anthropic", help="Logout from Anthropic only"),
    google: bool = typer.Option(False, "--google", help="Logout from Google only"),
) -> None:
    """Remove stored authentication credentials."""
    from ..auth.token_store import TokenStore

    token_store = TokenStore()

    if anthropic:
        token_store.clear_anthropic()
        console.print("[green]Logged out from Anthropic[/green]")
    elif google:
        token_store.clear_google()
        console.print("[green]Logged out from Google[/green]")
    else:
        token_store.clear_all()
        console.print("[green]Logged out from all providers[/green]")


@app.command()
def version() -> None:
    """Show version information."""
    from ..utils.solc import get_solc_version

    console.print(f"contract-audit: [bold]{__version__}[/bold]")

    solc_v = get_solc_version()
    console.print(f"solc: {solc_v or '[dim]not installed[/dim]'}")

    import shutil
    for tool in ["slither", "aderyn", "forge", "hevm"]:
        installed = "installed" if shutil.which(tool) else "[dim]not installed[/dim]"
        console.print(f"{tool}: {installed}")


def _build_pipeline(audit_config: "Any", llm_config: "Any") -> "Any":
    """Build the pipeline with configured analyzers and detectors."""
    from ..analyzers.ast_parser.analyzer import ASTAnalyzer
    from ..analyzers.slither.analyzer import SlitherAnalyzer
    from ..analyzers.aderyn.analyzer import AderynAnalyzer
    from ..detectors.proxy_detector import ProxyDetector
    from ..detectors.flash_loan_detector import FlashLoanDetector
    from ..detectors.oracle_detector import OracleDetector
    from ..detectors.storage_collision import StorageCollisionDetector
    from ..detectors.gas_griefing import GasGriefingDetector
    from ..detectors.governance_detector import GovernanceDetector
    from ..scoring.engine import RiskScoringEngine
    from ..scoring.false_positive import FalsePositiveReducer
    from ..core.pipeline import PipelineOrchestrator

    analyzers = []
    if audit_config.ast_parser_enabled:
        analyzers.append(ASTAnalyzer())
    if audit_config.slither_enabled:
        analyzers.append(SlitherAnalyzer())
    if audit_config.aderyn_enabled:
        analyzers.append(AderynAnalyzer())

    detectors = []
    if audit_config.proxy_detector_enabled:
        detectors.append(ProxyDetector())
    if audit_config.flash_loan_detector_enabled:
        detectors.append(FlashLoanDetector())
    if audit_config.oracle_detector_enabled:
        detectors.append(OracleDetector())
    if audit_config.storage_collision_enabled:
        detectors.append(StorageCollisionDetector())
    if audit_config.gas_griefing_enabled:
        detectors.append(GasGriefingDetector())
    if audit_config.governance_detector_enabled:
        detectors.append(GovernanceDetector())

    scoring_engine = RiskScoringEngine(
        severity_overrides=audit_config.severity_scores
    )

    llm_router = None
    if audit_config.llm_enabled:
        try:
            llm_router = _build_llm_router(llm_config)
        except Exception as e:
            logging.warning(f"LLM router not available: {e}")

    fp_reducer = FalsePositiveReducer(llm_router=llm_router)

    return PipelineOrchestrator(
        analyzers=analyzers,
        detectors=detectors,
        scoring_engine=scoring_engine,
        fp_reducer=fp_reducer,
        llm_router=llm_router,
    )


def _build_llm_router(llm_config: "Any") -> "Any | None":
    """Build the LLM router from config."""
    try:
        from ..auth.token_store import TokenStore
        from ..llm.router import LLMRouter

        token_store = TokenStore()
        return LLMRouter(config=llm_config, token_store=token_store)
    except Exception as e:
        logging.debug(f"LLM router build failed: {e}")
        return None


def _generate_reports(
    result: "Any",
    config: "Any",
    output_sarif: "Path | None" = None,
    output_markdown: "Path | None" = None,
    output_json: "Path | None" = None,
) -> None:
    """Generate reports in all configured formats."""
    from ..reporting.generator import ReportGenerator

    generator = ReportGenerator(config)
    output_dir = config.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    formats = set(config.report_formats)

    if "sarif" in formats or output_sarif:
        sarif_path = output_sarif or (output_dir / "audit-results.sarif")
        generator.generate_sarif(result, sarif_path)
        console.print(f"[dim]SARIF:[/dim] {sarif_path}")

    if "json" in formats or output_json:
        json_path = output_json or (output_dir / "audit-results.json")
        generator.generate_json(result, json_path)
        console.print(f"[dim]JSON:[/dim] {json_path}")

    if "markdown" in formats or output_markdown:
        md_path = output_markdown or (output_dir / "audit-results.md")
        generator.generate_markdown(result, md_path)
        console.print(f"[dim]Markdown:[/dim] {md_path}")

    if "html" in formats:
        html_path = output_dir / "audit-results.html"
        generator.generate_html(result, html_path)
        console.print(f"[dim]HTML:[/dim] {html_path}")


def _print_summary(result: "Any") -> None:
    """Print a summary table to the terminal."""
    summary = result.summary

    table = Table(title="Audit Summary", show_header=True, header_style="bold")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    if summary.critical_count > 0:
        table.add_row("[bold red]Critical[/bold red]", str(summary.critical_count))
    if summary.high_count > 0:
        table.add_row("[red]High[/red]", str(summary.high_count))
    if summary.medium_count > 0:
        table.add_row("[yellow]Medium[/yellow]", str(summary.medium_count))
    if summary.low_count > 0:
        table.add_row("[blue]Low[/blue]", str(summary.low_count))
    if summary.informational_count > 0:
        table.add_row("[dim]Informational[/dim]", str(summary.informational_count))
    if summary.gas_count > 0:
        table.add_row("[dim]Gas[/dim]", str(summary.gas_count))
    if summary.suppressed_count > 0:
        table.add_row("[dim]Suppressed (FP)[/dim]", str(summary.suppressed_count))

    table.add_row("[bold]Total[/bold]", f"[bold]{summary.total_findings}[/bold]")

    console.print()
    console.print(table)


if __name__ == "__main__":
    app()
