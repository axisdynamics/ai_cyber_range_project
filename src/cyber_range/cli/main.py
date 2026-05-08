"""
cyber_range.cli.main
=====================
CLI entrypoints for the AI Cyber Range.

Commands:
    cyber-range run               Run a full simulation
    cyber-range validate-config   Validate a config file
    cyber-range verify-evidence   Verify evidence hashes for a run
    cyber-range generate-report   Generate reports for a run
    cyber-range serve-api         Start the FastAPI dashboard server
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

console = Console()


def _find_project_root(start: Path) -> Path:
    """Walk up to find project root (contains pyproject.toml or install.sh)."""
    cur = start.resolve()
    for _ in range(8):
        if (cur / "pyproject.toml").exists() or (cur / "install.sh").exists():
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent
    return start.resolve()


@click.group()
@click.version_option(version="0.2.0-beta", prog_name="cyber-range")
def cli():
    """AI Cyber Range — Secure defensive validation and purple-team simulation.

    \b
    Powered by AxisDynamics — https://axisdynamics.cl
    MIT License
    """


# ── validate-config ───────────────────────────────────────────────────────────

@cli.command("validate-config")
@click.option("--config", "-c", default="configs/default.yaml",
              help="Path to YAML config file")
@click.option("--verbose", "-v", is_flag=True)
def validate_config(config: str, verbose: bool):
    """Validate a configuration file. Exits non-zero if invalid."""
    from cyber_range.config.schema import load_config

    path = Path(config)
    try:
        cfg = load_config(path)
        console.print(f"[green]✓[/green] Config valid: {path}")
        if verbose:
            console.print_json(cfg.model_dump_json(indent=2))
        sys.exit(0)
    except FileNotFoundError as e:
        console.print(f"[red]✗[/red] {e}")
        sys.exit(2)
    except ValueError as e:
        console.print(f"[red]✗[/red] Invalid config: {e}")
        sys.exit(1)


# ── run ───────────────────────────────────────────────────────────────────────

@cli.command("run")
@click.option("--config", "-c", default="configs/default.yaml",
              help="Path to YAML config file")
@click.option("--dry-run", is_flag=True, help="Validate and plan without executing")
@click.option("--project-root", default=None, help="Project root directory")
def run_command(config: str, dry_run: bool, project_root: Optional[str]):
    """Run a full cyber range simulation."""
    from cyber_range.config.schema import load_config
    from cyber_range.pipeline.runner import PipelineRunner

    config_path = Path(config)
    root = Path(project_root) if project_root else _find_project_root(Path.cwd())

    console.rule("[bold red]AI Cyber Range[/bold red]")
    console.print(f"Config:  {config_path}")
    console.print(f"Root:    {root}")
    console.print(f"Dry run: {dry_run}")
    console.print()

    # 1. Validate config first
    try:
        cfg = load_config(config_path)
    except Exception as e:
        console.print(f"[red]✗ Config error:[/red] {e}")
        sys.exit(1)

    # 2. Run pipeline
    runner = PipelineRunner(cfg, config_path, root, dry_run=dry_run)
    summary = runner.run()

    # 3. Show results
    _print_run_summary(summary)
    sys.exit(0 if summary.status == "success" else 1)


def _print_run_summary(summary) -> None:
    console.rule()
    status_color = "green" if summary.status == "success" else "red"
    console.print(f"\n[{status_color}]Run {summary.run_id}: {summary.status.upper()}[/{status_color}]")
    console.print(f"  Findings:     {summary.findings_count} "
                  f"(critical={summary.critical_count}, high={summary.high_count})")
    console.print(f"  Coverage:     {summary.coverage_pct}%")
    console.print(f"  Detection gap:{summary.detection_gap_pct}%")
    console.print(f"  Artifacts:    {summary.artifacts_dir}")

    t = Table(title="Phases", show_header=True)
    t.add_column("Phase", style="cyan")
    t.add_column("Status")
    for p in summary.phases:
        color = {"success":"green","failed":"red","blocked":"yellow",
                 "skipped":"dim","pending":"dim","running":"blue"}.get(p.status,"white")
        t.add_row(p.name, f"[{color}]{p.status}[/{color}]")
    console.print(t)


# ── verify-evidence ───────────────────────────────────────────────────────────

@cli.command("verify-evidence")
@click.option("--run-id", default=None, help="Run ID to verify")
@click.option("--artifacts-dir", default="artifacts", help="Artifacts directory")
@click.option("--project-root", default=None)
def verify_evidence(run_id: Optional[str], artifacts_dir: str, project_root: Optional[str]):
    """Verify evidence hashes. Exits non-zero if any evidence is tampered or missing."""
    from cyber_range.evidence.verifier import verify_run, verify_legacy_artifacts

    root = Path(project_root) if project_root else _find_project_root(Path.cwd())

    if run_id:
        run_dir = root / artifacts_dir / "runs" / run_id
        if not run_dir.exists():
            console.print(f"[red]✗[/red] Run directory not found: {run_dir}")
            sys.exit(2)
        report = verify_run(run_dir)
    else:
        report = verify_legacy_artifacts(root / artifacts_dir)

    console.print(report.summary())

    if report.modified > 0:
        console.print(f"\n[red]✗ TAMPERED EVIDENCE DETECTED[/red]")
        for r in report.records:
            if r.status.value == "modified":
                console.print(f"  [red]MODIFIED:[/red] {r.id} — {r.path}")
        sys.exit(1)

    if report.missing > 0:
        console.print(f"\n[yellow]⚠ Missing evidence[/yellow]")
        sys.exit(1)

    console.print(f"\n[green]✓ All evidence verified[/green]")
    sys.exit(0)


# ── generate-report ───────────────────────────────────────────────────────────

@cli.command("generate-report")
@click.option("--run-id", default=None, help="Run ID (latest if omitted)")
@click.option("--output-dir", default=None)
@click.option("--project-root", default=None)
def generate_report(run_id: Optional[str], output_dir: Optional[str], project_root: Optional[str]):
    """Generate markdown and JSON reports for a run."""
    from cyber_range.reporting.generator import generate_run_report

    root = Path(project_root) if project_root else _find_project_root(Path.cwd())

    if run_id:
        run_dir = root / "artifacts" / "runs" / run_id
    else:
        # Use latest_report.json for backward compat
        report_file = root / "python_orchestrator" / "reports" / "latest_report.json"
        if not report_file.exists():
            console.print("[red]✗[/red] No report found. Run 'cyber-range run' first.")
            sys.exit(1)
        out = Path(output_dir) if output_dir else root / "python_orchestrator" / "reports"
        generate_run_report(report_file=report_file, output_dir=out)
        console.print(f"[green]✓[/green] Reports written to {out}")
        return

    if not run_dir.exists():
        console.print(f"[red]✗[/red] Run directory not found: {run_dir}")
        sys.exit(1)

    out = Path(output_dir) if output_dir else run_dir
    generate_run_report(run_dir=run_dir, output_dir=out)
    console.print(f"[green]✓[/green] Reports written to {out}")


# ── serve-api ─────────────────────────────────────────────────────────────────

@cli.command("serve-api")
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8080)
@click.option("--reload", is_flag=True)
@click.option("--project-root", default=None)
def serve_api(host: str, port: int, reload: bool, project_root: Optional[str]):
    """Start the FastAPI dashboard server."""
    try:
        import uvicorn
    except ImportError:
        console.print("[red]✗[/red] uvicorn not installed. Run: pip install 'cyber-range[api]'")
        sys.exit(1)

    root = Path(project_root) if project_root else _find_project_root(Path.cwd())
    console.print(f"[green]Starting API server on http://{host}:{port}[/green]")
    console.print(f"[dim]Project root: {root}[/dim]")

    import os
    os.environ.setdefault("CYBER_RANGE_ROOT", str(root))

    uvicorn.run(
        "cyber_range.api.app:app",
        host=host, port=port, reload=reload,
        log_level="info",
    )
