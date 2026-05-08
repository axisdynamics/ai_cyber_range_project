"""
cyber_range.cli.main — CLI completo del AI Cyber Range.

Comandos:
    cyber-range run [--mode standard|agent]
    cyber-range validate-config
    cyber-range verify-evidence [--run-id ID]
    cyber-range generate-report [--run-id ID]
    cyber-range serve-api [--host --port --api-key]
    cyber-range status
    cyber-range memory show|clear|gaps
"""
from __future__ import annotations
import json, os, subprocess, sys, uuid
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()
err     = Console(stderr=True)
VERSION = "0.2.0-beta"


def _root(hint=None):
    if hint: return Path(hint).resolve()
    cur = Path.cwd().resolve()
    for _ in range(8):
        if (cur/"pyproject.toml").exists() or (cur/"install.sh").exists():
            return cur
        if cur.parent == cur: break
        cur = cur.parent
    return Path.cwd().resolve()


def _banner(sub=""):
    console.print(Panel(
        f"[bold red]AI CYBER RANGE[/bold red]  [dim]v{VERSION}[/dim]\n"
        f"[dim]Powered by [/dim][cyan]AxisDynamics[/cyan][dim] · axisdynamics.cl[/dim]"
        +(f"\n{sub}" if sub else ""),
        border_style="red", expand=False,
    ))


# ── CLI root ──────────────────────────────────────────────────────────────────

@click.group()
@click.version_option(VERSION, prog_name="cyber-range")
def cli():
    """AI Cyber Range — validación defensiva segura y simulación purple-team.

    \b
    Modos de ejecución:
      standard   Pipeline agentivo completo (por defecto)
      agent      Hermes multi-agente con memoria cross-run

    \b
    Powered by AxisDynamics — axisdynamics.cl · MIT License
    """

# ── validate-config ───────────────────────────────────────────────────────────

@cli.command("validate-config")
@click.option("--config","-c", default="configs/default.yaml", show_default=True)
@click.option("--verbose","-v", is_flag=True)
def validate_config(config, verbose):
    """Valida un archivo de configuración. Exit 1 si inválido, 2 si no existe."""
    from cyber_range.config.schema import load_config
    path = Path(config)
    try:
        cfg = load_config(path)
        console.print(f"[green]✓[/green] Config válida: [cyan]{path}[/cyan] — perfil: {cfg.profile}")
        if verbose:
            console.print_json(cfg.model_dump_json(indent=2))
        sys.exit(0)
    except FileNotFoundError as e:
        err.print(f"[red]✗[/red] {e}"); sys.exit(2)
    except ValueError as e:
        err.print(f"[red]✗[/red] Config inválida: {e}"); sys.exit(1)

# ── run ───────────────────────────────────────────────────────────────────────

@cli.command("run")
@click.option("--config","-c", default="configs/default.yaml", show_default=True)
@click.option("--mode", type=click.Choice(["standard","agent"]), default="standard",
              show_default=True, help="standard=pipeline completo · agent=Hermes multi-agente")
@click.option("--dry-run", is_flag=True)
@click.option("--project-root","-r", default=None)
def run_command(config, mode, dry_run, project_root):
    """Ejecuta simulación completa.

    \b
    Ejemplos:
      cyber-range run
      cyber-range run --config examples/local.yaml
      cyber-range run --mode agent
      cyber-range run --dry-run
    """
    from cyber_range.config.schema import load_config
    cfg_path = Path(config)
    root = _root(project_root)
    _banner(f"[dim]Modo: [bold]{mode}[/bold] · Config: {cfg_path}[/dim]")
    try:
        cfg = load_config(cfg_path)
        console.print(f"  [green]✓[/green] Config — perfil: [cyan]{cfg.profile}[/cyan]")
    except Exception as e:
        err.print(f"[red]✗[/red] {e}"); sys.exit(1)

    if dry_run:
        console.print(f"  [yellow]Dry run[/yellow] — perfil: {cfg.profile}, "
                      f"activos: {len(cfg.engagement.authorized_assets)}, "
                      f"bloqueadas: {cfg.engagement.blocked_techniques}")
        sys.exit(0)

    run_id = "RUN-" + uuid.uuid4().hex[:8].upper()
    console.print(f"  Run ID: [cyan]{run_id}[/cyan]\n")

    if mode == "agent":
        _run_hermes(cfg, cfg_path, root, run_id)
    else:
        _run_standard(cfg, cfg_path, root, run_id)


def _run_standard(cfg, cfg_path, root, run_id):
    out_dir = root/"artifacts"/"runs"/run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    from cyber_range.logging.structured import StructuredLogger
    logger = StructuredLogger(run_id=run_id, log_path=out_dir/"logs.jsonl",
                               min_level=cfg.log_level)
    console.print("[bold]Ejecutando pipeline estándar...[/bold]")
    with console.status("[cyan]Pipeline ofensivo en curso...[/cyan]"):
        try:
            r = subprocess.run(
                [sys.executable, "-m", "python_orchestrator.main",
                 "--config", str(cfg_path)],
                cwd=str(root), timeout=cfg.engagement.timeout_seconds,
            )
            ok = r.returncode == 0
        except Exception as e:
            err.print(f"[red]✗[/red] {e}"); ok = False
    if not ok:
        err.print("[red]✗ Pipeline terminó con errores[/red]"); sys.exit(1)

    findings = _load_findings(root)
    _save_artifacts(run_id, findings, cfg, cfg_path, out_dir)
    _show_summary(run_id, findings, out_dir, "standard")
    _make_reports(root, out_dir, findings, run_id, cfg_path)
    logger.info("run_complete", f"Run {run_id} OK", phase="summary")
    logger.close()
    _update_memory(root, run_id, findings, cfg)


def _run_hermes(cfg, cfg_path, root, run_id):
    from cyber_range.agents.hermes import HermesOrchestrator
    from cyber_range.logging.structured import StructuredLogger
    out_dir = root/"artifacts"/"runs"/run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    logger = StructuredLogger(run_id=run_id, log_path=out_dir/"logs.jsonl",
                               min_level=cfg.log_level)
    orch = HermesOrchestrator(cfg, root, run_id, logger)
    stats = orch.memory.stats()
    if stats["total_runs"] > 0:
        console.print(f"  [dim]Memoria: {stats['total_runs']} runs · "
                      f"{stats['persistent_gaps']} gaps persistentes[/dim]")
        gaps = orch.memory.get_persistent_gaps(min_occurrences=2)
        if gaps:
            console.print(f"  [yellow]Gaps persistentes: "
                          f"{', '.join(g.technique_id for g in gaps[:4])}[/yellow]")
    else:
        console.print("  [dim]Primera ejecución — sin memoria previa[/dim]")
    console.print()
    with console.status("[cyan]Agentes Hermes en ejecución...[/cyan]"):
        result = orch.run()

    # Save artifacts
    (out_dir/"summary.json").write_text(json.dumps(result.to_dict(), indent=2))
    (out_dir/"findings.json").write_text(json.dumps(result.findings, indent=2))
    (out_dir/"agent_results.json").write_text(json.dumps([
        {"agent":r.agent_name,"findings":len(r.findings),
         "blocked":r.blocked,"duration_s":r.duration_s,"error":r.error}
        for r in result.agent_results
    ], indent=2))

    # Summary table
    t = Table(title=f"Hermes {run_id}", box=box.ROUNDED, border_style="green")
    t.add_column("Métrica", style="cyan", min_width=24)
    t.add_column("Valor", justify="right")
    t.add_row("Agentes",         str(result.agents_run))
    t.add_row("Findings",        str(result.findings_count))
    t.add_row("  Críticos",      f"[red]{result.critical_count}[/red]")
    t.add_row("Cobertura",       f"{result.coverage_pct:.1f}%")
    t.add_row("Gap detección",   f"{result.detection_gap_pct:.1f}%")
    t.add_row("Gaps persistentes",f"[yellow]{len(result.persistent_gaps)}[/yellow]")
    console.print(t)

    # Agents table
    t2 = Table(title="Por Agente", box=box.SIMPLE)
    t2.add_column("Agente", style="cyan"); t2.add_column("Findings", justify="right")
    t2.add_column("Bloqueados", justify="right"); t2.add_column("Duración", justify="right")
    for r in sorted(result.agent_results, key=lambda x: -len(x.findings)):
        t2.add_row(r.agent_name, str(len(r.findings)), str(len(r.blocked)), f"{r.duration_s:.1f}s")
    console.print(t2)

    _make_reports(root, out_dir, result.findings, run_id, cfg_path)
    logger.close()


# ── verify-evidence ───────────────────────────────────────────────────────────

@cli.command("verify-evidence")
@click.option("--run-id", default=None)
@click.option("--artifacts-dir", default="artifacts", show_default=True)
@click.option("--project-root","-r", default=None)
def verify_evidence(run_id, artifacts_dir, project_root):
    """Verifica integridad de evidencias. Exit 1 si hay evidencia alterada/faltante.

    \b
    Ejemplos:
      cyber-range verify-evidence
      cyber-range verify-evidence --run-id RUN-ABC12345
    """
    from cyber_range.evidence.verifier import verify_run, verify_legacy_artifacts
    root = _root(project_root)
    if run_id:
        d = root/artifacts_dir/"runs"/run_id
        if not d.exists():
            err.print(f"[red]✗[/red] Run no encontrado: {d}"); sys.exit(2)
        report = verify_run(d)
    else:
        report = verify_legacy_artifacts(root/artifacts_dir)

    t = Table(title=f"Verificación — {report.run_id}", box=box.ROUNDED)
    t.add_column("Métrica", style="cyan"); t.add_column("Valor", justify="right")
    t.add_row("Total",          str(report.total))
    t.add_row("Válidas",        f"[green]{report.valid}[/green]")
    t.add_row("Faltantes",      f"[red]{report.missing}[/red]" if report.missing else "0")
    t.add_row("Modificadas",    f"[red]{report.modified}[/red]" if report.modified else "0")
    t.add_row("Sin hash",       f"[yellow]{report.no_hash}[/yellow]" if report.no_hash else "0")
    t.add_row("No referenciadas", str(report.unreferenced))
    console.print(t)

    if report.modified:
        err.print("[bold red]✗ EVIDENCIA ALTERADA[/bold red]")
        for r in report.records:
            if r.status.value == "modified":
                err.print(f"  [red]MODIFIED:[/red] {r.id}")
        sys.exit(1)
    if report.missing:
        err.print(f"[yellow]⚠ {report.missing} evidencia(s) faltante(s)[/yellow]"); sys.exit(1)
    console.print("[bold green]✓ Toda la evidencia es válida[/bold green]")

# ── generate-report ───────────────────────────────────────────────────────────

@cli.command("generate-report")
@click.option("--run-id", default=None)
@click.option("--output-dir", default=None)
@click.option("--project-root","-r", default=None)
def generate_report_cmd(run_id, output_dir, project_root):
    """Genera report.md y report.json.

    \b
    Ejemplos:
      cyber-range generate-report
      cyber-range generate-report --run-id RUN-ABC12345 --output-dir ./out/
    """
    from cyber_range.reporting.generator import generate_run_report
    root = _root(project_root)
    if run_id:
        run_dir = root/"artifacts"/"runs"/run_id
        if not run_dir.exists():
            err.print(f"[red]✗[/red] Run no encontrado: {run_dir}"); sys.exit(1)
        out = Path(output_dir) if output_dir else run_dir
        generate_run_report(run_dir=run_dir, output_dir=out)
    else:
        rf = root/"python_orchestrator"/"reports"/"latest_report.json"
        if not rf.exists():
            err.print("[red]✗[/red] Sin reportes. Ejecuta 'cyber-range run' primero."); sys.exit(1)
        out = Path(output_dir) if output_dir else rf.parent
        generate_run_report(report_file=rf, output_dir=out)
    console.print(f"[green]✓[/green] Reportes generados en [cyan]{out}[/cyan]")

# ── serve-api ─────────────────────────────────────────────────────────────────

@cli.command("serve-api")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8080, show_default=True)
@click.option("--reload", is_flag=True)
@click.option("--project-root","-r", default=None)
@click.option("--api-key", default=None, envvar="CYBER_RANGE_API_KEY",
              help="Habilita auth por header X-API-Key")
def serve_api(host, port, reload, project_root, api_key):
    """Inicia servidor API + dashboard React.

    \b
    Seguridad:
      --api-key <key>          Habilita auth (X-API-Key header requerido)
      CYBER_RANGE_API_KEY      Variable de entorno equivalente
      CYBER_RANGE_CORS         Orígenes CORS separados por coma

    \b
    Ejemplos:
      cyber-range serve-api
      cyber-range serve-api --port 9090
      cyber-range serve-api --api-key mysecretkey
    """
    try: import uvicorn
    except ImportError:
        err.print("[red]✗[/red] uvicorn no instalado. Run: pip install 'cyber-range[api]'")
        sys.exit(1)

    root = _root(project_root)
    if api_key: os.environ["CYBER_RANGE_API_KEY"] = api_key
    os.environ.setdefault("CYBER_RANGE_ROOT", str(root))

    console.print(Panel(
        f"[green]API + Dashboard iniciando[/green]\n"
        f"  URL:       [cyan]http://{host}:{port}[/cyan]\n"
        f"  Docs:      [cyan]http://{host}:{port}/docs[/cyan]\n"
        f"  Auth:      {'[green]habilitada[/green]' if api_key else '[yellow]deshabilitada[/yellow]'}\n"
        f"  Root:      [dim]{root}[/dim]",
        border_style="green",
    ))
    uvicorn.run("cyber_range.api.app:app", host=host, port=port,
                reload=reload, log_level="info")

# ── status ────────────────────────────────────────────────────────────────────

@cli.command("status")
@click.option("--project-root","-r", default=None)
def status_cmd(project_root):
    """Estado del sistema: último run, artefactos, memoria Hermes.

    \b
    Muestra:
      - Métricas del último run
      - Estado de la memoria Hermes
      - Gaps persistentes detectados
    """
    from cyber_range.agents.memory import AgentMemory
    from cyber_range.config.schema import load_config
    from cyber_range.scoring.engine import clamp
    root = _root(project_root)
    _banner()

    # Config
    for cfg_path in [root/"configs"/"default.yaml", root/"examples"/"local.yaml"]:
        if cfg_path.exists():
            try:
                cfg = load_config(cfg_path)
                console.print(f"[green]✓[/green] Config: [cyan]{cfg_path.name}[/cyan] — {cfg.profile}")
                break
            except Exception: pass

    console.print()

    # Last run
    rp = root/"python_orchestrator"/"reports"/"latest_report.json"
    if rp.exists():
        try:
            data = json.loads(rp.read_text())
            s = data.get("offensive_summary", {})
            t = Table(title="Último Run", box=box.ROUNDED, border_style="cyan")
            t.add_column("Métrica", style="cyan", min_width=22); t.add_column("Valor", justify="right")
            t.add_row("Run ID",           data.get("run_id","—"))
            t.add_row("Timestamp",        (s.get("finished_at","—") or "—")[:19].replace("T"," "))
            t.add_row("Findings",         str(s.get("findings_count",0)))
            t.add_row("  Críticos",       str(s.get("critical_count",0)))
            t.add_row("Cobertura ATT&CK", f"{clamp(s.get('coverage_pct',0)):.1f}%")
            t.add_row("Gap detección",    f"{s.get('detection_gap_pct',0):.1f}%")
            t.add_row("Kill chains",      str(s.get("chains_simulated",0)))
            console.print(t)
        except Exception: console.print("[dim]Error leyendo reporte[/dim]")
    else:
        console.print("[dim]Sin runs. Ejecuta: cyber-range run[/dim]")

    console.print()

    # Hermes memory
    mem = AgentMemory(root/"artifacts"/"agent_memory.db")
    st = mem.stats()
    t2 = Table(title="Memoria Hermes", box=box.ROUNDED, border_style="yellow")
    t2.add_column("Métrica", style="yellow", min_width=22); t2.add_column("Valor", justify="right")
    t2.add_row("Runs en memoria",    str(st["total_runs"]))
    t2.add_row("Findings acumulados",str(st["total_findings"]))
    t2.add_row("Técnicas vistas",    str(st["techniques_seen"]))
    t2.add_row("Gaps persistentes",  f"[red]{st['persistent_gaps']}[/red]"
               if st["persistent_gaps"] else "0")
    console.print(t2)

    if st["persistent_gaps"]:
        for g in mem.get_persistent_gaps(min_occurrences=2)[:4]:
            console.print(f"  [red]•[/red] [cyan]{g.technique_id}[/cyan]@{g.asset} — "
                          f"{g.occurrence_count}x · score={g.max_score:.0f}")

    # Runs dir
    runs_dir = root/"artifacts"/"runs"
    if runs_dir.exists():
        runs = sorted(runs_dir.iterdir(), reverse=True)[:3]
        if runs:
            console.print(f"\n[dim]Últimos runs:[/dim]")
            for r in runs:
                sf = r/"summary.json"
                if sf.exists():
                    try:
                        s = json.loads(sf.read_text())
                        console.print(f"  [dim]{s.get('run_id','?')} · {s.get('status','?')} · "
                                      f"{s.get('findings_count',0)} findings[/dim]")
                    except: pass

# ── memory group ──────────────────────────────────────────────────────────────

@cli.group("memory")
def memory_group():
    """Gestión de memoria cross-run del modo Hermes.

    \b
    Subcomandos:
      show    Historial y aprendizaje por técnica
      clear   Resetea toda la memoria (irreversible)
      gaps    Lista gaps de detección en detalle
    """

@memory_group.command("show")
@click.option("--project-root","-r", default=None)
@click.option("--top", default=10, show_default=True)
def memory_show(project_root, top):
    """Muestra historial, gaps y aprendizaje por técnica."""
    from cyber_range.agents.memory import AgentMemory
    root = _root(project_root)
    mem  = AgentMemory(root/"artifacts"/"agent_memory.db")
    st   = mem.stats()

    console.print(Panel(
        f"[yellow]Memoria Hermes[/yellow]\n"
        f"  Runs: {st['total_runs']} · Findings: {st['total_findings']} · "
        f"Técnicas: {st['techniques_seen']} · Gaps persistentes: {st['persistent_gaps']}",
        border_style="yellow",
    ))

    history = mem.get_run_history(limit=8)
    if history:
        t = Table(title="Historial", box=box.SIMPLE)
        t.add_column("Run ID", style="cyan"); t.add_column("Timestamp", style="dim")
        t.add_column("Estado"); t.add_column("Findings",justify="right")
        t.add_column("Coverage",justify="right"); t.add_column("Gap",justify="right")
        for r in history:
            c = "green" if r["status"]=="success" else "red"
            t.add_row(r["run_id"], (r["started_at"] or "")[:16].replace("T"," "),
                      f"[{c}]{r['status']}[/{c}]", str(r["findings_count"]),
                      f"{r['coverage_pct']:.1f}%", f"{r['gap_pct']:.1f}%")
        console.print(t)
    else:
        console.print("[dim]Sin runs. Ejecuta: cyber-range run --mode agent[/dim]")
        return

    gaps = mem.get_all_gaps()
    if gaps:
        t2 = Table(title="Gaps de Detección", box=box.SIMPLE)
        t2.add_column("Técnica",style="red"); t2.add_column("Asset",style="cyan")
        t2.add_column("Veces",justify="right"); t2.add_column("Score",justify="right")
        for g in gaps[:top]:
            t2.add_row(g.technique_id, g.asset, str(g.occurrence_count), f"{g.max_score:.0f}")
        console.print(t2)

    techs = list({g.technique_id for g in gaps})
    if techs:
        t3 = Table(title="Aprendizaje", box=box.SIMPLE)
        t3.add_column("Técnica",style="cyan"); t3.add_column("Runs",justify="right")
        t3.add_column("Gap%",justify="right"); t3.add_column("Score avg",justify="right")
        t3.add_column("Repro%",justify="right")
        for tech in techs[:top]:
            l = mem.get_technique_learning(tech)
            if l:
                t3.add_row(tech, str(l.total_runs), f"{l.gap_rate*100:.0f}%",
                           f"{l.avg_score:.1f}", f"{l.reproducible_rate*100:.0f}%")
        console.print(t3)


@memory_group.command("clear")
@click.option("--project-root","-r", default=None)
@click.confirmation_option(prompt="¿Resetear TODA la memoria Hermes? (irreversible)")
def memory_clear(project_root):
    """Resetea la memoria Hermes. IRREVERSIBLE."""
    from cyber_range.agents.memory import AgentMemory
    AgentMemory(_root(project_root)/"artifacts"/"agent_memory.db").clear()
    console.print("[green]✓[/green] Memoria Hermes reseteada.")


@memory_group.command("gaps")
@click.option("--project-root","-r", default=None)
@click.option("--min-occurrences", default=1, show_default=True)
def memory_gaps(project_root, min_occurrences):
    """Lista gaps de detección ordenados por criticidad."""
    from cyber_range.agents.memory import AgentMemory
    root = _root(project_root)
    gaps = AgentMemory(root/"artifacts"/"agent_memory.db"
                       ).get_persistent_gaps(min_occurrences=min_occurrences)
    if not gaps:
        console.print(f"[dim]Sin gaps con ≥{min_occurrences} ocurrencia(s)[/dim]"); return
    t = Table(title=f"Gaps (min={min_occurrences})", box=box.ROUNDED)
    t.add_column("Técnica",style="red"); t.add_column("Asset",style="cyan")
    t.add_column("Veces",justify="right"); t.add_column("Score",justify="right")
    t.add_column("Desde", style="dim")
    for g in gaps:
        t.add_row(g.technique_id, g.asset, str(g.occurrence_count),
                  f"{g.max_score:.0f}", (g.first_seen or "")[:10])
    console.print(t)
    console.print(f"[dim]{len(gaps)} gaps[/dim]")


# ── Internal helpers ──────────────────────────────────────────────────────────

def _load_findings(root):
    p = root/"python_orchestrator"/"reports"/"latest_report.json"
    return json.loads(p.read_text()).get("findings",[]) if p.exists() else []


def _save_artifacts(run_id, findings, cfg, cfg_path, out_dir):
    from datetime import datetime, timezone
    summary = {"run_id":run_id,"config_path":str(cfg_path),"profile":cfg.profile,
               "started_at":datetime.now(timezone.utc).isoformat(),
               "finished_at":datetime.now(timezone.utc).isoformat(),"status":"success",
               "findings_count":len(findings),
               "critical_count":sum(1 for f in findings if f.get("severity")=="critical")}
    (out_dir/"summary.json").write_text(json.dumps(summary,indent=2))
    (out_dir/"findings.json").write_text(json.dumps(findings,indent=2))


def _show_summary(run_id, findings, out_dir, mode):
    from cyber_range.scoring.engine import severity_counts, detection_gap_pct
    sc = severity_counts(findings)
    t = Table(title=f"Run {run_id}", box=box.ROUNDED, border_style="green")
    t.add_column("Métrica",style="cyan",min_width=22); t.add_column("Valor",justify="right")
    t.add_row("Findings",     str(len(findings)))
    t.add_row("  Críticos",   f"[red]{sc.get('critical',0)}[/red]")
    t.add_row("  Altos",      f"[orange1]{sc.get('high',0)}[/orange1]")
    t.add_row("Gap detección",f"{detection_gap_pct(findings):.1f}%")
    t.add_row("Artefactos",   str(out_dir))
    console.print(t)


def _make_reports(root, out_dir, findings, run_id, cfg_path):
    try:
        from cyber_range.reporting.generator import generate_run_report
        ff = out_dir/"findings.json"
        if not ff.exists(): ff.write_text(json.dumps(findings,indent=2))
        if (out_dir/"summary.json").exists():
            generate_run_report(run_dir=out_dir, output_dir=out_dir)
        console.print(f"  [dim]Reportes → {out_dir/'report.md'}[/dim]")
    except Exception as e:
        console.print(f"  [dim]Reportes: {e}[/dim]")


def _update_memory(root, run_id, findings, cfg):
    try:
        from cyber_range.agents.memory import AgentMemory
        from cyber_range.scoring.engine import clamp, coverage_pct, detection_gap_pct
        mem = AgentMemory(root/"artifacts"/"agent_memory.db")
        mem.remember_run({
            "run_id":run_id,"status":"success",
            "findings_count":len(findings),
            "critical_count":sum(1 for f in findings if f.get("severity")=="critical"),
            "coverage_pct":coverage_pct([f.get("technique_id","") for f in findings],[]),
            "detection_gap_pct":detection_gap_pct(findings),
            "profile":cfg.profile,
        })
        mem.remember_findings(run_id, findings)
    except Exception: pass
