"""
# Powered by AxisDynamics — https://axisdynamics.cl · MIT License
main.py
=======
AI Cyber Range Orchestrator — Ofensiva Controlada con IA

Full pipeline:
  1. Governance + perimeter validation
  2. Change detection (CI/CD trigger)
  3. Attack route discovery (AttackMapper)
  4. Offensive cycle (OffensiveHarness):
       - Hypothesis generation
       - Kill chain simulation
       - Evasion testing
       - PoC construction
  5. Red team execution (RedTeamAgent)
  6. Detection validation (DetectionAgent)
  7. Evidence collection (EvidenceEngine)
  8. Review + deduplication (ReviewerAgent)
  9. Risk scoring (RiskScoringEngine)
 10. Remediation backlog (RemediationEngine)
 11. Hardening recommendations (HardeningAgent)
 12. Executive reporting + dashboard
"""
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from python_orchestrator.core.io import read_json, read_yaml, write_json, write_text
from python_orchestrator.core.models import (
    Asset, Technique, Finding, EngagementPerimeter,
)
from python_orchestrator.agents.governance import GovernanceAgent
from python_orchestrator.agents.attack_mapper import AttackMapper
from python_orchestrator.agents.red_team import RedTeamAgent
from python_orchestrator.agents.detection import DetectionAgent
from python_orchestrator.agents.reviewer import ReviewerAgent
from python_orchestrator.agents.scoring import RiskScoringEngine
from python_orchestrator.agents.hardening import HardeningAgent
from python_orchestrator.agents.offensive_harness import OffensiveHarness
from python_orchestrator.agents.cicd_trigger import CICDTrigger
from python_orchestrator.engine.evidence_engine import EvidenceEngine
from python_orchestrator.engine.remediation_engine import RemediationEngine

console = Console()


# ─── Loaders ─────────────────────────────────────────────────────────────────

def load_assets(root: Path) -> list[Asset]:
    data = read_json(root / "python_orchestrator" / "data" / "assets.json")
    return [Asset(**x) for x in data["assets"]]


def load_techniques(root: Path) -> list[Technique]:
    data = read_json(root / "python_orchestrator" / "data" / "attack_subset.json")
    return [Technique(**x) for x in data["techniques"]]


def load_perimeter(root: Path, config: dict) -> EngagementPerimeter:
    perimeter_file = root / "configs" / "engagement_perimeter.yaml"
    if perimeter_file.exists():
        p = read_yaml(perimeter_file)
        return EngagementPerimeter(
            authorized_asset_ids=p.get("authorized_asset_ids", []),
            authorized_technique_ids=p.get("authorized_technique_ids", []),
            max_chain_depth=p.get("max_chain_depth", 6),
            allow_evasion_tests=p.get("allow_evasion_tests", True),
            allow_chain_simulation=p.get("allow_chain_simulation", True),
            disallowed_actions=p.get("disallowed_actions", []),
            engagement_id=p.get("engagement_id", "ENG-001"),
            authorized_by=p.get("authorized_by", "governance_agent"),
        )
    # Fallback: derive from config
    allowed = config.get("rules_of_engagement", {}).get("allowed_targets", [])
    return EngagementPerimeter(
        authorized_asset_ids=allowed,
        authorized_technique_ids=[],  # will be populated from catalog
        max_chain_depth=6,
        engagement_id="ENG-FALLBACK",
    )


def maybe_validate_with_rust(root: Path, finding_json: Path) -> str:
    validator = root / "rust_validator" / "target" / "release" / "evidence_validator"
    if not validator.exists():
        return "SKIPPED: rust validator not built (run: make -C rust_validator)"
    result = subprocess.run(
        [str(validator), str(finding_json)],
        capture_output=True, text=True, check=False,
    )
    return result.stdout.strip() or result.stderr.strip()


# ─── Severity inference ────────────────────────────────────────────────────────

def infer_severity(scorer: RiskScoringEngine, technique_id: str, detection_status: str, asset_criticality: int) -> str:
    return scorer.classify_severity(technique_id, detection_status, asset_criticality)


# ─── Report generation ────────────────────────────────────────────────────────

def generate_markdown_report(
    config: dict,
    governance: GovernanceAgent,
    findings: list[Finding],
    remediations: dict,
    offensive_result,
    cicd_events,
) -> str:
    sov = governance.sovereignty_summary()
    lines = [
        "# AI Cyber Range — Reporte de Ofensiva Controlada",
        "",
        f"**Programa:** {config.get('program',{}).get('name','AI Cyber Range')}",
        f"**Modo:** {config.get('program',{}).get('mode','local_lab_only')}",
        f"**Run ID:** {offensive_result.run_id}",
        f"**Engagement:** {offensive_result.engagement_id}",
        f"**Inicio:** {offensive_result.started_at}",
        f"**Fin:** {offensive_result.finished_at}",
        "",
        "## Soberanía",
        "",
        f"- Política de modelo: `{sov['model_policy']}`",
        f"- Residencia de datos: `{sov['data_residency']}`",
        f"- Jurisdicción: `{sov['jurisdiction']}`",
        f"- Auditoría requerida: `{sov['audit_required']}`",
        "",
        "## Ciclo Ofensivo — Resumen Ejecutivo",
        "",
        f"| Métrica | Valor |",
        f"|---|---|",
        f"| Hipótesis generadas | {offensive_result.hypotheses_generated} |",
        f"| Cadenas de ataque simuladas | {offensive_result.chains_simulated} |",
        f"| Tests de evasión ejecutados | {offensive_result.evasion_tests_run} |",
        f"| PoCs construidos | {offensive_result.pocs_built} |",
        f"| Hallazgos totales | {offensive_result.findings_count} |",
        f"| Críticos | {offensive_result.critical_count} |",
        f"| Altos | {offensive_result.high_count} |",
        f"| Medios | {offensive_result.medium_count} |",
        f"| Bajos | {offensive_result.low_count} |",
        f"| Cobertura ATT&CK | {offensive_result.coverage_pct}% |",
        f"| Gap de detección | {offensive_result.detection_gap_pct}% |",
        "",
    ]

    if cicd_events:
        lines += [
            "## Cambios Detectados (CI/CD Trigger)",
            "",
        ]
        for e in cicd_events:
            lines.append(f"- **{e.change_type.upper()}** | {e.asset_affected}: {e.description}")
        lines.append("")

    lines += [
        "## Hallazgos Priorizados",
        "",
        "| ID | Activo | ATT&CK | Severidad | Detección | PoC | Score |",
        "|---|---|---|---|---|---|---:|",
    ]
    for f in sorted(findings, key=lambda x: x.score, reverse=True):
        poc_flag = "✓" if f.poc_id else "—"
        lines.append(
            f"| {f.id} | {f.asset} | {f.technique_id} | **{f.severity}** "
            f"| {f.detection_status} | {poc_flag} | {f.score} |"
        )

    lines += ["", "## Backlog de Remediación", ""]
    for fid, ticket in remediations.items():
        if hasattr(ticket, "title"):
            lines.append(f"### [{ticket.priority}] {ticket.title}")
            lines.append(f"**Owner:** {ticket.owner_team} | **SLA:** {ticket.sla_days} días")
            lines.append("")
            lines.append("**Controles a aplicar:**")
            for c in ticket.controls_to_apply:
                lines.append(f"- {c}")
            lines.append("")
            lines.append("**Reglas de detección a crear:**")
            for d in ticket.detection_rules_needed:
                lines.append(f"- {d}")
            lines.append("")
        else:
            lines.append(f"### {fid}")
            for rec in (ticket if isinstance(ticket, list) else [ticket]):
                lines.append(f"- {rec}")
            lines.append("")

    return "\n".join(lines)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI Cyber Range — Ofensiva Controlada con IA"
    )
    parser.add_argument("--config", required=True, help="Path to config YAML")
    parser.add_argument(
        "--mode",
        choices=["full", "offensive_only", "defensive_only"],
        default="full",
        help="Execution mode",
    )
    args = parser.parse_args()

    root   = Path(__file__).resolve().parents[1]
    config = read_yaml(root / args.config)

    # ── Banner ────────────────────────────────────────────────────────────────
    console.print(Panel(
        "[bold red]AI Cyber Range — Ofensiva Controlada con IA[/]\n"
        "[dim]MITRE ATT&CK · Agentive Red Team · Evidence Engine · CI/CD Loop[/]",
        border_style="red",
    ))

    # ── Load data ─────────────────────────────────────────────────────────────
    assets     = load_assets(root)
    techniques = load_techniques(root)
    console.print(f"[cyan]Activos cargados:[/] {len(assets)}  [cyan]Técnicas:[/] {len(techniques)}")

    # ── Governance ────────────────────────────────────────────────────────────
    governance = GovernanceAgent(config)
    console.print(f"[green]Governance:[/] modelo={governance.model_policy()}, auditoría={governance.audit_required()}")

    # ── Perimeter ─────────────────────────────────────────────────────────────
    perimeter = load_perimeter(root, config)
    if not perimeter.authorized_technique_ids:
        perimeter.authorized_technique_ids = [t.id for t in techniques]
    console.print(
        f"[green]Perímetro:[/] {len(perimeter.authorized_asset_ids)} activos | "
        f"{len(perimeter.authorized_technique_ids)} técnicas | "
        f"chain_depth={perimeter.max_chain_depth}"
    )

    # ── CI/CD change detection ────────────────────────────────────────────────
    cicd = CICDTrigger(state_file=root / "artifacts" / "cicd_state.json")
    cicd_events = cicd.detect_changes([a.to_dict() for a in assets], config)
    if cicd_events:
        console.print(f"[yellow]CI/CD:[/] {len(cicd_events)} cambio(s) detectado(s) → ofensiva re-triggered")
    else:
        console.print("[dim]CI/CD: Sin cambios relevantes desde último run[/]")

    # ── Components ────────────────────────────────────────────────────────────
    mapper      = AttackMapper()
    red         = RedTeamAgent(root)
    detection   = DetectionAgent(root / "python_orchestrator" / "data" / "synthetic_logs.jsonl")
    reviewer    = ReviewerAgent()
    scorer      = RiskScoringEngine(config.get("scoring", {}).get("weights", {}))
    hardening   = HardeningAgent()
    evidence_eng = EvidenceEngine(root / "artifacts" / "evidence")
    remediation_eng = RemediationEngine()
    harness     = OffensiveHarness(perimeter=perimeter, config=config)

    # ── Scenario building ─────────────────────────────────────────────────────
    all_scenarios = mapper.build_scenarios(assets, techniques)
    # Filter to governance-authorized targets
    scenarios = [s for s in all_scenarios if governance.authorize(s.asset_id)]
    console.print(f"[cyan]Escenarios:[/] {len(all_scenarios)} generados → {len(scenarios)} autorizados")

    asset_by_id = {a.id: a for a in assets}
    tech_by_id  = {t.id: t for t in techniques}
    findings: list[Finding] = []
    remediation_map: dict = {}

    # ── Core execution loop ───────────────────────────────────────────────────
    console.print("\n[bold red]── Ejecución Ofensiva Controlada ──────────────────────[/]")

    for scenario in scenarios:
        asset = asset_by_id.get(scenario.asset_id)
        if not asset:
            continue

        # Red team execution
        evidence = red.run_scenario(scenario)

        # Persist raw evidence
        evidence_path = root / "artifacts" / f"{scenario.id}_evidence.json"
        write_json(evidence_path, evidence)

        # Collect into evidence engine
        evidence_eng.ingest_execution_output(
            scenario_id=scenario.id,
            asset_id=scenario.asset_id,
            technique_id=scenario.technique_id,
            stdout=evidence.get("stdout", ""),
            stderr=evidence.get("stderr", ""),
            returncode=evidence.get("returncode", 0),
        )

        # Detection validation
        detection_result = detection.validate(scenario.asset_id)
        evidence_eng.ingest_detection_signals(
            scenario_id=scenario.id,
            asset_id=scenario.asset_id,
            technique_id=scenario.technique_id,
            signals=detection_result.get("signals", []),
        )

        # Review & quality gate
        review = reviewer.review(evidence, detection_result)
        if not review.get("accepted"):
            console.print(f"  [dim]SKIP {scenario.id}: {review.get('rejection_reason')}[/]")
            continue

        detection_status = review["detection_status"]
        severity = infer_severity(scorer, scenario.technique_id, detection_status, asset.criticality)
        score = scorer.score(
            asset_criticality=asset.criticality,
            detected=detection_result["detected"],
            reproducible=bool(evidence["reproducible"]),
            severity=severity,
        )

        finding = Finding(
            id=f"FND-{scenario.id}",
            asset=scenario.asset_id,
            technique_id=scenario.technique_id,
            severity=severity,
            reproducible=bool(evidence["reproducible"]),
            evidence_path=str(evidence_path.relative_to(root)),
            summary=evidence["summary"],
            detection_status=detection_status,
            score=score,
        )
        finding_path = root / "artifacts" / f"{finding.id}.json"
        write_json(finding_path, finding.to_dict())

        # Rust validation
        validation_status = maybe_validate_with_rust(root, finding_path)

        # Hardening recs
        recs = hardening.recommend(finding.technique_id, finding.detection_status)
        recs.append(f"Validación Rust: {validation_status}")

        findings.append(finding)
        remediation_map[finding.id] = recs

        sev_color = {"critical": "bright_red", "high": "red", "medium": "yellow", "low": "green"}.get(severity, "white")
        console.print(
            f"  [{sev_color}]{finding.id}[/] | {scenario.technique_id} | "
            f"{asset.name} | {severity} | det={detection_status} | score={score}"
        )

    # ── Offensive harness cycle ───────────────────────────────────────────────
    console.print("\n[bold red]── Ciclo Ofensivo IA (hipótesis · cadenas · evasión · PoCs) ──[/]")
    authorized_assets = [a for a in assets if perimeter.is_asset_authorized(a.id)]
    authorized_techs  = [t for t in techniques if perimeter.is_technique_authorized(t.id)]
    offensive_result  = harness.run_offensive_cycle(authorized_assets, authorized_techs, findings)

    console.print(
        f"  [green]✓[/] Hipótesis: {offensive_result.hypotheses_generated} | "
        f"Cadenas: {offensive_result.chains_simulated} | "
        f"Evasión tests: {offensive_result.evasion_tests_run} | "
        f"PoCs: {offensive_result.pocs_built}"
    )
    console.print(
        f"  [yellow]Cobertura ATT&CK:[/] {offensive_result.coverage_pct}% | "
        f"[red]Gap de detección:[/] {offensive_result.detection_gap_pct}%"
    )

    # ── Remediation engine ────────────────────────────────────────────────────
    console.print("\n[bold blue]── Backlog de Remediación ──────────────────────────────────[/]")
    tickets = remediation_eng.process_findings(findings)
    ticket_map = {t.finding_id: t for t in tickets}
    # Merge ticket info into remediation_map
    for fid, ticket in ticket_map.items():
        remediation_map[fid] = ticket
    backlog_summary = remediation_eng.backlog_summary()
    console.print(
        f"  Tickets: {backlog_summary['total_tickets']} | "
        f"Por owner: {backlog_summary['by_owner']} | "
        f"SLA crítico (1d): {backlog_summary['critical_sla_1day']}"
    )

    # ── CI/CD state save ──────────────────────────────────────────────────────
    cicd.record_run([a.to_dict() for a in assets])

    # ── Reports ───────────────────────────────────────────────────────────────
    findings_sorted = sorted(findings, key=lambda x: x.score, reverse=True)

    evidence_summary = evidence_eng.build_evidence_summary()
    report_json = {
        "program":         config.get("program", {"name":"AI Cyber Range","version":"2.0","mode":"local_lab_only"}),
        "sovereignty":     config["sovereignty"],
        "run_id":          offensive_result.run_id,
        "engagement_id":   offensive_result.engagement_id,
        "scenario_count":  len(scenarios),
        "finding_count":   len(findings_sorted),
        "findings":        [f.to_dict() for f in findings_sorted],
        "remediation_backlog": {fid: t.to_dict() if hasattr(t, "to_dict") else t for fid, t in ticket_map.items()},
        "offensive_summary": offensive_result.to_dict(),
        "evidence_summary":  evidence_summary,
        "cicd_events":       [e.to_dict() for e in cicd_events],
    }
    reports_dir = root / "python_orchestrator" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    write_json(reports_dir / "latest_report.json", report_json)

    md = generate_markdown_report(
        config, governance, findings_sorted, remediation_map, offensive_result, cicd_events
    )
    write_text(reports_dir / "latest_report.md", md)

    # ── Console dashboard ─────────────────────────────────────────────────────
    table = Table(title="[bold red]AI Cyber Range — Hallazgos Priorizados[/]", border_style="red")
    table.add_column("Finding",    style="cyan")
    table.add_column("Activo",     style="white")
    table.add_column("ATT&CK",     style="yellow")
    table.add_column("Tactic",     style="dim")
    table.add_column("Severidad",  style="bold")
    table.add_column("Detección",  style="white")
    table.add_column("PoC",        style="green")
    table.add_column("Score",      justify="right", style="bold red")
    for f in findings_sorted:
        sev_style = {"critical": "bright_red", "high": "red", "medium": "yellow", "low": "green"}.get(f.severity, "white")
        table.add_row(
            f.id, f.asset, f.technique_id,
            tech_by_id.get(f.technique_id, Technique(f.technique_id, "", "", "")).tactic if f.technique_id in tech_by_id else "—",
            f"[{sev_style}]{f.severity}[/]",
            f.detection_status,
            "✓" if f.poc_id else "—",
            str(f.score),
        )
    console.print(table)

    # Summary panel
    console.print(Panel(
        f"[bold]Findings:[/] {len(findings_sorted)} | "
        f"[red]Crítico: {offensive_result.critical_count}[/] | "
        f"[yellow]Alto: {offensive_result.high_count}[/] | "
        f"Cobertura: {offensive_result.coverage_pct}% | "
        f"Gap detección: [red]{offensive_result.detection_gap_pct}%[/]\n"
        f"[green]Reportes:[/] python_orchestrator/reports/latest_report.md",
        title="Executive Summary",
        border_style="blue",
    ))


if __name__ == "__main__":
    main()
