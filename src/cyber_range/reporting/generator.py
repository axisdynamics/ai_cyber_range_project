"""
cyber_range.reporting.generator
================================
Generates report.md and report.json from run data.

report.json has a stable, documented schema.
report.md is human-readable with executive summary, ATT&CK matrix, etc.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cyber_range.scoring.engine import (
    clamp, coverage_pct, detection_gap_pct, severity_counts
)

# ── JSON Report Schema (stable v1) ────────────────────────────────────────────

REPORT_SCHEMA_VERSION = "1.0"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_json_report(
    run_id: str,
    config_path: str,
    findings: List[Dict],
    evidence_summary: Dict,
    scope_techniques: List[str],
    started_at: str = "",
    finished_at: str = "",
    extra: Dict = {},
) -> Dict[str, Any]:
    """Build the stable JSON report schema."""
    sc = severity_counts(findings)
    all_techniques = [f.get("technique_id", "") for f in findings]
    cov = coverage_pct(all_techniques, scope_techniques)
    gap = detection_gap_pct(findings)

    return {
        "schema_version":    REPORT_SCHEMA_VERSION,
        "report_type":       "cyber_range_run",
        "generated_at":      _now_iso(),
        "run": {
            "run_id":         run_id,
            "config_path":    config_path,
            "started_at":     started_at,
            "finished_at":    finished_at,
        },
        "executive_summary": {
            "findings_total":      len(findings),
            "critical_count":      sc.get("critical", 0),
            "high_count":          sc.get("high", 0),
            "medium_count":        sc.get("medium", 0),
            "low_count":           sc.get("low", 0),
            "informational_count": sc.get("informational", 0),
            "coverage_pct":        cov,
            "detection_gap_pct":   gap,
            "scope_techniques":    len(scope_techniques),
        },
        "findings":          findings,
        "evidence_summary":  evidence_summary,
        "limitations": [
            "All scenarios are synthetic simulations on local authorized fixtures.",
            "Detections are based on synthetic telemetry, not production SIEM data.",
            "Coverage metric counts techniques with at least one finding; "
            "depth of coverage per technique is not measured.",
        ],
        "metadata": extra,
    }


def build_md_report(report: Dict[str, Any]) -> str:
    """Build a human-readable Markdown report from the JSON report."""
    r = report
    run  = r.get("run", {})
    es   = r.get("executive_summary", {})
    fs   = r.get("findings", [])
    lims = r.get("limitations", [])

    lines: List[str] = []
    a = lines.append

    a("# AI Cyber Range — Run Report")
    a("")
    a("> Powered by [AxisDynamics](https://axisdynamics.cl) · MIT License")
    a("")
    a(f"**Run ID:** `{run.get('run_id','—')}`  ")
    a(f"**Generated:** {r.get('generated_at','—')}  ")
    a(f"**Started:** {run.get('started_at','—')}  ")
    a(f"**Finished:** {run.get('finished_at','—')}  ")
    a(f"**Config:** `{run.get('config_path','—')}`")
    a("")

    # Executive summary
    a("## Executive Summary")
    a("")
    a(f"| Metric | Value |")
    a(f"|--------|-------|")
    a(f"| Total Findings | {es.get('findings_total', 0)} |")
    a(f"| Critical | {es.get('critical_count', 0)} |")
    a(f"| High | {es.get('high_count', 0)} |")
    a(f"| Medium | {es.get('medium_count', 0)} |")
    a(f"| Low | {es.get('low_count', 0)} |")
    a(f"| ATT&CK Coverage | {es.get('coverage_pct', 0):.1f}% |")
    a(f"| Detection Gap | {es.get('detection_gap_pct', 0):.1f}% |")
    a(f"| Techniques in Scope | {es.get('scope_techniques', 0)} |")
    a("")

    # Findings by severity
    a("## Findings by Severity")
    a("")
    for sev in ("critical", "high", "medium", "low", "informational"):
        sev_fs = [f for f in fs if f.get("severity", "").lower() == sev]
        if not sev_fs:
            continue
        a(f"### {sev.capitalize()} ({len(sev_fs)})")
        a("")
        a("| Finding ID | Asset | Technique | Detection | Score |")
        a("|------------|-------|-----------|-----------|-------|")
        for f in sorted(sev_fs, key=lambda x: -x.get("score", 0)):
            fid  = f.get("id", "—")
            ast  = f.get("asset", "—")
            tech = f.get("technique_id", "—")
            det  = f.get("detection_status", "—")
            sc   = f"{clamp(float(f.get('score', 0))):.0f}"
            a(f"| `{fid}` | {ast} | {tech} | {det} | {sc} |")
        a("")

    # ATT&CK coverage matrix (simplified)
    a("## ATT&CK Technique Coverage")
    a("")
    covered_techs = {f.get("technique_id") for f in fs if f.get("technique_id")}
    for t in sorted(covered_techs):
        det_count = sum(1 for f in fs if f.get("technique_id") == t and f.get("detection_status") == "detected")
        gap_count = sum(1 for f in fs if f.get("technique_id") == t and f.get("detection_status") == "gap")
        status_icon = "🟢" if gap_count == 0 else "🔴"
        a(f"- {status_icon} **{t}** — {len([f for f in fs if f.get('technique_id')==t])} findings, {gap_count} gaps")
    a("")

    # Detection gaps
    gap_fs = [f for f in fs if f.get("detection_status") == "gap"]
    if gap_fs:
        a("## Detection Gaps")
        a("")
        a("The following findings had no detective coverage at time of simulation:")
        a("")
        for f in sorted(gap_fs, key=lambda x: -x.get("score", 0))[:10]:
            a(f"- `{f.get('technique_id','?')}` on `{f.get('asset','?')}` — score {f.get('score',0):.0f}")
        a("")

    # Recommendations (top 5 by score)
    top = sorted(fs, key=lambda x: -x.get("score", 0))[:5]
    if top:
        a("## Top Recommendations")
        a("")
        for i, f in enumerate(top, 1):
            summary = f.get("summary", "No summary available")
            a(f"{i}. **{f.get('technique_id','?')} on {f.get('asset','?')}** (score {f.get('score',0):.0f}, {f.get('severity','?')})")
            a(f"   {summary}")
        a("")

    # Evidence summary
    ev = r.get("evidence_summary", {})
    if ev:
        a("## Evidence Summary")
        a("")
        a(f"- Total records: {ev.get('total_records', 0)}")
        a(f"- Assets covered: {ev.get('assets_covered', 0)}")
        a(f"- Techniques covered: {ev.get('techniques_covered', 0)}")
        a("")

    # Limitations
    a("## Limitations")
    a("")
    for lim in lims:
        a(f"- {lim}")
    a("")
    a("---")
    a(f"*Report generated by AI Cyber Range v0.2.0-beta · AxisDynamics · MIT License*")

    return "\n".join(lines)


def generate_run_report(
    run_dir: Optional[Path] = None,
    report_file: Optional[Path] = None,
    output_dir: Optional[Path] = None,
) -> None:
    """Generate MD + JSON reports from either a run_dir or a legacy report file."""
    if run_dir and (run_dir / "findings.json").exists():
        findings = json.loads((run_dir / "findings.json").read_text())
        summary  = json.loads((run_dir / "summary.json").read_text()) if (run_dir/"summary.json").exists() else {}
        run_id   = summary.get("run_id", run_dir.name)
        cfg_path = summary.get("config_path", "—")
        started  = summary.get("started_at", "")
        finished = summary.get("finished_at", "")
        evd_sum  = {}
        out = output_dir or run_dir
    elif report_file and report_file.exists():
        data     = json.loads(report_file.read_text())
        findings = data.get("findings", [])
        s        = data.get("offensive_summary", {})
        run_id   = data.get("run_id", "latest")
        cfg_path = "configs/default.yaml"
        started  = s.get("started_at", "")
        finished = s.get("finished_at", "")
        evd_sum  = data.get("evidence_summary", {})
        out = output_dir or report_file.parent
    else:
        raise ValueError("Provide either run_dir or report_file")

    # Clamp scores before reporting
    for f in findings:
        f["score"] = clamp(float(f.get("score", 0)))

    json_report = build_json_report(
        run_id=run_id, config_path=cfg_path,
        findings=findings, evidence_summary=evd_sum,
        scope_techniques=[],  # ideally load from data/attack_subset.json
        started_at=started, finished_at=finished,
    )
    md_report = build_md_report(json_report)

    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(json_report, indent=2, ensure_ascii=False))
    (out / "report.md").write_text(md_report, encoding="utf-8")
