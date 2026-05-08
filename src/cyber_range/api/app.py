"""
cyber_range.api.app
====================
Stable FastAPI application.

Security:
  - Optional API key authentication (X-API-Key header)
  - CORS via allowlist (no wildcard by default)
  - All errors return structured JSON

Endpoints:
  GET  /health
  GET  /version
  POST /runs
  GET  /runs
  GET  /runs/{run_id}
  GET  /runs/{run_id}/findings
  GET  /runs/{run_id}/evidence
  POST /runs/{run_id}/verify-evidence
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Depends, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security.api_key import APIKeyHeader

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="AI Cyber Range API",
    version="0.2.0-beta",
    description="Secure defensive validation API. Powered by AxisDynamics.",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS — NO wildcard by default ─────────────────────────────────────────────

_CORS_ORIGINS = [o.strip() for o in os.environ.get("CYBER_RANGE_CORS", "").split(",") if o.strip()]
if not _CORS_ORIGINS:
    _CORS_ORIGINS = ["http://localhost:8080", "http://127.0.0.1:8080",
                     "http://localhost:5173", "http://127.0.0.1:5173"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)

# ── API key auth ───────────────────────────────────────────────────────────────

_API_KEY = os.environ.get("CYBER_RANGE_API_KEY", "")
_API_KEY_ENABLED = bool(_API_KEY)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(api_key: Optional[str] = Security(_api_key_header)) -> None:
    if not _API_KEY_ENABLED:
        return  # Auth disabled — no key required
    if not api_key or api_key != _API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_error("UNAUTHORIZED", "Valid X-API-Key header required"),
        )


# ── Error helper ──────────────────────────────────────────────────────────────

def _error(code: str, message: str, details: Dict = {}) -> Dict:
    return {"error": {"code": code, "message": message, "details": details}}


def _not_found(run_id: str) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail=_error("RUN_NOT_FOUND", f"Run '{run_id}' not found"),
    )


# ── Project root resolution ───────────────────────────────────────────────────

def _project_root() -> Path:
    env = os.environ.get("CYBER_RANGE_ROOT")
    if env:
        return Path(env)
    # Walk up from current file
    cur = Path(__file__).resolve()
    for _ in range(6):
        if (cur / "pyproject.toml").exists() or (cur / "install.sh").exists():
            return cur
        cur = cur.parent
    return Path.cwd()


ROOT = _project_root()
RUNS_DIR = ROOT / "artifacts" / "runs"
REPORTS_DIR = ROOT / "python_orchestrator" / "reports"


def _run_dir(run_id: str) -> Path:
    return RUNS_DIR / run_id


def _list_runs() -> List[Dict]:
    if not RUNS_DIR.exists():
        return []
    runs = []
    for d in sorted(RUNS_DIR.iterdir(), reverse=True):
        if d.is_dir():
            summary_f = d / "summary.json"
            if summary_f.exists():
                try:
                    s = json.loads(summary_f.read_text())
                    runs.append({
                        "run_id": s.get("run_id", d.name),
                        "status": s.get("status", "unknown"),
                        "started_at": s.get("started_at"),
                        "findings_count": s.get("findings_count", 0),
                        "coverage_pct": s.get("coverage_pct", 0),
                    })
                except Exception:
                    pass
    return runs


def _read_latest_report() -> Dict:
    f = REPORTS_DIR / "latest_report.json"
    return json.loads(f.read_text()) if f.exists() else {}


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["system"])
async def health():
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "auth_enabled": _API_KEY_ENABLED,
    }


@app.get("/version", tags=["system"])
async def version():
    return {
        "version": "0.2.0-beta",
        "product": "AI Cyber Range",
        "powered_by": "AxisDynamics — https://axisdynamics.cl",
    }


@app.post("/runs", dependencies=[Depends(require_api_key)], tags=["runs"])
async def create_run(body: Dict[str, Any] = {}):
    """
    Launch a new simulation run.

    Returns run_id and initial state immediately.
    Background execution via separate process.
    """
    from cyber_range.config.schema import load_config
    config_path = ROOT / body.get("config", "configs/default.yaml")
    try:
        cfg = load_config(config_path)
    except Exception as e:
        raise HTTPException(400, detail=_error("INVALID_CONFIG", str(e)))

    import uuid, subprocess, sys
    run_id = "RUN-" + uuid.uuid4().hex[:8].upper()
    # Async execution — return run_id immediately
    # (For full async, use BackgroundTasks; for simplicity use subprocess detach)
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(exist_ok=True)
    (run_dir / "summary.json").write_text(json.dumps({
        "run_id": run_id, "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "config": str(config_path),
    }, indent=2))

    return {"run_id": run_id, "status": "running",
            "message": "Run started. Poll GET /runs/{run_id} for status."}


@app.get("/runs", dependencies=[Depends(require_api_key)], tags=["runs"])
async def list_runs():
    """List all available runs."""
    runs = _list_runs()
    # Also expose the latest report as a virtual run if no run dirs exist
    if not runs:
        r = _read_latest_report()
        if r:
            s = r.get("offensive_summary", {})
            from cyber_range.scoring.engine import clamp
            runs = [{
                "run_id": r.get("run_id", "latest"),
                "status": "success",
                "started_at": s.get("started_at"),
                "findings_count": s.get("findings_count", 0),
                "coverage_pct": clamp(s.get("coverage_pct", 0)),
            }]
    return {"runs": runs, "count": len(runs)}


@app.get("/runs/{run_id}", dependencies=[Depends(require_api_key)], tags=["runs"])
async def get_run(run_id: str):
    """Get run summary."""
    # Check run dir first
    d = _run_dir(run_id)
    if d.exists():
        sf = d / "summary.json"
        if sf.exists():
            return json.loads(sf.read_text())

    # Fall back to latest_report for "latest"
    if run_id in ("latest", "RUN-DEMO"):
        r = _read_latest_report()
        if r:
            from cyber_range.scoring.engine import clamp
            s = r.get("offensive_summary", {})
            return {
                "run_id": r.get("run_id", run_id),
                "status": "success",
                "findings_count": s.get("findings_count", 0),
                "coverage_pct": clamp(s.get("coverage_pct", 0)),
                "detection_gap_pct": s.get("detection_gap_pct", 0),
            }

    raise _not_found(run_id)


@app.get("/runs/{run_id}/findings", dependencies=[Depends(require_api_key)], tags=["runs"])
async def get_findings(run_id: str, severity: str = "", detection_status: str = ""):
    """Get findings for a run."""
    d = _run_dir(run_id)
    ff = d / "findings.json"

    if ff.exists():
        findings = json.loads(ff.read_text())
    else:
        r = _read_latest_report()
        findings = r.get("findings", [])

    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    if detection_status:
        findings = [f for f in findings if f.get("detection_status") == detection_status]

    return {"run_id": run_id, "count": len(findings), "findings": findings}


@app.get("/runs/{run_id}/evidence", dependencies=[Depends(require_api_key)], tags=["runs"])
async def get_evidence(run_id: str):
    """Get evidence records for a run."""
    d = _run_dir(run_id)
    evd_dir = d / "evidence"
    if not evd_dir.exists():
        evd_dir = ROOT / "artifacts" / "evidence"

    records = []
    if evd_dir.exists():
        for p in sorted(evd_dir.glob("EVD-*.json"))[:50]:
            try:
                records.append(json.loads(p.read_text()))
            except Exception:
                pass
    return {"run_id": run_id, "count": len(records), "records": records}


@app.post("/runs/{run_id}/verify-evidence",
          dependencies=[Depends(require_api_key)], tags=["runs"])
async def post_verify_evidence(run_id: str):
    """Verify evidence integrity for a run. Returns non-200 if tampered."""
    from cyber_range.evidence.verifier import verify_run, verify_legacy_artifacts

    d = _run_dir(run_id)
    if d.exists():
        report = verify_run(d)
    else:
        report = verify_legacy_artifacts(ROOT / "artifacts")

    result = {
        "run_id": run_id,
        "passed": report.passed,
        "total": report.total,
        "valid": report.valid,
        "missing": report.missing,
        "modified": report.modified,
    }

    if not report.passed:
        raise HTTPException(
            status_code=422,
            detail=_error(
                "EVIDENCE_INTEGRITY_FAILURE",
                f"{report.modified} modified, {report.missing} missing",
                {"report": result},
            ),
        )
    return result


# ── Keep backward compat routes from old web/api/main.py ─────────────────────

@app.get("/api/status", include_in_schema=False)
async def compat_status():
    r = _read_latest_report()
    return {"status": "idle", "run_id": r.get("run_id", "—"),
            "last_scan_at": r.get("offensive_summary", {}).get("finished_at")}


@app.get("/api/summary", include_in_schema=False)
async def compat_summary():
    r = _read_latest_report()
    from cyber_range.scoring.engine import clamp
    s = r.get("offensive_summary", {})
    return {**s, "coverage_pct": clamp(s.get("coverage_pct", 0)),
            "top_findings": r.get("findings", [])[:6],
            "open_tickets": len(r.get("remediation_backlog", {}))}


@app.get("/api/findings", include_in_schema=False)
async def compat_findings(severity: str = "", detection_status: str = "", limit: int = 100):
    r = _read_latest_report()
    fs = r.get("findings", [])
    if severity:        fs = [f for f in fs if f.get("severity") == severity]
    if detection_status:fs = [f for f in fs if f.get("detection_status") == detection_status]
    return {"count": len(fs[:limit]), "total": len(r.get("findings", [])), "findings": fs[:limit]}


@app.get("/api/remediation", include_in_schema=False)
async def compat_remediation():
    from cyber_range.scoring.engine import clamp
    r = _read_latest_report()
    bl = r.get("remediation_backlog", {})
    tickets = list(bl.values()) if isinstance(bl, dict) else []
    tickets.sort(key=lambda t: t.get("priority", 5))
    bp: Dict = {"critical": [], "high": [], "medium": [], "low": []}
    for t in tickets:
        s = t.get("sla_days", 90)
        if s <= 1:   bp["critical"].append(t)
        elif s <= 7: bp["high"].append(t)
        elif s <= 30:bp["medium"].append(t)
        else:        bp["low"].append(t)
    oc = {"security": 0, "platform": 0, "engineering": 0}
    for t in tickets:
        k = t.get("owner_team", "security")
        oc[k] = oc.get(k, 0) + 1
    return {"total": len(tickets), "by_priority": bp, "tickets": tickets,
            "summary": {"open": len(tickets), "by_owner": oc}}


@app.get("/api/chains", include_in_schema=False)
async def compat_chains():
    r = _read_latest_report()
    s = r.get("offensive_summary", {})
    return {"chains_simulated": s.get("chains_simulated", 0),
            "top_findings": r.get("findings", [])[:8], "engagement_id": r.get("engagement_id", "")}


@app.get("/api/evidence", include_in_schema=False)
async def compat_evidence(limit: int = 40):
    evd_dir = ROOT / "artifacts" / "evidence"
    records = []
    if evd_dir.exists():
        for p in sorted(evd_dir.glob("EVD-*.json"))[:limit]:
            try: records.append(json.loads(p.read_text()))
            except: pass
    r = _read_latest_report()
    return {"summary": r.get("evidence_summary", {}), "records": records, "count": len(records)}


@app.get("/api/detections", include_in_schema=False)
async def compat_detections():
    r = _read_latest_report()
    try:
        import sys; sys.path.insert(0, str(ROOT))
        from python_orchestrator.detectors.hybrid_detector import HybridDetector
        hd = HybridDetector()
        result = hd.analyze(r.get("findings", [])[:15], [], run_llm_enrichment=True)
        return result.to_dict()
    except Exception as e:
        return {"error": str(e), "all_alerts": [], "engine_stats": {}}


@app.get("/api/metrics", include_in_schema=False)
async def compat_metrics():
    from cyber_range.scoring.engine import clamp, coverage_pct, detection_gap_pct
    r = _read_latest_report()
    s = r.get("offensive_summary", {})
    fs = r.get("findings", [])
    tactic_map = {"T1190":"Initial Access","T1078":"Initial Access","T1059":"Execution",
        "T1053":"Persistence","T1548":"Privilege Escalation","T1562":"Defense Evasion",
        "T1003":"Credential Access","T1082":"Discovery","T1021":"Lateral Movement",
        "T1005":"Collection","T1041":"Exfiltration","T1499":"Impact"}
    tac: Dict[str, int] = {}
    for f in fs:
        k = tactic_map.get(f.get("technique_id", ""), "Other"); tac[k] = tac.get(k, 0) + 1
    buckets = [{"range": "90-100","count":0},{"range":"70-89","count":0},
               {"range":"50-69","count":0},{"range":"0-49","count":0}]
    for f in fs:
        sc = float(f.get("score", 0))
        if sc >= 90: buckets[0]["count"] += 1
        elif sc >= 70: buckets[1]["count"] += 1
        elif sc >= 50: buckets[2]["count"] += 1
        else: buckets[3]["count"] += 1
    return {"coverage_pct": clamp(s.get("coverage_pct", 0)),
            "detection_gap_pct": s.get("detection_gap_pct", 0),
            "score_distribution": buckets, "findings_by_tactic": tac,
            "severity_breakdown": {"critical": s.get("critical_count", 0),
                                    "high": s.get("high_count", 0),
                                    "medium": 0, "low": 0},
            "detection_by_status": {"gap": sum(1 for f in fs if f.get("detection_status") == "gap"),
                                     "detected": sum(1 for f in fs if f.get("detection_status") == "detected")}}


@app.post("/api/run", include_in_schema=False)
async def compat_run():
    import uuid, subprocess, sys as _sys
    _sys.path.insert(0, str(ROOT))
    import asyncio
    cfg_path = ROOT / "configs" / "default.yaml"
    proc = await asyncio.create_subprocess_exec(
        _sys.executable, "-m", "python_orchestrator.main",
        "--config", str(cfg_path),
        cwd=str(ROOT),
    )
    return {"status": "started", "pid": proc.pid}


# ── Serve Vite dashboard ───────────────────────────────────────────────────────

from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

_FRONTEND = ROOT / "web" / "frontend"
_DIST     = _FRONTEND / "dist"

if (_DIST / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(_DIST / "assets")), name="assets")


def _read_index() -> str:
    idx = _DIST / "index.html"
    if idx.exists():
        return idx.read_text(encoding="utf-8")
    return "<h1>Dashboard not built. Run: cd web/frontend && npm run build</h1>"


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def serve_root():
    return HTMLResponse(_read_index())


@app.get("/{path:path}", response_class=HTMLResponse, include_in_schema=False)
async def serve_spa(path: str):
    if path.startswith(("api/", "runs", "health", "version", "docs", "redoc")):
        raise HTTPException(404)
    return HTMLResponse(_read_index())
