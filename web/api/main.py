"""
web/api/main.py — FastAPI backend for the AI Cyber Range dashboard.
Serves dist/index.html (Vite build) by default.
"""
from __future__ import annotations
import json, subprocess, sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

HERE     = Path(__file__).resolve().parent
WEB      = HERE.parent
PROJECT  = WEB.parent
FRONTEND = WEB / "frontend"
DIST     = FRONTEND / "dist"
REPORTS  = PROJECT / "python_orchestrator" / "reports"
ARTIFACTS= PROJECT / "artifacts"
EVIDENCE = ARTIFACTS / "evidence"

sys.path.insert(0, str(PROJECT))

app = FastAPI(title="AI Cyber Range API", version="2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_scan_running = False
_last_scan_at: Optional[str] = None
_det_cache: Optional[Dict] = None

# ── Static assets from Vite build ─────────────────────────────────────────────
if (DIST / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(DIST / "assets")), name="assets")

# ── Helpers ───────────────────────────────────────────────────────────────────
def report() -> Dict:
    p = REPORTS / "latest_report.json"
    return json.loads(p.read_text()) if p.exists() else {}

def evidence_records(limit=50) -> List[Dict]:
    if not EVIDENCE.exists(): return []
    out = []
    for p in sorted(EVIDENCE.glob("EVD-*.json"))[:limit]:
        try: out.append(json.loads(p.read_text()))
        except: pass
    return out

def run_detectors(r: Dict) -> Dict:
    global _det_cache
    if _det_cache: return _det_cache
    try:
        from python_orchestrator.detectors.hybrid_detector import HybridDetector
        hd = HybridDetector()
        res = hd.analyze(r.get("findings", []), evidence_records(30), run_llm_enrichment=True)
        _det_cache = res.to_dict()
        return _det_cache
    except Exception as e:
        return {"error": str(e), "all_alerts": [], "rule_matches": 0, "correlation_alerts": 0,
                "ioc_matches": 0, "anomaly_alerts": 0, "llm_enrichments": 0, "engine_stats": {}}

def _by(items, key): return {str(i.get(key,"?")): items.count(i) for i in items}
def _count(items, key):
    c: Dict[str,int] = {}
    for i in items: c[str(i.get(key,"?"))] = c.get(str(i.get(key,"?")),0)+1
    return c

# ── API routes ─────────────────────────────────────────────────────────────────
@app.get("/api/status")
async def status():
    r = report()
    return {"status":"running" if _scan_running else "idle",
            "last_scan_at": _last_scan_at or r.get("offensive_summary",{}).get("finished_at"),
            "run_id": r.get("run_id","—"), "program": r.get("program",{})}

@app.get("/api/summary")
async def summary():
    r = report(); s = r.get("offensive_summary",{})
    bl = r.get("remediation_backlog",{})
    tickets = list(bl.values()) if isinstance(bl,dict) else []
    return {**s,
        "evidence_records": r.get("evidence_summary",{}).get("total_records",0),
        "open_tickets": len(tickets),
        "sla_breach_count": sum(1 for t in tickets if t.get("sla_days",99)<=7),
        "scenario_count": r.get("scenario_count",0),
        "top_findings": r.get("findings",[])[:6]}

@app.get("/api/findings")
async def findings(severity:str="", asset:str="", detection_status:str="", limit:int=100):
    r = report(); fs = r.get("findings",[])
    if severity: fs = [f for f in fs if f.get("severity")==severity]
    if asset:    fs = [f for f in fs if asset.lower() in f.get("asset","").lower()]
    if detection_status: fs = [f for f in fs if f.get("detection_status")==detection_status]
    return {"count":len(fs[:limit]),"total":len(r.get("findings",[])),"findings":fs[:limit]}

@app.get("/api/remediation")
async def remediation(owner_team:str="", status:str=""):
    r = report(); bl = r.get("remediation_backlog",{})
    tickets = list(bl.values()) if isinstance(bl,dict) else []
    if owner_team: tickets=[t for t in tickets if t.get("owner_team")==owner_team]
    if status:     tickets=[t for t in tickets if t.get("status")==status]
    tickets.sort(key=lambda t:t.get("priority",5))
    bp: Dict[str,list] = {"critical":[],"high":[],"medium":[],"low":[]}
    for t in tickets:
        s = t.get("sla_days",90)
        if s<=1: bp["critical"].append(t)
        elif s<=7: bp["high"].append(t)
        elif s<=30: bp["medium"].append(t)
        else: bp["low"].append(t)
    return {"total":len(tickets),"by_priority":bp,"tickets":tickets,
            "summary":{"open":sum(1 for t in tickets if t.get("status")=="open"),
                       "by_owner":_count(tickets,"owner_team")}}

@app.get("/api/chains")
async def chains():
    r = report(); s = r.get("offensive_summary",{})
    return {"chains_simulated":s.get("chains_simulated",0),
            "top_findings":r.get("findings",[])[:8],
            "cicd_events":r.get("cicd_events",[]), "engagement_id":r.get("engagement_id","")}

@app.get("/api/evidence")
async def evidence(limit:int=40, evidence_type:str=""):
    recs = evidence_records(limit)
    if evidence_type: recs=[r for r in recs if r.get("evidence_type")==evidence_type]
    r = report(); es = r.get("evidence_summary",{})
    return {"summary":es, "records":recs[:limit], "count":len(recs)}

@app.get("/api/detections")
async def detections():
    global _det_cache; _det_cache=None
    r = report()
    if not r: raise HTTPException(404,"No report found. Run the pipeline first.")
    return run_detectors(r)

@app.get("/api/metrics")
async def metrics():
    r = report(); s = r.get("offensive_summary",{}); fs = r.get("findings",[])
    tactic_map={"T1190":"Initial Access","T1078":"Initial Access","T1059":"Execution",
        "T1053":"Persistence","T1548":"Privilege Escalation","T1562":"Defense Evasion",
        "T1003":"Credential Access","T1082":"Discovery","T1021":"Lateral Movement",
        "T1005":"Collection","T1041":"Exfiltration","T1499":"Impact"}
    tac: Dict[str,int]={}
    for f in fs:
        k=tactic_map.get(f.get("technique_id",""),"Other"); tac[k]=tac.get(k,0)+1
    buckets=[{"range":"90-100","count":0},{"range":"70-89","count":0},{"range":"50-69","count":0},{"range":"0-49","count":0}]
    for f in fs:
        sc=float(f.get("score",0))
        if sc>=90: buckets[0]["count"]+=1
        elif sc>=70: buckets[1]["count"]+=1
        elif sc>=50: buckets[2]["count"]+=1
        else: buckets[3]["count"]+=1
    return {"coverage_pct":s.get("coverage_pct",0),"detection_gap_pct":s.get("detection_gap_pct",0),
            "techniques_tested":len({f.get("technique_id") for f in fs}),
            "assets_tested":len({f.get("asset") for f in fs}),
            "pocs_with_evidence":s.get("pocs_built",0),"evasion_tests":s.get("evasion_tests_run",0),
            "score_distribution":buckets,
            "severity_breakdown":{"critical":s.get("critical_count",0),"high":s.get("high_count",0),
                                   "medium":s.get("medium_count",0),"low":s.get("low_count",0)},
            "detection_by_status":_count(fs,"detection_status"),
            "findings_by_tactic":tac}

@app.post("/api/run")
async def run(bg: BackgroundTasks):
    global _scan_running, _det_cache
    if _scan_running: return {"status":"already_running"}
    _det_cache=None; bg.add_task(_bg_scan)
    return {"status":"started","started_at":datetime.utcnow().isoformat()}

async def _bg_scan():
    global _scan_running, _last_scan_at, _det_cache
    _scan_running=True
    try:
        subprocess.run([sys.executable,"-m","python_orchestrator.main","--config","configs/default.yaml"],
            cwd=str(PROJECT),capture_output=True,timeout=120)
        _last_scan_at=datetime.utcnow().isoformat(); _det_cache=None
    except: pass
    finally: _scan_running=False

# ── Serve Vite React app ───────────────────────────────────────────────────────
def _read_index() -> str:
    idx = DIST / "index.html"
    if idx.exists():
        return idx.read_text(encoding="utf-8")
    return """<!DOCTYPE html><html><body style="background:#07090f;color:#cdd6f4;font-family:monospace;padding:40px">
<h2>Dashboard not built</h2>
<p>Run: <code>cd web/frontend && npm install && npm run build</code></p>
</body></html>"""

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(_read_index())

@app.get("/{path:path}", response_class=HTMLResponse)
async def spa(path: str):
    if path.startswith("api/"): raise HTTPException(404)
    return HTMLResponse(_read_index())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("web.api.main:app", host="0.0.0.0", port=8080, reload=True)
