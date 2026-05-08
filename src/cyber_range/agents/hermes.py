"""
cyber_range.agents.hermes
==========================
Hermes multi-agent orchestrator.

Architecture:
    HermesOrchestrator (master)
        ├── Memory (SQLite, cross-run)
        ├── GapAnalysisAgent  — lee memoria, prioriza técnicas
        ├── [parallel via ThreadPoolExecutor]
        │   ├── InitialAccessAgent    (T1190, T1078)
        │   ├── ExecutionAgent        (T1059, T1053)
        │   ├── PrivilegeAgent        (T1548)
        │   ├── EvasionAgent          (T1562)
        │   ├── CredentialAgent       (T1003)
        │   ├── DiscoveryAgent        (T1082)
        │   ├── LateralAgent          (T1021)
        │   ├── CollectionAgent       (T1005, T1041)
        │   └── ImpactAgent           (T1499)
        └── SynthesisAgent    — consolida, corre HybridDetector, genera findings

Todos los agentes pasan por PolicyEnforcer antes de ejecutar cualquier tool.
La PolicyEnforcer es la primera capa, no el agente.

Los agentes NO tienen autonomía para ejecutar fuera de scope.
"""
from __future__ import annotations

import sys
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cyber_range.agents.memory import AgentMemory, PersistentGap
from cyber_range.config.schema import CyberRangeConfig
from cyber_range.logging.structured import StructuredLogger, get_noop_logger
from cyber_range.policy.enforcer import PolicyEnforcer
from cyber_range.scoring.engine import clamp, coverage_pct, detection_gap_pct


# ── Technique clusters per agent ─────────────────────────────────────────────

AGENT_CLUSTERS: Dict[str, List[str]] = {
    "initial_access":  ["T1190", "T1078", "T1133"],
    "execution":       ["T1059", "T1053", "T1203"],
    "privilege":       ["T1548", "T1055", "T1134"],
    "evasion":         ["T1562", "T1078", "T1027"],
    "credential":      ["T1003", "T1552", "T1558"],
    "discovery":       ["T1082", "T1046", "T1049"],
    "lateral":         ["T1021", "T1091", "T1550"],
    "collection":      ["T1005", "T1041", "T1074"],
    "impact":          ["T1499", "T1486", "T1490"],
}


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class AgentResult:
    agent_name:  str
    techniques:  List[str]
    findings:    List[Dict]
    blocked:     List[str]   # technique IDs blocked by policy
    duration_s:  float
    error:       Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None


@dataclass
class HermesRunResult:
    run_id:       str
    mode:         str  # "hermes"
    started_at:   str
    finished_at:  str
    agents_run:   int
    findings:     List[Dict]
    findings_count: int
    critical_count: int
    coverage_pct:   float
    detection_gap_pct: float
    persistent_gaps: List[Dict]
    agent_results:  List[AgentResult]
    memory_stats:   Dict[str, Any]
    status:         str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "mode": self.mode,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "agents_run": self.agents_run,
            "findings_count": self.findings_count,
            "critical_count": self.critical_count,
            "coverage_pct": self.coverage_pct,
            "detection_gap_pct": self.detection_gap_pct,
            "persistent_gaps": self.persistent_gaps,
            "memory_stats": self.memory_stats,
            "status": self.status,
        }


# ── Specialized agent ─────────────────────────────────────────────────────────

class SpecializedAgent:
    """
    One agent per ATT&CK tactic cluster.

    Receives pre-validated (scope + policy) targets.
    Executes simulations via the existing RedTeamAgent tool.
    Cannot execute anything not pre-approved by PolicyEnforcer.
    """

    def __init__(
        self,
        name:     str,
        techniques: List[str],
        assets:   List[str],
        enforcer: PolicyEnforcer,
        project_root: Path,
        logger:   StructuredLogger,
    ):
        self.name       = name
        self.techniques = techniques
        self.assets     = assets
        self.enforcer   = enforcer
        self.root       = project_root
        self.logger     = logger

    def run(self) -> AgentResult:
        start = time.monotonic()
        findings: List[Dict] = []
        blocked:  List[str]  = []

        # Import lazily to avoid circular deps
        sys.path.insert(0, str(self.root))
        try:
            from python_orchestrator.agents.red_team import RedTeamAgent
            from python_orchestrator.core.models import Scenario
        except ImportError:
            return AgentResult(
                agent_name=self.name,
                techniques=self.techniques,
                findings=[], blocked=[],
                duration_s=time.monotonic() - start,
                error="Cannot import python_orchestrator — run pipeline first",
            )

        red = RedTeamAgent(self.root)

        for tech in self.techniques:
            for asset in self.assets[:4]:  # cap per agent
                # Policy check FIRST — always
                decision = self.enforcer.check_scenario(asset, tech)
                if not decision.allowed:
                    blocked.append(f"{tech}@{asset}: {decision.reason}")
                    continue

                try:
                    from python_orchestrator.core.models import Scenario as S
                    scn = S(
                        id=f"SCN-{asset}-{tech}",
                        asset_id=asset,
                        technique_id=tech,
                        objective=f"Hermes agent: {self.name}",
                        authorized=True,
                        tactic=self.name,
                    )
                    result = red.run_scenario(scn)
                    if result and isinstance(result, dict):
                        result["agent"] = self.name
                        findings.append(result)
                except Exception as exc:
                    self.logger.warning(
                        "agent_scenario_error",
                        f"{self.name}: {tech}@{asset} — {exc}",
                        phase="hermes",
                    )

        return AgentResult(
            agent_name=self.name,
            techniques=self.techniques,
            findings=findings,
            blocked=blocked,
            duration_s=round(time.monotonic() - start, 2),
        )


# ── Gap analysis ──────────────────────────────────────────────────────────────

def _run_gap_analysis(
    memory: AgentMemory,
    scope_techs: List[str],
    logger: StructuredLogger,
) -> List[str]:
    """
    GapAnalysisAgent: decides which techniques to focus on this run.
    Priority: persistent gaps first, then techniques never seen, then rest.
    """
    persistent = [g.technique_id for g in memory.get_persistent_gaps(min_occurrences=2)
                  if g.technique_id in scope_techs]
    priority   = memory.get_priority_techniques(scope_techs, top_n=len(scope_techs))

    # Put persistent gaps first, then priority order, deduplicated
    ordered: List[str] = []
    for t in persistent + priority:
        if t not in ordered:
            ordered.append(t)

    logger.info(
        "gap_analysis",
        f"Gap analysis: {len(persistent)} persistent gaps, {len(priority)} priority techs",
        phase="hermes",
        persistent_gaps=persistent,
    )
    return ordered


# ── Hermes Orchestrator ───────────────────────────────────────────────────────

class HermesOrchestrator:
    """
    Multi-agent orchestrator with persistent memory.

    Usage:
        orch = HermesOrchestrator(config, project_root=Path("."))
        result = orch.run()
    """

    MAX_WORKERS = 4  # concurrent agents

    def __init__(
        self,
        config:       CyberRangeConfig,
        project_root: Path,
        run_id:       str,
        logger:       Optional[StructuredLogger] = None,
    ):
        self.cfg      = config
        self.root     = project_root
        self.run_id   = run_id
        self.logger   = logger or get_noop_logger()
        self.enforcer = PolicyEnforcer(config)
        self.memory   = AgentMemory(project_root / "artifacts" / "agent_memory.db")

    def run(self) -> HermesRunResult:
        started = datetime.now(timezone.utc).isoformat()
        self.logger.info("hermes_start", f"Hermes orchestrator starting run {self.run_id}",
                         phase="hermes")

        # 1. Load scope
        assets      = self.cfg.engagement.authorized_assets or self._default_assets()
        scope_techs = self._load_scope_techniques()

        # 2. GapAnalysisAgent — prioritize techniques
        priority_techs = _run_gap_analysis(self.memory, scope_techs, self.logger)

        # 3. Build agents — only for techniques in scope
        agents = self._build_agents(assets, priority_techs)
        self.logger.info("hermes_agents", f"Spawning {len(agents)} specialized agents",
                         phase="hermes", agent_count=len(agents))

        # 4. Execute concurrently
        agent_results = self._run_concurrent(agents)

        # 5. SynthesisAgent — consolidate findings
        all_findings = []
        for r in agent_results:
            all_findings.extend(r.findings)

        # Deduplicate by (asset, technique_id)
        seen: set = set()
        deduped: List[Dict] = []
        for f in all_findings:
            key = (f.get("asset_id", f.get("asset", "")), f.get("technique_id", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        # Clamp scores
        for f in deduped:
            f["score"] = clamp(float(f.get("score", 50)))

        # 6. Run HybridDetector on findings
        det_summary = self._run_detector(deduped)

        # 7. Update memory
        summary_for_mem = {
            "run_id": self.run_id,
            "started_at": started,
            "findings_count": len(deduped),
            "critical_count": sum(1 for f in deduped if f.get("severity") == "critical"),
            "coverage_pct": coverage_pct(
                [f.get("technique_id","") for f in deduped], scope_techs
            ),
            "detection_gap_pct": detection_gap_pct(deduped),
            "profile": self.cfg.profile,
        }
        self.memory.remember_run(summary_for_mem)
        self.memory.remember_findings(self.run_id, deduped)

        finished = datetime.now(timezone.utc).isoformat()
        persistent = [
            {"technique_id": g.technique_id, "asset": g.asset,
             "occurrences": g.occurrence_count, "max_score": g.max_score}
            for g in self.memory.get_persistent_gaps(min_occurrences=2)
        ]

        sc = {s: sum(1 for f in deduped if f.get("severity") == s)
              for s in ("critical","high","medium","low")}

        result = HermesRunResult(
            run_id=self.run_id,
            mode="hermes",
            started_at=started,
            finished_at=finished,
            agents_run=len(agents),
            findings=deduped,
            findings_count=len(deduped),
            critical_count=sc.get("critical", 0),
            coverage_pct=summary_for_mem["coverage_pct"],
            detection_gap_pct=summary_for_mem["detection_gap_pct"],
            persistent_gaps=persistent,
            agent_results=agent_results,
            memory_stats=self.memory.stats(),
            status="success",
        )

        self.logger.info(
            "hermes_complete",
            f"Hermes run complete: {len(deduped)} findings, {len(persistent)} persistent gaps",
            phase="hermes",
            findings=len(deduped),
            persistent_gaps=len(persistent),
        )
        return result

    # ── Private helpers ───────────────────────────────────────────────────────

    def _build_agents(
        self, assets: List[str], priority_techs: List[str]
    ) -> List[SpecializedAgent]:
        agents = []
        for name, cluster_techs in AGENT_CLUSTERS.items():
            # Only include techs that are both in cluster AND in priority scope
            relevant = [t for t in priority_techs if t in cluster_techs]
            if not relevant:
                continue
            agents.append(SpecializedAgent(
                name=name,
                techniques=relevant,
                assets=assets,
                enforcer=self.enforcer,
                project_root=self.root,
                logger=self.logger,
            ))
        return agents

    def _run_concurrent(self, agents: List[SpecializedAgent]) -> List[AgentResult]:
        results: List[AgentResult] = []
        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as pool:
            futures: Dict[Future, str] = {
                pool.submit(agent.run): agent.name
                for agent in agents
            }
            for future in as_completed(futures, timeout=300):
                name = futures[future]
                try:
                    r = future.result()
                    results.append(r)
                    self.logger.info(
                        "agent_complete",
                        f"Agent '{name}' finished: {len(r.findings)} findings",
                        phase="hermes",
                        agent=name,
                        findings=len(r.findings),
                        blocked=len(r.blocked),
                        duration_s=r.duration_s,
                    )
                except Exception as exc:
                    self.logger.error(
                        "agent_failed",
                        f"Agent '{name}' raised: {exc}",
                        phase="hermes",
                        agent=name,
                    )
                    results.append(AgentResult(
                        agent_name=name, techniques=[], findings=[], blocked=[],
                        duration_s=0, error=str(exc),
                    ))
        return results

    def _run_detector(self, findings: List[Dict]) -> Dict:
        try:
            sys.path.insert(0, str(self.root))
            from python_orchestrator.detectors.hybrid_detector import HybridDetector
            hd = HybridDetector()
            r = hd.analyze(findings[:20], [], run_llm_enrichment=True)
            return {"alerts": len(r.all_alerts), "engine_stats": r.engine_stats}
        except Exception as exc:
            return {"error": str(exc)}

    def _load_scope_techniques(self) -> List[str]:
        p = self.root / "python_orchestrator" / "data" / "attack_subset.json"
        if not p.exists():
            return list({t for ts in AGENT_CLUSTERS.values() for t in ts})
        raw = json.loads(p.read_text())
        # Handle both list-of-dicts and {techniques: [...]} formats
        if isinstance(raw, dict):
            items = raw.get("techniques", list(raw.values())[0] if raw else [])
        else:
            items = raw
        result = []
        for item in items:
            if isinstance(item, dict):
                tid = item.get("id") or item.get("technique_id") or item.get("external_id","")
                if tid: result.append(tid)
            elif isinstance(item, str) and item.startswith("T"):
                result.append(item)
        return result or list({t for ts in AGENT_CLUSTERS.values() for t in ts})

    def _default_assets(self) -> List[str]:
        p = self.root / "python_orchestrator" / "data" / "assets.json"
        if not p.exists():
            return ["iam_role_demo", "api_gateway_demo", "pipeline_demo",
                    "secrets_store_demo", "cloud_storage_demo", "local_c_lab_service"]
        raw = json.loads(p.read_text())
        if isinstance(raw, dict):
            items = raw.get("assets", list(raw.values())[0] if raw else [])
        else:
            items = raw
        result = []
        for item in items:
            if isinstance(item, dict):
                aid = item.get("id") or item.get("asset_id","")
                if aid: result.append(aid)
            elif isinstance(item, str):
                result.append(item)
        return result or ["iam_role_demo", "api_gateway_demo", "pipeline_demo"]
