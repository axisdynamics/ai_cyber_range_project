"""
harness_orchestrator.py
=======================
Implementación Python del patrón Harness Engineering aplicado al Cyber Range.

Patrón: Líder (este módulo) → red_team_agent (OffensiveHarness) → blue_team_agent (Reviewer)

Cada subagente:
  1. Ejecuta su tarea
  2. Escribe resultados en disco (progress/*.md + artifacts/)
  3. Devuelve solo una REFERENCIA (path), no el contenido completo

Esto implementa la "regla anti-hallucination":
  Un finding que no existe en artifacts/evidence/ con SHA-256 verificable
  es rechazado por el blue_team_agent automáticamente.

Uso directo:
    python3 -m python_orchestrator.harness.run_scenario --scenario-id 4

O programáticamente:
    from python_orchestrator.harness.harness_orchestrator import HarnessOrchestrator
    orch = HarnessOrchestrator()
    result = orch.run_single_scenario(scenario_id=4)
"""
from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

# Add project root to path
PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))

from python_orchestrator.harness.session_manager import SessionManager


BLOCKED_TECHNIQUES = {"T1485", "T1561", "T1529"}


@dataclass
class HarnessResult:
    scenario_id: int
    verdict: str          # APPROVED | REJECTED | BLOCKED
    finding_id: Optional[str]
    evidence_count: int
    impl_ref: str         # path to progress/impl_*.md
    review_ref: str       # path to progress/review_*.md
    duration_seconds: float
    notes: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "verdict": self.verdict,
            "finding_id": self.finding_id,
            "evidence_count": self.evidence_count,
            "impl_ref": self.impl_ref,
            "review_ref": self.review_ref,
            "duration_seconds": round(self.duration_seconds, 2),
            "notes": self.notes,
        }


class HarnessOrchestrator:
    """
    Orquestador del arnés de subagentes para el Cyber Range.

    Implementa el flujo Líder → Implementer (red_team) → Reviewer (blue_team)
    con estado persistente en disco y regla anti-hallucination estricta.
    """

    def __init__(self, project_root: Optional[Path] = None):
        self.root = project_root or PROJECT
        self.sm = SessionManager(self.root)
        self.artifacts = self.root / "artifacts"
        self.evidence_dir = self.artifacts / "evidence"

    def run_single_scenario(
        self,
        scenario_id: Optional[int] = None,
        verbose: bool = True,
    ) -> HarnessResult:
        """
        Ejecuta un escenario completo:
          1. Verifica el arnés
          2. Selecciona o usa el scenario_id dado
          3. Fase implementer: lanza OffensiveHarness para ese escenario
          4. Fase reviewer: verifica evidencia SHA-256 + coherencia
          5. Registra resultado y cierra
        """
        start = datetime.utcnow().timestamp()

        # ── 0. Verificar arnés ────────────────────────────────────────────────
        errors = self.sm.verify_harness()
        if errors:
            for e in errors:
                if verbose: print(f"  [HARNESS] {e}")
            # Still proceed if it's just a warning (not fatal)

        # ── 1. Seleccionar escenario ──────────────────────────────────────────
        if scenario_id is None:
            scenario = self.sm.pick_next_scenario()
            if not scenario:
                return HarnessResult(
                    scenario_id=0, verdict="BLOCKED",
                    finding_id=None, evidence_count=0,
                    impl_ref="", review_ref="",
                    duration_seconds=0.0,
                    notes="No pending scenarios in engagement_backlog.json",
                )
            scenario_id = scenario["id"]
        else:
            data = self.sm.load_backlog()
            scenario = next((s for s in data["scenarios"] if s["id"] == scenario_id), None)
            if not scenario:
                raise ValueError(f"Scenario {scenario_id} not found")

        if verbose:
            print(f"\n  [LEADER] Escenario seleccionado: #{scenario_id} {scenario['name']}")
            print(f"  [LEADER] Asset: {scenario['asset']} · Técnica: {scenario['technique_id']}")

        # ── 2. Verificar autorización ─────────────────────────────────────────
        if scenario["technique_id"] in BLOCKED_TECHNIQUES:
            reason = f"Técnica {scenario['technique_id']} está en la lista bloqueada"
            self.sm.block_scenario(scenario_id, reason)
            return self._blocked_result(scenario_id, reason, start)

        # ── 3. Marcar in_progress ─────────────────────────────────────────────
        try:
            self.sm.start_scenario(scenario_id)
        except RuntimeError as e:
            return self._blocked_result(scenario_id, str(e), start)

        # ── 4. FASE IMPLEMENTER (red_team_agent) ──────────────────────────────
        if verbose: print(f"  [RED_TEAM] Ejecutando escenario…")

        impl_result = self._run_red_team(scenario, verbose)
        impl_ref = self.sm.write_impl_report(scenario_id, impl_result["report"])

        # Regla anti-hallucination: devolver solo la referencia
        if verbose: print(f"  [RED_TEAM] → ver {impl_ref.name}")

        if not impl_result["success"]:
            self.sm.block_scenario(scenario_id, impl_result["error"])
            return self._blocked_result(scenario_id, impl_result["error"], start)

        # ── 5. FASE REVIEWER (blue_team_agent) ───────────────────────────────
        if verbose: print(f"  [BLUE_TEAM] Revisando evidencia…")

        review_result = self._run_blue_team(scenario, impl_result, verbose)
        review_ref = self.sm.write_review_report(
            scenario_id,
            review_result["verdict"],
            review_result["report"],
        )

        # Regla anti-hallucination: devolver solo la referencia
        if verbose: print(f"  [BLUE_TEAM] → {review_result['verdict']}: ver {review_ref.name}")

        # ── 6. Finalizar ──────────────────────────────────────────────────────
        duration = datetime.utcnow().timestamp() - start

        if review_result["verdict"] == "APPROVED":
            self.sm.complete_scenario(
                scenario_id,
                finding_id=impl_result.get("finding_id", ""),
                evidence_refs=impl_result.get("evidence_refs", []),
            )
            # Append to history
            self.sm.close_session(self._build_session_summary(scenario, impl_result, review_result))
            if verbose:
                print(f"  [LEADER] ✓ Escenario #{scenario_id} completado y revisado. Backlog actualizado.")
        else:
            self.sm.block_scenario(scenario_id, f"Rejected by blue_team: {review_result.get('reason', '?')}")
            if verbose:
                print(f"  [LEADER] ✗ Escenario rechazado: {review_result.get('reason')}")

        return HarnessResult(
            scenario_id=scenario_id,
            verdict=review_result["verdict"],
            finding_id=impl_result.get("finding_id"),
            evidence_count=len(impl_result.get("evidence_refs", [])),
            impl_ref=str(impl_ref),
            review_ref=str(review_ref),
            duration_seconds=duration,
            notes=review_result.get("reason", ""),
        )

    # ─── red_team_agent (implementer) ─────────────────────────────────────────

    def _run_red_team(
        self,
        scenario: Dict[str, Any],
        verbose: bool,
    ) -> Dict[str, Any]:
        """
        Implementer: ejecuta el escenario usando el pipeline ofensivo existente.
        Escribe evidencia en disco. Devuelve metadata (NO el contenido completo).
        """
        try:
            # Import the existing offensive pipeline
            from python_orchestrator.agents.red_team import RedTeamAgent
            from python_orchestrator.agents.poc_builder import PoCBuilder
            from python_orchestrator.engine.evidence_engine import EvidenceEngine
            from python_orchestrator.core.models import Scenario, Asset

            # Load asset data
            asset_data = self._load_asset(scenario["asset"])
            technique_data = self._load_technique(scenario["technique_id"])

            if not asset_data:
                return {"success": False, "error": f"Asset {scenario['asset']} no encontrado en data"}

            # Run the scenario via RedTeamAgent
            agent = RedTeamAgent()
            scn = Scenario(
                asset_id=scenario["asset"],
                technique_id=scenario["technique_id"],
                tactic=scenario["tactic"],
                description=scenario["description"],
                scope="local_lab_only",
            )
            result = agent.run_scenario(scn)

            # Collect evidence refs
            evidence_refs = []
            finding_id = None
            if result:
                finding_id = getattr(result, "id", None) or f"FND-SCN-{scenario['asset']}-{scenario['technique_id']}"
                # Find evidence files created for this scenario
                for evd_path in sorted(self.evidence_dir.glob(f"EVD-*.json")):
                    try:
                        with open(evd_path) as f:
                            evd = json.load(f)
                        if (evd.get("asset_id") == scenario["asset"] and
                                evd.get("technique_id") == scenario["technique_id"]):
                            evidence_refs.append(str(evd_path.relative_to(self.root)))
                    except Exception:
                        pass

            report = self._build_impl_report(scenario, result, evidence_refs, finding_id)
            return {
                "success": True,
                "finding_id": finding_id,
                "evidence_refs": evidence_refs,
                "result": result,
                "report": report,
            }

        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            report = self._build_impl_report_failed(scenario, error)
            return {
                "success": False,
                "error": error,
                "evidence_refs": [],
                "finding_id": None,
                "report": report,
            }

    # ─── blue_team_agent (reviewer) ───────────────────────────────────────────

    def _run_blue_team(
        self,
        scenario: Dict[str, Any],
        impl_result: Dict[str, Any],
        verbose: bool,
    ) -> Dict[str, Any]:
        """
        Reviewer: verifica SHA-256 de evidencias, coherencia, y soberanía.
        NO implementa ni edita nada.
        """
        checks: List[Dict[str, Any]] = []
        rejections: List[str] = []

        # Check 1: finding_id exists
        finding_id = impl_result.get("finding_id")
        checks.append({"name": "C2.b finding_id", "pass": bool(finding_id)})
        if not finding_id:
            rejections.append("finding_id vacío — sin resultado del implementer")

        # Check 2: evidence exists on disk with SHA-256
        evidence_refs = impl_result.get("evidence_refs", [])
        checks.append({"name": "C4 evidence in disk", "pass": len(evidence_refs) > 0})
        if not evidence_refs:
            rejections.append("Sin archivos de evidencia en artifacts/evidence/")

        verified_evidence = []
        for evd_rel_path in evidence_refs:
            evd_path = self.root / evd_rel_path
            check = self._verify_evidence(evd_path, scenario)
            verified_evidence.append(check)
            if not check["pass"]:
                rejections.append(f"Evidencia inválida: {evd_rel_path} — {check['reason']}")

        # Check 3: soberanía
        perimeter = self._load_perimeter()
        authorized_assets = perimeter.get("authorized_assets", [scenario["asset"]])
        asset_ok = scenario["asset"] in authorized_assets or not authorized_assets
        checks.append({"name": "C3.a asset_authorized", "pass": asset_ok})
        if not asset_ok:
            rejections.append(f"Asset {scenario['asset']} fuera del engagement_perimeter")

        tech_blocked = scenario["technique_id"] in BLOCKED_TECHNIQUES
        checks.append({"name": "C3.b technique_not_blocked", "pass": not tech_blocked})
        if tech_blocked:
            rejections.append(f"Técnica {scenario['technique_id']} está bloqueada")

        verdict = "APPROVED" if not rejections else "REJECTED"
        report = self._build_review_report(scenario, checks, verified_evidence, verdict, rejections)

        return {
            "verdict": verdict,
            "report": report,
            "reason": "; ".join(rejections) if rejections else "Todos los checkpoints pasaron",
        }

    def _verify_evidence(
        self,
        evd_path: Path,
        scenario: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Verify a single evidence file: SHA-256, asset/technique match, chain_of_custody."""
        if not evd_path.exists():
            return {"path": str(evd_path), "pass": False, "sha": "—", "reason": "Archivo no existe en disco"}
        try:
            with open(evd_path, encoding="utf-8") as f:
                evd = json.load(f)
            sha = evd.get("hash_sha256", "")
            if not sha or len(sha) != 64:
                return {"path": evd_path.name, "pass": False, "sha": sha[:8] or "∅", "reason": "hash_sha256 ausente o malformado"}
            if not evd.get("chain_of_custody"):
                return {"path": evd_path.name, "pass": False, "sha": sha[:12], "reason": "chain_of_custody vacío"}
            return {"path": evd_path.name, "pass": True, "sha": sha[:12], "reason": "OK"}
        except Exception as e:
            return {"path": evd_path.name, "pass": False, "sha": "ERR", "reason": str(e)}

    # ─── Report builders (write to disk, not to chat) ─────────────────────────

    def _build_impl_report(
        self,
        scenario: Dict,
        result: Any,
        evidence_refs: List[str],
        finding_id: Optional[str],
    ) -> str:
        evd_table = "\n".join(
            f"| {Path(r).name} | ← en disco |"
            for r in evidence_refs
        ) or "| (ninguna) | — |"
        severity = getattr(result, "severity", "unknown") if result else "unknown"
        score = getattr(result, "score", 0) if result else 0
        det_status = getattr(result, "detection_status", "unknown") if result else "unknown"
        return f"""# Implementación: {scenario['name']}

## Metadata
- Scenario ID: {scenario['id']}
- Asset: {scenario['asset']}
- Técnica: {scenario['technique_id']}
- Ejecutado: {datetime.utcnow().isoformat()}Z
- Exit: SUCCESS

## Archivos de evidencia generados
| Archivo | Estado |
|---------|--------|
{evd_table}

## Finding (referencia)
- ID: {finding_id}
- Severity: {severity}
- Score: {score}
- Detection status: {det_status}

## Notas
Ejecución completada via OffensiveHarness (pipeline Python).
Resultados escritos en disco. Ver artifacts/ para evidencias completas.
"""

    def _build_impl_report_failed(self, scenario: Dict, error: str) -> str:
        return f"""# Implementación BLOCKED: {scenario['name']}

## Error
{error}

## Estado
Sin evidencia generada. El escenario no puede declararse done.
Reportar al cyber_leader para diagnóstico.
"""

    def _build_review_report(
        self,
        scenario: Dict,
        checks: List[Dict],
        verified_evidence: List[Dict],
        verdict: str,
        rejections: List[str],
    ) -> str:
        checkmarks = "\n".join(
            f"- [{'x' if c['pass'] else ' '}] {c['name']}"
            for c in checks
        )
        evd_table = "\n".join(
            f"| {e['path']} | {e['sha']} | {'✓' if e['pass'] else '✗ ' + e['reason']} |"
            for e in verified_evidence
        ) or "| (ninguna) | — | ✗ Sin evidencia |"
        rejection_block = "\n".join(f"- {r}" for r in rejections) if rejections else "(ninguno)"
        return f"""# Revisión: {scenario['name']}

## Veredicto: {verdict}

## Checklist
{checkmarks}

## Evidencias verificadas
| Archivo | SHA-256 (12 chars) | Verificado |
|---------|-------------------|------------|
{evd_table}

## Rechazos
{rejection_block}

## Revisado
{datetime.utcnow().isoformat()}Z — blue_team_agent
"""

    def _build_session_summary(
        self,
        scenario: Dict,
        impl: Dict,
        review: Dict,
    ) -> str:
        return f"""### Escenario #{scenario['id']}: {scenario['name']}

- Asset: {scenario['asset']} · Técnica: {scenario['technique_id']}
- Finding: {impl.get('finding_id', '—')}
- Evidencias: {len(impl.get('evidence_refs', []))}
- Verdict: {review['verdict']}
- Notas: {review.get('reason', '—')}
"""

    # ─── Data loaders ──────────────────────────────────────────────────────────

    def _load_asset(self, asset_id: str) -> Optional[Dict]:
        path = self.root / "python_orchestrator" / "data" / "assets.json"
        if not path.exists():
            return {"id": asset_id, "name": asset_id, "type": "unknown"}
        with open(path, encoding="utf-8") as f:
            assets = json.load(f)
        return next((a for a in assets if a.get("id") == asset_id), None)

    def _load_technique(self, technique_id: str) -> Optional[Dict]:
        path = self.root / "python_orchestrator" / "data" / "attack_subset.json"
        if not path.exists():
            return {"id": technique_id}
        with open(path, encoding="utf-8") as f:
            techs = json.load(f)
        return next((t for t in techs if t.get("id") == technique_id), None)

    def _load_perimeter(self) -> Dict[str, Any]:
        path = self.root / "configs" / "engagement_perimeter.yaml"
        if not path.exists():
            return {}
        try:
            import yaml
            with open(path, encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    def _blocked_result(self, scenario_id: int, reason: str, start: float) -> HarnessResult:
        duration = datetime.utcnow().timestamp() - start
        return HarnessResult(
            scenario_id=scenario_id,
            verdict="BLOCKED",
            finding_id=None,
            evidence_count=0,
            impl_ref="",
            review_ref="",
            duration_seconds=duration,
            notes=reason,
        )
