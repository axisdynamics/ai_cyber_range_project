"""
session_manager.py
==================
Gestiona los archivos de estado del arnés en progress/:
  - progress/current.md       (estado de la sesión activa)
  - progress/history.md       (bitácora append-only)
  - progress/impl_<id>.md     (resultado del red_team_agent)
  - progress/review_<id>.md   (resultado del blue_team_agent)

También gestiona engagement_backlog.json (una feature a la vez).

Principio clave: el estado vive en disco, no en memoria ni en chat.
Si el proceso muere a la mitad, el estado sobrevive y puede recuperarse.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any


class SessionManager:
    """
    Gestiona el ciclo de vida de una sesión de engagement.

    Usage:
        sm = SessionManager(project_root)
        scenario = sm.pick_next_scenario()
        sm.start_scenario(scenario['id'])
        sm.write_impl_report(scenario['id'], report_content)
        sm.write_review_report(scenario['id'], verdict, content)
        sm.complete_scenario(scenario['id'])
        sm.close_session(summary)
    """

    def __init__(self, project_root: Optional[Path] = None):
        self.root = project_root or Path(__file__).resolve().parents[2]
        self.backlog_path = self.root / "engagement_backlog.json"
        self.progress_dir = self.root / "progress"
        self.progress_dir.mkdir(exist_ok=True)
        self.current_path = self.progress_dir / "current.md"
        self.history_path = self.progress_dir / "history.md"

    # ─── Backlog management ───────────────────────────────────────────────────

    def load_backlog(self) -> Dict[str, Any]:
        if not self.backlog_path.exists():
            return {"scenarios": []}
        with open(self.backlog_path, encoding="utf-8") as f:
            return json.load(f)

    def save_backlog(self, data: Dict[str, Any]) -> None:
        data["_meta"]["last_updated"] = datetime.utcnow().isoformat() + "Z"
        with open(self.backlog_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def pick_next_scenario(self) -> Optional[Dict[str, Any]]:
        """Return the lowest-id pending scenario, or None if none exist."""
        data = self.load_backlog()
        pending = [s for s in data["scenarios"] if s.get("status") == "pending"]
        if not pending:
            return None
        return sorted(pending, key=lambda s: s["id"])[0]

    def count_in_progress(self) -> int:
        data = self.load_backlog()
        return sum(1 for s in data["scenarios"] if s.get("status") == "in_progress")

    def assert_single_in_progress(self) -> None:
        """Enforce the one-at-a-time rule. Raises if violated."""
        count = self.count_in_progress()
        if count > 1:
            raise RuntimeError(
                f"Harness violation: {count} scenarios in_progress. "
                f"Only 1 allowed at a time. Run ./init.sh to diagnose."
            )

    def start_scenario(self, scenario_id: int) -> Dict[str, Any]:
        """Mark scenario as in_progress. Enforce single-active rule."""
        self.assert_single_in_progress()
        data = self.load_backlog()
        scenario = None
        for s in data["scenarios"]:
            if s["id"] == scenario_id:
                if s["status"] != "pending":
                    raise ValueError(f"Scenario {scenario_id} is not pending (status={s['status']})")
                s["status"] = "in_progress"
                s["started_at"] = datetime.utcnow().isoformat() + "Z"
                scenario = s
                break
        if not scenario:
            raise ValueError(f"Scenario {scenario_id} not found in backlog")
        self.save_backlog(data)
        self._update_current_md(scenario)
        return scenario

    def complete_scenario(
        self,
        scenario_id: int,
        finding_id: str,
        evidence_refs: List[str],
    ) -> None:
        """Mark scenario as done (only after blue_team approval)."""
        data = self.load_backlog()
        for s in data["scenarios"]:
            if s["id"] == scenario_id:
                s["status"] = "done"
                s["completed_at"] = datetime.utcnow().isoformat() + "Z"
                s["finding_id"] = finding_id
                s["evidence_refs"] = evidence_refs
                s["impl_ref"] = f"progress/impl_scenario_{scenario_id}.md"
                s["review_ref"] = f"progress/review_scenario_{scenario_id}.md"
                break
        self.save_backlog(data)

    def block_scenario(self, scenario_id: int, reason: str) -> None:
        data = self.load_backlog()
        for s in data["scenarios"]:
            if s["id"] == scenario_id:
                s["status"] = "blocked"
                s["notes"] = f"BLOCKED: {reason}"
                break
        self.save_backlog(data)

    # ─── Progress file management ─────────────────────────────────────────────

    def _update_current_md(self, scenario: Dict[str, Any]) -> None:
        content = f"""# progress/current.md — Sesión activa

## Estado: IN PROGRESS

- Scenario ID: {scenario['id']}
- Nombre: {scenario['name']}
- Asset: {scenario['asset']}
- Técnica: {scenario['technique_id']} — {scenario['tactic']}
- Prioridad: {scenario['priority']}
- Inicio: {scenario.get('started_at', datetime.utcnow().isoformat())}
- Agente asignado: red_team_agent

## Plan

1. [ ] red_team_agent ejecuta escenario
2. [ ] Evidencia generada en artifacts/evidence/
3. [ ] progress/impl_scenario_{scenario['id']}.md escrito
4. [ ] blue_team_agent revisa
5. [ ] progress/review_scenario_{scenario['id']}.md escrito
6. [ ] APPROVED → engagement_backlog.json (status: done)

## Bloqueos / notas

(ninguno)
"""
        self.current_path.write_text(content, encoding="utf-8")

    def write_impl_report(self, scenario_id: int, content: str) -> Path:
        """Write the red_team_agent implementation report to disk."""
        path = self.progress_dir / f"impl_scenario_{scenario_id}.md"
        path.write_text(content, encoding="utf-8")
        return path

    def write_review_report(
        self,
        scenario_id: int,
        verdict: str,   # "APPROVED" | "REJECTED"
        content: str,
    ) -> Path:
        """Write the blue_team_agent review report to disk."""
        path = self.progress_dir / f"review_scenario_{scenario_id}.md"
        path.write_text(content, encoding="utf-8")
        return path

    def read_impl_report(self, scenario_id: int) -> Optional[str]:
        path = self.progress_dir / f"impl_scenario_{scenario_id}.md"
        return path.read_text(encoding="utf-8") if path.exists() else None

    def reset_current_md(self) -> None:
        """Reset current.md to idle template."""
        content = """# progress/current.md — Sesión activa

## Estado: IDLE

Sin sesión activa. Ejecuta ./init.sh y selecciona un escenario de engagement_backlog.json.
"""
        self.current_path.write_text(content, encoding="utf-8")

    def close_session(self, summary: str) -> None:
        """Append session summary to history.md and reset current.md."""
        timestamp = datetime.utcnow().isoformat()
        entry = f"\n---\n\n## Sesión {timestamp}\n\n{summary}\n"
        with open(self.history_path, "a", encoding="utf-8") as f:
            f.write(entry)
        self.reset_current_md()

    # ─── Harness verification ─────────────────────────────────────────────────

    def verify_harness(self) -> List[str]:
        """
        Run harness verification checks. Returns list of error messages.
        Empty list = harness is clean.
        """
        errors: List[str] = []
        data = self.load_backlog()
        scenarios = data.get("scenarios", [])

        # C2: single in_progress
        in_progress = [s for s in scenarios if s.get("status") == "in_progress"]
        if len(in_progress) > 1:
            ids = [s["id"] for s in in_progress]
            errors.append(f"C2 FAIL: {len(in_progress)} scenarios in_progress ({ids}). Max: 1.")

        # C2: done scenarios must have evidence_refs
        for s in scenarios:
            if s.get("status") == "done":
                if not s.get("evidence_refs"):
                    errors.append(f"C2 FAIL: scenario {s['id']} is done but has no evidence_refs.")
                if not s.get("finding_id"):
                    errors.append(f"C2 FAIL: scenario {s['id']} is done but has no finding_id.")

        # C1: progress/current.md exists
        if not self.current_path.exists():
            errors.append("C1 FAIL: progress/current.md missing.")

        return errors
