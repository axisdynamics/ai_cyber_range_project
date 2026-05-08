"""
cicd_trigger.py
===============
Detects relevant changes in code, infrastructure, configuration, or
external exposure, and triggers new controlled offensive runs.

In a real deployment this module would:
  - Subscribe to Git webhooks (new commits, PRs, merges)
  - Monitor infrastructure-as-code diff events (Terraform plan, Helm diff)
  - Poll for new CVEs/advisories matching the asset inventory
  - Watch for exposure changes (new public endpoints, certificate expiry)

In the lab/demo mode it operates on a simulated change manifest,
producing ChangeEvents that the orchestrator can act on.
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from python_orchestrator.core.models import ChangeEvent
from python_orchestrator.core.io import read_json, write_json


# Change type to risk multiplier (determines if full scan is needed)
CHANGE_RISK: Dict[str, float] = {
    "code":       0.70,
    "infra":      0.85,
    "config":     0.60,
    "exposure":   1.00,   # new external surface always triggers full scan
    "model":      0.75,
    "dependency": 0.80,
    "iam":        0.90,
}

FULL_SCAN_THRESHOLD = 0.75


class CICDTrigger:
    """
    Monitors for change events and determines which offensive scenarios
    should be re-executed as a result.

    In demo mode, simulated_changes provides a synthetic change manifest.
    In integration mode, external inputs (git sha, iac plan, etc.) drive events.
    """

    def __init__(self, state_file: Optional[Path] = None):
        self.state_file = state_file or Path("artifacts/cicd_state.json")
        self._last_run_hash: str = self._load_state()
        self._events: List[ChangeEvent] = []

    # ─── Change detection ──────────────────────────────────────────────────

    def detect_changes(
        self,
        assets: List[Dict[str, Any]],
        config: Dict[str, Any],
    ) -> List[ChangeEvent]:
        """
        Simulate change detection across asset inventory and config.
        Returns list of ChangeEvents that should trigger new offensive runs.
        """
        events: List[ChangeEvent] = []

        # Simulate: check if asset inventory hash has changed
        current_hash = self._compute_hash(str(assets))
        if current_hash != self._last_run_hash:
            events.append(ChangeEvent(
                id=f"CHG-{uuid.uuid4().hex[:8].upper()}",
                change_type="infra",
                asset_affected="asset_inventory",
                description="Asset inventory has changed since last offensive run. Re-evaluation needed.",
                detected_at=datetime.utcnow().isoformat(),
                trigger_full_scan=True,
            ))

        # Simulate: check program mode for risky config changes
        if config.get("program", {}).get("allow_external_targets", False):
            events.append(ChangeEvent(
                id=f"CHG-{uuid.uuid4().hex[:8].upper()}",
                change_type="config",
                asset_affected="engagement_config",
                description="External targets flag was enabled — full perimeter re-validation required.",
                detected_at=datetime.utcnow().isoformat(),
                trigger_full_scan=True,
            ))

        # Simulate: synthetic CVE/advisory event for demo
        events.append(ChangeEvent(
            id=f"CHG-{uuid.uuid4().hex[:8].upper()}",
            change_type="dependency",
            asset_affected="all",
            description=(
                "Synthetic advisory: new CVE detected in dependency category 'http_parsing'. "
                "Re-test Initial Access and Execution scenarios."
            ),
            detected_at=datetime.utcnow().isoformat(),
            trigger_full_scan=False,
            triggered_scenarios=["T1190", "T1059"],
        ))

        self._events = events
        return events

    def should_trigger_run(self, events: List[ChangeEvent]) -> bool:
        """Return True if any event requires triggering a new offensive run."""
        return len(events) > 0

    def should_run_full_scan(self, events: List[ChangeEvent]) -> bool:
        """Return True if at least one event requires a full scan."""
        return any(e.trigger_full_scan for e in events)

    def get_triggered_techniques(self, events: List[ChangeEvent]) -> List[str]:
        """Return the union of technique IDs that should be re-tested."""
        techniques: set = set()
        for event in events:
            for t in event.triggered_scenarios:
                techniques.add(t)
        return list(techniques)

    def record_run(self, assets: List[Dict[str, Any]]) -> None:
        """Persist current state after a successful run."""
        self._last_run_hash = self._compute_hash(str(assets))
        self._save_state(self._last_run_hash)

    def format_change_report(self, events: List[ChangeEvent]) -> str:
        """Return a human-readable summary of detected changes."""
        if not events:
            return "No relevant changes detected since last run."
        lines = [f"## Cambios detectados ({len(events)} eventos)", ""]
        for e in events:
            flag = "🔴 FULL SCAN" if e.trigger_full_scan else "🟡 PARTIAL"
            lines.append(f"- [{flag}] {e.change_type.upper()} | {e.asset_affected}")
            lines.append(f"  {e.description}")
            if e.triggered_scenarios:
                lines.append(f"  Técnicas a re-testear: {', '.join(e.triggered_scenarios)}")
        return "\n".join(lines)

    # ─── State persistence ─────────────────────────────────────────────────

    def _load_state(self) -> str:
        try:
            if self.state_file.exists():
                data = read_json(self.state_file)
                return data.get("last_hash", "")
        except Exception:
            pass
        return ""

    def _save_state(self, hash_val: str) -> None:
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            write_json(self.state_file, {
                "last_hash": hash_val,
                "updated_at": datetime.utcnow().isoformat(),
            })
        except Exception:
            pass

    @staticmethod
    def _compute_hash(data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()[:16]
