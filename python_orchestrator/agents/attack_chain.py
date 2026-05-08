"""
attack_chain.py
===============
Simulates multi-stage kill chains based on MITRE ATT&CK tactics,
building a realistic adversary progression for a given scenario.

The chain follows the standard ATT&CK tactic ordering:
  Recon → Resource Dev → Initial Access → Execution → Persistence
  → Priv Esc → Defense Evasion → Credential Access → Discovery
  → Lateral Movement → Collection → Exfil → Impact

Each chain is bounded by max_depth and by which techniques are present
in the active technique catalog.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Dict, Any

from python_orchestrator.core.models import (
    Asset, Technique, Scenario,
    AttackChain, AttackChainStep,
)


# MITRE tactic ordering (realistic adversary progression)
TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Impact",
]

# Technique-to-action templates
TECHNIQUE_ACTIONS: Dict[str, Dict[str, str]] = {
    "T1595": {
        "action": "Perform active scanning of the target's exposed network surface",
        "artifact": "Port scan results, service banner captures",
    },
    "T1589": {
        "action": "Harvest employee/identity information from public sources",
        "artifact": "Email addresses, usernames, org chart data",
    },
    "T1190": {
        "action": "Exploit a vulnerability in a public-facing application or API",
        "artifact": "HTTP 500 errors, application crash logs, WAF alerts",
    },
    "T1059": {
        "action": "Execute commands via scripting interpreter (bash, python, PowerShell)",
        "artifact": "Shell process spawn events, command history entries",
    },
    "T1053": {
        "action": "Schedule a task or cron job to maintain persistence",
        "artifact": "New crontab entries, at-job events, scheduled task logs",
    },
    "T1078": {
        "action": "Use valid credentials to access a system or service",
        "artifact": "Authentication logs, successful login from unexpected IP",
    },
    "T1548": {
        "action": "Abuse elevation control mechanism to gain higher privileges",
        "artifact": "Sudo/SUID invocations, UAC bypass events",
    },
    "T1562": {
        "action": "Disable or tamper with defensive sensors (SIEM rules, EDR agents)",
        "artifact": "Agent stop events, missing telemetry gaps, rule modifications",
    },
    "T1003": {
        "action": "Dump credentials from OS memory or credential stores",
        "artifact": "LSASS memory access, /etc/shadow reads, secrets manager calls",
    },
    "T1082": {
        "action": "Enumerate system information: OS, architecture, installed software",
        "artifact": "Unusual system calls, recon tool execution (systeminfo, uname)",
    },
    "T1021": {
        "action": "Use remote services to move laterally to adjacent systems",
        "artifact": "SSH/RDP/WinRM login events from non-standard origins",
    },
    "T1005": {
        "action": "Access and stage sensitive data from the local system",
        "artifact": "Mass file read events, unusual data access patterns",
    },
    "T1041": {
        "action": "Exfiltrate staged data over an established C2 or HTTPS channel",
        "artifact": "Large outbound transfers, DNS queries to unknown domains",
    },
    "T1486": {
        "action": "Encrypt or destroy data to impact availability",
        "artifact": "Mass file modification events, ransom notes",
    },
    "T1499": {
        "action": "Perform endpoint or service denial-of-service via resource exhaustion",
        "artifact": "CPU/memory spike, connection exhaustion alerts",
    },
}

# Fallback action template
DEFAULT_ACTION = {
    "action": "Execute technique-specific adversarial action within authorized scope",
    "artifact": "Technique-specific telemetry and log evidence",
}

# How each tactic maps to which technique IDs are relevant
TACTIC_TECHNIQUES: Dict[str, List[str]] = {
    "Reconnaissance":        ["T1595", "T1589"],
    "Resource Development":  [],
    "Initial Access":        ["T1190", "T1078"],
    "Execution":             ["T1059"],
    "Persistence":           ["T1053", "T1078"],
    "Privilege Escalation":  ["T1548", "T1078"],
    "Defense Evasion":       ["T1562"],
    "Credential Access":     ["T1003"],
    "Discovery":             ["T1082", "T1005"],
    "Lateral Movement":      ["T1021"],
    "Collection":            ["T1005"],
    "Exfiltration":          ["T1041"],
    "Impact":                ["T1486", "T1499"],
}


class AttackChainSimulator:
    """
    Builds synthetic multi-stage kill chains for a scenario.

    The simulator uses the available technique catalog to pick relevant
    steps, then assembles them in MITRE tactic order up to max_depth.
    All chains are purely synthetic — no real actions are taken.
    """

    def __init__(self, max_depth: int = 6):
        self.max_depth = max_depth

    def simulate(
        self,
        scenario: Scenario,
        asset: Asset,
        primary_tech: Technique,
        all_techniques: List[Technique],
    ) -> AttackChain:
        """
        Build a kill chain starting from the scenario's entry technique
        and progressing through subsequent tactics.
        """
        tech_by_id = {t.id: t for t in all_techniques}
        available_ids = {t.id for t in all_techniques}

        # Determine starting tactic index
        start_tactic = primary_tech.tactic
        try:
            start_idx = TACTIC_ORDER.index(start_tactic)
        except ValueError:
            start_idx = 2  # default to Initial Access

        steps: List[AttackChainStep] = []
        prev_step_no: List[int] = []

        for tactic in TACTIC_ORDER[start_idx:]:
            if len(steps) >= self.max_depth:
                break

            candidate_ids = TACTIC_TECHNIQUES.get(tactic, [])
            selected_id: str | None = None

            # Prefer techniques that are in the active catalog
            for cid in candidate_ids:
                if cid in available_ids:
                    selected_id = cid
                    break
            # Fall back to the first candidate even if not in catalog
            if not selected_id and candidate_ids:
                selected_id = candidate_ids[0]
            # As last resort, use primary technique for the start tactic
            if not selected_id and tactic == start_tactic:
                selected_id = primary_tech.id

            if not selected_id:
                continue

            tech_obj = tech_by_id.get(selected_id)
            tech_name = tech_obj.name if tech_obj else selected_id

            tmpl = TECHNIQUE_ACTIONS.get(selected_id, DEFAULT_ACTION)
            step_no = len(steps) + 1

            steps.append(AttackChainStep(
                step_no=step_no,
                tactic=tactic,
                technique_id=selected_id,
                technique_name=tech_name,
                action=self._contextualize(tmpl["action"], asset),
                expected_artifact=tmpl["artifact"],
                depends_on=list(prev_step_no),
            ))
            prev_step_no = [step_no]

        chain_id = f"CHN-{scenario.id}-{uuid.uuid4().hex[:6].upper()}"
        return AttackChain(
            id=chain_id,
            asset_id=scenario.asset_id,
            chain_name=f"{primary_tech.tactic} → Impact chain on '{asset.name}'",
            objective=(
                f"Simulate full adversary progression from {primary_tech.tactic} "
                f"to end-game against '{asset.name}' ({asset.exposure} exposure, "
                f"criticality {asset.criticality}/5)"
            ),
            steps=steps,
            simulated_at=datetime.utcnow().isoformat(),
        )

    @staticmethod
    def _contextualize(action_template: str, asset: Asset) -> str:
        """Inject asset context into the action description."""
        return (
            f"[Target: {asset.name} | {asset.type} | {asset.exposure}] "
            + action_template
        )
