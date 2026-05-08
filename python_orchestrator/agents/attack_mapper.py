"""
attack_mapper.py
================
Maps assets and techniques to authorized offensive scenarios.
Extended to support full ATT&CK kill chain coverage and
per-asset-type scenario prioritization.
"""
from __future__ import annotations

from typing import List, Dict

from python_orchestrator.core.models import Asset, Technique, Scenario


# Which asset types are meaningful targets for each tactic
TACTIC_ASSET_MAP: Dict[str, List[str]] = {
    "Reconnaissance":        ["api_gateway", "web_app", "local_service", "cloud_storage"],
    "Initial Access":        ["api_gateway", "web_app", "local_service", "cloud_storage", "iam_role"],
    "Execution":             ["local_service", "pipeline", "notebook", "api_gateway"],
    "Persistence":           ["pipeline", "local_service", "iam_role"],
    "Privilege Escalation":  ["iam_role", "local_service", "pipeline"],
    "Defense Evasion":       ["telemetry_fixture", "local_service", "pipeline"],
    "Credential Access":     ["secrets_store", "api_gateway", "local_service", "iam_role"],
    "Discovery":             ["asset_inventory", "local_service", "api_gateway"],
    "Lateral Movement":      ["local_service", "api_gateway", "pipeline"],
    "Collection":            ["asset_inventory", "cloud_storage", "local_service"],
    "Exfiltration":          ["cloud_storage", "api_gateway", "telemetry_fixture"],
    "Impact":                ["local_service", "pipeline", "cloud_storage"],
}


class AttackMapper:
    """
    Builds a comprehensive list of offensive scenarios from the
    asset graph and technique catalog. Respects the tactic-to-asset
    affinity map and assigns priorities.
    """

    def build_scenarios(
        self,
        assets: List[Asset],
        techniques: List[Technique],
    ) -> List[Scenario]:
        scenarios: List[Scenario] = []
        exposure_priority = {"external": 1, "internal": 2, "local_only": 3, "local_file": 4}

        for asset in assets:
            for tech in techniques:
                affine_types = TACTIC_ASSET_MAP.get(tech.tactic, [])
                if asset.type not in affine_types:
                    continue

                # Priority: lower = more urgent
                base_prio = exposure_priority.get(asset.exposure, 3)
                crit_bonus = max(0, 3 - (asset.criticality // 2))  # high criticality reduces priority number
                priority = max(1, min(5, base_prio + crit_bonus - 1))

                scenarios.append(Scenario(
                    id=f"SCN-{asset.id}-{tech.id}",
                    asset_id=asset.id,
                    technique_id=tech.id,
                    objective=(
                        f"Validar exposición del activo '{asset.name}' "
                        f"({asset.type}, {asset.exposure}) "
                        f"contra {tech.name} [{tech.tactic}]"
                    ),
                    authorized=True,
                    tactic=tech.tactic,
                    priority=priority,
                ))

        return sorted(scenarios, key=lambda s: (s.priority, s.asset_id))
