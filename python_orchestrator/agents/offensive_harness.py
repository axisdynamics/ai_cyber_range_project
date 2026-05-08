"""
offensive_harness.py
====================
Agentive harness that drives the controlled offensive program.

Responsibilities:
  - Define and validate the engagement perimeter
  - Drive attack route discovery across authorized assets
  - Generate attack hypotheses for each (asset, technique) pair
  - Coordinate the AttackChainSimulator, EvasionTester, and PoCBuilder
  - Produce a consolidated OffensiveRunResult for the pipeline
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Dict, Any

from python_orchestrator.core.models import (
    Asset, Technique, Scenario, EngagementPerimeter,
    AttackHypothesis, OffensiveRunResult, Finding,
    PoCArtifact, EvasionResult, AttackChain,
)
from python_orchestrator.agents.attack_chain import AttackChainSimulator
from python_orchestrator.agents.evasion_tester import EvasionTester
from python_orchestrator.agents.poc_builder import PoCBuilder


class OffensiveHarness:
    """
    Central harness for the 'ofensiva controlada con IA' program.

    The harness respects the EngagementPerimeter at every step —
    no action is executed against an asset or technique that has
    not been explicitly authorized.
    """

    def __init__(
        self,
        perimeter: EngagementPerimeter,
        config: Dict[str, Any],
    ):
        self.perimeter = perimeter
        self.config = config
        self.chain_sim = AttackChainSimulator(max_depth=perimeter.max_chain_depth)
        self.evasion_tester = EvasionTester()
        self.poc_builder = PoCBuilder()
        self._run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"

    # ─── Perimeter validation ──────────────────────────────────────────────

    def validate_perimeter(self, assets: List[Asset], techniques: List[Technique]) -> None:
        """Fail-fast check: every asset/technique referenced must be authorized."""
        for asset in assets:
            if not self.perimeter.is_asset_authorized(asset.id):
                raise ValueError(
                    f"Asset '{asset.id}' is NOT in the authorized engagement perimeter. "
                    "Update configs/engagement_perimeter.yaml to include it."
                )
        for tech in techniques:
            if not self.perimeter.is_technique_authorized(tech.id):
                raise ValueError(
                    f"Technique '{tech.id}' is NOT authorized for this engagement. "
                    "Review rules of engagement before proceeding."
                )

    # ─── Attack route discovery ────────────────────────────────────────────

    def discover_attack_routes(
        self,
        assets: List[Asset],
        techniques: List[Technique],
    ) -> List[Scenario]:
        """
        Enumerate all viable (asset × technique) combinations that are:
          1. Within the engagement perimeter
          2. Plausible given the asset type and technique tactic
        Returns a prioritized list of Scenarios.
        """
        # Exposure risk multiplier: external > internal > local
        exposure_rank = {"external": 1, "internal": 2, "local_only": 3, "local_file": 3}
        # Asset types that match each tactic category
        tactic_asset_affinity: Dict[str, List[str]] = {
            "Initial Access":    ["api_gateway", "web_app", "local_service", "cloud_storage"],
            "Execution":         ["local_service", "pipeline", "notebook", "api_gateway"],
            "Persistence":       ["pipeline", "local_service", "iam_role"],
            "Privilege Escalation": ["iam_role", "local_service", "pipeline"],
            "Defense Evasion":   ["telemetry_fixture", "siem", "local_service", "pipeline"],
            "Credential Access": ["secrets_store", "api_gateway", "local_service"],
            "Discovery":         ["asset_inventory", "local_service", "api_gateway"],
            "Lateral Movement":  ["local_service", "api_gateway", "pipeline"],
            "Collection":        ["asset_inventory", "cloud_storage", "local_service"],
            "Exfiltration":      ["cloud_storage", "api_gateway", "telemetry_fixture"],
            "Impact":            ["local_service", "pipeline", "cloud_storage"],
        }

        routes: List[Scenario] = []
        for asset in assets:
            if not self.perimeter.is_asset_authorized(asset.id):
                continue
            for tech in techniques:
                if not self.perimeter.is_technique_authorized(tech.id):
                    continue
                affine_types = tactic_asset_affinity.get(tech.tactic, [])
                if asset.type not in affine_types:
                    continue
                # Priority = exposure_rank × (6 - criticality)  → lower = higher priority
                priority = exposure_rank.get(asset.exposure, 3) + (6 - asset.criticality)
                routes.append(Scenario(
                    id=f"SCN-{asset.id}-{tech.id}",
                    asset_id=asset.id,
                    technique_id=tech.id,
                    objective=(
                        f"Validar exposición del activo '{asset.name}' "
                        f"({asset.exposure}) contra {tech.name} [{tech.tactic}]"
                    ),
                    authorized=True,
                    tactic=tech.tactic,
                    priority=min(priority, 5),
                ))

        # Sort by priority ascending (1 = most urgent)
        return sorted(routes, key=lambda s: s.priority)

    # ─── Hypothesis generation ─────────────────────────────────────────────

    def generate_hypothesis(self, scenario: Scenario, asset: Asset) -> AttackHypothesis:
        """
        Generate an attack hypothesis for a given scenario.
        The hypothesis describes the assumed entry point, goal,
        and expected control gaps.
        """
        exposure_entry = {
            "external":    "public endpoint / internet-facing surface",
            "internal":    "internal network service or shared resource",
            "local_only":  "local process or loopback interface",
            "local_file":  "local filesystem path",
        }
        tactic_goals = {
            "Initial Access":       "gain initial foothold on the asset",
            "Execution":            "execute arbitrary code or commands",
            "Persistence":          "maintain access across restarts or re-deployments",
            "Privilege Escalation": "elevate privileges to a higher trust level",
            "Defense Evasion":      "disable or degrade defensive telemetry",
            "Credential Access":    "obtain valid credentials or secrets",
            "Discovery":            "enumerate systems, users, and sensitive data",
            "Lateral Movement":     "pivot from this asset to adjacent systems",
            "Collection":           "access and stage sensitive data",
            "Exfiltration":         "exfiltrate data outside the authorized boundary",
            "Impact":               "disrupt availability or integrity of the asset",
        }
        assumed_gaps = []
        if asset.criticality >= 4:
            assumed_gaps.append("High-criticality asset may lack compensating controls.")
        if asset.exposure == "external":
            assumed_gaps.append("External exposure increases attack surface significantly.")
        if asset.exposure in ("internal", "external"):
            assumed_gaps.append("Network-accessible asset; lateral movement paths possible.")
        if scenario.tactic == "Defense Evasion":
            assumed_gaps.append("Telemetry coverage may not extend to all sub-components.")

        return AttackHypothesis(
            id=f"HYP-{scenario.id}",
            asset_id=asset.id,
            technique_id=scenario.technique_id,
            entry_point=exposure_entry.get(asset.exposure, "unknown surface"),
            attack_goal=tactic_goals.get(scenario.tactic, "achieve offensive objective"),
            assumed_control_gaps=assumed_gaps or ["No specific gaps assumed; validate coverage."],
            confidence=min(0.4 + asset.criticality * 0.1 + (0.2 if asset.exposure == "external" else 0.0), 1.0),
            generated_at=datetime.utcnow().isoformat(),
        )

    # ─── Full offensive cycle ──────────────────────────────────────────────

    def run_offensive_cycle(
        self,
        assets: List[Asset],
        techniques: List[Technique],
        findings: List[Finding],
    ) -> OffensiveRunResult:
        """
        Execute the full controlled offensive cycle:
          1. Route discovery
          2. Hypothesis generation per route
          3. Kill chain simulation (if authorized)
          4. Evasion testing (if authorized)
          5. PoC construction for reproducible findings
          6. Aggregate results
        """
        started_at = datetime.utcnow().isoformat()
        asset_by_id = {a.id: a for a in assets}
        tech_by_id  = {t.id: t for t in techniques}

        routes = self.discover_attack_routes(assets, techniques)

        chains: List[AttackChain] = []
        evasion_results: List[EvasionResult] = []
        pocs: List[PoCArtifact] = []
        hypotheses: List[AttackHypothesis] = []

        for route in routes:
            asset = asset_by_id.get(route.asset_id)
            tech  = tech_by_id.get(route.technique_id)
            if not asset or not tech:
                continue

            # Hypothesis
            hyp = self.generate_hypothesis(route, asset)
            hypotheses.append(hyp)

            # Kill chain simulation
            if self.perimeter.allow_chain_simulation:
                chain = self.chain_sim.simulate(route, asset, tech, techniques)
                chains.append(chain)

            # Evasion testing
            if self.perimeter.allow_evasion_tests:
                ev = self.evasion_tester.test(route, asset)
                evasion_results.extend(ev)

        # PoC for each finding that is reproducible and has no PoC yet
        for finding in findings:
            if finding.reproducible and not finding.poc_id:
                asset = asset_by_id.get(finding.asset)
                tech  = tech_by_id.get(finding.technique_id)
                if asset and tech:
                    poc = self.poc_builder.build(finding, asset, tech)
                    pocs.append(poc)
                    finding.poc_id = poc.id

        # Aggregate statistics
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        total_authorized = len(routes)
        tested = len(findings)
        coverage_pct = round(100 * tested / total_authorized, 1) if total_authorized else 0.0

        gap_findings = [f for f in findings if f.detection_status == "gap"]
        detection_gap_pct = round(100 * len(gap_findings) / tested, 1) if tested else 0.0

        top_findings = sorted(
            [f.to_dict() for f in findings],
            key=lambda x: x.get("score", 0),
            reverse=True,
        )[:10]

        finished_at = datetime.utcnow().isoformat()

        return OffensiveRunResult(
            run_id=self._run_id,
            engagement_id=self.perimeter.engagement_id,
            started_at=started_at,
            finished_at=finished_at,
            hypotheses_generated=len(hypotheses),
            chains_simulated=len(chains),
            evasion_tests_run=len(evasion_results),
            pocs_built=len(pocs),
            findings_count=len(findings),
            critical_count=sev_counts.get("critical", 0),
            high_count=sev_counts.get("high", 0),
            medium_count=sev_counts.get("medium", 0),
            low_count=sev_counts.get("low", 0),
            top_findings=top_findings,
            remediation_tickets=[],   # filled in by RemediationEngine
            coverage_pct=coverage_pct,
            detection_gap_pct=detection_gap_pct,
        )

    @property
    def run_id(self) -> str:
        return self._run_id
