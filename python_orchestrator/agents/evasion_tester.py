"""
evasion_tester.py
=================
Tests whether a simulated attack step would evade specific defensive controls.

All tests are purely synthetic — no real traffic is generated and no
real controls are modified. Results represent estimated detection gaps
based on control coverage data and technique characteristics.

Controls tested per tactic:
  Initial Access   → WAF, IDS/IPS, API Gateway, anomaly detection
  Execution        → EDR, command audit, script block logging
  Defense Evasion  → SIEM correlation rules, agent health monitoring
  Exfiltration     → DLP, egress filtering, DNS monitoring
  (etc.)
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Dict, Tuple

from python_orchestrator.core.models import Asset, Scenario, EvasionResult


# Control catalogue: maps tactic → list of (control_name, base_evasion_probability)
# base_evasion_probability = probability the control has a gap (0.0 = perfect detection)
CONTROLS_BY_TACTIC: Dict[str, List[Tuple[str, float]]] = {
    "Reconnaissance":        [("Network IDS", 0.45), ("Threat Intel Feed", 0.60)],
    "Initial Access":        [("WAF", 0.30), ("API Rate Limiting", 0.25), ("IDS/IPS", 0.40)],
    "Execution":             [("EDR Agent", 0.20), ("Command Audit Log", 0.15), ("Script Block Logging", 0.30)],
    "Persistence":           [("CSPM Config Monitor", 0.50), ("FIM (File Integrity)", 0.35)],
    "Privilege Escalation":  [("PAM Solution", 0.30), ("Sudo Audit Log", 0.25)],
    "Defense Evasion":       [("SIEM Correlation Rules", 0.55), ("Agent Health Monitor", 0.60)],
    "Credential Access":     [("Vault / Secrets Manager", 0.25), ("Memory Scanning EDR", 0.40)],
    "Discovery":             [("Honeypot / Canary Token", 0.65), ("User Behavior Analytics", 0.50)],
    "Lateral Movement":      [("Network Segmentation", 0.35), ("East-West IDS", 0.45)],
    "Collection":            [("DLP Endpoint Agent", 0.40), ("Data Classification Tags", 0.50)],
    "Exfiltration":          [("Egress Filtering", 0.35), ("DNS Monitoring", 0.45), ("DLP Network", 0.40)],
    "Impact":                [("Backup Integrity Check", 0.60), ("Availability Monitoring", 0.20)],
}

# Exposure multiplier: external targets are harder to detect early
EXPOSURE_GAP_BONUS: Dict[str, float] = {
    "external":   0.10,
    "internal":   0.05,
    "local_only": 0.00,
    "local_file": 0.00,
}

# Criticality: higher criticality assets *should* have better controls
# but often don't — we model a slight improvement
CRITICALITY_GAP_REDUCTION: Dict[int, float] = {
    1: 0.00, 2: 0.00, 3: 0.05, 4: 0.10, 5: 0.15,
}


class EvasionTester:
    """
    Produces synthetic evasion test results for a scenario.

    For each applicable control in the scenario's tactic, calculates
    whether an attack at this exposure level would likely evade it.
    """

    def test(
        self,
        scenario: Scenario,
        asset: Asset,
    ) -> List[EvasionResult]:
        """
        Run evasion tests for all controls relevant to the scenario's tactic.
        Returns a list of EvasionResult (one per control tested).
        """
        tactic = scenario.tactic
        controls = CONTROLS_BY_TACTIC.get(tactic, [])
        if not controls:
            # Generic fallback
            controls = [("Generic SIEM Rule", 0.50)]

        results: List[EvasionResult] = []
        exposure_bonus = EXPOSURE_GAP_BONUS.get(asset.exposure, 0.0)
        crit_reduction = CRITICALITY_GAP_REDUCTION.get(asset.criticality, 0.0)

        for control_name, base_prob in controls:
            effective_prob = min(1.0, max(0.0, base_prob + exposure_bonus - crit_reduction))
            # Deterministic per (scenario, control) — avoids random noise in reports
            # Use a hash-based pseudo-random to keep results reproducible
            seed = hash(f"{scenario.id}:{control_name}") % 1000
            evaded = (seed / 1000.0) < effective_prob

            latency_ms: int | None = None
            evasion_method = "N/A"
            notes_parts = []

            if evaded:
                # Simulate typical evasion patterns
                if tactic == "Defense Evasion":
                    evasion_method = "Telemetry gap — control not generating events for this action"
                    notes_parts.append("Control may not have a detection rule for this technique variant.")
                elif tactic == "Exfiltration":
                    evasion_method = "Low-and-slow exfil below threshold triggers"
                    notes_parts.append("Volume-based threshold may not catch small repeated transfers.")
                elif tactic == "Initial Access":
                    evasion_method = "Unusual but syntactically valid request bypassed signature-based control"
                    notes_parts.append("WAF/IDS rule may be based on known-bad signatures, not anomaly.")
                else:
                    evasion_method = f"Control '{control_name}' has insufficient coverage for {scenario.technique_id}"
                    notes_parts.append("Recommend reviewing detection rule coverage for this tactic.")
            else:
                latency_ms = 200 + (seed % 800)  # Simulated detection latency 200-1000ms
                evasion_method = "Detected by control"
                notes_parts.append(
                    f"Control '{control_name}' would detect this activity "
                    f"(estimated latency ~{latency_ms}ms)."
                )

            if asset.exposure == "external" and evaded:
                notes_parts.append("External exposure amplifies risk of this gap.")

            results.append(EvasionResult(
                scenario_id=scenario.id,
                technique_id=scenario.technique_id,
                control_tested=control_name,
                evaded=evaded,
                detection_latency_ms=latency_ms,
                evasion_method=evasion_method,
                notes=" ".join(notes_parts),
                tested_at=datetime.utcnow().isoformat(),
            ))

        return results
