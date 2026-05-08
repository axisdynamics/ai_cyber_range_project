from __future__ import annotations
from typing import Dict, List


class RiskScoringEngine:
    def __init__(self, weights: Dict[str, float]):
        self.weights = weights or {
            "severity": 0.40,
            "asset_criticality": 0.25,
            "detectability_gap": 0.20,
            "reproducibility": 0.15,
        }

    def score(
        self,
        asset_criticality: int,
        detected: bool,
        reproducible: bool,
        severity: str,
        evasion_rate: float = 0.0,
    ) -> float:
        sev_map = {"low": 0.25, "medium": 0.5, "high": 0.8, "critical": 1.0}
        severity_value    = sev_map.get(severity, 0.25)
        detectability_gap = (1.0 - evasion_rate) if not detected else max(0.0, evasion_rate)
        reproducibility   = 1.0 if reproducible else 0.0
        criticality       = min(max(asset_criticality, 1), 5) / 5.0

        raw = (
            self.weights.get("severity", 0.4)            * severity_value    +
            self.weights.get("asset_criticality", 0.25)  * criticality       +
            self.weights.get("detectability_gap", 0.2)   * detectability_gap +
            self.weights.get("reproducibility", 0.15)    * reproducibility
        )
        return round(100 * raw, 2)

    def classify_severity(
        self,
        technique_id: str,
        detection_status: str,
        asset_criticality: int,
    ) -> str:
        """Auto-classify severity from technique + detection + criticality."""
        high_risk_techniques = {"T1190", "T1003", "T1078", "T1548", "T1041", "T1486"}
        medium_risk_techniques = {"T1059", "T1021", "T1005", "T1499"}

        if technique_id in high_risk_techniques:
            base = "high"
        elif technique_id in medium_risk_techniques:
            base = "medium"
        else:
            base = "low"

        # Elevate if detection gap and high criticality
        if detection_status == "gap" and asset_criticality >= 4:
            if base == "high":
                return "critical"
            if base == "medium":
                return "high"
        if detection_status == "gap":
            if base == "low":
                return "medium"
        return base
