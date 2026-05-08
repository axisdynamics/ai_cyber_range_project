"""
anomaly_detector.py
===================
Deterministic statistical anomaly detection engine.

Maintains rolling baselines (mean + stddev) for numeric metrics derived
from events. Fires alerts when values deviate significantly (Z-score > threshold).

Metrics tracked:
  - score distribution (risk scores of findings)
  - detection_gap_rate (% findings with gap status)
  - evasion_rate (% controls evaded)
  - findings_per_asset (count per asset ID)
  - severity_escalation (rolling critical/high count)

All computation is deterministic given the same event sequence.
No randomness. No external calls.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple


@dataclass
class AnomalyAlert:
    metric_name: str
    current_value: float
    baseline_mean: float
    baseline_stddev: float
    z_score: float
    severity: str
    description: str
    technique_ids: List[str]
    asset_id: str
    confidence: float
    detected_at: str = ""

    def __post_init__(self):
        if not self.detected_at:
            self.detected_at = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Z-score thresholds → severity
ZSCORE_SEVERITY: List[Tuple[float, str]] = [
    (4.0, "critical"),
    (3.0, "high"),
    (2.5, "medium"),
    (2.0, "low"),
]


def _z_to_severity(z: float) -> str:
    for threshold, sev in ZSCORE_SEVERITY:
        if z >= threshold:
            return sev
    return "low"


class RollingStats:
    """Online mean and variance (Welford's algorithm)."""

    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self._M2 = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self._M2 += delta * delta2

    @property
    def variance(self) -> float:
        return self._M2 / self.n if self.n > 1 else 0.0

    @property
    def stddev(self) -> float:
        return math.sqrt(self.variance)

    def z_score(self, x: float) -> float:
        if self.stddev < 1e-9:
            return 0.0
        return abs(x - self.mean) / self.stddev


class AnomalyDetector:
    """
    Tracks per-metric rolling baselines and detects statistical deviations.

    Call .train(findings) to initialize baselines from historical data,
    then .detect_from_findings(findings) or .detect_from_event(event) for live detection.
    """

    # Minimum samples before anomaly detection activates (avoid false alarms on cold start)
    MIN_SAMPLES = 5
    Z_THRESHOLD = 2.0  # minimum Z-score to fire an alert

    def __init__(self):
        self._baselines: Dict[str, RollingStats] = defaultdict(RollingStats)
        self._per_asset_counts: Dict[str, int] = defaultdict(int)

    def train(self, findings: List[Dict[str, Any]]) -> None:
        """Seed baselines from a batch of historical findings."""
        for f in findings:
            self._ingest_finding_metrics(f)

    def detect_from_findings(self, findings: List[Dict[str, Any]]) -> List[AnomalyAlert]:
        """Detect anomalies across a batch of findings."""
        if not findings:
            return []

        alerts: List[AnomalyAlert] = []

        # Metric 1: score distribution anomaly
        scores = [float(f.get("score", 0)) for f in findings]
        alert = self._check_metric(
            "risk_score_spike",
            max(scores) if scores else 0.0,
            technique_ids=[],
            asset_id="all",
            description=f"Risk score spike: max score {max(scores):.1f} deviates from baseline",
        )
        if alert:
            alerts.append(alert)

        # Metric 2: detection gap rate
        gap_count = sum(1 for f in findings if f.get("detection_status") == "gap")
        gap_rate = gap_count / len(findings) if findings else 0.0
        alert = self._check_metric(
            "detection_gap_rate",
            gap_rate,
            technique_ids=["T1562"],
            asset_id="all",
            description=f"Detection gap rate {gap_rate:.1%} is anomalous vs baseline",
        )
        if alert:
            alerts.append(alert)

        # Metric 3: critical finding count
        crit_count = sum(1 for f in findings if f.get("severity") == "critical")
        alert = self._check_metric(
            "critical_finding_count",
            float(crit_count),
            technique_ids=[],
            asset_id="all",
            description=f"{crit_count} critical findings — statistical anomaly vs baseline",
        )
        if alert:
            alerts.append(alert)

        # Metric 4: per-asset finding density
        asset_counts: Dict[str, int] = defaultdict(int)
        for f in findings:
            asset_counts[f.get("asset", "unknown")] += 1
        for asset_id, count in asset_counts.items():
            alert = self._check_metric(
                f"findings_per_asset_{asset_id}",
                float(count),
                technique_ids=[],
                asset_id=asset_id,
                description=f"Asset '{asset_id}' has {count} findings — anomalous density",
            )
            if alert:
                alerts.append(alert)

        # Update baselines with this batch
        for f in findings:
            self._ingest_finding_metrics(f)

        return alerts

    def detect_from_evasion_results(
        self,
        evasion_results: List[Dict[str, Any]],
    ) -> List[AnomalyAlert]:
        """Detect anomalous evasion rates."""
        if not evasion_results:
            return []
        evaded = sum(1 for e in evasion_results if e.get("evaded"))
        rate = evaded / len(evasion_results)
        alert = self._check_metric(
            "evasion_rate",
            rate,
            technique_ids=["T1562"],
            asset_id="all",
            description=f"Evasion rate {rate:.1%} ({evaded}/{len(evasion_results)} controls bypassed)",
        )
        return [alert] if alert else []

    def _check_metric(
        self,
        metric_name: str,
        value: float,
        technique_ids: List[str],
        asset_id: str,
        description: str,
    ) -> Optional[AnomalyAlert]:
        stats = self._baselines[metric_name]
        stats.update(value)

        if stats.n < self.MIN_SAMPLES:
            return None

        z = stats.z_score(value)
        if z < self.Z_THRESHOLD:
            return None

        severity = _z_to_severity(z)
        confidence = min(0.5 + z * 0.1, 0.95)

        return AnomalyAlert(
            metric_name=metric_name,
            current_value=round(value, 4),
            baseline_mean=round(stats.mean, 4),
            baseline_stddev=round(stats.stddev, 4),
            z_score=round(z, 2),
            severity=severity,
            description=description,
            technique_ids=technique_ids,
            asset_id=asset_id,
            confidence=round(confidence, 2),
        )

    def _ingest_finding_metrics(self, f: Dict[str, Any]) -> None:
        score = float(f.get("score", 0))
        self._baselines["risk_score_history"].update(score)

        is_gap = 1.0 if f.get("detection_status") == "gap" else 0.0
        self._baselines["gap_history"].update(is_gap)

        is_crit = 1.0 if f.get("severity") == "critical" else 0.0
        self._baselines["critical_history"].update(is_crit)

    @property
    def tracked_metrics(self) -> List[str]:
        return list(self._baselines.keys())
