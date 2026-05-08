"""
cyber_range.scoring.engine
===========================
Deterministic scoring engine for findings.

All percentage metrics are clamped to [0, 100].
All formulas are documented and tested.

Formulas:
---------
risk_score(finding) =
    0.40 * severity_weight
  + 0.25 * asset_criticality_norm
  + 0.20 * detectability_gap
  + 0.15 * reproducibility_weight
  (clamped to [0, 100])

coverage_pct =
    (techniques_with_at_least_one_finding / total_techniques_in_scope) * 100
    Clamped to [0, 100].
    Rationale: cannot exceed 100% — having multiple findings per technique
    does not increase coverage above 100%.

detection_gap_pct =
    (findings_with_status_gap / total_findings) * 100
    Clamped to [0, 100].

confidence_score(finding) =
    base confidence from reproducibility and evidence presence
    Clamped to [0.0, 1.0].
"""
from __future__ import annotations

from typing import Dict, List

_SEVERITY_WEIGHT: Dict[str, float] = {
    "informational": 0.05,
    "low":           0.25,
    "medium":        0.50,
    "high":          0.80,
    "critical":      1.00,
}

_SEVERITY_VALID = set(_SEVERITY_WEIGHT.keys())


def clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    """Clamp value to [lo, hi]. Used for all percentage outputs."""
    return max(lo, min(hi, value))


def clamp01(value: float) -> float:
    return clamp(value, 0.0, 1.0)


def risk_score(
    severity: str,
    asset_criticality: int,
    detected: bool,
    reproducible: bool,
    evasion_rate: float = 0.0,
    weights: Dict[str, float] | None = None,
) -> float:
    """
    Compute a 0–100 risk score for a finding.

    Args:
        severity:         one of informational/low/medium/high/critical
        asset_criticality: 1–5 (5 = most critical)
        detected:         True if the detection fired
        reproducible:     True if the finding can be reproduced on demand
        evasion_rate:     fraction of controls evaded (0.0–1.0)
        weights:          optional override of the default weight dictionary

    Returns:
        float in [0, 100]
    """
    w = weights or {"severity": 0.40, "asset_criticality": 0.25,
                    "detectability_gap": 0.20, "reproducibility": 0.15}

    sev = _SEVERITY_WEIGHT.get(severity.lower() if severity else "", 0.25)
    crit = clamp01((min(max(int(asset_criticality), 1), 5)) / 5.0)
    gap = (1.0 - clamp01(evasion_rate)) if not detected else max(0.0, clamp01(evasion_rate))
    repro = 1.0 if reproducible else 0.0

    raw = (
        w.get("severity", 0.40)            * sev   +
        w.get("asset_criticality", 0.25)   * crit  +
        w.get("detectability_gap", 0.20)   * gap   +
        w.get("reproducibility", 0.15)     * repro
    )
    return round(clamp(raw * 100.0), 1)


def coverage_pct(
    finding_technique_ids: List[str],
    total_techniques_in_scope: List[str],
) -> float:
    """
    Percentage of in-scope techniques that have at least one finding.

    Always ≤ 100%. Cannot exceed scope — having N findings for T1078
    does not count as N% coverage.
    """
    if not total_techniques_in_scope:
        return 0.0
    covered = len(set(finding_technique_ids) & set(total_techniques_in_scope))
    pct = (covered / len(total_techniques_in_scope)) * 100.0
    return round(clamp(pct), 1)


def detection_gap_pct(findings: List[Dict]) -> float:
    """
    Percentage of findings where detection_status == 'gap'.
    Always in [0, 100].
    """
    if not findings:
        return 0.0
    gaps = sum(1 for f in findings if f.get("detection_status") == "gap")
    return round(clamp((gaps / len(findings)) * 100.0), 1)


def confidence_score(
    reproducible: bool,
    has_evidence: bool,
    evidence_verified: bool = False,
) -> float:
    """
    Confidence 0.0–1.0 for a finding.

    Base:          0.40 (finding exists)
    + 0.30 if evidence present
    + 0.20 if evidence verified (hash check passed)
    + 0.10 if reproducible
    """
    score = 0.40
    if has_evidence:     score += 0.30
    if evidence_verified: score += 0.20
    if reproducible:     score += 0.10
    return round(clamp01(score), 2)


def remediation_priority(severity: str, risk: float, detection_gap: bool) -> int:
    """
    Return remediation priority 1–4 (1 = most urgent).

    1 = critical or (high + gap)
    2 = high, or (medium + gap)
    3 = medium
    4 = low / informational
    """
    s = severity.lower() if severity else "low"
    if s == "critical":                              return 1
    if s == "high" and detection_gap:               return 1
    if s == "high":                                  return 2
    if s == "medium" and detection_gap:             return 2
    if s == "medium":                               return 3
    return 4


def severity_counts(findings: List[Dict]) -> Dict[str, int]:
    counts = {s: 0 for s in _SEVERITY_VALID}
    for f in findings:
        sev = f.get("severity", "informational").lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["informational"] += 1
    return counts
