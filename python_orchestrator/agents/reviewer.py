from __future__ import annotations
from typing import Dict, Any


class ReviewerAgent:
    """
    Quality gating for findings: validates evidence, deduplicates,
    and assigns detection status.
    """

    def __init__(self):
        self._seen_signatures: set = set()

    def review(
        self,
        evidence: Dict[str, Any],
        detection_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Returns a review result dict with:
          - accepted: bool
          - detection_status: 'detected' | 'partial' | 'gap'
          - quality_score: 0.0-1.0
          - rejection_reason: str (if not accepted)
        """
        # Deduplication: reject identical (asset, technique, reproducible) combos
        sig = f"{evidence.get('asset')}:{evidence.get('technique_id')}:{evidence.get('reproducible')}"
        if sig in self._seen_signatures:
            return {
                "accepted": False,
                "detection_status": detection_result.get("status", "gap"),
                "quality_score": 0.0,
                "rejection_reason": "Duplicate finding — already reviewed in this run.",
            }
        self._seen_signatures.add(sig)

        # Reject if no reproducibility and no signals
        reproducible    = evidence.get("reproducible", False)
        has_signals     = len(detection_result.get("signals", [])) > 0
        has_output      = bool(evidence.get("stdout") or evidence.get("summary"))
        detection_status = detection_result.get("status", "gap")

        # Quality score
        quality = 0.0
        if reproducible:       quality += 0.5
        if has_signals:        quality += 0.3
        if has_output:         quality += 0.2
        quality = min(1.0, quality)

        if not reproducible and not has_signals:
            return {
                "accepted": False,
                "detection_status": detection_status,
                "quality_score": quality,
                "rejection_reason": "Insufficient evidence: not reproducible and no detection signals.",
            }

        return {
            "accepted": True,
            "detection_status": detection_status,
            "quality_score": quality,
            "rejection_reason": None,
        }
