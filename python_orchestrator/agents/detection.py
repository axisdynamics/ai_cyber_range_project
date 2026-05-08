"""
detection.py
============
Blue team detection validation agent.

Validates synthetic telemetry coverage, computes detection metrics
(MTTD, coverage %, alert quality), and flags detection gaps.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Dict, Any


class DetectionAgent:
    """Validates blue team telemetry coverage for a given asset."""

    def __init__(self, logs_path: Path):
        self.logs_path = logs_path
        self._all_events: List[Dict[str, Any]] = self._load_logs()

    def _load_logs(self) -> List[Dict[str, Any]]:
        if not self.logs_path.exists():
            return []
        events = []
        for line in self.logs_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return events

    def validate(self, asset_id: str) -> Dict[str, Any]:
        """Return detection status for a specific asset."""
        signals = [e for e in self._all_events if e.get("asset") == asset_id and e.get("detected") is True]
        gaps    = [e for e in self._all_events if e.get("asset") == asset_id and e.get("detected") is False]

        total = len(signals) + len(gaps)
        coverage_pct = round(100 * len(signals) / total, 1) if total > 0 else 0.0

        # Simulated MTTD (mean time to detect) in seconds
        mttd_seconds = 45 if signals else None

        return {
            "detected": len(signals) > 0,
            "signals": signals,
            "gap_events": gaps,
            "status": "detected" if signals else ("partial" if gaps else "gap"),
            "coverage_pct": coverage_pct,
            "mttd_seconds": mttd_seconds,
            "alert_count": len(signals),
        }

    def compute_overall_coverage(self, asset_ids: List[str]) -> Dict[str, Any]:
        """Compute aggregate detection coverage across all assets."""
        results = {aid: self.validate(aid) for aid in asset_ids}
        total_assets = len(asset_ids)
        detected_assets = sum(1 for r in results.values() if r["detected"])
        gap_assets = sum(1 for r in results.values() if r["status"] == "gap")

        return {
            "total_assets": total_assets,
            "detected_assets": detected_assets,
            "gap_assets": gap_assets,
            "overall_coverage_pct": round(100 * detected_assets / total_assets, 1) if total_assets else 0.0,
            "per_asset": results,
        }
