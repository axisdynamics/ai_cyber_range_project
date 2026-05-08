"""
sigma_correlator.py
===================
Deterministic multi-event correlation engine, inspired by Sigma rule logic.

Supports three correlation modes:
  1. count    — fire when N events matching a filter appear within a time window
  2. sequence — fire when events appear in a specific ordered sequence
  3. threshold — fire when a numeric field exceeds a threshold

All correlation is purely deterministic — no ML, no LLM.
Events are bucketed by time window; old buckets are discarded.

Designed to be fed individual events as they arrive, or batched.
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Deque


@dataclass
class CorrelationRule:
    id: str
    name: str
    description: str
    severity: str
    technique_ids: List[str]
    mode: str                    # count | sequence | threshold
    filter_field: str            # event field to inspect
    filter_pattern: str          # regex to match filter_field
    count_threshold: int = 2     # for mode=count: how many events to fire
    time_window_seconds: int = 60
    threshold_field: str = ""    # for mode=threshold: numeric field
    threshold_value: float = 0.0
    sequence_patterns: List[str] = field(default_factory=list)  # ordered regexes for mode=sequence
    confidence: float = 0.80
    tactic: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CorrelationAlert:
    rule_id: str
    rule_name: str
    severity: str
    technique_ids: List[str]
    tactic: str
    confidence: float
    mode: str
    event_count: int
    correlated_events: List[Dict[str, Any]]
    trigger_description: str
    detected_at: str = ""

    def __post_init__(self):
        if not self.detected_at:
            self.detected_at = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── Built-in correlation rules ───────────────────────────────────────────────

BUILTIN_CORRELATION_RULES: List[Dict[str, Any]] = [
    {
        "id": "COR-001",
        "name": "Multiple High-Severity Findings on Same Asset",
        "description": "Fires when 3+ high/critical findings target the same asset within the analysis window.",
        "severity": "critical",
        "technique_ids": [],
        "mode": "count",
        "filter_field": "severity",
        "filter_pattern": r"^(high|critical)$",
        "count_threshold": 3,
        "time_window_seconds": 3600,
        "confidence": 0.92,
        "tactic": "Multiple Tactics",
    },
    {
        "id": "COR-002",
        "name": "Initial Access → Credential Access Kill Chain",
        "description": "Detects progression from initial access to credential dumping (partial kill chain).",
        "severity": "critical",
        "technique_ids": ["T1190", "T1003", "T1078"],
        "mode": "sequence",
        "filter_field": "technique_id",
        "filter_pattern": r"T(1190|1078)",
        "count_threshold": 1,
        "time_window_seconds": 300,
        "sequence_patterns": [r"T(1190|1078)", r"T(1059|1082)", r"T(1003|1548)"],
        "confidence": 0.95,
        "tactic": "Kill Chain Progression",
    },
    {
        "id": "COR-003",
        "name": "Defense Evasion Followed by Exfiltration",
        "description": "Detects defense evasion then exfiltration — classic APT pattern.",
        "severity": "critical",
        "technique_ids": ["T1562", "T1041"],
        "mode": "sequence",
        "filter_field": "technique_id",
        "filter_pattern": r"T1562",
        "count_threshold": 1,
        "time_window_seconds": 300,
        "sequence_patterns": [r"T1562", r"T1041"],
        "confidence": 0.90,
        "tactic": "Kill Chain Progression",
    },
    {
        "id": "COR-004",
        "name": "Multiple Detection Gaps on Critical Assets",
        "description": "Fires when 2+ detection gaps are found on criticality-5 assets.",
        "severity": "critical",
        "technique_ids": [],
        "mode": "count",
        "filter_field": "detection_status",
        "filter_pattern": r"^gap$",
        "count_threshold": 2,
        "time_window_seconds": 3600,
        "confidence": 0.88,
        "tactic": "Defense Evasion",
    },
    {
        "id": "COR-005",
        "name": "Credential Theft → Lateral Movement Chain",
        "description": "Detects credential access followed by lateral movement.",
        "severity": "high",
        "technique_ids": ["T1003", "T1078", "T1021"],
        "mode": "sequence",
        "filter_field": "technique_id",
        "filter_pattern": r"T(1003|1078)",
        "count_threshold": 1,
        "time_window_seconds": 300,
        "sequence_patterns": [r"T(1003|1078)", r"T1021"],
        "confidence": 0.87,
        "tactic": "Kill Chain Progression",
    },
    {
        "id": "COR-006",
        "name": "Privilege Escalation on IAM/Secrets Assets",
        "description": "Privilege escalation against IAM roles or secrets stores — very high risk.",
        "severity": "critical",
        "technique_ids": ["T1548"],
        "mode": "count",
        "filter_field": "technique_id",
        "filter_pattern": r"T1548",
        "count_threshold": 1,
        "time_window_seconds": 3600,
        "confidence": 0.93,
        "tactic": "Privilege Escalation",
    },
    {
        "id": "COR-007",
        "name": "Broad Attack Surface Coverage",
        "description": "Fires when 5+ different techniques are tested against the same asset.",
        "severity": "high",
        "technique_ids": [],
        "mode": "count",
        "filter_field": "asset",
        "filter_pattern": r".+",
        "count_threshold": 5,
        "time_window_seconds": 3600,
        "confidence": 0.75,
        "tactic": "Multiple Tactics",
    },
]


class SigmaCorrelator:
    """
    Deterministic multi-event correlation engine.

    Maintains a rolling event buffer per rule and fires alerts
    when correlation thresholds are reached.
    """

    def __init__(self):
        self._rules: List[CorrelationRule] = []
        self._event_buffers: Dict[str, Deque] = {}  # rule_id → deque of (timestamp, event)
        self._sequence_state: Dict[str, int] = {}    # rule_id → next expected sequence index
        self._load_builtin_rules()

    def _load_builtin_rules(self) -> None:
        for r in BUILTIN_CORRELATION_RULES:
            rule = CorrelationRule(**r)
            self._rules.append(rule)
            self._event_buffers[rule.id] = deque()
            self._sequence_state[rule.id] = 0

    def process_events(self, events: List[Dict[str, Any]]) -> List[CorrelationAlert]:
        """Process a batch of events and return any triggered alerts."""
        all_alerts: List[CorrelationAlert] = []
        now = datetime.utcnow()

        for event in events:
            for rule in self._rules:
                # Expire old events from buffer
                cutoff = now - timedelta(seconds=rule.time_window_seconds)
                buf = self._event_buffers[rule.id]
                while buf and buf[0][0] < cutoff:
                    buf.popleft()

                # Check if this event matches the rule filter
                field_val = str(event.get(rule.filter_field, ""))
                if not re.search(rule.filter_pattern, field_val, re.IGNORECASE):
                    continue

                # Add to buffer
                buf.append((now, event))

                # Evaluate based on mode
                alert = None
                if rule.mode == "count":
                    alert = self._eval_count(rule, list(buf))
                elif rule.mode == "sequence":
                    alert = self._eval_sequence(rule, event, now)
                elif rule.mode == "threshold":
                    alert = self._eval_threshold(rule, event)

                if alert:
                    all_alerts.append(alert)
                    # Reset buffer and sequence after firing to avoid duplicate alerts
                    self._event_buffers[rule.id].clear()
                    self._sequence_state[rule.id] = 0

        return all_alerts

    def _eval_count(
        self,
        rule: CorrelationRule,
        buffered: List[tuple],
    ) -> Optional[CorrelationAlert]:
        if len(buffered) < rule.count_threshold:
            return None
        events = [e for _, e in buffered]
        return CorrelationAlert(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            technique_ids=rule.technique_ids,
            tactic=rule.tactic,
            confidence=rule.confidence,
            mode="count",
            event_count=len(buffered),
            correlated_events=events[:5],
            trigger_description=(
                f"Rule '{rule.name}' fired: {len(buffered)} matching events "
                f"(threshold={rule.count_threshold}) in {rule.time_window_seconds}s window."
            ),
        )

    def _eval_sequence(
        self,
        rule: CorrelationRule,
        event: Dict[str, Any],
        now: datetime,
    ) -> Optional[CorrelationAlert]:
        """Check if this event advances the sequence state machine."""
        if not rule.sequence_patterns:
            return None

        idx = self._sequence_state.get(rule.id, 0)
        if idx >= len(rule.sequence_patterns):
            self._sequence_state[rule.id] = 0
            idx = 0

        pattern = rule.sequence_patterns[idx]
        field_val = str(event.get(rule.filter_field, ""))

        if re.search(pattern, field_val, re.IGNORECASE):
            self._sequence_state[rule.id] = idx + 1
            buf = self._event_buffers[rule.id]
            buf.append((now, event))

            if self._sequence_state[rule.id] == len(rule.sequence_patterns):
                events = [e for _, e in buf]
                return CorrelationAlert(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    technique_ids=rule.technique_ids,
                    tactic=rule.tactic,
                    confidence=rule.confidence,
                    mode="sequence",
                    event_count=len(events),
                    correlated_events=events,
                    trigger_description=(
                        f"Kill chain sequence completed: {' → '.join(rule.sequence_patterns)}. "
                        f"All {len(rule.sequence_patterns)} steps observed."
                    ),
                )
        return None

    def _eval_threshold(
        self,
        rule: CorrelationRule,
        event: Dict[str, Any],
    ) -> Optional[CorrelationAlert]:
        try:
            val = float(event.get(rule.threshold_field, 0))
        except (TypeError, ValueError):
            return None
        if val > rule.threshold_value:
            return CorrelationAlert(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                technique_ids=rule.technique_ids,
                tactic=rule.tactic,
                confidence=rule.confidence,
                mode="threshold",
                event_count=1,
                correlated_events=[event],
                trigger_description=(
                    f"Threshold exceeded: {rule.threshold_field}={val} > {rule.threshold_value}"
                ),
            )
        return None

    @property
    def rule_count(self) -> int:
        return len(self._rules)
