"""
rule_engine.py
==============
Deterministic pattern-based detection engine — operates like a simplified YARA/Sigma
rule matcher, but in pure Python with no external dependencies.

Each rule defines:
  - patterns    : list of regex patterns (AND logic within a rule)
  - any_of      : list of patterns (OR logic — at least one must match)
  - fields      : specific event fields to inspect
  - severity    : low | medium | high | critical
  - technique_ids: associated MITRE ATT&CK technique IDs
  - confidence  : 0.0-1.0 base confidence when rule fires

The engine is completely deterministic — same input always produces same output.
No randomness, no LLM calls, no external network.
"""
from __future__ import annotations

import re
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional


@dataclass
class DetectionRule:
    id: str
    name: str
    description: str
    severity: str
    technique_ids: List[str]
    tactic: str
    confidence: float           # 0.0-1.0
    patterns: List[str]         # ALL must match (AND)
    any_of: List[str]           # AT LEAST ONE must match (OR)
    fields: List[str]           # event fields to search in (empty = all fields)
    false_positive_notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    severity: str
    technique_ids: List[str]
    tactic: str
    confidence: float
    matched_patterns: List[str]
    matched_field: str
    event_snapshot: Dict[str, Any]
    detected_at: str = ""

    def __post_init__(self):
        if not self.detected_at:
            self.detected_at = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── Built-in rule catalog ────────────────────────────────────────────────────

BUILTIN_RULES: List[Dict[str, Any]] = [
    {
        "id": "RULE-001",
        "name": "Oversized Input / Buffer Overflow Attempt",
        "description": "Detects inputs significantly larger than normal, indicative of buffer overflow probing.",
        "severity": "high",
        "technique_ids": ["T1190"],
        "tactic": "Initial Access",
        "confidence": 0.85,
        "patterns": [],
        "any_of": [r"A{64,}", r"\\x41{64,}", r"payload_size=[0-9]{4,}", r"input_validation_warning"],
        "fields": ["stdout", "stderr", "summary", "content"],
        "false_positive_notes": "Large test payloads in legitimate load tests may trigger this.",
    },
    {
        "id": "RULE-002",
        "name": "Shell Metacharacter Injection",
        "description": "Detects shell metacharacters in inputs that could indicate command injection.",
        "severity": "critical",
        "technique_ids": ["T1059"],
        "tactic": "Execution",
        "confidence": 0.90,
        "patterns": [],
        "any_of": [r";\s*(id|whoami|cat\s+/etc)", r"\|\s*(bash|sh|cmd)", r"`[^`]+`", r"\$\(.*\)"],
        "fields": ["stdout", "content", "summary"],
        "false_positive_notes": "Legitimate shell scripts in automation may contain these patterns.",
    },
    {
        "id": "RULE-003",
        "name": "Synthetic Credential Token Detected",
        "description": "Detects use of synthetic credential tokens in evidence.",
        "severity": "high",
        "technique_ids": ["T1078", "T1003"],
        "tactic": "Credential Access",
        "confidence": 0.75,
        "patterns": [],
        "any_of": [r"SYNTHETIC_VALID_TOKEN", r"synthetic_credential", r"credential_check", r"LSASS"],
        "fields": ["stdout", "content", "summary"],
        "false_positive_notes": "These patterns are lab-specific and should not appear in production logs.",
    },
    {
        "id": "RULE-004",
        "name": "Telemetry Gap Event",
        "description": "Detects events explicitly marked as undetected — indicates coverage gap.",
        "severity": "medium",
        "technique_ids": ["T1562"],
        "tactic": "Defense Evasion",
        "confidence": 0.95,
        "patterns": ['"detected"'],
        "any_of": [r'"detected":\s*false', r"detected.*false", r"gap_events_found=[1-9]"],
        "fields": ["content", "stdout", "summary"],
        "false_positive_notes": "Only applies to synthetic telemetry fixtures.",
    },
    {
        "id": "RULE-005",
        "name": "Privilege Escalation Simulation Detected",
        "description": "Detects privilege escalation scenario execution in evidence.",
        "severity": "critical",
        "technique_ids": ["T1548"],
        "tactic": "Privilege Escalation",
        "confidence": 0.80,
        "patterns": [],
        "any_of": [
            r"SYNTHETIC_PRIVILEGE_TEST",
            r"privilege.*escal",
            r"escalat.*privilege",
            r"sudo.*NOPASSWD",
            r"elevation.*control",
        ],
        "fields": ["stdout", "content", "summary"],
        "false_positive_notes": "Only applies within lab scope.",
    },
    {
        "id": "RULE-006",
        "name": "Data Exfiltration Marker",
        "description": "Detects synthetic exfiltration markers in evidence records.",
        "severity": "critical",
        "technique_ids": ["T1041"],
        "tactic": "Exfiltration",
        "confidence": 0.90,
        "patterns": [],
        "any_of": [
            r"SYNTHETIC_EXFIL",
            r"exfil.*channel",
            r"exfiltrat",
            r"Simulated POST to https://",
            r"Simulated DNS query.*attacker",
        ],
        "fields": ["stdout", "content", "summary"],
        "false_positive_notes": "All exfiltration patterns are synthetic in this environment.",
    },
    {
        "id": "RULE-007",
        "name": "Lateral Movement Simulation",
        "description": "Detects lateral movement simulation evidence.",
        "severity": "high",
        "technique_ids": ["T1021"],
        "tactic": "Lateral Movement",
        "confidence": 0.78,
        "patterns": [],
        "any_of": [
            r"SYNTHETIC_PIVOT",
            r"lateral.*movement",
            r"pivot.*asset",
            r"remote.*service.*simulat",
        ],
        "fields": ["stdout", "content", "summary"],
        "false_positive_notes": "Only applicable to fixture-based scenarios.",
    },
    {
        "id": "RULE-008",
        "name": "Scheduled Task Persistence Attempt",
        "description": "Detects persistence mechanism evidence via scheduled tasks.",
        "severity": "high",
        "technique_ids": ["T1053"],
        "tactic": "Persistence",
        "confidence": 0.82,
        "patterns": [],
        "any_of": [
            r"SYNTHETIC_CRON",
            r"cron.*entry",
            r"scheduled.*task.*creat",
            r"crontab",
            r"at-job",
        ],
        "fields": ["stdout", "content", "summary"],
        "false_positive_notes": "Legitimate cron changes may match.",
    },
    {
        "id": "RULE-009",
        "name": "Sensitive Data File Access",
        "description": "Detects access to sensitive classified data files.",
        "severity": "medium",
        "technique_ids": ["T1005"],
        "tactic": "Collection",
        "confidence": 0.88,
        "patterns": [],
        "any_of": [
            r"file_accessible=True",
            r"data_classification.*confidential",
            r"assets\.json.*accessible",
            r"accesible sin autenticaci",
        ],
        "fields": ["stdout", "content", "summary"],
        "false_positive_notes": "Lab fixtures; check real data access in production.",
    },
    {
        "id": "RULE-010",
        "name": "High-Criticality Asset Under Attack",
        "description": "Cross-asset rule: detects any evidence against criticality-4/5 assets.",
        "severity": "critical",
        "technique_ids": [],
        "tactic": "Any",
        "confidence": 0.70,
        "patterns": [],
        "any_of": [r"iam_role", r"secrets_store", r"criticality.*[45]"],
        "fields": ["asset", "asset_id", "content", "stdout"],
        "false_positive_notes": "Applies to any technique against privileged assets.",
    },
    {
        "id": "RULE-011",
        "name": "DoS / Resource Exhaustion Simulation",
        "description": "Detects DoS simulation evidence.",
        "severity": "high",
        "technique_ids": ["T1499"],
        "tactic": "Impact",
        "confidence": 0.80,
        "patterns": [],
        "any_of": [
            r"SYNTHETIC_LOAD_SPIKE",
            r"load.*spike",
            r"resource.*exhaust",
            r"denial.*service",
        ],
        "fields": ["stdout", "content", "summary"],
        "false_positive_notes": "Load testing tools may trigger.",
    },
    {
        "id": "RULE-012",
        "name": "Discovery / Enumeration Activity",
        "description": "Detects system enumeration and discovery activity.",
        "severity": "medium",
        "technique_ids": ["T1082"],
        "tactic": "Discovery",
        "confidence": 0.72,
        "patterns": [],
        "any_of": [
            r"enumerate_fixtures",
            r"system.*info",
            r"uname.*-a",
            r"systeminfo",
            r"discovery.*asset",
        ],
        "fields": ["stdout", "content", "summary"],
        "false_positive_notes": "Monitoring and inventory tools may trigger.",
    },
]


class RuleEngine:
    """
    Deterministic rule-based detection engine.

    Rules are matched against event dictionaries using compiled regex patterns.
    The engine is fully deterministic — no external calls, no randomness.
    """

    def __init__(self):
        self._rules: List[DetectionRule] = []
        self._compiled: Dict[str, Dict[str, List[re.Pattern]]] = {}
        self._load_builtin_rules()

    def _load_builtin_rules(self) -> None:
        for r in BUILTIN_RULES:
            rule = DetectionRule(**r)
            self._rules.append(rule)
            self._compiled[rule.id] = {
                "patterns": [re.compile(p, re.IGNORECASE | re.DOTALL) for p in rule.patterns],
                "any_of":   [re.compile(p, re.IGNORECASE | re.DOTALL) for p in rule.any_of],
            }

    def load_rules_from_file(self, path: Path) -> None:
        """Load additional rules from a JSON file."""
        if not path.exists():
            return
        with open(path, encoding="utf-8") as f:
            rules_data = json.load(f)
        for r in rules_data.get("rules", []):
            rule = DetectionRule(**r)
            self._rules.append(rule)
            self._compiled[rule.id] = {
                "patterns": [re.compile(p, re.IGNORECASE | re.DOTALL) for p in rule.patterns],
                "any_of":   [re.compile(p, re.IGNORECASE | re.DOTALL) for p in rule.any_of],
            }

    def add_rule(self, rule: DetectionRule) -> None:
        """Dynamically add a rule (e.g., generated by LLM)."""
        self._rules.append(rule)
        self._compiled[rule.id] = {
            "patterns": [re.compile(p, re.IGNORECASE | re.DOTALL) for p in rule.patterns],
            "any_of":   [re.compile(p, re.IGNORECASE | re.DOTALL) for p in rule.any_of],
        }

    def match_event(self, event: Dict[str, Any]) -> List[RuleMatch]:
        """Match a single event against all loaded rules."""
        matches: List[RuleMatch] = []
        for rule in self._rules:
            result = self._test_rule(rule, event)
            if result:
                matches.append(result)
        return matches

    def match_all(self, events: List[Dict[str, Any]]) -> List[RuleMatch]:
        """Match all events and return all rule matches."""
        all_matches: List[RuleMatch] = []
        for event in events:
            all_matches.extend(self.match_event(event))
        return all_matches

    def _test_rule(self, rule: DetectionRule, event: Dict[str, Any]) -> Optional[RuleMatch]:
        compiled = self._compiled[rule.id]
        search_str = self._build_search_string(event, rule.fields)

        # All 'patterns' must match (AND logic)
        matched_patterns: List[str] = []
        for pat in compiled["patterns"]:
            m = pat.search(search_str)
            if not m:
                return None   # AND failed
            matched_patterns.append(pat.pattern)

        # At least one of 'any_of' must match (OR logic)
        if compiled["any_of"]:
            or_matched = False
            for pat in compiled["any_of"]:
                m = pat.search(search_str)
                if m:
                    matched_patterns.append(pat.pattern)
                    or_matched = True
                    break
            if not or_matched:
                return None   # OR failed

        # Rule fires
        matched_field = self._find_matched_field(event, rule.fields, matched_patterns)
        return RuleMatch(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            technique_ids=rule.technique_ids,
            tactic=rule.tactic,
            confidence=rule.confidence,
            matched_patterns=matched_patterns,
            matched_field=matched_field,
            event_snapshot=self._safe_snapshot(event),
        )

    @staticmethod
    def _build_search_string(event: Dict[str, Any], fields: List[str]) -> str:
        """Build a single string from the relevant event fields."""
        if fields:
            parts = []
            for f in fields:
                val = event.get(f, "")
                if isinstance(val, dict):
                    parts.append(json.dumps(val))
                elif val is not None:
                    parts.append(str(val))
            return " ".join(parts)
        return json.dumps(event, ensure_ascii=False)

    @staticmethod
    def _find_matched_field(event: Dict[str, Any], fields: List[str], patterns: List[str]) -> str:
        for f in (fields or list(event.keys())):
            val = str(event.get(f, ""))
            for p in patterns:
                try:
                    if re.search(p, val, re.IGNORECASE):
                        return f
                except re.error:
                    pass
        return "content"

    @staticmethod
    def _safe_snapshot(event: Dict[str, Any]) -> Dict[str, Any]:
        """Return a truncated snapshot safe for serialization."""
        snap = {}
        for k, v in event.items():
            if isinstance(v, str) and len(v) > 200:
                snap[k] = v[:200] + "…"
            elif isinstance(v, (str, int, float, bool, type(None))):
                snap[k] = v
            elif isinstance(v, list):
                snap[k] = f"[{len(v)} items]"
            else:
                snap[k] = str(v)[:100]
        return snap

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def rules(self) -> List[DetectionRule]:
        return list(self._rules)
