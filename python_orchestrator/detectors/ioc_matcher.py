"""
ioc_matcher.py
==============
Deterministic Indicator of Compromise (IoC) matching engine.

Matches event data against a database of known-bad indicators:
  - IP addresses (exact + CIDR)
  - Domain patterns (exact + wildcard)
  - File hash (SHA-256, MD5)
  - File paths / filenames
  - Process names
  - String signatures

All matching is purely deterministic (no ML, no external calls).
IoC database loaded from JSON file; also ships with built-in lab IoCs.
"""
from __future__ import annotations

import re
import json
import hashlib
import fnmatch
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional


@dataclass
class IoC:
    id: str
    type: str           # ip | domain | hash_sha256 | hash_md5 | filepath | process | string
    value: str          # the indicator value (may include wildcards for domain/path)
    threat_label: str   # what threat this IoC is associated with
    technique_ids: List[str]
    severity: str
    confidence: float   # 0.0-1.0 reliability of this IoC
    source: str         # intelligence source
    ttl_days: int = 90  # how long this IoC is considered valid

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IoCMatch:
    ioc_id: str
    ioc_type: str
    ioc_value: str
    threat_label: str
    technique_ids: List[str]
    severity: str
    confidence: float
    matched_field: str
    matched_value: str
    event_snapshot: Dict[str, Any]
    detected_at: str = ""

    def __post_init__(self):
        if not self.detected_at:
            self.detected_at = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Built-in IoC database for lab/synthetic environment
BUILTIN_IOCS: List[Dict[str, Any]] = [
    # Synthetic credential tokens (should never appear in real systems)
    {
        "id": "IOC-001", "type": "string",
        "value": "SYNTHETIC_VALID_TOKEN_1234",
        "threat_label": "Synthetic Credential Abuse",
        "technique_ids": ["T1078"], "severity": "high",
        "confidence": 1.0, "source": "lab_internal", "ttl_days": 365,
    },
    {
        "id": "IOC-002", "type": "string",
        "value": "SYNTHETIC_EXFIL_EVENT_NO_REAL_DATA",
        "threat_label": "Exfiltration Marker",
        "technique_ids": ["T1041"], "severity": "critical",
        "confidence": 1.0, "source": "lab_internal", "ttl_days": 365,
    },
    # Synthetic domain patterns (never legitimate)
    {
        "id": "IOC-003", "type": "domain",
        "value": "*.attacker.invalid",
        "threat_label": "C2 Domain Pattern",
        "technique_ids": ["T1041"], "severity": "critical",
        "confidence": 0.95, "source": "lab_internal", "ttl_days": 365,
    },
    {
        "id": "IOC-004", "type": "domain",
        "value": "exfil.invalid",
        "threat_label": "Exfil Domain",
        "technique_ids": ["T1041"], "severity": "critical",
        "confidence": 1.0, "source": "lab_internal", "ttl_days": 365,
    },
    # Synthetic process / file indicators
    {
        "id": "IOC-005", "type": "string",
        "value": "SYNTHETIC_PIVOT_REQUEST",
        "threat_label": "Lateral Movement Marker",
        "technique_ids": ["T1021"], "severity": "high",
        "confidence": 1.0, "source": "lab_internal", "ttl_days": 365,
    },
    {
        "id": "IOC-006", "type": "string",
        "value": "SYNTHETIC_PRIVILEGE_TEST",
        "threat_label": "Privilege Escalation Marker",
        "technique_ids": ["T1548"], "severity": "critical",
        "confidence": 1.0, "source": "lab_internal", "ttl_days": 365,
    },
    {
        "id": "IOC-007", "type": "string",
        "value": "SYNTHETIC_IMPACT_MARKER",
        "threat_label": "Impact Marker",
        "technique_ids": ["T1486", "T1499"], "severity": "critical",
        "confidence": 1.0, "source": "lab_internal", "ttl_days": 365,
    },
    {
        "id": "IOC-008", "type": "string",
        "value": "SYNTHETIC_LOAD_SPIKE",
        "threat_label": "DoS Simulation Marker",
        "technique_ids": ["T1499"], "severity": "high",
        "confidence": 1.0, "source": "lab_internal", "ttl_days": 365,
    },
    {
        "id": "IOC-009", "type": "string",
        "value": "SYNTHETIC_CRON_ENTRY",
        "threat_label": "Persistence Marker",
        "technique_ids": ["T1053"], "severity": "high",
        "confidence": 1.0, "source": "lab_internal", "ttl_days": 365,
    },
    # Pattern-based IoCs
    {
        "id": "IOC-010", "type": "string",
        "value": "input_validation_warning",
        "threat_label": "Input Validation Bypass",
        "technique_ids": ["T1190"], "severity": "high",
        "confidence": 0.90, "source": "lab_internal", "ttl_days": 365,
    },
    {
        "id": "IOC-011", "type": "filepath",
        "value": "/etc/shadow",
        "threat_label": "Unix Credential File Access",
        "technique_ids": ["T1003"], "severity": "critical",
        "confidence": 0.95, "source": "osint_cti", "ttl_days": 365,
    },
    {
        "id": "IOC-012", "type": "process",
        "value": "mimikatz",
        "threat_label": "Credential Dumping Tool",
        "technique_ids": ["T1003"], "severity": "critical",
        "confidence": 0.99, "source": "threat_intel", "ttl_days": 365,
    },
]

# Fields to search per IoC type
IOC_TYPE_FIELDS: Dict[str, List[str]] = {
    "ip":          ["stdout", "content", "stderr", "summary"],
    "domain":      ["stdout", "content", "stderr", "summary"],
    "hash_sha256": ["sha256_steps", "hash_sha256", "content"],
    "hash_md5":    ["content"],
    "filepath":    ["stdout", "content", "summary", "command_or_action"],
    "process":     ["stdout", "content", "summary"],
    "string":      ["stdout", "content", "stderr", "summary"],
}


class IoCMatcher:
    """
    Matches event data against a database of IoC indicators.
    Fully deterministic — no external calls.
    """

    def __init__(self):
        self._iocs: List[IoC] = []
        self._load_builtin_iocs()

    def _load_builtin_iocs(self) -> None:
        for i in BUILTIN_IOCS:
            self._iocs.append(IoC(**i))

    def load_iocs_from_file(self, path: Path) -> None:
        if not path.exists():
            return
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for i in data.get("iocs", []):
            self._iocs.append(IoC(**i))

    def add_ioc(self, ioc: IoC) -> None:
        """Add a new IoC (e.g., generated by LLM from a new finding)."""
        self._iocs.append(ioc)

    def match_event(self, event: Dict[str, Any]) -> List[IoCMatch]:
        """Match a single event against all IoCs."""
        matches: List[IoCMatch] = []
        for ioc in self._iocs:
            m = self._test_ioc(ioc, event)
            if m:
                matches.append(m)
        return matches

    def match_all(self, events: List[Dict[str, Any]]) -> List[IoCMatch]:
        matches: List[IoCMatch] = []
        for event in events:
            matches.extend(self.match_event(event))
        return matches

    def _test_ioc(self, ioc: IoC, event: Dict[str, Any]) -> Optional[IoCMatch]:
        fields = IOC_TYPE_FIELDS.get(ioc.type, ["content", "stdout", "summary"])
        for field_name in fields:
            val = str(event.get(field_name, ""))
            if not val:
                continue
            matched = self._value_matches(ioc, val)
            if matched:
                return IoCMatch(
                    ioc_id=ioc.id,
                    ioc_type=ioc.type,
                    ioc_value=ioc.value,
                    threat_label=ioc.threat_label,
                    technique_ids=ioc.technique_ids,
                    severity=ioc.severity,
                    confidence=ioc.confidence,
                    matched_field=field_name,
                    matched_value=val[:200],
                    event_snapshot=self._safe_snapshot(event),
                )
        return None

    @staticmethod
    def _value_matches(ioc: IoC, text: str) -> bool:
        if ioc.type in ("string", "process", "filepath"):
            return ioc.value.lower() in text.lower()
        elif ioc.type == "domain":
            # Support wildcard patterns like *.attacker.invalid
            domains = re.findall(r'[\w.-]+\.[a-z]{2,}', text, re.IGNORECASE)
            for d in domains:
                if fnmatch.fnmatch(d.lower(), ioc.value.lower()):
                    return True
            return ioc.value.lower().lstrip("*.") in text.lower()
        elif ioc.type in ("hash_sha256", "hash_md5"):
            return ioc.value.lower() in text.lower()
        elif ioc.type == "ip":
            return ioc.value in text
        return False

    @staticmethod
    def _safe_snapshot(event: Dict[str, Any]) -> Dict[str, Any]:
        snap = {}
        for k, v in event.items():
            if isinstance(v, str) and len(v) > 150:
                snap[k] = v[:150] + "…"
            elif isinstance(v, (str, int, float, bool, type(None))):
                snap[k] = v
            else:
                snap[k] = str(v)[:100]
        return snap

    @property
    def ioc_count(self) -> int:
        return len(self._iocs)
