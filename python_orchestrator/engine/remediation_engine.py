"""
engine/remediation_engine.py
============================
Converts findings into a prioritized remediation backlog with:
  - Ticket creation per finding
  - Owner team assignment (security / platform / engineering)
  - SLA calculation based on severity
  - Detection rule generation recommendations
  - Backlog deduplication
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

from python_orchestrator.core.models import Finding, RemediationTicket


# SLA in days per severity level
SLA_BY_SEVERITY: Dict[str, int] = {
    "critical": 1,
    "high":     7,
    "medium":  30,
    "low":     90,
}

# Owner team assignment rules
OWNER_BY_TACTIC: Dict[str, str] = {
    "Initial Access":        "security",
    "Execution":             "platform",
    "Persistence":           "platform",
    "Privilege Escalation":  "security",
    "Defense Evasion":       "security",
    "Credential Access":     "security",
    "Discovery":             "security",
    "Lateral Movement":      "platform",
    "Collection":            "engineering",
    "Exfiltration":          "security",
    "Impact":                "platform",
    "Reconnaissance":        "security",
}

# Controls to apply per technique
CONTROLS_BY_TECHNIQUE: Dict[str, List[str]] = {
    "T1190": [
        "Input validation hardening at all API/service boundaries",
        "Dependency scanning + patching (SCA in CI)",
        "WAF rule tuning for payload patterns",
        "Compile-time hardening flags (-fstack-protector-strong, RELRO)",
    ],
    "T1059": [
        "Restrict script execution via allowlist (AppLocker, seccomp)",
        "Replace shell=True with explicit argument arrays",
        "Command audit logging (auditd, eBPF) for all scripting interpreters",
        "Enforce least-privilege for automation service accounts",
    ],
    "T1053": [
        "Audit and prune all scheduled tasks / cron jobs",
        "Monitor crontab and at-job changes via FIM",
        "Restrict cron write permissions to authorized users only",
    ],
    "T1078": [
        "Enforce MFA for all interactive and service accounts",
        "Rotate compromised or long-lived credentials immediately",
        "Implement credential anomaly detection (UEBA)",
    ],
    "T1548": [
        "Audit sudo rules and remove broad NOPASSWD grants",
        "Enable PAM logging for elevation events",
        "Implement just-in-time privilege access model",
    ],
    "T1562": [
        "Implement agent health monitoring with alerting",
        "Enforce immutable/append-only logging to separate storage",
        "Alert on absence of expected telemetry (gap detection)",
    ],
    "T1003": [
        "Enable LSA protection / Credential Guard",
        "Restrict LSASS memory reads via EDR policy",
        "Rotate all secrets exposed by credential access event",
    ],
    "T1082": [
        "Deploy canary tokens / honeypot data to detect discovery",
        "Baseline and alert on unusual system enumeration commands",
    ],
    "T1021": [
        "Enforce network segmentation and micro-segmentation",
        "Restrict lateral SSH/RDP/WinRM to authorized management hosts only",
        "Deploy east-west traffic monitoring",
    ],
    "T1005": [
        "Apply filesystem ACLs to data directories",
        "Enable file access auditing (auditd -w on sensitive paths)",
        "Enforce data classification tagging and DLP policies",
    ],
    "T1041": [
        "Implement egress filtering with destination allowlisting",
        "Deploy DLP with network inspection for outbound transfers",
        "Enable DNS monitoring / sinkholing for anomalous domains",
    ],
    "T1486": [
        "Implement offline / immutable backups",
        "Deploy ransomware-specific EDR behavioral detections",
        "Test backup restoration procedures quarterly",
    ],
    "T1499": [
        "Deploy rate limiting and connection quotas",
        "Implement availability monitoring with auto-remediation",
        "Conduct load test to validate capacity thresholds",
    ],
}

# Detection rules to create per technique
DETECTION_RULES_BY_TECHNIQUE: Dict[str, List[str]] = {
    "T1190": [
        "SIEM: Alert on HTTP 5xx spike from single source IP",
        "WAF: Rule for oversized request bodies (>8KB default)",
        "EDR: Alert on application crash / core dump creation",
    ],
    "T1059": [
        "EDR: Alert on unexpected scripting interpreter spawned by service account",
        "SIEM: Sigma rule for shell metacharacters in process arguments",
        "Audit: Enable script block logging (PowerShell, Python exec events)",
    ],
    "T1562": [
        "SIEM: Alert on agent health heartbeat absence >5 minutes",
        "SIEM: Alert on security rule modification events",
        "Monitor: Dashboard tile for telemetry coverage % per asset",
    ],
    "T1003": [
        "EDR: Alert on LSASS memory read from non-system process",
        "SIEM: Alert on /etc/shadow or Windows SAM access",
        "Monitor: Alert on secrets manager unusual access patterns",
    ],
    "T1041": [
        "Network: DLP alert on outbound transfer >100MB to unknown destination",
        "DNS: Alert on queries to newly-registered or randomized domains",
        "Proxy: Block outbound to non-allow-listed external endpoints",
    ],
    "T1005": [
        "Audit: Alert on mass file read from non-standard process",
        "DLP: Alert on access to data_classification=confidential files",
        "SIEM: Correlation rule for unusual data staging patterns",
    ],
}

DEFAULT_CONTROLS    = ["Review and apply appropriate compensating controls"]
DEFAULT_DETECTIONS  = ["Create SIEM use case for this technique variant"]


class RemediationEngine:
    """
    Converts confirmed findings into a prioritized, deduplicated remediation backlog.
    """

    def __init__(self):
        self._tickets: Dict[str, RemediationTicket] = {}   # keyed by finding_id

    def process_findings(self, findings: List[Finding]) -> List[RemediationTicket]:
        """
        Create one RemediationTicket per unique finding.
        Deduplication: if a ticket already exists for finding.id, update priority only.
        """
        for finding in findings:
            if finding.id in self._tickets:
                # Update priority if new finding is more severe
                existing = self._tickets[finding.id]
                if self._severity_rank(finding.severity) < existing.priority:
                    existing.priority = self._severity_rank(finding.severity)
                continue

            ticket = self._create_ticket(finding)
            self._tickets[finding.id] = ticket

        return self.get_backlog()

    def _create_ticket(self, finding: Finding) -> RemediationTicket:
        sla   = SLA_BY_SEVERITY.get(finding.severity, 30)
        prio  = self._severity_rank(finding.severity)

        # Determine owner team from technique → tactic mapping (simplified)
        tactic_hint = self._tactic_from_technique(finding.technique_id)
        owner = OWNER_BY_TACTIC.get(tactic_hint, "security")

        controls   = CONTROLS_BY_TECHNIQUE.get(finding.technique_id, DEFAULT_CONTROLS)
        detections = DETECTION_RULES_BY_TECHNIQUE.get(finding.technique_id, DEFAULT_DETECTIONS)

        # If detection gap, add gap-specific detection rule
        if finding.detection_status == "gap":
            detections = detections + [
                f"PRIORITY: Create detection rule for {finding.technique_id} — "
                "currently ZERO coverage on this technique."
            ]

        title = (
            f"[{finding.severity.upper()}] Harden {finding.asset} against "
            f"{finding.technique_id} (score: {finding.score})"
        )
        description = (
            f"Finding {finding.id} confirmed {finding.technique_id} exposure on "
            f"asset '{finding.asset}'. "
            f"Detection status: {finding.detection_status}. "
            f"Reproducible: {finding.reproducible}. "
            f"Summary: {finding.summary}"
        )

        return RemediationTicket(
            id=f"REM-{uuid.uuid4().hex[:8].upper()}",
            finding_id=finding.id,
            title=title,
            description=description,
            priority=prio,
            owner_team=owner,
            sla_days=sla,
            controls_to_apply=controls,
            detection_rules_needed=detections,
            status="open",
            created_at=datetime.utcnow().isoformat(),
        )

    def get_backlog(self) -> List[RemediationTicket]:
        """Return all tickets sorted by priority (1 = most urgent)."""
        return sorted(self._tickets.values(), key=lambda t: t.priority)

    def backlog_summary(self) -> Dict[str, Any]:
        tickets = self.get_backlog()
        by_owner: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        for t in tickets:
            by_owner[t.owner_team]  = by_owner.get(t.owner_team, 0) + 1
            by_status[t.status]     = by_status.get(t.status, 0) + 1
        return {
            "total_tickets": len(tickets),
            "by_owner": by_owner,
            "by_status": by_status,
            "critical_sla_1day": sum(1 for t in tickets if t.sla_days == 1),
            "high_sla_7day":     sum(1 for t in tickets if t.sla_days == 7),
        }

    @staticmethod
    def _severity_rank(severity: str) -> int:
        return {"critical": 1, "high": 2, "medium": 3, "low": 4}.get(severity, 3)

    @staticmethod
    def _tactic_from_technique(technique_id: str) -> str:
        mapping = {
            "T1190": "Initial Access",
            "T1059": "Execution",
            "T1053": "Persistence",
            "T1078": "Credential Access",
            "T1548": "Privilege Escalation",
            "T1562": "Defense Evasion",
            "T1003": "Credential Access",
            "T1082": "Discovery",
            "T1021": "Lateral Movement",
            "T1005": "Collection",
            "T1041": "Exfiltration",
            "T1486": "Impact",
            "T1499": "Impact",
            "T1595": "Reconnaissance",
        }
        return mapping.get(technique_id, "Defense Evasion")
