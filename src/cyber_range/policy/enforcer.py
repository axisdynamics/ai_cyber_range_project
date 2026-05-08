"""
cyber_range.policy.enforcer
============================
Policy enforcement module. Every execution passes through a pre-flight
policy check before any simulation code runs.

The enforcer is the single authority on what is and is not permitted.
It logs every authorization decision.

Fail-closed by design: when in doubt, block and explain.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from cyber_range.config.schema import CyberRangeConfig

_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# Techniques that are ALWAYS blocked regardless of config
HARDCODED_BLOCKED = frozenset({"T1485", "T1561", "T1529"})

# IP patterns that indicate external targets
_EXTERNAL_IP_RE = re.compile(
    r"^(?!(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.))\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
)


class PolicyVerdict(str, Enum):
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"


@dataclass
class PolicyDecision:
    verdict:   PolicyVerdict
    reason:    str
    technique: Optional[str] = None
    asset:     Optional[str] = None
    context:   dict = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.verdict == PolicyVerdict.ALLOWED

    def __str__(self) -> str:
        prefix = "✓" if self.allowed else "✗"
        return f"[{prefix} {self.verdict.value}] {self.reason}"


class PolicyEnforcer:
    """
    Stateless policy enforcer.

    All checks are deterministic given a config.
    No external calls, no side effects — only returns PolicyDecision.
    """

    def __init__(self, config: CyberRangeConfig):
        self.cfg = config
        self._decisions: List[PolicyDecision] = []

    # ── Public API ─────────────────────────────────────────────────────────────

    def check_technique(self, technique_id: str) -> PolicyDecision:
        """Check if a technique is permitted."""
        if not _TECHNIQUE_RE.match(technique_id):
            d = PolicyDecision(
                verdict=PolicyVerdict.BLOCKED,
                reason=f"Invalid technique ID format: '{technique_id}'",
                technique=technique_id,
            )
            return self._record(d)

        if technique_id in HARDCODED_BLOCKED:
            d = PolicyDecision(
                verdict=PolicyVerdict.BLOCKED,
                reason=f"Technique {technique_id} is hardcoded-blocked (destructive action)",
                technique=technique_id,
            )
            return self._record(d)

        if technique_id in self.cfg.engagement.blocked_techniques:
            d = PolicyDecision(
                verdict=PolicyVerdict.BLOCKED,
                reason=f"Technique {technique_id} is blocked by engagement configuration",
                technique=technique_id,
            )
            return self._record(d)

        return self._record(PolicyDecision(
            verdict=PolicyVerdict.ALLOWED,
            reason=f"Technique {technique_id} is authorized",
            technique=technique_id,
        ))

    def check_asset(self, asset_id: str) -> PolicyDecision:
        """Check if an asset is within authorized scope."""
        authorized = self.cfg.engagement.authorized_assets
        if authorized and asset_id not in authorized:
            return self._record(PolicyDecision(
                verdict=PolicyVerdict.BLOCKED,
                reason=f"Asset '{asset_id}' is outside authorized scope",
                asset=asset_id,
            ))

        if self._looks_like_external_target(asset_id):
            return self._record(PolicyDecision(
                verdict=PolicyVerdict.BLOCKED,
                reason=f"Asset '{asset_id}' appears to be an external target. "
                       f"allow_external_targets={self.cfg.engagement.allow_external_targets}",
                asset=asset_id,
            ))

        return self._record(PolicyDecision(
            verdict=PolicyVerdict.ALLOWED,
            reason=f"Asset '{asset_id}' is within authorized scope",
            asset=asset_id,
        ))

    def check_scenario(self, asset_id: str, technique_id: str) -> PolicyDecision:
        """Check if a complete scenario (asset × technique) is permitted."""
        asset_check = self.check_asset(asset_id)
        if not asset_check.allowed:
            return asset_check

        tech_check = self.check_technique(technique_id)
        if not tech_check.allowed:
            return tech_check

        return self._record(PolicyDecision(
            verdict=PolicyVerdict.ALLOWED,
            reason=f"Scenario {technique_id} on {asset_id} is authorized",
            technique=technique_id,
            asset=asset_id,
        ))

    def check_external_target(self, target: str) -> PolicyDecision:
        """Explicit check for external target attempts."""
        if self._looks_like_external_target(target):
            return self._record(PolicyDecision(
                verdict=PolicyVerdict.BLOCKED,
                reason=f"SOVEREIGNTY VIOLATION: '{target}' is an external target. "
                       "This system only operates on local authorized fixtures.",
                context={"target": target},
            ))
        return self._record(PolicyDecision(
            verdict=PolicyVerdict.ALLOWED,
            reason=f"Target '{target}' is local",
        ))

    def assert_allowed(self, decision: PolicyDecision) -> None:
        """Raise PolicyViolationError if decision is BLOCKED."""
        if not decision.allowed:
            raise PolicyViolationError(decision)

    @property
    def decisions(self) -> List[PolicyDecision]:
        return list(self._decisions)

    @property
    def blocked_count(self) -> int:
        return sum(1 for d in self._decisions if not d.allowed)

    # ── Internal ───────────────────────────────────────────────────────────────

    def _record(self, decision: PolicyDecision) -> PolicyDecision:
        self._decisions.append(decision)
        return decision

    @staticmethod
    def _looks_like_external_target(target: str) -> bool:
        """Heuristic: detect IPs or hostnames that suggest external targets."""
        if _EXTERNAL_IP_RE.match(target):
            return True
        external_markers = [".com", ".net", ".org", ".io", ".gov",
                            "amazonaws", "azure", "gcloud", "external"]
        low = target.lower()
        return any(m in low for m in external_markers)


class PolicyViolationError(Exception):
    """Raised when a policy check fails and execution must stop."""

    def __init__(self, decision: PolicyDecision):
        self.decision = decision
        super().__init__(str(decision))
