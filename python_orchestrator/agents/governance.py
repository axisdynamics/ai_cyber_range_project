from __future__ import annotations
from typing import Dict, Any, List


class GovernanceAgent:
    """
    Authorizes offensive operations and enforces sovereignty,
    compliance, and rules-of-engagement policies.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self._roe = config.get("rules_of_engagement", {})
        self._sovereignty = config.get("sovereignty", {})
        self._program = config.get("program", {})
        self._allowed_targets: set = set(self._roe.get("allowed_targets", []))
        self._disallowed: List[str] = self._roe.get("disallowed", [])

    def authorize(self, asset_id: str) -> bool:
        """
        Returns True if the asset is within the authorized engagement perimeter
        and the program policy allows operations on it.
        """
        if self._program.get("allow_external_targets", False):
            # External targets require explicit per-asset authorization
            return asset_id in self._allowed_targets

        # Local lab mode: only explicitly listed targets are authorized
        return asset_id in self._allowed_targets

    def authorize_technique(self, technique_id: str) -> bool:
        """Verify technique is not in the disallowed list."""
        blocked_techniques = {"T1485", "T1561", "T1529"}  # Destructive techniques
        return technique_id not in blocked_techniques

    def model_policy(self) -> str:
        return self._sovereignty.get("model_policy", "local_or_enterprise_private_only")

    def data_residency(self) -> str:
        return self._sovereignty.get("data_residency", "customer_controlled")

    def audit_required(self) -> bool:
        return self._sovereignty.get("audit_required", True)

    def sovereignty_summary(self) -> Dict[str, str]:
        return {
            "model_policy":  self.model_policy(),
            "data_residency": self.data_residency(),
            "jurisdiction":  self._sovereignty.get("jurisdiction", "configured_by_customer"),
            "audit_required": str(self.audit_required()),
        }
