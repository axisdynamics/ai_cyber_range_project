from __future__ import annotations
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Any, Optional
from datetime import datetime


# ─── Base inventory ───────────────────────────────────────────────────────────

@dataclass
class Asset:
    id: str
    name: str
    type: str
    criticality: int          # 1-5
    exposure: str             # local_only | internal | external
    data_classification: str  # synthetic | internal | confidential | secret

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Technique:
    id: str
    name: str
    tactic: str
    safe_lab_use: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── Engagement perimeter ─────────────────────────────────────────────────────

@dataclass
class EngagementPerimeter:
    """Defines the authorized attack surface and rules of engagement."""
    authorized_asset_ids: List[str]
    authorized_technique_ids: List[str]
    max_chain_depth: int = 5
    allow_evasion_tests: bool = True
    allow_chain_simulation: bool = True
    disallowed_actions: List[str] = field(default_factory=list)
    engagement_id: str = ""
    authorized_by: str = "governance_agent"

    def is_asset_authorized(self, asset_id: str) -> bool:
        return asset_id in self.authorized_asset_ids

    def is_technique_authorized(self, technique_id: str) -> bool:
        return technique_id in self.authorized_technique_ids

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── Offensive scenarios ──────────────────────────────────────────────────────

@dataclass
class Scenario:
    id: str
    asset_id: str
    technique_id: str
    objective: str
    authorized: bool
    tactic: str = ""
    priority: int = 3         # 1 (highest) – 5 (lowest)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackHypothesis:
    """A hypothesis about a possible attack route for a given asset."""
    id: str
    asset_id: str
    technique_id: str
    entry_point: str
    attack_goal: str
    assumed_control_gaps: List[str]
    confidence: float         # 0.0 – 1.0
    generated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackChainStep:
    """One step in a multi-stage kill chain."""
    step_no: int
    tactic: str               # MITRE tactic name
    technique_id: str
    technique_name: str
    action: str               # what the attacker does
    expected_artifact: str    # what evidence this step leaves
    depends_on: List[int] = field(default_factory=list)  # step_no dependencies

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackChain:
    """A complete simulated kill chain for an asset/scenario."""
    id: str
    asset_id: str
    chain_name: str
    objective: str
    steps: List[AttackChainStep]
    total_steps: int = 0
    simulated_at: str = ""

    def __post_init__(self):
        self.total_steps = len(self.steps)
        if not self.simulated_at:
            self.simulated_at = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── Evasion testing ──────────────────────────────────────────────────────────

@dataclass
class EvasionResult:
    """Result of testing whether an attack step evades a specific control."""
    scenario_id: str
    technique_id: str
    control_tested: str
    evaded: bool              # True = control bypassed (detection gap)
    detection_latency_ms: Optional[int]
    evasion_method: str
    notes: str
    tested_at: str = ""

    def __post_init__(self):
        if not self.tested_at:
            self.tested_at = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── PoC artifacts ────────────────────────────────────────────────────────────

@dataclass
class PoCStep:
    order: int
    description: str
    command_or_action: str
    expected_output: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PoCArtifact:
    """A reproducible, documented proof-of-concept for a finding."""
    id: str
    finding_id: str
    technique_id: str
    asset_id: str
    title: str
    description: str
    prerequisites: List[str]
    steps: List[PoCStep]
    indicators_of_compromise: List[str]
    remediation_hint: str
    reproducible: bool
    created_at: str = ""
    sha256_steps: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── Evidence ─────────────────────────────────────────────────────────────────

@dataclass
class EvidenceRecord:
    """Structured evidence item with traceability."""
    id: str
    scenario_id: str
    asset_id: str
    technique_id: str
    evidence_type: str        # log | stdout | poc | chain_step | evasion
    content: str
    hash_sha256: str
    collected_at: str
    collector: str            # which agent collected this
    chain_of_custody: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── Findings & scoring ───────────────────────────────────────────────────────

@dataclass
class Finding:
    id: str
    asset: str
    technique_id: str
    severity: str             # low | medium | high | critical
    reproducible: bool
    evidence_path: str
    summary: str
    detection_status: str     # detected | gap | partial
    score: float
    attack_chain_id: Optional[str] = None
    poc_id: Optional[str] = None
    evasion_results: List[str] = field(default_factory=list)
    cve_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── Remediation ─────────────────────────────────────────────────────────────

@dataclass
class RemediationTicket:
    """A prioritized remediation work item."""
    id: str
    finding_id: str
    title: str
    description: str
    priority: int             # 1 (critical) – 5 (low)
    owner_team: str           # security | platform | engineering
    sla_days: int
    controls_to_apply: List[str]
    detection_rules_needed: List[str]
    status: str = "open"      # open | in_progress | resolved | accepted_risk
    created_at: str = ""
    resolved_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── Change events (CI/CD trigger) ────────────────────────────────────────────

@dataclass
class ChangeEvent:
    """A detected change that should trigger a new offensive run."""
    id: str
    change_type: str          # code | infra | config | exposure | model
    asset_affected: str
    description: str
    detected_at: str
    trigger_full_scan: bool = False
    triggered_scenarios: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── Full offensive run result ────────────────────────────────────────────────

@dataclass
class OffensiveRunResult:
    """Aggregated result of a complete offensive program cycle."""
    run_id: str
    engagement_id: str
    started_at: str
    finished_at: str
    hypotheses_generated: int
    chains_simulated: int
    evasion_tests_run: int
    pocs_built: int
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    top_findings: List[Dict[str, Any]]
    remediation_tickets: List[Dict[str, Any]]
    coverage_pct: float       # % of techniques tested vs authorized perimeter
    detection_gap_pct: float  # % findings that evaded detection

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
